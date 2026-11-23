"""Look at what an interactive SSH shell really sends back, before guessing why a screen-scraping script fails.

Three questions, each answered from the raw bytes:
  1. Does LF ("\\n") alone run a command, or does the shell wait for CR?
  2. Does CR LF run it?
  3. Are there terminal control codes in the output, and does command text hide inside them
     (a window-title sequence repeating the command line can make a naive "is X in the output" match)?
"""

from __future__ import annotations

import re
import time
from dataclasses import dataclass, field

CSI = re.compile(r"\x1b\[[0-9;?]*[ -/]*[@-~]")
OSC = re.compile(r"\x1b\]([^\x07\x1b]*)(?:\x07|\x1b\\)")


def strip(text: str) -> str:
    return OSC.sub("", CSI.sub("", text)).replace("\r", "")


def read_quiet(chan, quiet: float = 1.0, limit: float = 6.0) -> bytes:
    """Read until nothing arrives for `quiet` seconds (or `limit` in total)."""
    buf, start, last = bytearray(), time.monotonic(), time.monotonic()
    while time.monotonic() - start < limit:
        if chan.recv_ready():
            buf += chan.recv(65536)
            last = time.monotonic()
        elif time.monotonic() - last >= quiet:
            break
        else:
            time.sleep(0.05)
    return bytes(buf)


def ran(raw: bytes, token: str) -> bool:
    """The command ran if its output appears as a line of its own, not only as the echoed `echo <token>`."""
    return any(line.strip() == token for line in strip(raw.decode("utf-8", "replace")).split("\n"))


@dataclass
class Report:
    lf_runs: bool
    crlf_runs: bool
    merged_after_lf: bool          # LF-separated commands ended up on one line
    csi: int
    osc: int
    titles: list[str] = field(default_factory=list)
    command_in_title: bool = False
    raw: dict[str, bytes] = field(default_factory=dict)

    def text(self, show_raw: int = 300) -> str:
        yes = {True: "yes", False: "no"}
        lines = [
            f"LF alone runs a command:      {yes[self.lf_runs]}",
            f"CR LF runs a command:         {yes[self.crlf_runs]}",
            f"LF commands merged into one:  {yes[self.merged_after_lf]}",
            f"control sequences:            CSI {self.csi}, OSC {self.osc}",
            f"command text in window title: {yes[self.command_in_title]}",
        ]
        for t in self.titles[:5]:
            lines.append(f"  title: {t!r}")
        if show_raw:
            for phase, data in self.raw.items():
                lines.append(f"--- raw {phase} ({len(data)} bytes, first {show_raw}):")
                lines.append(repr(data[:show_raw]))
        return "\n".join(lines)


def analyze(lf: bytes, flush: bytes, crlf: bytes) -> Report:
    everything = (lf + flush + crlf).decode("utf-8", "replace")
    titles = OSC.findall(everything)
    return Report(
        lf_runs=ran(lf, "WSPR_LF_1"),
        crlf_runs=ran(crlf, "WSPR_CRLF"),
        merged_after_lf=not ran(lf, "WSPR_LF_1") and "WSPR_LF_1echo WSPR_LF_2" in strip(lf.decode("utf-8", "replace")
                                                                                    + flush.decode("utf-8", "replace")),
        csi=len(CSI.findall(everything)),
        osc=len(titles),
        titles=titles,
        command_in_title=any("WSPR_" in t for t in titles),
        raw={"lf": lf, "flush": flush, "crlf": crlf},
    )


def run(session) -> Report:
    chan = session.shell()
    try:
        read_quiet(chan, quiet=1.5, limit=8)               # banner and first prompt
        chan.sendall(b"echo WSPR_LF_1\necho WSPR_LF_2\n")  # what a Unix-minded script sends
        lf = read_quiet(chan)
        chan.sendall(b"\r")                                 # flush whatever is still waiting on the line
        flush = read_quiet(chan)
        chan.sendall(b"echo WSPR_CRLF\r\n")
        crlf = read_quiet(chan)
        return analyze(lf, flush, crlf)
    finally:
        chan.close()
