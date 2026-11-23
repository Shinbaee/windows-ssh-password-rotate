"""A stand-in for a Windows host behind OpenSSH, for the cases the tool must tell apart.

It decodes the -EncodedCommand the tool sends and understands exactly the two scripts in
winssh_rotate/remote.py; anything else gets no marker line, which the tool must treat as a failure.
Its answers carry a banner and terminal codes, as real ones can.
"""

from __future__ import annotations

import base64
import re
from dataclasses import dataclass

from winssh_rotate.remote import MARKER
from winssh_rotate.ssh import AuthFailed, Unreachable

NAME = re.compile(r"^\$name = '((?:[^']|'')*)'$", re.M)
NOISE = "\x1b]0;C:\\Windows\\system32\\conhost.exe\x07\x1b[?25l"


@dataclass
class User:
    password: str
    admin: bool = False
    locked: bool = False
    disabled: bool = False
    failures: int = 0


class FakeHost:
    def __init__(self):
        self.users = {"admin": User("Admin-pass-0001", admin=True), "svc_app": User("Initial-pass-001"),
                      "O'Brien": User("Obrien-pass-0001")}
        self.min_length = 12
        self.lock_after = 3
        self.down = False
        self.silent_no_save = False
        self.store_other = False
        self.commands: list[str] = []
        self.stdins: list[str] = []
        self.attempts: list[tuple[str, bool]] = []

    def connect(self, user, password):
        if self.down:
            raise Unreachable("host:22: TimeoutError: timed out")
        u = self.users.get(user)
        ok = u is not None and not u.locked and not u.disabled and u.password == password
        self.attempts.append((user, ok))
        if not ok:
            if u is not None and not u.locked and u.password != password:
                u.failures += 1
                u.locked = u.failures >= self.lock_after
            raise AuthFailed(f"{user}: authentication failed")  # Windows says no more than this
        u.failures = 0
        return FakeSession(self, user)


class FakeSession:
    def __init__(self, host, user):
        self.host, self.user = host, user

    def run(self, command, stdin=""):
        h = self.host
        h.commands.append(command)
        h.stdins.append(stdin)
        if " -EncodedCommand " not in command:
            return 1, "'x' is not recognized as an internal or external command", ""
        script = base64.b64decode(command.rsplit(" ", 1)[1]).decode("utf-16-le")
        name = NAME.search(script).group(1).replace("''", "'")
        u = h.users.get(name)

        def answer(status, detail=""):
            return 0, f"{NOISE}Windows PowerShell\r\n{NOISE}{MARKER}{status}:{detail}\r\n", ""

        if "Win32_UserAccount" in script:
            if u is None:
                return answer("NOT_FOUND")
            return answer("STATUS", f"locked={u.locked},disabled={u.disabled}")
        if "Set-LocalUser" not in script:
            return 0, "", ""
        pw = stdin.rstrip("\n")
        if not pw:
            return answer("NO_PASSWORD")
        if u is None:
            return answer("NOT_FOUND")
        if not h.users[self.user].admin and name != self.user:
            return answer("DENIED", "Access denied.")
        if len(pw) < h.min_length:
            return answer("REJECTED", "The password does not meet the password policy requirements.")
        if not h.silent_no_save:
            u.password = pw + "x" if h.store_other else pw
        return answer("OK")

    def shell(self):
        raise NotImplementedError

    def close(self):
        pass
