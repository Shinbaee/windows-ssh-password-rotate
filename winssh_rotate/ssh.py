"""The only module that imports paramiko. The flow talks to `connect(user, password)` returning a
session with `run(command, stdin)` and `shell()`, so it can be tested against a fake host."""

from __future__ import annotations

import socket
from dataclasses import dataclass


class AuthFailed(Exception):
    pass


class Unreachable(Exception):
    pass


@dataclass(frozen=True)
class Host:
    address: str
    port: int = 22
    known_hosts: str | None = None
    timeout: float = 20.0


class Session:
    def __init__(self, client, timeout: float):
        self._client = client
        self._timeout = timeout

    def run(self, command: str, stdin: str = "") -> tuple[int, str, str]:
        """Exec channel, no terminal: no ConPTY, no prompt, no echo. stdin is written then closed."""
        chan = self._client.get_transport().open_session(timeout=self._timeout)
        chan.settimeout(self._timeout)
        chan.exec_command(command)
        if stdin:
            chan.sendall(stdin.encode("utf-8"))
        chan.shutdown_write()
        out = chan.makefile("rb").read()          # until the remote side closes stdout
        err = chan.makefile_stderr("rb").read()   # small here; paramiko buffers it meanwhile
        code = chan.recv_exit_status()
        chan.close()
        return code, out.decode("utf-8", "replace"), err.decode("utf-8", "replace")

    def shell(self, width: int = 120, height: int = 40):
        """An interactive shell with a pseudo terminal: what screen-scraping scripts use. Only `probe` needs it."""
        chan = self._client.invoke_shell(width=width, height=height)
        chan.settimeout(self._timeout)
        return chan

    def close(self) -> None:
        self._client.close()


def connect(host: Host, user: str, password: str) -> Session:
    import paramiko
    client = paramiko.SSHClient()
    client.load_system_host_keys()
    if host.known_hosts:
        client.load_host_keys(host.known_hosts)
    client.set_missing_host_key_policy(paramiko.RejectPolicy())  # unknown host key -> refuse
    try:
        client.connect(host.address, port=host.port, username=user, password=password, timeout=host.timeout,
                       banner_timeout=host.timeout, auth_timeout=host.timeout, allow_agent=False,
                       look_for_keys=False)
    except paramiko.AuthenticationException:
        client.close()
        raise AuthFailed(f"{user}: authentication failed") from None
    except paramiko.SSHException as e:
        client.close()
        msg = str(e)
        if "not found in known_hosts" in msg:
            msg += " (add the host key to known_hosts first; unknown keys are never accepted)"
        elif "kex" in msg.lower() or "incompatible" in msg.lower():
            msg += " (no common key exchange or host key algorithm with the server)"
        raise Unreachable(msg) from None
    except (socket.error, OSError) as e:
        client.close()
        raise Unreachable(f"{host.address}:{host.port}: {type(e).__name__}: {e}") from None
    return Session(client, host.timeout)
