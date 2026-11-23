"""Two commands:

  winssh-rotate rotate ...   change a local account's password and verify it over SSH
  winssh-rotate probe ...    show how an interactive shell on this host treats LF, CR LF and control codes
"""

from __future__ import annotations

import argparse
import os
import sys
import time

from . import flow, probe
from .ssh import AuthFailed, Host, Unreachable, connect


def parse_args(argv=None):
    p = argparse.ArgumentParser(prog="winssh-rotate", epilog="Passwords are read from environment variables only.")
    sub = p.add_subparsers(dest="cmd", required=True)

    def common(sp):
        sp.add_argument("--host", required=True)
        sp.add_argument("--port", type=int, default=22)
        sp.add_argument("--known-hosts", help="extra known_hosts file; unknown host keys are always refused")
        sp.add_argument("--timeout", type=float, default=20.0)

    r = sub.add_parser("rotate", help="change a local account's password and verify it")
    common(r)
    r.add_argument("--account", required=True, help="local account whose password is changed")
    r.add_argument("--admin-user", required=True, help="administrator account used for the change")
    r.add_argument("--admin-password-env", required=True, metavar="NAME")
    r.add_argument("--new-password-env", required=True, metavar="NAME")
    r.add_argument("--old-password-env", metavar="NAME", help="current password, to explain a failed verification")
    r.add_argument("--no-diagnose", action="store_true",
                   help="never try the old password (each wrong attempt counts toward the lockout threshold)")

    pr = sub.add_parser("probe", help="show how an interactive shell treats LF, CR LF and control codes")
    common(pr)
    pr.add_argument("--user", required=True)
    pr.add_argument("--password-env", required=True, metavar="NAME")
    pr.add_argument("--raw", type=int, default=300, help="bytes of raw output to show per phase (0 = none)")
    return p.parse_args(argv)


def env(name: str | None, what: str) -> str | None:
    if not name:
        return None
    value = os.environ.get(name)
    if not value:
        raise SystemExit(f"error: {what}: environment variable {name} is not set or empty")
    return value


def redact(text: str, secrets) -> str:
    for s in secrets:
        if s:
            text = text.replace(s, "[redacted]")
    return text


def main(argv=None, connect_fn=None) -> int:
    args = parse_args(argv)
    host = Host(args.host, args.port, args.known_hosts, args.timeout)
    fn = connect_fn or (lambda user, pw: connect(host, user, pw))

    if args.cmd == "probe":
        try:
            pw = env(args.password_env, "password")
        except SystemExit as e:
            print(e, file=sys.stderr)
            return flow.USAGE
        try:
            s = fn(args.user, pw)
        except (AuthFailed, Unreachable) as e:
            print(f"FAIL: {e}")
            return flow.UNREACHABLE if isinstance(e, Unreachable) else flow.ADMIN_SIGN_IN_FAILED
        try:
            print(redact(probe.run(s).text(args.raw), [pw]))
        finally:
            s.close()
        return 0

    secrets: list[str] = []

    def log(msg: str) -> None:
        print(f"{time.strftime('%H:%M:%S')} {redact(msg, secrets)}", file=sys.stderr, flush=True)

    def result(code: int, msg: str) -> int:
        print(redact("OK: " + msg if code == 0 else f"FAIL {code}: {msg}", secrets), flush=True)
        return code

    try:
        admin_pw = env(args.admin_password_env, "admin password")
        new = env(args.new_password_env, "new password")
        old = env(args.old_password_env, "old password")
    except SystemExit as e:
        print(e, file=sys.stderr)
        return flow.USAGE
    secrets += [s for s in (admin_pw, new, old) if s]
    if "\n" in new or "\r" in new:
        print("error: new password contains a line break", file=sys.stderr)
        return flow.USAGE
    if old is not None and old == new:
        print("error: new password equals the old one; the verification could not tell them apart", file=sys.stderr)
        return flow.USAGE

    req = flow.Request(args.account, new, old, args.admin_user, admin_pw, diagnose=not args.no_diagnose)
    log(f"start: {args.account} on {args.host}:{args.port}")
    try:
        return result(flow.OK, flow.rotate(fn, req, log))
    except flow.Failure as e:
        return result(e.code, str(e))
    except Unreachable as e:
        return result(flow.UNREACHABLE, str(e))
    except Exception as e:  # never a traceback: frames may hold the password
        return result(1, f"unexpected {type(e).__name__}: {str(e).splitlines()[0] if str(e) else ''}")


if __name__ == "__main__":
    sys.exit(main())
