"""Change a Windows local account's password over SSH, then sign in over SSH with the new one.

    admin session:  PowerShell via exec channel, password on stdin -> one marker line
    new session:    the account itself, new password                 -> success
    (if refused)    admin asks Windows whether the account is locked or disabled
    (if neither)    the account with its OLD password                -> "not changed" or "both refused"
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable

from .remote import BadName, change_command, parse, status_command
from .ssh import AuthFailed, Unreachable

OK = 0
USAGE = 2
ADMIN_SIGN_IN_FAILED = 10
UNREACHABLE = 12
NOT_FOUND = 20
REJECTED = 21
NOT_PERMITTED = 22
CHANGE_FAILED = 23
NOT_CHANGED = 30
BOTH_REFUSED = 31
UNVERIFIED = 32
CANNOT_SIGN_IN = 33   # changed, but the account is locked or disabled: the new password cannot be tried
TIMEOUT = 41


class Failure(Exception):
    def __init__(self, code: int, message: str):
        super().__init__(message)
        self.code = code


@dataclass
class Request:
    account: str
    new_password: str
    old_password: str | None
    admin_user: str
    admin_password: str
    diagnose: bool = True


def _admin(connect: Callable, req: Request):
    try:
        return connect(req.admin_user, req.admin_password)
    except AuthFailed as e:
        raise Failure(ADMIN_SIGN_IN_FAILED, f"admin sign-in refused: {e}") from None
    except Unreachable as e:
        raise Failure(UNREACHABLE, f"cannot reach the host: {e}") from None


def _signs_in(connect: Callable, user: str, password: str) -> bool:
    try:
        connect(user, password).close()
        return True
    except AuthFailed:
        return False


def _account_state(connect: Callable, req: Request) -> str | None:
    """'locked', 'disabled', or None. Asked as admin, because a failed sign-in does not say why."""
    s = _admin(connect, req)
    try:
        _, out, _ = s.run(status_command(req.account))
    finally:
        s.close()
    status, detail = parse(out)
    if status != "STATUS":
        return None
    flags = dict(kv.split("=", 1) for kv in detail.split(",") if "=" in kv)
    if flags.get("locked", "").lower() == "true":
        return "locked"
    if flags.get("disabled", "").lower() == "true":
        return "disabled"
    return None


def rotate(connect: Callable, req: Request, log: Callable[[str], None]) -> str:
    try:
        command = change_command(req.account)
    except BadName as e:
        raise Failure(USAGE, str(e)) from None

    # 1) change, as admin
    s = _admin(connect, req)
    log(f"admin sign-in: ok ({req.admin_user})")
    try:
        code, out, err = s.run(command, stdin=req.new_password + "\n")
    except TimeoutError:
        raise Failure(TIMEOUT, "the change command did not answer in time") from None
    finally:
        s.close()
    status, detail = parse(out)
    log(f"change: {status}{' (' + detail + ')' if detail else ''} (exit {code})")
    if status == "NOT_FOUND":
        raise Failure(NOT_FOUND, f"account {req.account!r} does not exist")
    if status == "REJECTED":
        raise Failure(REJECTED, f"password refused by the Windows password policy: {detail}")
    if status == "DENIED":
        raise Failure(NOT_PERMITTED, f"not allowed to change {req.account!r}: {detail}")
    if status != "OK":
        hint = f"; stderr: {err.strip().splitlines()[0][:200]}" if err.strip() else ""
        raise Failure(CHANGE_FAILED, f"change failed: {status} {detail}{hint}")

    # 2) verify: a new SSH session as the account
    if _signs_in(connect, req.account, req.new_password):
        log("verify: new password signs in over SSH")
        return f"password of {req.account} changed and verified"
    log("verify: new password refused")

    # 3) why? Windows answers a locked or disabled account the same as a wrong password, so ask.
    state = _account_state(connect, req)
    if state:
        raise Failure(CANNOT_SIGN_IN, f"password changed, but {req.account} is {state}; new password not verified")
    if not req.diagnose or not req.old_password:
        raise Failure(UNVERIFIED, "new password does not sign in; old password not tried")
    if _signs_in(connect, req.account, req.old_password):
        raise Failure(NOT_CHANGED, "password was not changed: the old password still signs in")
    raise Failure(BOTH_REFUSED, "neither the new nor the old password signs in "
                                "(SSH access for this account? AllowUsers/DenyUsers in sshd_config?)")
