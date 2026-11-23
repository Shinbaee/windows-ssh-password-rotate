"""The PowerShell that runs on the Windows host, and how its answer is read.

The old way: open an interactive shell, type `net user <name> <password>`, read the screen.
That puts the password on a command line, breaks on & | ^ % in passwords, depends on the
display language, and on newer OpenSSH goes through a pseudo console (ConPTY) that adds
terminal control codes and wants CR for Enter.

Here: one exec channel, no terminal. The script is passed base64-encoded, so neither cmd.exe
nor PowerShell parses any of it; the account name is a single-quoted string literal inside it,
and the password arrives on stdin. The answer is one marker line, the same on any Windows language.
"""

from __future__ import annotations

import base64
import re

# Characters Windows does not allow in local user names, and its length limit.
FORBIDDEN = set('"/\\[]:;|=,+*?<>@')
MAX_NAME = 20
MARKER = "WSPR-RESULT:"

SCRIPT = r"""
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$name = __NAME__
function Done($status, $detail) { [Console]::Out.WriteLine('__MARK__' + $status + ':' + $detail); exit 0 }
try {
  $pw = [Console]::In.ReadLine()
  if ([string]::IsNullOrEmpty($pw)) { Done 'NO_PASSWORD' '' }
  $user = Get-LocalUser -Name $name
  Set-LocalUser -InputObject $user -Password (ConvertTo-SecureString $pw -AsPlainText -Force)
  Done 'OK' ''
} catch {
  # matched by name: the LocalAccounts types may not be loaded yet when the catch is evaluated
  $e = $_.Exception
  switch ($e.GetType().Name) {
    'UserNotFoundException'       { Done 'NOT_FOUND' '' }
    'InvalidPasswordException'    { Done 'REJECTED' $e.Message }
    'AccessDeniedException'       { Done 'DENIED' $e.Message }
    'UnauthorizedAccessException' { Done 'DENIED' $e.Message }
    default                       { Done 'ERROR' ($e.GetType().Name + ': ' + $e.Message) }
  }
}
"""

STATUS_SCRIPT = r"""
$ErrorActionPreference = 'Stop'
$name = __NAME__
$a = Get-CimInstance Win32_UserAccount -Filter ("LocalAccount=True AND Name='" + $name.Replace("'", "''") + "'")
if ($null -eq $a) { [Console]::Out.WriteLine('__MARK__NOT_FOUND:'); exit 0 }
[Console]::Out.WriteLine('__MARK__STATUS:locked=' + $a.Lockout + ',disabled=' + $a.Disabled)
"""


class BadName(ValueError):
    pass


def check_account(name: str) -> None:
    if not name or len(name) > MAX_NAME or name != name.strip() or name.endswith("."):
        raise BadName(f"not a valid Windows local account name: {name!r}")
    bad = sorted(set(name) & FORBIDDEN) + [c for c in name if ord(c) < 32]
    if bad:
        raise BadName(f"account name contains characters Windows does not allow: {''.join(bad)!r}")


def ps_literal(s: str) -> str:
    """A PowerShell single-quoted string: nothing inside is expanded; ' is written as ''."""
    return "'" + s.replace("'", "''") + "'"


def encoded_command(script: str) -> str:
    """powershell -EncodedCommand takes base64 of UTF-16LE. No quoting layer is left to get wrong."""
    b64 = base64.b64encode(script.encode("utf-16-le")).decode("ascii")
    return f"powershell -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -EncodedCommand {b64}"


def change_command(account: str) -> str:
    check_account(account)
    return encoded_command(SCRIPT.replace("__NAME__", ps_literal(account)).replace("__MARK__", MARKER))


def status_command(account: str) -> str:
    check_account(account)
    return encoded_command(STATUS_SCRIPT.replace("__NAME__", ps_literal(account)).replace("__MARK__", MARKER))


ANSI = re.compile(r"\x1b\[[0-9;?]*[ -/]*[@-~]|\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)")


def parse(stdout: str) -> tuple[str, str]:
    """(status, detail) from the marker line. Anything before it (banners, profile noise) is ignored;
    no marker at all is an error, never a success."""
    for line in ANSI.sub("", stdout).splitlines():
        line = line.strip()
        if line.startswith(MARKER):
            status, _, detail = line[len(MARKER):].partition(":")
            return status, detail.strip()
    return "NO_MARKER", stdout.strip().splitlines()[0][:200] if stdout.strip() else "(no output)"
