"""Against a real Windows OpenSSH server on localhost (CI: windows-latest). Skipped unless WSPR_TEST_KNOWN_HOSTS
is set. The test process must run as an administrator of that machine: it creates and resets the accounts.

    WSPR_TEST_KNOWN_HOSTS   known_hosts file holding localhost's host key
    WSPR_TEST_ADMIN         admin account for the tool (default rot_admin), password in WSPR_TEST_ADMIN_PW
"""

import os
import subprocess
import sys

import pytest

from winssh_rotate import cli, flow, probe
from winssh_rotate.ssh import AuthFailed, Host, connect

KNOWN = os.environ.get("WSPR_TEST_KNOWN_HOSTS")
ADMIN = os.environ.get("WSPR_TEST_ADMIN", "rot_admin")
ADMIN_PW = os.environ.get("WSPR_TEST_ADMIN_PW", "")
pytestmark = pytest.mark.skipif(not KNOWN or sys.platform != "win32", reason="no Windows test host")

HOST = Host("localhost", 22, KNOWN, 120)  # the first sign-in of an account creates its profile: slow
INITIAL = "Initial-pass-0001"
NEW = 'N3w&pass|with^cmd%chars"!'


def ps(script):
    # Windows PowerShell 5.1 started from PowerShell 7 inherits 7's PSModulePath and then fails to load
    # its own modules; drop it so 5.1 uses its defaults. (sshd sessions start clean and are not affected.)
    env = {k: v for k, v in os.environ.items() if k.upper() != "PSMODULEPATH"}
    r = subprocess.run(["powershell", "-NoProfile", "-NonInteractive", "-Command", script],
                       capture_output=True, text=True, env=env)
    assert r.returncode == 0, r.stderr
    return r.stdout.strip()


@pytest.fixture
def account():
    ps("Remove-LocalUser -Name rot_app -ErrorAction SilentlyContinue; "
       f"New-LocalUser -Name rot_app -Password (ConvertTo-SecureString '{INITIAL}' -AsPlainText -Force) "
       "-PasswordNeverExpires | Out-Null; "
       # New-LocalUser does not add the account to Users; without it the account cannot sign in over SSH
       "Add-LocalGroupMember -Group Users -Member rot_app")
    yield "rot_app"
    ps("Remove-LocalUser -Name rot_app -ErrorAction SilentlyContinue")


def signs_in(password):
    try:
        connect(HOST, "rot_app", password).close()
        return True
    except AuthFailed:
        return False


def run(monkeypatch, *extra, new=NEW, account="rot_app", admin=ADMIN, admin_pw=ADMIN_PW):
    for k, v in {"T_NEW": new, "T_OLD": INITIAL, "T_ADMIN": admin_pw}.items():
        monkeypatch.setenv(k, v)
    return cli.main(["rotate", "--host", "localhost", "--known-hosts", KNOWN, "--account", account,
                     "--admin-user", admin, "--admin-password-env", "T_ADMIN", "--new-password-env", "T_NEW",
                     "--old-password-env", "T_OLD", "--timeout", "120", *extra])


def clean(capsys):
    out = capsys.readouterr()
    for s in (NEW, INITIAL, ADMIN_PW):
        assert s not in out.out + out.err
    return out


def test_change_with_cmd_metacharacters(account, monkeypatch, capsys):
    """& | ^ % " would break `net user name password` typed into cmd.exe. Here they are just bytes on stdin."""
    assert run(monkeypatch) == flow.OK, clean(capsys).out
    assert signs_in(NEW) and not signs_in(INITIAL)


def test_policy_rejection(account, monkeypatch, capsys):
    assert run(monkeypatch, new="Sh0rt!") == flow.REJECTED
    print(clean(capsys).out)
    assert signs_in(INITIAL)


def test_missing_account(account, monkeypatch, capsys):
    assert run(monkeypatch, account="rot_nobody") == flow.NOT_FOUND


def test_not_an_administrator(account, monkeypatch, capsys):
    ps("Remove-LocalUser -Name rot_other -ErrorAction SilentlyContinue; "
       f"New-LocalUser -Name rot_other -Password (ConvertTo-SecureString '{INITIAL}' -AsPlainText -Force) | Out-Null; "
       "Add-LocalGroupMember -Group Users -Member rot_other")
    try:
        code = run(monkeypatch, account="rot_other", admin="rot_app", admin_pw=INITIAL)
        print(capsys.readouterr().out)
        assert code == flow.NOT_PERMITTED
    finally:
        ps("Remove-LocalUser -Name rot_other -ErrorAction SilentlyContinue")


def test_disabled_account(account, monkeypatch, capsys):
    ps("Disable-LocalUser -Name rot_app")
    code = run(monkeypatch)
    out = clean(capsys)
    print("disabled account:", out.err, out.out)  # records how the failed sign-in looked (refused or dropped)
    assert code == flow.CANNOT_SIGN_IN and "is disabled" in out.out


def test_locked_account(account, monkeypatch, capsys):
    """Locked by failed sign-ins (CI sets the lockout threshold to 3). Recorded: does a password reset unlock it?"""
    for _ in range(3):
        assert not signs_in("Wrong-pass-00001")
    assert ps("(Get-CimInstance Win32_UserAccount -Filter \"LocalAccount=True AND Name='rot_app'\").Lockout") == "True"
    code = run(monkeypatch)
    out = clean(capsys).out
    print("locked account:", code, out)
    assert code == flow.CANNOT_SIGN_IN and "is locked" in out


def test_probe_records_how_this_host_treats_enter():
    s = connect(HOST, ADMIN, ADMIN_PW)
    try:
        report = probe.run(s)
    finally:
        s.close()
    print(report.text(400))  # the CI log keeps the raw bytes of a real Windows OpenSSH session
    # what the practice found, checked again on a current Windows OpenSSH:
    assert not report.lf_runs and report.merged_after_lf  # LF is not Enter; the two commands become one line
    assert report.crlf_runs                               # CR LF is
    assert report.csi > 0                                 # the output carries terminal control codes
