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

HOST = Host("localhost", 22, KNOWN, 30)
INITIAL = "Initial-pass-0001"
NEW = 'N3w&pass|with^cmd%chars"!'


def ps(script):
    r = subprocess.run(["powershell", "-NoProfile", "-NonInteractive", "-Command", script],
                       capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    return r.stdout.strip()


@pytest.fixture
def account():
    ps("Remove-LocalUser -Name rot_app -ErrorAction SilentlyContinue; "
       f"New-LocalUser -Name rot_app -Password (ConvertTo-SecureString '{INITIAL}' -AsPlainText -Force) "
       "-PasswordNeverExpires | Out-Null")
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
                     "--old-password-env", "T_OLD", *extra])


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
       f"New-LocalUser -Name rot_other -Password (ConvertTo-SecureString '{INITIAL}' -AsPlainText -Force) | Out-Null")
    try:
        code = run(monkeypatch, account="rot_other", admin="rot_app", admin_pw=INITIAL)
        print(capsys.readouterr().out)
        assert code == flow.NOT_PERMITTED
    finally:
        ps("Remove-LocalUser -Name rot_other -ErrorAction SilentlyContinue")


def test_disabled_account(account, monkeypatch, capsys):
    ps("Disable-LocalUser -Name rot_app")
    assert run(monkeypatch) == flow.CANNOT_SIGN_IN
    assert "is disabled" in capsys.readouterr().out


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
    assert report.crlf_runs
