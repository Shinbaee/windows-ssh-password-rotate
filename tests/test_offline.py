"""Script building, answer parsing, the decision flow and the probe analysis. No Windows host needed."""

import base64

import pytest
from fake_host import FakeHost

from winssh_rotate import cli, flow, probe
from winssh_rotate.remote import BadName, change_command, check_account, parse, ps_literal

NEW = 'N3w&pass|with^cmd%chars"!'
OLD = "Initial-pass-001"
ADMIN = "Admin-pass-0001"


@pytest.fixture
def host():
    return FakeHost()


def run(host, monkeypatch, *extra, account="svc_app", new=NEW, old=OLD, admin="admin", admin_pw=ADMIN):
    for k, v in {"T_NEW": new, "T_OLD": old, "T_ADMIN": admin_pw}.items():
        monkeypatch.setenv(k, v)
    argv = ["rotate", "--host", "win.example.test", "--account", account, "--admin-user", admin,
            "--admin-password-env", "T_ADMIN", "--new-password-env", "T_NEW", "--old-password-env", "T_OLD"]
    return cli.main(argv + list(extra), connect_fn=host.connect)


def decoded(command):
    return base64.b64decode(command.rsplit(" ", 1)[1]).decode("utf-16-le")


# --- script and parsing ---

def test_password_never_in_the_command(host, monkeypatch, capsys):
    assert run(host, monkeypatch) == flow.OK
    for c in host.commands:
        assert NEW not in c and NEW not in decoded(c)
    assert host.stdins[0] == NEW + "\n"  # it travels on stdin only
    out = capsys.readouterr()
    assert NEW not in out.out + out.err and ADMIN not in out.out + out.err


def test_command_is_one_opaque_token_for_cmd():
    c = change_command("svc_app")
    assert c.startswith("powershell -NoLogo -NoProfile -NonInteractive")
    assert not set(c.rsplit(" ", 1)[1]) & set("&|^%\"'<>()")  # base64: nothing for cmd.exe to interpret


def test_account_name_is_a_literal():
    assert ps_literal("O'Brien") == "'O''Brien'"
    s = decoded(change_command("a$(b)"))
    assert "$name = 'a$(b)'" in s  # single quotes: PowerShell does not expand $(...)


@pytest.mark.parametrize("bad", ["a;b", 'x"y', "a/b", "", " lead", "dot.", "x" * 21, "a|b"])
def test_names_windows_would_refuse_are_refused_here(bad):
    with pytest.raises(BadName):
        check_account(bad)


def test_parse_ignores_noise_and_requires_the_marker():
    assert parse("\x1b]0;title\x07banner\r\nWSPR-RESULT:REJECTED:too short\r\n") == ("REJECTED", "too short")
    assert parse("The operation completed successfully.")[0] == "NO_MARKER"  # never mistaken for success
    assert parse("")[0] == "NO_MARKER"


# --- flow ---

def test_change_and_verify(host, monkeypatch, capsys):
    assert run(host, monkeypatch) == flow.OK
    assert host.users["svc_app"].password == NEW
    assert host.attempts[-1] == ("svc_app", True)
    assert capsys.readouterr().out.strip() == "OK: password of svc_app changed and verified"


def test_name_with_a_quote(host, monkeypatch, capsys):
    assert run(host, monkeypatch, account="O'Brien", old="Obrien-pass-0001") == flow.OK


def test_bad_name_is_a_usage_error_before_connecting(host, monkeypatch, capsys):
    assert run(host, monkeypatch, account="a;b") == flow.USAGE
    assert host.attempts == []


def test_not_found(host, monkeypatch, capsys):
    assert run(host, monkeypatch, account="nobody") == flow.NOT_FOUND


def test_policy(host, monkeypatch, capsys):
    assert run(host, monkeypatch, new="Short-1") == flow.REJECTED
    assert host.users["svc_app"].password == OLD


def test_not_an_admin(host, monkeypatch, capsys):
    host.users["helper"] = host.users["svc_app"].__class__("Helper-pass-0001")
    assert run(host, monkeypatch, admin="helper", admin_pw="Helper-pass-0001") == flow.NOT_PERMITTED


def test_wrong_admin_password(host, monkeypatch, capsys):
    assert run(host, monkeypatch, admin_pw="wrong-admin-pass") == flow.ADMIN_SIGN_IN_FAILED


def test_unreachable(host, monkeypatch, capsys):
    host.down = True
    assert run(host, monkeypatch) == flow.UNREACHABLE


@pytest.mark.parametrize("state", ["locked", "disabled"])
def test_locked_or_disabled_is_asked_not_guessed(host, monkeypatch, capsys, state):
    setattr(host.users["svc_app"], state, True)
    assert run(host, monkeypatch) == flow.CANNOT_SIGN_IN
    assert f"is {state}" in capsys.readouterr().out
    assert ("svc_app", False) in host.attempts and host.attempts.count(("svc_app", False)) == 1  # old not tried


def test_saved_nothing(host, monkeypatch, capsys):
    host.silent_no_save = True
    assert run(host, monkeypatch) == flow.NOT_CHANGED


def test_no_diagnose(host, monkeypatch, capsys):
    host.silent_no_save = True
    assert run(host, monkeypatch, "--no-diagnose") == flow.UNVERIFIED
    assert host.users["svc_app"].failures == 1


def test_both_refused(host, monkeypatch, capsys):
    host.store_other = True
    assert run(host, monkeypatch) == flow.BOTH_REFUSED


def test_new_equal_to_old(host, monkeypatch, capsys):
    assert run(host, monkeypatch, new=OLD) == flow.USAGE


# --- probe analysis, on hand-made samples (the CI job records real hosts) ---

def test_probe_unix_like_shell():
    lf = b"echo WSPR_LF_1\r\nWSPR_LF_1\r\n$ echo WSPR_LF_2\r\nWSPR_LF_2\r\n$ "
    r = probe.analyze(lf, b"\r\n$ ", b"echo WSPR_CRLF\r\nWSPR_CRLF\r\n$ ")
    assert r.lf_runs and r.crlf_runs and not r.merged_after_lf and r.osc == 0


def test_probe_recorded_windows_openssh_9_5():
    """Bytes recorded by the windows-openssh CI job (OpenSSH_for_Windows_9.5p2, cmd.exe); host name replaced.
    The next line starts with a cursor move (ESC[7;1H), not a line break."""
    lf = b"echo WSPR_LF_1echo WSPR_LF_2"
    flush = b"\r\n\x1b[?25lWSPR_LF_1echo WSPR_LF_2\x1b[7;1Huser@host C:\\Users\\user>\x1b[?25h"
    crlf = b"echo WSPR_CRLF\r\n\x1b[?25lWSPR_CRLF\x1b[10;1Huser@host C:\\Users\\user>\x1b[?25h"
    r = probe.analyze(lf, flush, crlf)
    assert not r.lf_runs and r.merged_after_lf and r.crlf_runs
    assert r.csi == 6 and r.osc == 0
    assert probe.strip(crlf.decode()).split("\n") == ["echo WSPR_CRLF", "WSPR_CRLF", "user@host C:\\Users\\user>"]


def test_probe_console_that_wants_cr():
    """Shaped like the failure in the practice: LF is not Enter, both lines end up as one, and a
    window-title sequence repeats the typed command."""
    lf = b"\x1b]0;Administrator: echo WSPR_LF_1\x07echo WSPR_LF_1echo WSPR_LF_2\x1b[K"
    flush = b"\r\nWSPR_LF_1echo WSPR_LF_2\r\n\x1b]0;C:\\Windows\\system32\\cmd.exe\x07C:\\> "
    crlf = b"echo WSPR_CRLF\r\nWSPR_CRLF\r\nC:\\> "
    r = probe.analyze(lf, flush, crlf)
    assert not r.lf_runs and r.crlf_runs and r.merged_after_lf
    assert r.command_in_title and r.osc == 2 and r.csi == 1
