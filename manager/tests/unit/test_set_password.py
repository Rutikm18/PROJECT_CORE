"""
manager/tests/unit/test_set_password.py — the set/reset-password command edits
.env correctly and only ever writes a policy-checked, verifiable hash.
"""
from __future__ import annotations

from manager.manager.scripts import set_password as sp
from manager.manager.security_policy import verify_password

STRONG = "Str0ng!Passw0rd#2026"


# ── The pure .env editor ─────────────────────────────────────────────────────

def test_appends_a_missing_key():
    out = sp.apply_env_updates("PUBLIC_IP=1.2.3.4\n", {"DASHBOARD_PASSWORD_HASH": "h"})
    assert out == "PUBLIC_IP=1.2.3.4\nDASHBOARD_PASSWORD_HASH=h\n"


def test_replaces_an_existing_key_in_place():
    text = "A=1\nDASHBOARD_PASSWORD_HASH=old\nB=2\n"
    out = sp.apply_env_updates(text, {"DASHBOARD_PASSWORD_HASH": "new"})
    assert out == "A=1\nDASHBOARD_PASSWORD_HASH=new\nB=2\n"


def test_collapses_duplicate_assignments():
    text = "DASHBOARD_PASSWORD_HASH=\nX=9\nDASHBOARD_PASSWORD_HASH=stale\n"
    out = sp.apply_env_updates(text, {"DASHBOARD_PASSWORD_HASH": "new"})
    assert out == "DASHBOARD_PASSWORD_HASH=new\nX=9\n"


def test_removes_plaintext_password_but_keeps_comments():
    text = "# creds\nDASHBOARD_PASSWORD=hunter2\nPUBLIC_IP=x\n"
    out = sp.apply_env_updates(
        text, {"DASHBOARD_PASSWORD_HASH": "h"}, remove=("DASHBOARD_PASSWORD",))
    assert "DASHBOARD_PASSWORD=hunter2" not in out
    assert "# creds" in out and "PUBLIC_IP=x" in out
    assert "DASHBOARD_PASSWORD_HASH=h" in out


# ── main(): writes a verifiable hash ─────────────────────────────────────────

def test_main_writes_a_hash_that_verifies(tmp_path):
    env = tmp_path / ".env"
    env.write_text("PUBLIC_IP=localhost\n")

    rc = sp.main(["--password", STRONG, "--env", str(env)])
    assert rc == 0

    lines = dict(ln.split("=", 1) for ln in env.read_text().splitlines() if "=" in ln)
    assert verify_password(STRONG, lines["DASHBOARD_PASSWORD_HASH"]) is True
    assert lines["PUBLIC_IP"] == "localhost"          # untouched


def test_main_sets_email_too(tmp_path):
    env = tmp_path / ".env"
    env.write_text("")
    rc = sp.main(["--email", "admin@acme.com", "--password", STRONG, "--env", str(env)])
    assert rc == 0
    assert "DASHBOARD_EMAIL=admin@acme.com" in env.read_text()


def test_main_removes_any_plaintext_password(tmp_path):
    env = tmp_path / ".env"
    env.write_text("DASHBOARD_PASSWORD=oldplain\n")
    sp.main(["--password", STRONG, "--env", str(env)])
    without_hash = env.read_text().replace("DASHBOARD_PASSWORD_HASH=", "")
    assert "DASHBOARD_PASSWORD=" not in without_hash


def test_main_rejects_a_weak_password(tmp_path):
    env = tmp_path / ".env"
    env.write_text("")
    rc = sp.main(["--password", "short", "--env", str(env)])
    assert rc == 2
    assert env.read_text() == ""                      # nothing written on rejection


def test_allow_weak_bypasses_the_policy(tmp_path):
    env = tmp_path / ".env"
    env.write_text("")
    rc = sp.main(["--password", "short", "--allow-weak", "--env", str(env)])
    assert rc == 0
    lines = dict(ln.split("=", 1) for ln in env.read_text().splitlines() if "=" in ln)
    assert verify_password("short", lines["DASHBOARD_PASSWORD_HASH"]) is True


def test_main_rejects_a_bad_email(tmp_path):
    env = tmp_path / ".env"
    env.write_text("")
    rc = sp.main(["--email", "not-an-email", "--password", STRONG, "--env", str(env)])
    assert rc == 2
    assert env.read_text() == ""
