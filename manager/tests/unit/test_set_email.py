"""
manager/tests/unit/test_set_email.py — the set-email command changes only
DASHBOARD_EMAIL, validates the address, and leaves everything else untouched.
"""
from __future__ import annotations

from manager.manager.scripts import set_email as se


def test_sets_email_and_preserves_other_lines(tmp_path):
    env = tmp_path / ".env"
    env.write_text("PUBLIC_IP=localhost\nDASHBOARD_PASSWORD_HASH=pbkdf2:sha256:x\n")

    rc = se.main(["--email", "admin@acme.com", "--env", str(env)])
    assert rc == 0

    text = env.read_text()
    assert "DASHBOARD_EMAIL=admin@acme.com" in text
    assert "PUBLIC_IP=localhost" in text
    assert "DASHBOARD_PASSWORD_HASH=pbkdf2:sha256:x" in text   # password untouched


def test_replaces_an_existing_email(tmp_path):
    env = tmp_path / ".env"
    env.write_text("DASHBOARD_EMAIL=old@acme.com\n")
    se.main(["--email", "new@acme.com", "--env", str(env)])
    text = env.read_text()
    assert "DASHBOARD_EMAIL=new@acme.com" in text
    assert "old@acme.com" not in text


def test_rejects_a_bad_email(tmp_path):
    env = tmp_path / ".env"
    env.write_text("PUBLIC_IP=x\n")
    rc = se.main(["--email", "not-an-email", "--env", str(env)])
    assert rc == 2
    assert env.read_text() == "PUBLIC_IP=x\n"          # nothing written
