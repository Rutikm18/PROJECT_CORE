"""
set_password.py — set or reset the dashboard login (email + password).

One command instead of the manual "generate a hash, paste it into .env, restart"
dance. It hashes the password with the manager's own policy-checked hasher and
writes DASHBOARD_PASSWORD_HASH (and optionally DASHBOARD_EMAIL) into the .env
file that docker-compose reads. Stdlib-only, so it runs on the host with plain
python3 — the manager container does not need to be up.

    # interactive (password is prompted, never shown or stored in shell history)
    python3 -m manager.manager.scripts.set_password

    # also change the login email
    python3 -m manager.manager.scripts.set_password --email admin@acme.com

    # non-interactive (CI); password is visible to `ps`, use with care
    python3 -m manager.manager.scripts.set_password --password '…' --allow-weak

The Makefile wraps this and recreates the container:
    make set-password [EMAIL=admin@acme.com] [PASSWORD=…]
    make reset-password …            # same thing
"""
from __future__ import annotations

import argparse
import getpass
import re
import sys

from ..security_policy import PasswordPolicyError, hash_password, validate_password

_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
_KEY_RE = re.compile(r"\s*([A-Za-z_][A-Za-z0-9_]*)\s*=")


def apply_env_updates(text: str, updates: dict[str, str], remove: tuple[str, ...] = ()) -> str:
    """Return .env text with `updates` upserted and `remove` keys dropped.

    An existing key is replaced in place (first occurrence wins, later duplicates
    dropped); a missing key is appended; comments, blank lines and unrelated keys
    keep their place and order. Pure string transform — no filesystem.
    """
    out: list[str] = []
    written: set[str] = set()
    for line in text.splitlines():
        m = _KEY_RE.match(line)
        key = m.group(1) if m else None
        if key is not None and key in updates:
            if key in written:
                continue                       # collapse duplicate assignments
            out.append(f"{key}={updates[key]}")
            written.add(key)
        elif key is not None and key in remove:
            continue                           # drop (e.g. plaintext password)
        else:
            out.append(line)
    for key, value in updates.items():
        if key not in written:
            out.append(f"{key}={value}")
    return "\n".join(out) + "\n"


def _read_env(path: str) -> str:
    try:
        with open(path, encoding="utf-8") as fh:
            return fh.read()
    except FileNotFoundError:
        return ""


def _prompt_password() -> str:
    pw = getpass.getpass("New dashboard password: ")
    if getpass.getpass("Confirm password: ") != pw:
        print("error: passwords do not match", file=sys.stderr)
        raise SystemExit(2)
    return pw


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="set_password",
        description="Set or reset the dashboard login email and password.",
    )
    parser.add_argument("--email", help="also set the login email (DASHBOARD_EMAIL)")
    parser.add_argument("--password", help="the new password (omit to be prompted)")
    parser.add_argument("--env", default=".env", help="path to the .env file (default: .env)")
    parser.add_argument("--allow-weak", action="store_true",
                        help="skip the password-policy check (not recommended)")
    args = parser.parse_args(argv)

    updates: dict[str, str] = {}

    if args.email is not None:
        email = args.email.strip()
        if not _EMAIL_RE.match(email):
            print(f"error: {email!r} is not a valid email address", file=sys.stderr)
            return 2
        updates["DASHBOARD_EMAIL"] = email

    password = args.password if args.password is not None else _prompt_password()
    if not password:
        print("error: password must not be empty", file=sys.stderr)
        return 2
    if not args.allow_weak:
        try:
            validate_password(password)
        except PasswordPolicyError as exc:
            print(f"error: {exc}", file=sys.stderr)
            print("       (re-run with --allow-weak to override)", file=sys.stderr)
            return 2

    updates["DASHBOARD_PASSWORD_HASH"] = hash_password(password)

    new_text = apply_env_updates(
        _read_env(args.env), updates, remove=("DASHBOARD_PASSWORD",)
    )
    with open(args.env, "w", encoding="utf-8") as fh:
        fh.write(new_text)

    changed = "email + password" if "DASHBOARD_EMAIL" in updates else "password"
    print(f"Updated {changed} in {args.env}.")
    if "DASHBOARD_EMAIL" in updates:
        print(f"  login email: {updates['DASHBOARD_EMAIL']}")
    print("Recreate the manager to apply:  docker compose up -d --force-recreate manager")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
