"""
set_email.py — change the dashboard login email (DASHBOARD_EMAIL) only.

The email is a plain env var, not a hashed secret, so changing it needs no
password. This is the "just fix the login id" path; use set_password when you
also want to change the password.

    python3 -m manager.manager.scripts.set_email --email admin@acme.com

The Makefile wraps this and recreates the manager:
    make set-email EMAIL=admin@acme.com
"""
from __future__ import annotations

import argparse
import sys

from .set_password import _EMAIL_RE, _read_env, apply_env_updates


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="set_email",
        description="Set the dashboard login email (DASHBOARD_EMAIL).",
    )
    parser.add_argument("--email", required=True, help="the new login email")
    parser.add_argument("--env", default=".env", help="path to the .env file (default: .env)")
    args = parser.parse_args(argv)

    email = args.email.strip()
    if not _EMAIL_RE.match(email):
        print(f"error: {email!r} is not a valid email address", file=sys.stderr)
        return 2

    new_text = apply_env_updates(_read_env(args.env), {"DASHBOARD_EMAIL": email})
    with open(args.env, "w", encoding="utf-8") as fh:
        fh.write(new_text)

    print(f"Updated login email to {email} in {args.env}.")
    print("Recreate the manager to apply:  docker compose up -d --force-recreate manager")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
