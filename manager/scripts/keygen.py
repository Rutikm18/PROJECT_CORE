#!/usr/bin/env python3
"""
scripts/keygen.py — Generate a new API key and derive child keys.

Usage:
    python3 scripts/keygen.py

Prints:
  - Master API key (put in agent.toml + API_KEY env var on manager)
  - Derived enc_key and mac_key in hex (for audit / manual verification)
  - Ready-to-paste agent.toml [manager] block
  - Ready-to-paste manager export command

NEVER run this on an untrusted machine. Output goes to stdout only.
"""

import secrets
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
from manager.crypto import derive_keys

def main():
    api_key  = secrets.token_hex(32)          # 256-bit
    enc_key, mac_key = derive_keys(api_key)

    print("=" * 64)
    print("  mac_intel — New API Key Generated")
    print("=" * 64)
    print(f"\n  API Key    : {api_key}")
    print(f"  enc_key    : {enc_key.hex()}  (AES-256-GCM, derived via HKDF)")
    print(f"  mac_key    : {mac_key.hex()}  (HMAC-SHA256, derived via HKDF)")
    print()
    print("─" * 64)
    print("  Paste into agent.toml → [manager] section:")
    print("─" * 64)
    print(f"""
[manager]
url     = "https://YOUR_SERVER_IP:8443"
api_key = "{api_key}"
""")
    print("─" * 64)
    print("  Set on the manager server (bash / zsh):")
    print("─" * 64)
    print(f"\n  export API_KEY=\"{api_key}\"")
    print()
    print("  ⚠  Store this key securely. It cannot be recovered.")
    print("  ⚠  Do NOT commit agent.toml to version control.\n")

if __name__ == "__main__":
    main()
