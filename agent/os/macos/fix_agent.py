#!/usr/bin/env python3
"""
Run as:  sudo python3 fix_agent.py
Applies two fixes to the live AttackLens installation:
  1. Patches core.py: spool-to-disk instead of drop when queue is full
  2. Patches agent.toml: raises max_queue_size, slows 10s intervals to 60s
"""
import re, shutil, sys, os
from datetime import datetime

if os.getuid() != 0:
    print("ERROR: must run as root — use: sudo python3 fix_agent.py")
    sys.exit(1)

CORE   = "/Library/AttackLens/src/agent/agent/core.py"
CONFIG = "/Library/AttackLens/agent.toml"
SRC    = "/Users/rutikmangale/Downloads/macbook_data/agent/os/macos/installer/pkg_build/root/Library/AttackLens/src/agent/agent/core.py"

# ── 1. Deploy patched core.py ─────────────────────────────────────────────────

bak = CORE + f".bak.{datetime.now().strftime('%Y%m%d_%H%M%S')}"
shutil.copy2(CORE, bak)
print(f"  Backed up core.py → {bak}")

shutil.copy2(SRC, CORE)
os.chmod(CORE, 0o644)
print(f"  Deployed patched core.py → {CORE}")

# ── 2. Patch agent.toml intervals ────────────────────────────────────────────

with open(CONFIG) as f:
    toml = f.read()

bak2 = CONFIG + f".bak.{datetime.now().strftime('%Y%m%d_%H%M%S')}"
shutil.copy2(CONFIG, bak2)
print(f"  Backed up agent.toml → {bak2}")

changes = {
    # section name        old interval   new interval
    "metrics":            (10,           60),
    "connections":        (10,           60),
    "processes":          (10,           60),
}

for section, (old_s, new_s) in changes.items():
    pattern = (
        r'(\[collection\.sections\.' + re.escape(section) + r'\][^\[]*?'
        r'interval_sec\s*=\s*)' + str(old_s)
    )
    replacement = rf'\g<1>{new_s}'
    new_toml, n = re.subn(pattern, replacement, toml, flags=re.DOTALL)
    if n:
        toml = new_toml
        print(f"  {section}: interval_sec {old_s}s → {new_s}s")
    else:
        print(f"  {section}: no change needed (already updated or not found)")

# Also raise max_queue_size if still at default
toml, n = re.subn(r'^(max_queue_size\s*=\s*)(?:500|1000)\b',
                  r'\g<1>2000', toml, flags=re.MULTILINE)
if n:
    print("  max_queue_size → 2000")

with open(CONFIG, "w") as f:
    f.write(toml)
print(f"  Saved agent.toml")

print()
print("  Done. Now run:")
print("    cd /")
print("    sudo attacklens-service restart")
