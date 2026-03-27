#!/usr/bin/env python3
"""
mac_intel monitor — Continuous security monitor
Collects at intervals, shows ONLY what changed, human-readable.

Usage:
  python3 monitor.py                    # volatile every 5min, full every 6h
  python3 monitor.py --volatile-mins 2  # faster volatile cycle
  python3 monitor.py --once volatile    # single run, show deltas
  sudo python3 monitor.py               # full data (TCC, firewall, etc.)
"""

import subprocess, json, os, sys, time, datetime, sqlite3, argparse, tempfile, signal
sys.stdout.reconfigure(line_buffering=True)  # flush every line in background

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
COLLECTOR  = os.path.join(SCRIPT_DIR, "collector.sh")
STORAGE    = os.path.join(SCRIPT_DIR, "storage.py")
DB         = os.path.join(SCRIPT_DIR, "data", "intel.db")
LOCK       = "/tmp/mac_intel_collector.lock"

# ── Changeable fields only (static identity fields excluded) ──────────────────
SKIP_PATHS = {
    "meta.", "identity.uptime_s", "identity.boot_epoch",
    "volatile_extras.arm_cpu_metrics", "volatile_extras.memory",
    "volatile_extras.net_stats", "volatile_extras.disk_root",
    "volatile_extras.battery", "volatile_extras.frontmost_app",
}
# Skip parse-error fields (domain failed to collect, not a real change)
SKIP_SUFFIX = (".error",)

SEV_COLOR = {
    "CRITICAL": "\033[1;31m",  # bold red
    "HIGH":     "\033[0;31m",  # red
    "MEDIUM":   "\033[1;33m",  # yellow
    "LOW":      "\033[0;36m",  # cyan
}
R = "\033[0m"
G = "\033[0;32m"
B = "\033[1;34m"
BOLD = "\033[1m"

def ts() -> str:
    return datetime.datetime.now().strftime("%H:%M:%S")

def log(msg: str):
    print(f"\033[0;90m[{ts()}]\033[0m {msg}")

def banner(msg: str):
    print(f"\n{BOLD}{B}{'─'*60}{R}")
    print(f"{BOLD}{B}  {msg}{R}")
    print(f"{BOLD}{B}{'─'*60}{R}")

def sev_label(sev: str) -> str:
    c = SEV_COLOR.get(sev, "")
    return f"{c}{sev:<8}{R}"

# ── Collect ───────────────────────────────────────────────────────────────────
def collect(mode: str) -> str | None:
    """Run collector, return path to clean JSON file or None on failure."""
    os.remove(LOCK) if os.path.exists(LOCK) else None

    raw = tempfile.NamedTemporaryFile(delete=False, suffix=".json")
    raw.close()
    clean = tempfile.NamedTemporaryFile(delete=False, suffix=".json")
    clean.close()

    timeout = 300 if mode == "full" else 90

    try:
        proc = subprocess.Popen(
            ["bash", COLLECTOR, "--mode", mode],
            stdout=open(raw.name, "w"), stderr=subprocess.DEVNULL,
            preexec_fn=os.setsid
        )
        try:
            proc.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            import signal as _sig
            try:
                os.killpg(os.getpgid(proc.pid), _sig.SIGKILL)
            except Exception:
                proc.kill()
            proc.wait()
            log(f"  [warn] collector timed out after {timeout}s — using partial data")

        # Strip non-JSON prefix (e.g. pip output on stdout)
        data = open(raw.name).read()
        start = data.find('{"meta":')
        if start == -1:
            start = data.find('{')
        if start == -1:
            log(f"  collector produced no JSON for mode={mode}")
            return None
        obj = json.loads(data[start:])
        json.dump(obj, open(clean.name, "w"))
        os.remove(raw.name)
        return clean.name
    except Exception as e:
        log(f"  collection error: {e}")
        return None

# ── Ingest ────────────────────────────────────────────────────────────────────
def ingest(json_file: str) -> int | None:
    """Ingest file into DB. Returns new snapshot ID or None."""
    try:
        result = subprocess.run(
            [sys.executable, STORAGE, "--ingest", json_file, "--db", DB],
            capture_output=True, text=True
        )
        for line in result.stdout.splitlines():
            if line.startswith("[OK]"):
                parts = line.split()
                for p in parts:
                    if p.startswith("snap=#"):
                        return int(p[6:])
            if line.startswith("[SKIP]"):
                return None   # duplicate
        return None
    except Exception as e:
        log(f"  ingest error: {e}")
        return None

# ── Fetch deltas for a snapshot ───────────────────────────────────────────────
def get_deltas(snap_id: int) -> list[dict]:
    db = sqlite3.connect(DB)
    db.row_factory = sqlite3.Row
    rows = db.execute(
        "SELECT path, prev_value, curr_value, severity, mitre, regression "
        "FROM deltas WHERE snap_id=? ORDER BY "
        "CASE severity WHEN 'CRITICAL' THEN 1 WHEN 'HIGH' THEN 2 WHEN 'MEDIUM' THEN 3 ELSE 4 END, path",
        (snap_id,)
    ).fetchall()
    db.close()
    return [dict(r) for r in rows]

def get_snapshot_meta(snap_id: int) -> dict:
    db = sqlite3.connect(DB)
    db.row_factory = sqlite3.Row
    row = db.execute("SELECT * FROM snapshots WHERE id=?", (snap_id,)).fetchone()
    db.close()
    return dict(row) if row else {}

def get_fields_sample(snap_id: int) -> dict:
    """Pull key security fields — uses current snap first, falls back to latest with value."""
    db = sqlite3.connect(DB)
    db.row_factory = sqlite3.Row
    KEYS = [
        "identity.hostname", "identity.chip_name", "identity.os_version",
        "identity.sip_status", "security_config.filevault",
        "security_config.gatekeeper", "network.app_fw",
        "identity.developer_mode", "security_config.arm_authenticated_root",
        "identity.rosetta2_installed", "volatile_extras.battery",
        "volatile_extras.disk_root", "volatile_extras.memory",
        "network.wifi_current",
    ]
    out = {}
    for k in KEYS:
        # Try current snapshot first
        r = db.execute(
            "SELECT value FROM fields WHERE snapshot_id=? AND path=? AND value != '' LIMIT 1",
            (snap_id, k)
        ).fetchone()
        if r:
            out[k] = r["value"]
        else:
            # Fall back to most recent snapshot that has this field
            r2 = db.execute(
                "SELECT value FROM fields WHERE path=? AND value != '' ORDER BY epoch DESC LIMIT 1",
                (k,)
            ).fetchone()
            out[k] = r2["value"] if r2 else ""
    db.close()
    return out

# ── Display deltas ────────────────────────────────────────────────────────────
def show_deltas(deltas: list[dict], snap_meta: dict, fields: dict):
    mode = snap_meta.get("mode", "?")
    ts_  = snap_meta.get("ts", "")[:16]

    banner(f"Snapshot #{snap_meta.get('id')}  mode={mode}  {ts_}")

    # Quick security summary line
    chip = fields.get("identity.chip_name", "")
    host = fields.get("identity.hostname", "")
    sip  = "✓SIP" if "enabled" in (fields.get("identity.sip_status") or "").lower() else "✗SIP"
    fv   = "✓FV"  if "on"      in (fields.get("security_config.filevault") or "").lower() else "✗FV"
    gk   = "✓GK"  if "enabled" in (fields.get("security_config.gatekeeper") or "").lower() else "✗GK"
    fw   = "✓FW"  if "enabled" in (fields.get("network.app_fw") or "").lower() else "✗FW"

    # Battery
    batt_raw = fields.get("volatile_extras.battery", "{}")
    try:
        b = json.loads(batt_raw)
        batt = f"🔋{b.get('pct','?')}% {b.get('state','')}"
    except:
        batt = ""

    # Disk
    disk_raw = fields.get("volatile_extras.disk_root", "{}")
    try:
        d = json.loads(disk_raw)
        disk = f"💾{d.get('used','?')}/{d.get('size','?')} ({d.get('pct','?')})"
    except:
        disk = ""

    # WiFi
    wifi_raw = fields.get("network.wifi_current", "{}")
    try:
        w = json.loads(wifi_raw)
        wifi = f"📶{w.get('ssid','?')}" if w.get('ssid') else ""
    except:
        wifi = ""

    print(f"  {BOLD}{host}{R}  {chip}  {G}{sip}  {fv}  {gk}  {fw}{R}  {batt}  {disk}  {wifi}")

    # Filter out collection parse-error fields (not real security changes)
    deltas = [d for d in deltas if not any(d["path"].endswith(s) for s in SKIP_SUFFIX)]

    if not deltas:
        print(f"\n  {G}✓ No changes detected{R}\n")
        return

    print(f"\n  {BOLD}CHANGES ({len(deltas)}){R}")
    print(f"  {'SEV':<10} {'FIELD':<45} {'CHANGE'}")
    print(f"  {'─'*9} {'─'*44} {'─'*30}")

    for d in deltas:
        path  = d["path"]
        prev  = (d["prev_value"] or "—")[:50].replace("\n", " ")
        curr  = (d["curr_value"] or "—")[:50].replace("\n", " ")
        sev   = d["severity"]
        reg   = " ⚠ REGRESSION" if d["regression"] else ""
        mitre = f" [{d['mitre']}]" if d["mitre"] else ""
        label = sev_label(sev)

        print(f"  {label} {path:<45}{mitre}{reg}")
        print(f"           {'BEFORE:':<8} {prev}")
        print(f"           {'AFTER: ':<8} {curr}")
        print()

# ── Summary display (no deltas) ───────────────────────────────────────────────
def show_summary(snap_id: int):
    fields = get_fields_sample(snap_id)
    meta   = get_snapshot_meta(snap_id)
    show_deltas([], meta, fields)

# ── Single run ────────────────────────────────────────────────────────────────
def run_once(mode: str, quiet: bool = False) -> bool:
    log(f"Collecting [{mode}]...")
    t0 = time.monotonic()

    json_file = collect(mode)
    if not json_file:
        return False

    snap_id = ingest(json_file)
    os.remove(json_file)
    elapsed = time.monotonic() - t0

    if snap_id is None:
        log(f"  [skip] duplicate or no new data  ({elapsed:.1f}s)")
        return True

    log(f"  ingested snap=#{snap_id}  ({elapsed:.1f}s)")
    deltas = get_deltas(snap_id)
    fields = get_fields_sample(snap_id)
    meta   = get_snapshot_meta(snap_id)

    if deltas:
        show_deltas(deltas, meta, fields)
    elif not quiet:
        show_deltas([], meta, fields)
    else:
        # Quiet heartbeat — one line showing posture + no changes
        chip = fields.get("identity.chip_name", "")
        sip  = "✓SIP" if "enabled" in (fields.get("identity.sip_status") or "").lower() else "✗SIP"
        fv   = "✓FV"  if "on"      in (fields.get("security_config.filevault") or "").lower() else "✗FV"
        gk   = "✓GK"  if "enabled" in (fields.get("security_config.gatekeeper") or "").lower() else "✗GK"
        fw   = "✓FW"  if "enabled" in (fields.get("network.app_fw") or "").lower() else "✗FW"
        batt_raw = fields.get("volatile_extras.battery", "{}")
        try:
            b    = json.loads(batt_raw)
            batt = f"🔋{b.get('pct','?')}%"
        except:
            batt = ""
        print(f"  [{ts()}] snap=#{snap_id} {meta.get('mode','?'):<8} {sip} {fv} {gk} {fw}  {batt}  ✓ no changes")

    return True

# ── Continuous loop ───────────────────────────────────────────────────────────
def monitor_loop(volatile_mins: int, full_hours: int):
    volatile_secs = volatile_mins * 60
    quick_secs    = 30 * 60          # security posture check every 30 min
    last_quick    = 0

    banner(f"mac_intel monitor  —  volatile={volatile_mins}min  posture=30min")
    print(f"  DB: {DB}")
    print(f"  volatile = network, processes, logs")
    print(f"  posture  = SIP, Gatekeeper, FileVault, TCC, accounts, persistence")
    print(f"  Ctrl+C to stop\n")

    # Initial quick posture snapshot
    run_once("quick", quiet=False)
    last_quick = time.monotonic()

    while True:
        time.sleep(volatile_secs)

        now = time.monotonic()
        if now - last_quick >= quick_secs:
            run_once("quick", quiet=True)
            last_quick = now
        else:
            run_once("volatile", quiet=True)

# ── Main ──────────────────────────────────────────────────────────────────────
def main():
    global DB  # noqa: PLW0603
    p = argparse.ArgumentParser(description="mac_intel continuous monitor")
    p.add_argument("--volatile-mins", type=int, default=5,  metavar="N")
    p.add_argument("--full-hours",    type=int, default=6,  metavar="N")
    p.add_argument("--once",          metavar="MODE",       help="Run once and exit (volatile|quick)")
    p.add_argument("--db",            default=DB,           metavar="PATH")
    args = p.parse_args()

    DB = args.db

    signal.signal(signal.SIGINT, lambda *_: (print("\n\nStopped."), sys.exit(0)))

    if args.once:
        run_once(args.once, quiet=False)
    else:
        monitor_loop(args.volatile_mins, args.full_hours)

if __name__ == "__main__":
    main()
