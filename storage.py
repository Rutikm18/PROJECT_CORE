#!/usr/bin/env python3
"""
mac_intel storage — v4.1 (Apple Silicon / ARM)

ARM-specific additions over v4.0:
  • FIELD_RULES extended for ARM-only fields:
      arm_boot_security_mode  → CRITICAL regression if Permissive Security
      arm_authenticated_root  → CRITICAL regression if disabled
      arm_developer_mode      → HIGH risk if enabled
      arm_kern_developer_mode → HIGH risk if 1
      identity.pac_support    → informational
      identity.rosetta2_installed → tracked
      software.rosetta_apps_x86   → HIGH (x86_64-only apps = no PAC)
  • Page size 16KB on Apple Silicon (fixes memory calc)
  • Battery cycle count tracked in timeline
  • P/E cluster usage tracked as volatile (rolling window)
"""

import sqlite3, json, os, sys, argparse, datetime, zlib, glob, time
from typing import Generator, Any

# ── Config ────────────────────────────────────────────────────────────────────
DB_PATH    = os.path.join(os.path.dirname(__file__), "data", "intel.db")
MAX_FIELD  = 4096
VOL_KEEP   = 2000
BATCH_SIZE = 500

# ── Regression helpers ────────────────────────────────────────────────────────
def _reg_disabled(p, c):   return "disabled" in c.lower() and "enabled" in p.lower()
def _reg_off(p, c):        return "off" in c.lower() or "not enabled" in c.lower()
def _reg_zero(p, c):       return c.strip() in ("0", "false", "")
def _reg_permissive(p, c): return "permissive" in c.lower()
def _reg_any_to_off(p, c): return c.strip().lower() in ("disabled", "off", "0", "false")

# ── Field rules — (severity, mitre_id, regression_fn) ────────────────────────
FIELD_RULES: dict[str, tuple[str, str | None, Any]] = {
    # Core security config
    "security_config.filevault":              ("CRITICAL",  "T1486",      _reg_off),
    "security_config.gatekeeper":             ("CRITICAL",  "T1553.001",  _reg_disabled),
    "security_config.tcc_full_disk":          ("CRITICAL",  "T1005",      None),
    "security_config.tcc_screen":             ("CRITICAL",  "T1113",      None),
    "security_config.tcc_microphone":         ("CRITICAL",  "T1123",      None),
    "security_config.tcc_camera":             ("CRITICAL",  "T1123",      None),
    "security_config.tcc_accessibility":      ("CRITICAL",  "T1056.001",  None),
    "security_config.sudo_nopasswd":          ("CRITICAL",  "T1548.003",  None),
    "security_config.modified_sys_bins":      ("CRITICAL",  "T1036.005",  None),
    "security_config.writable_path_dirs":     ("CRITICAL",  "T1574.007",  None),
    "security_config.sshd_config":            ("HIGH",      "T1021.004",  None),
    "security_config.suid_sgid_bins":         ("HIGH",      "T1548.001",  None),
    "security_config.aslr":                   ("HIGH",      "T1068",      _reg_zero),
    "security_config.screen_lock":            ("MEDIUM",    None,         _reg_zero),

    # ARM-specific boot security
    "security_config.arm_boot_security_mode": ("CRITICAL",  "T1542.001",  _reg_permissive),
    "security_config.arm_authenticated_root": ("CRITICAL",  "T1562.001",  _reg_any_to_off),
    "security_config.arm_developer_mode":     ("HIGH",      "T1562.001",  None),
    "security_config.arm_kern_developer_mode":("HIGH",      "T1562.001",  None),
    "security_config.arm_local_policy_info":  ("HIGH",      "T1542.001",  None),

    # Identity — ARM boot args / SIP
    "identity.sip_status":                    ("CRITICAL",  "T1562.001",  _reg_disabled),
    "identity.nvram_boot_args":               ("CRITICAL",  "T1542.001",  None),
    "identity.authenticated_root":            ("CRITICAL",  "T1562.001",  _reg_any_to_off),
    "identity.boot_security_mode":            ("CRITICAL",  "T1542.001",  _reg_permissive),
    "identity.boot_args_filtering":           ("HIGH",      "T1542.001",  _reg_any_to_off),
    "identity.gatekeeper":                    ("CRITICAL",  "T1553.001",  _reg_disabled),
    "identity.rosetta2_installed":            ("LOW",       None,         None),
    "identity.developer_mode":                ("HIGH",      "T1562.001",  None),
    "identity.kern_developer_mode":           ("HIGH",      "T1562.001",  None),
    "identity.pac_support":                   ("LOW",       None,         None),
    "identity.hypervisor_support":            ("LOW",       None,         None),

    # Software — ARM Rosetta / arch audit
    "software.rosetta_apps_x86":              ("HIGH",      "T1195.002",  None),  # x86-only = no PAC
    "software.system_extensions":             ("HIGH",      "T1547",      None),
    "software.bundled_libs":                  ("HIGH",      "T1195.002",  None),

    # Credentials
    "credentials.authorized_keys":            ("CRITICAL",  "T1098.004",  None),
    "credentials.cloud":                      ("CRITICAL",  "T1552.001",  None),
    "credentials.shell_hist_hits":            ("CRITICAL",  "T1552.003",  None),
    "credentials.env_files":                  ("CRITICAL",  "T1552.001",  None),

    # Processes
    "processes.suspicious":                   ("CRITICAL",  "T1036.005",  None),
    "processes.dyld_injection":               ("CRITICAL",  "T1574.006",  None),
    "processes.rosetta_translated":           ("HIGH",      "T1055",      None),

    # Persistence
    "persistence.daemons":                    ("CRITICAL",  "T1543.004",  None),
    "persistence.agents":                     ("HIGH",      "T1543.004",  None),
    "persistence.cron":                       ("HIGH",      "T1053.003",  None),
    "persistence.login_hook":                 ("CRITICAL",  "T1037.002",  None),
    "persistence.shell_init_suspicious":      ("CRITICAL",  "T1546.004",  None),

    # Accounts
    "accounts.admins":                        ("CRITICAL",  "T1078.003",  None),

    # Network
    "network.hosts_custom":                   ("CRITICAL",  "T1565.001",  None),
    "network.listening":                      ("HIGH",      "T1049",      None),

    # Browser
    "browser.quarantine_events":              ("HIGH",      "T1566",      None),
    "browser.chrome_extensions":              ("HIGH",      "T1176",      None),

    # Logs — ARM-specific boot policy events
    "logs.arm_boot_policy_events":            ("HIGH",      "T1542.001",  None),
}

# Volatile paths — rolling window, skip delta
VOLATILE_PATHS = frozenset({
    "processes.running",
    "network.arp",
    "network.established",
    "network.listening",
    "services.launchctl_list",
    "volatile_extras.battery",
    "volatile_extras.net_stats",
    "volatile_extras.memory",
    "volatile_extras.disk_root",
    "volatile_extras.frontmost_app",
    "volatile_extras.arm_cpu_metrics",   # ARM: P/E cluster usage always changes
    "behavior.app_infocus",
    "behavior.lock_events",
    "logs.tcc_decisions",
    "logs.auth_failures",
    "logs.gatekeeper",
})

# ── Database ───────────────────────────────────────────────────────────────────
def open_db(path: str = DB_PATH) -> sqlite3.Connection:
    db = sqlite3.connect(path, isolation_level=None, check_same_thread=False)
    db.row_factory = sqlite3.Row
    db.executescript("""
        PRAGMA journal_mode  = WAL;
        PRAGMA synchronous   = NORMAL;
        PRAGMA page_size     = 8192;
        PRAGMA mmap_size     = 268435456;
        PRAGMA cache_size    = -65536;
        PRAGMA temp_store    = MEMORY;
        PRAGMA foreign_keys  = ON;
        PRAGMA auto_vacuum   = INCREMENTAL;
    """)
    _schema(db)
    return db

def _schema(db):
    db.executescript("""
        CREATE TABLE IF NOT EXISTS snapshots (
            id         INTEGER PRIMARY KEY,
            epoch      INTEGER NOT NULL,
            ts         TEXT    NOT NULL,
            mode       TEXT    NOT NULL,
            hostname   TEXT,
            os_version TEXT,
            chip_name  TEXT,
            crc32      INTEGER UNIQUE NOT NULL
        );
        CREATE TABLE IF NOT EXISTS fields (
            id          INTEGER PRIMARY KEY,
            snapshot_id INTEGER NOT NULL REFERENCES snapshots(id) ON DELETE CASCADE,
            path        TEXT    NOT NULL,
            value       TEXT,
            crc32       INTEGER NOT NULL,
            epoch       INTEGER NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_fld_path_epoch ON fields(path, epoch DESC);
        CREATE INDEX IF NOT EXISTS idx_fld_snap       ON fields(snapshot_id);
        CREATE TABLE IF NOT EXISTS deltas (
            id          INTEGER PRIMARY KEY,
            detected_ts TEXT    NOT NULL,
            epoch       INTEGER NOT NULL,
            path        TEXT    NOT NULL,
            prev_value  TEXT,
            curr_value  TEXT,
            severity    TEXT    NOT NULL,
            mitre       TEXT,
            regression  INTEGER DEFAULT 0,
            snap_id     INTEGER REFERENCES snapshots(id)
        );
        CREATE INDEX IF NOT EXISTS idx_delta_sev ON deltas(severity, epoch DESC);
        CREATE TABLE IF NOT EXISTS risks (
            path       TEXT    PRIMARY KEY,
            severity   TEXT    NOT NULL,
            mitre      TEXT,
            first_ts   TEXT    NOT NULL,
            last_ts    TEXT    NOT NULL,
            status     TEXT    DEFAULT 'OPEN',
            delta_id   INTEGER
        );
        CREATE INDEX IF NOT EXISTS idx_risk_sev ON risks(severity, status);
    """)

# ── Flatten ───────────────────────────────────────────────────────────────────
def flatten(obj: Any, prefix: str = "") -> Generator[tuple[str, Any], None, None]:
    if isinstance(obj, dict):
        for k, v in obj.items():
            full = f"{prefix}.{k}" if prefix else k
            if isinstance(v, (dict, list)):
                yield from flatten(v, full)
            else:
                yield full, v
    elif isinstance(obj, list):
        yield prefix, json.dumps(obj, separators=(',', ':'), default=str)
    else:
        yield prefix, obj

def crc(s: str) -> int:
    return zlib.crc32(s.encode("utf-8", errors="replace")) & 0xFFFFFFFF

def truncate(v: Any) -> str:
    s = v if isinstance(v, str) else json.dumps(v, separators=(',', ':'), default=str)
    return s[:MAX_FIELD]

def load_prev(db) -> dict[str, tuple[str, int]]:
    row = db.execute("SELECT id FROM snapshots ORDER BY epoch DESC LIMIT 1").fetchone()
    if not row: return {}
    rows = db.execute("SELECT path,value,crc32 FROM fields WHERE snapshot_id=?", (row["id"],)).fetchall()
    return {r["path"]: (r["value"], r["crc32"]) for r in rows}

def trim_volatile(db):
    for path in VOLATILE_PATHS:
        db.execute("""DELETE FROM fields WHERE path=? AND id NOT IN (
            SELECT id FROM fields WHERE path=? ORDER BY epoch DESC LIMIT ?)""",
            (path, path, VOL_KEEP))

# ── Ingest ────────────────────────────────────────────────────────────────────
def ingest(source: str, db) -> None:
    t0 = time.monotonic()
    doc = json.load(sys.stdin) if source == "-" else json.load(open(source))

    meta      = doc.get("meta", {})
    epoch     = int(meta.get("epoch", time.time()))
    ts        = meta.get("timestamp_utc", datetime.datetime.utcnow().isoformat() + "Z")
    mode      = meta.get("mode", "unknown")
    arch      = meta.get("arch", "apple_silicon")
    hostname  = doc.get("identity", {}).get("hostname", "")
    os_ver    = doc.get("identity", {}).get("os_version", "")
    chip_name = doc.get("identity", {}).get("chip_name", "")

    snap_crc = crc(f"{epoch}:{hostname}:{mode}")
    if db.execute("SELECT 1 FROM snapshots WHERE crc32=?", (snap_crc,)).fetchone():
        print(f"[SKIP] Duplicate (crc={snap_crc})"); return

    now_ts   = datetime.datetime.utcnow().isoformat() + "Z"
    prev_fld = load_prev(db)

    with db:
        cur = db.execute(
            "INSERT INTO snapshots (epoch,ts,mode,hostname,os_version,chip_name,crc32) VALUES (?,?,?,?,?,?,?)",
            (epoch, ts, mode, hostname, os_ver, chip_name, snap_crc)
        )
        snap_id = cur.lastrowid

        field_rows: list[tuple] = []
        delta_rows: list[tuple] = []
        risk_rows:  list[tuple] = []

        for path, raw in flatten(doc):
            if path.startswith("meta."): continue
            val_str = truncate(raw)
            val_crc = crc(val_str)
            field_rows.append((snap_id, path, val_str, val_crc, epoch))

            if path in VOLATILE_PATHS or path not in prev_fld: continue
            prev_str, prev_crc = prev_fld[path]
            if prev_crc == val_crc or prev_str == val_str: continue

            rule = FIELD_RULES.get(path, ("MEDIUM", None, None))
            sev, mitre, reg_fn = rule
            is_reg = int(reg_fn(prev_str, val_str)) if reg_fn else 0
            if is_reg: sev = "CRITICAL"

            delta_rows.append((now_ts, epoch, path, prev_str[:500], val_str[:500],
                                sev, mitre, is_reg, snap_id))
            if sev in ("CRITICAL", "HIGH"):
                risk_rows.append((path, sev, mitre, now_ts, now_ts, "OPEN", None))

        for i in range(0, len(field_rows), BATCH_SIZE):
            db.executemany(
                "INSERT INTO fields (snapshot_id,path,value,crc32,epoch) VALUES (?,?,?,?,?)",
                field_rows[i:i+BATCH_SIZE]
            )
        if delta_rows:
            db.executemany(
                "INSERT INTO deltas (detected_ts,epoch,path,prev_value,curr_value,severity,mitre,regression,snap_id) VALUES (?,?,?,?,?,?,?,?,?)",
                delta_rows
            )
        if risk_rows:
            db.executemany(
                """INSERT INTO risks (path,severity,mitre,first_ts,last_ts,status,delta_id)
                   VALUES (?,?,?,?,?,?,?)
                   ON CONFLICT(path) DO UPDATE SET
                     severity=excluded.severity,last_ts=excluded.last_ts,status='OPEN'""",
                risk_rows
            )

    trim_volatile(db)
    db.execute("PRAGMA incremental_vacuum(100)")

    elapsed = time.monotonic() - t0
    crit    = sum(1 for r in delta_rows if r[5] == "CRITICAL")
    print(f"[OK] snap=#{snap_id} chip={chip_name} arch={arch} "
          f"fields={len(field_rows)} deltas={len(delta_rows)} "
          f"risks={len(risk_rows)} crit={crit} {elapsed:.2f}s")

    if crit:
        print("\n  ⚠  CRITICAL CHANGES:")
        for r in delta_rows:
            if r[5] == "CRITICAL":
                reg = " [REGRESSION!]" if r[7] else ""
                print(f"     {r[2]}{reg}")
                print(f"       BEFORE: {r[3][:100]}")
                print(f"       AFTER:  {r[4][:100]}")
        print()

def ingest_dir(directory: str, db) -> None:
    files = sorted(glob.glob(os.path.join(directory, "intel_*.json")))
    if not files: print(f"No intel_*.json in: {directory}"); return
    for f in files:
        try: ingest(f, db)
        except Exception as e: print(f"  [ERR] {f}: {e}")

# ── Report ────────────────────────────────────────────────────────────────────
def report(db) -> None:
    snap = db.execute("SELECT * FROM snapshots ORDER BY epoch DESC LIMIT 1").fetchone()
    if not snap: print("No snapshots."); return

    def g(path):
        r = db.execute("SELECT value FROM fields WHERE snapshot_id=? AND path=? LIMIT 1",
                       (snap["id"], path)).fetchone()
        return r["value"] if r else ""

    W = 72
    print("=" * W)
    print("  MAC INTELLIGENCE — APPLE SILICON POSTURE REPORT")
    print("=" * W)
    chip   = snap["chip_name"] or g("identity.chip_name")
    host   = g("identity.hostname")
    osv    = g("identity.os_version")
    p_c    = g("identity.performance_cores")
    e_c    = g("identity.efficiency_cores")
    pac    = g("identity.pac_support")
    roz    = g("identity.rosetta2_installed")
    dev_m  = g("identity.developer_mode")
    print(f"  Host:    {host}")
    print(f"  OS:      macOS {osv}   Chip: {chip}")
    print(f"  Cores:   {p_c} performance  +  {e_c} efficiency")
    print(f"  PAC:     {'✓ enabled' if pac == '1' else '✗ check'}   "
          f"Rosetta: {roz}   "
          f"DevMode: {dev_m}")
    print(f"  Snapshot: {snap['ts']}  mode={snap['mode']}")
    print()

    # ARM-specific boot security section
    boot_mode = g("security_config.arm_boot_security_mode") or g("identity.boot_security_mode")
    auth_root  = g("security_config.arm_authenticated_root") or g("identity.authenticated_root")
    kern_dev   = g("security_config.arm_kern_developer_mode")
    print("  ARM BOOT SECURITY:")
    boot_ok = "full security" in boot_mode.lower()
    auth_ok = "enabled" in (auth_root or "").lower()
    devk_ok = kern_dev.strip() in ("0", "")
    print(f"    {'✓' if boot_ok else '✗'} Boot Security Mode:    {boot_mode or 'unknown'}")
    print(f"    {'✓' if auth_ok else '✗'} Authenticated Root:    {auth_root or 'unknown'}")
    print(f"    {'✓' if devk_ok else '✗'} Developer Mode (kern): {kern_dev or '0'}")
    print()

    print("  SECURITY POSTURE:")
    checks = [
        ("SIP",          g("identity.sip_status"),          lambda v: "enabled" in v.lower()),
        ("Gatekeeper",   g("security_config.gatekeeper") or g("identity.gatekeeper"),
                         lambda v: "enabled" in v.lower() or "assessment" in v.lower()),
        ("FileVault",    g("security_config.filevault"),    lambda v: "on" in v.lower() or "enabled" in v.lower()),
        ("XProtect",     g("security_config.xprotect_version"), lambda v: bool(v and v != "unknown")),
        ("Remote Login", g("security_config.remote_login"), lambda v: "off" in v.lower()),
        ("Screen Lock",  g("security_config.screen_lock"),  lambda v: v.strip() == "1"),
        ("ASLR",         g("security_config.aslr"),         lambda v: v.strip() == "1"),
    ]
    for name, val, fn in checks:
        try:   ok = fn(val)
        except: ok = False
        print(f"    {'✓' if ok else '✗'} {name:<22} {val[:48]}")

    admins = g("accounts.admins")
    try:
        adm = json.loads(admins) if admins.startswith("[") else admins.split()
        print(f"\n  ADMINS ({len(adm)}): {', '.join(adm[:10])}")
    except: pass

    # Rosetta x86 app count
    rosetta_apps = g("software.rosetta_apps_x86")
    if rosetta_apps and rosetta_apps != "[]":
        try:
            apps = json.loads(rosetta_apps)
            x86_only = [a for a in apps if isinstance(a, dict) and a.get("arch") == "x86_64_only"]
            univ     = [a for a in apps if isinstance(a, dict) and a.get("arch") == "universal"]
            print(f"\n  ARM BINARY AUDIT:")
            print(f"    x86-only apps (no PAC): {len(x86_only)}  "
                  f"Universal: {len(univ)}")
            for a in x86_only[:5]:
                print(f"      • {a.get('app','')}")
        except: pass

    risks = db.execute(
        "SELECT severity, COUNT(*) cnt FROM risks WHERE status='OPEN' GROUP BY severity"
    ).fetchall()
    if risks:
        order = {"CRITICAL":0,"HIGH":1,"MEDIUM":2,"LOW":3}
        print(f"\n  OPEN RISKS:")
        for r in sorted(risks, key=lambda x: order.get(x["severity"], 9)):
            print(f"    {r['severity']:<10} {r['cnt']}")

    recent = db.execute(
        "SELECT path, severity, detected_ts, regression FROM deltas ORDER BY epoch DESC LIMIT 10"
    ).fetchall()
    if recent:
        print(f"\n  RECENT CHANGES:")
        for d in recent:
            reg = " [REG!]" if d["regression"] else ""
            print(f"    [{d['severity']:<8}] {d['path']}{reg}  ({d['detected_ts'][:16]})")

    total_s = db.execute("SELECT COUNT(*) FROM snapshots").fetchone()[0]
    total_f = db.execute("SELECT COUNT(*) FROM fields").fetchone()[0]
    print(f"\n  DB: {total_s} snapshots | {total_f:,} fields | {DB_PATH}")
    print("=" * W)

# ── Risks ─────────────────────────────────────────────────────────────────────
def show_risks(db, sev=None):
    sql    = "SELECT * FROM risks WHERE status='OPEN'"
    params = []
    if sev: sql += " AND severity=?"; params.append(sev.upper())
    sql += " ORDER BY CASE severity WHEN 'CRITICAL' THEN 1 WHEN 'HIGH' THEN 2 ELSE 3 END, last_ts DESC"
    rows = db.execute(sql, params).fetchall()
    if not rows: print("No open risks."); return
    print(f"\n{'='*70}\n  OPEN RISKS ({len(rows)})\n{'='*70}")
    cur_sev = None
    for r in rows:
        if r["severity"] != cur_sev:
            cur_sev = r["severity"]
            print(f"\n  ── {cur_sev} ──")
        m = f"  [{r['mitre']}]" if r["mitre"] else ""
        print(f"  {r['path']}{m}")
        print(f"    Last: {r['last_ts'][:16]}")

# ── Timeline ──────────────────────────────────────────────────────────────────
def timeline(db, path):
    rows = db.execute("""SELECT s.ts, f.value FROM fields f
        JOIN snapshots s ON f.snapshot_id=s.id
        WHERE f.path=? ORDER BY f.epoch ASC""", (path,)).fetchall()
    if not rows: print(f"No data for: {path}"); return
    print(f"\nTimeline: {path} ({len(rows)} points)")
    print("-" * 70)
    prev = None
    for r in rows:
        val = (r["value"] or "")[:80].replace("\n", " ")
        chg = " ◀ CHANGED" if prev is not None and val != prev else ""
        print(f"  {r['ts'][:19]}  {val}{chg}")
        prev = val

# ── Search ────────────────────────────────────────────────────────────────────
def search(db, kw):
    rows = db.execute("""SELECT DISTINCT f.path, f.value, s.ts
        FROM fields f JOIN snapshots s ON f.snapshot_id=s.id
        WHERE f.value LIKE ? OR f.path LIKE ?
        ORDER BY f.epoch DESC LIMIT 100""",
        (f"%{kw}%", f"%{kw}%")).fetchall()
    if not rows: print(f"No results for: {kw}"); return
    print(f"\nSearch '{kw}' — {len(rows)} matches:")
    print("-" * 70)
    seen = set()
    for r in rows:
        if r["path"] in seen: continue
        seen.add(r["path"])
        val = (r["value"] or "")[:100].replace("\n", " ")
        print(f"  {r['path']}")
        print(f"    {val}")

# ── Stats ─────────────────────────────────────────────────────────────────────
def stats(db):
    snaps  = db.execute("SELECT COUNT(*) FROM snapshots").fetchone()[0]
    fields = db.execute("SELECT COUNT(*) FROM fields").fetchone()[0]
    deltas = db.execute("SELECT COUNT(*) FROM deltas").fetchone()[0]
    risks  = db.execute("SELECT COUNT(*) FROM risks WHERE status='OPEN'").fetchone()[0]
    first  = db.execute("SELECT MIN(ts) FROM snapshots").fetchone()[0]
    last   = db.execute("SELECT MAX(ts) FROM snapshots").fetchone()[0]
    db_mb  = os.path.getsize(DB_PATH) / 1048576 if os.path.exists(DB_PATH) else 0

    # ARM: show chip name distribution
    chips  = db.execute("SELECT chip_name, COUNT(*) n FROM snapshots GROUP BY chip_name").fetchall()

    print(f"\n  Database: {DB_PATH}  ({db_mb:.1f} MB)")
    print(f"  Snapshots:  {snaps:>6,}")
    print(f"  Fields:     {fields:>6,}")
    print(f"  Deltas:     {deltas:>6,}")
    print(f"  Open risks: {risks:>6,}")
    if first: print(f"  Coverage: {first[:16]} → {(last or '?')[:16]}")
    if chips:
        print(f"\n  Chip names seen:")
        for r in chips:
            print(f"    {r['chip_name'] or 'unknown':<30} {r['n']} snapshots")

    print(f"\n  Most changed fields (top 12):")
    for r in db.execute("SELECT path,COUNT(*) n FROM deltas GROUP BY path ORDER BY n DESC LIMIT 12").fetchall():
        print(f"    {r['n']:4d}×  {r['path']}")

    print(f"\n  Snapshots by mode:")
    for r in db.execute("SELECT mode,COUNT(*) n FROM snapshots GROUP BY mode").fetchall():
        print(f"    {r['mode']:<12} {r['n']}")

# ── Main ───────────────────────────────────────────────────────────────────────
def main():
    global DB_PATH
    p = argparse.ArgumentParser(description="mac_intel storage v4.1 (Apple Silicon)")
    p.add_argument("--ingest",   metavar="PATH")
    p.add_argument("--report",   action="store_true")
    p.add_argument("--risks",    metavar="SEV", nargs="?", const="")
    p.add_argument("--timeline", metavar="FIELD")
    p.add_argument("--search",   metavar="KW")
    p.add_argument("--stats",    action="store_true")
    p.add_argument("--db",       metavar="PATH", default=DB_PATH)
    args = p.parse_args()

    DB_PATH = args.db
    db = open_db(DB_PATH)

    if args.ingest:
        src = args.ingest
        if src == "-":
            ingest("-", db)
        elif os.path.isdir(src):
            ingest_dir(src, db)
        elif os.path.exists(src):
            ingest(src, db)
        else:
            print(f"Not found: {src}"); sys.exit(1)

    if args.report:             report(db)
    if args.risks is not None:  show_risks(db, args.risks or None)
    if args.timeline:           timeline(db, args.timeline)
    if args.search:             search(db, args.search)
    if args.stats:              stats(db)

    if not any([args.ingest, args.report, args.risks is not None,
                args.timeline, args.search, args.stats]):
        p.print_help()

if __name__ == "__main__":
    main()
