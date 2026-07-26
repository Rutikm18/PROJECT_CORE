# AttackLens macOS Agent — Troubleshoot Guide

**Agent v2.1.0 · macOS 15+ (Sequoia / Tahoe)**

---

## Quick Diagnosis

Always start here:

```bash
sudo attacklens-service repair     # AUTO-FIX: one shot fixes every known
                                   # install fault (stale config paths, plist
                                   # missing 'run', wrappers, exec bits,
                                   # quarantine, stuck services) — idempotent,
                                   # safe to run any time
attacklens-service diagnose        # quick: install + connectivity checklist
                                   # (step 7 scans for repair-able faults)
attacklens-service status          # service state + recent log
sudo attacklens-service doctor     # DEEP: decodes log messages, identifies a
                                   # rogue server squatting the manager port (by
                                   # PID), and flags the spool-storm trend
sudo attacklens-service logs       # live log tail
```

**If the agent is crash-looping and you don't know why: run `repair` first.**
It covers every failure mode documented in this file's "PKG Issue" sections.

### Built-in self-healing (2026-07-06)

Even without running `repair`, the agent stack now recovers from the common
mismatches on its own:

- **Agent CLI** accepts the legacy `--config`-only invocation (auto-maps to
  `run`), so a stale plist or old watchdog can no longer cause exit-code-2
  restart loops.
- **Watchdog** falls back to known-good agent paths when `[binaries] agent`
  points at a missing file, and toggles the `run` subcommand form automatically
  if the agent rejects its command line twice.
- **PKG postinstall** migrates preserved configs from old `.py` entry-script
  paths to the native binaries on every upgrade.

`doctor` is the deep self-diagnosis (added 2026-06-22): it runs
`agent/os/macos/diagnostics.py`, which knows every agent log message and the
common failure modes below, and prints a single **TOP BLOCKER** with the exact
fix. A periodic **self-heal LaunchDaemon** (`com.attacklens.selfheal`, every
5 min) runs the same checks automatically — it re-loads the agent if launchd
dropped it, and escalates (never silently) when the agent is alive but can't
deliver. State it writes: `/Library/AttackLens/health_diagnosis.json`.

---

## Issues Found in v2.1.0 PKG Install (2026-06-18)

These errors all surface immediately after running
`sudo installer -pkg attacklens-agent-2.1.0-arm64.pkg -target /` on a fresh Mac.

> **Shortcut:** every issue in this section is auto-fixed by
> `sudo attacklens-service repair` — the manual steps below are kept for
> understanding and for machines where the CLI itself is missing.

---

### PKG Issue 1 — `attacklens-service: command not found`

**What you see:**
```
% attacklens-service status
zsh: command not found: attacklens-service
```

**Root cause:**
The v2.0.x `pkg/build_pkg.sh` never copied `pkg/attacklens-service` into the
pkgroot, so `/usr/local/bin/attacklens-service` was never installed.

**Fix (v2.1.0 — already resolved in the current build):**
The build script now copies the CLI into the pkgroot at Step 3:
```bash
cp pkg/attacklens-service "$PKGROOT/usr/local/bin/attacklens-service"
chmod 755 "$PKGROOT/usr/local/bin/attacklens-service"
```
On fresh installs the binary lands at `/usr/local/bin/attacklens-service`.

**If you're on an older PKG, install the CLI manually:**
```bash
sudo cp agent/os/macos/pkg/attacklens-service /usr/local/bin/
sudo chmod 755 /usr/local/bin/attacklens-service
sudo xattr -d com.apple.quarantine /usr/local/bin/attacklens-service 2>/dev/null || true
attacklens-service version          # should print v2.1.0
```

---

### PKG Issue 2 — `attacklens-watchdog start: unrecognized arguments`

**What you see:**
```
% sudo attacklens-service start
usage: attacklens-watchdog [-h] [--config CONFIG]
attacklens-watchdog: error: unrecognized arguments: start
```

**Root cause:**
`watchdog.py` in v2.0.x accepted only `--config`; it had no subcommand support.
When `attacklens-service start` called `attacklens-watchdog start`, argparse
rejected the `start` argument.

**Fix (v2.1.0 — already resolved):**
`watchdog.py` now uses:
```python
parser.add_argument("command", nargs="?",
    choices=["run","status","start","stop","restart","logs"],
    default="run")
```
LaunchDaemon invokes `attacklens-watchdog --config <path>` (no subcommand →
defaults to `run`, i.e. foreground mode). Human operators use
`attacklens-watchdog status|start|stop|restart|logs` from the terminal.

**Quick verify:**
```bash
attacklens-watchdog status          # shows ● com.attacklens.watchdog ...
sudo attacklens-watchdog restart    # restarts the LaunchDaemon
sudo attacklens-watchdog logs       # live log tail
```

**If you're on an older binary, rebuild the PKG:**
```bash
cd /Users/rutikmangale/Downloads/macbook_data
VERSION=2.1.0 ARCH=arm64 \
  MANAGER_URL="http://<your-manager-ip>:8080" \
  TLS_VERIFY=false \
  bash agent/os/macos/pkg/build_pkg.sh
sudo installer -pkg agent/os/macos/pkg/dist/attacklens-agent-2.1.0-arm64.pkg -target /
```

---

### PKG Issue 3 — `Bootstrap failed: 5: Input/output error`

**What you see:**
```
Bootstrap failed: 5: Input/output error
```
or
```
launchctl: service already loaded
```
(printed by the postinstall script, but the installer UI may show it as a
postinstall error)

**Root cause:**
Running `launchctl bootstrap system <plist>` when the service is already loaded
(from a previous install) always fails with error 5 (ENXIO — "Input/output
error"). The v2.0.x postinstall used the legacy `launchctl load -w`, which has
the same failure mode.

**Fix (v2.1.0 — already resolved in postinstall):**
The postinstall now runs a safe bootout→enable→bootstrap sequence with a
`kickstart -k` fallback:
```bash
launchctl bootout "system/${label}" 2>/dev/null || true
launchctl enable  "system/${label}" 2>/dev/null
out=$(launchctl bootstrap system "$plist" 2>&1)
if echo "$out" | grep -qE "Input/output error|already loaded| 5: "; then
  launchctl kickstart -k "system/${label}" 2>/dev/null
fi
```

**If you hit this during a reinstall (PKG already installed), fix manually:**
```bash
# Step 1 — bootout the old services
sudo launchctl bootout system/com.attacklens.agent    2>/dev/null || true
sudo launchctl bootout system/com.attacklens.watchdog 2>/dev/null || true

# Step 2 — enable them (required before bootstrap on macOS 13+)
sudo launchctl enable system/com.attacklens.agent
sudo launchctl enable system/com.attacklens.watchdog

# Step 3 — load
sudo launchctl bootstrap system /Library/LaunchDaemons/com.attacklens.agent.plist
sudo launchctl bootstrap system /Library/LaunchDaemons/com.attacklens.watchdog.plist

# Step 4 — verify
launchctl list | grep attacklens
attacklens-service status
```

**If bootstrap still fails after the above sequence:**
```bash
# Use kickstart to force-restart an already-running service
sudo launchctl kickstart -k system/com.attacklens.agent
sudo launchctl kickstart -k system/com.attacklens.watchdog
```

---

### PKG Issue 4 — SCA section missing from dashboard / `sca_apple_macos.yml not found`

**What you see:**
The Security Posture module in the dashboard shows no SCA data, or the agent
log contains:
```
agent.sca ERROR Policy file not found: .../agent/agent/sca/policies/sca_apple_macos.yml
```

**Root cause:**
PyInstaller `--onefile` does NOT bundle data files (YAML policy files) unless
explicitly passed with `--add-data`. Without it the `policies/` directory is
empty inside the frozen binary's `sys._MEIPASS` directory.

**Fix (v2.1.0 — already resolved in build_pkg.sh):**
```bash
--add-data "agent/agent/sca/policies/sca_apple_macos.yml:agent/agent/sca/policies"
```
This mirrors the package path so `os.path.dirname(__file__)`-relative resolution
works correctly inside the frozen binary.

**Verify the policies are bundled (before distributing):**
```bash
# Extract the binary's _MEIPASS and check
/Library/AttackLens/bin/attacklens-agent run --list-policies 2>&1 | head -5
# or check inside the build spec:
grep "sca_apple_macos" agent/os/macos/pkg/attacklens-agent.spec
```

**If you're on an older build, rebuild with the fix:**
```bash
VERSION=2.1.0 ARCH=arm64 \
  MANAGER_URL="http://<manager-ip>:8080" \
  TLS_VERIFY=false \
  bash agent/os/macos/pkg/build_pkg.sh
```

---

## Issues Found in Your Session (2026-05-15)

### Issue 1 — `getcwd: cannot access parent directories`

**What you saw:**
```
shell-init: error retrieving current directory: getcwd: cannot access parent directories: Operation not permitted
job-working-directory: error retrieving current directory: ...
```

**Root cause:**  
You ran `sudo attacklens-service` from a terminal whose current working directory
(`~/CTF`) no longer exists or is inaccessible — the directory was deleted, a
mounted volume was ejected, or the path moved while the terminal was open.
When `sudo` spawns a child process it inherits the invalid CWD.
The `job-working-directory` lines are `launchctl` failing to `chdir()` to the
same invalid path when managing the LaunchDaemon.

**This is cosmetic noise — it does NOT affect the agent.**  
The agent runs with an absolute `WorkingDirectory` in its plist
(`/Library/AttackLens`), so the service itself is unaffected.

**Fix: change to a valid directory before running sudo commands:**
```bash
cd /                             # or cd ~ or cd /tmp
sudo attacklens-service status   # clean output now
```

**Permanent fix — add to your shell config (`~/.zshrc`):**
```bash
# Recover when CWD is deleted (e.g. after ejecting a CTF volume)
PROMPT_COMMAND='[[ -d "$PWD" ]] || cd ~' 2>/dev/null || true
```

---

### Issue 2 — `HTTP 429` — Manager Rate-Limiting the Agent

**What you saw:**
```
agent.sender ERROR Manager rejected (HTTP 429) section=ports — dropping
agent.sender ERROR Manager rejected (HTTP 429) section=processes — dropping
agent.sender ERROR Manager rejected (HTTP 429) section=connections — dropping
agent.sender ERROR Manager rejected (HTTP 429) section=metrics — dropping
```

**Root cause:**  
The manager's ingest rate limiter rejected bursts from the agent.
On startup all collectors fire nearly simultaneously — ports (30 s), processes,
connections, metrics (60 s) all trigger at t=0, producing 4-6 POSTs inside one
second. The manager's per-agent rate window was exhausted.

**Update — 429 is no longer dropped (verified against the current sender.py):**
429 is treated as a *transient* failure, distinct from the other 4xx codes —
it logs the warning above, then falls through to the same exponential-backoff
retry loop as a network error. If all retries are exhausted, the payload is
spooled to disk like any other failed send, not discarded. Only a genuine 4xx
client error (malformed payload, schema rejection) is dropped as
unrecoverable — that case is correct to drop, since retrying a bad payload
forever would never succeed. If you still see payload loss on 429 specifically,
that's a regression worth re-reporting with the exact agent version.

**Fix A — space out collection intervals in `/Library/AttackLens/agent.toml`:**
```toml
[collection.sections]
# Stagger high-frequency sections so they don't all fire at boot
ports       = { enabled = true, interval_sec = 45,  send = true }
metrics     = { enabled = true, interval_sec = 75,  send = true }
processes   = { enabled = true, interval_sec = 90,  send = true }
connections = { enabled = true, interval_sec = 60,  send = true }
```

Reload without restart:
```bash
sudo attacklens-service reload     # sends SIGHUP — no process restart
```

**Fix B — raise the manager's per-agent rate limit.**  
Edit `manager/manager/api/ingest.py` and increase the `RATE_LIMIT_*` constants,
then restart the manager:
```bash
docker-compose restart manager     # or however you run it
```

---

### Issue 3 — `Connection refused` / Manager Offline

**What you saw:**
```
agent.sender WARNING Send failed (attempt 1/3): <urlopen error [Errno 61] Connection refused>
agent.sender WARNING Send failed (attempt 2/3): <urlopen error [Errno 61] Connection refused>
agent.sender WARNING Send failed (attempt 3/3): <urlopen error [Errno 61] Connection refused>
agent.sender WARNING Spooling ports to disk
```

**And from `diagnose`:**
```
✗  Manager reachable  http:8080    UNREACHABLE — check IP/firewall
⚠  Manager /health HTTP            502 (may be normal if endpoint differs)
```

**Root cause:**  
The manager service on `localhost` was not running (or was restarting).  
Errno 61 = `ECONNREFUSED` — the TCP port is not open.  
HTTP 502 means a reverse proxy (nginx/Caddy) is up but the app behind it is down.

**What the agent does automatically:**
- After all 3 retry attempts fail, the envelope is written to the disk spool at
  `/Library/AttackLens/spool/unsent.ndjson`
- The sender probes `/health` every 30 seconds
- When the manager comes back online the spool is **automatically drained** —
  no manual action needed

**Fix — start the manager:**
```bash
# If using Docker Compose (from the project root):
cd /Users/rutikmangale/Downloads/macbook_data
docker-compose up -d

# Verify manager is responding:
curl -s http://localhost/health
curl -s http://localhost:8080/health

# Run diagnose again to confirm:
attacklens-service diagnose
```

**Check what port the manager actually listens on:**
```bash
cat /Library/AttackLens/agent.toml | grep url
# If url = "http://localhost" (no port), nginx is expected on :80
# If url = "http://localhost:8080", the app is expected directly on :8080
```

**Check if the manager process is running:**
```bash
lsof -i :80 -i :8080 | grep LISTEN
ps aux | grep -E "uvicorn|gunicorn|fastapi|python"
docker ps                           # if containerized
```

---

### Issue 3b — Manager "reachable" but `/health` returns 404 (rogue server on the manager port)

**What you saw (from `attacklens-service diagnose`):**
```
✓  Manager reachable  127.0.0.1:8080      OK
⚠  Manager /health HTTP                   404 (may be normal if endpoint differs)
```
…and the dashboard stays empty even though the agent is "running".

**Root cause (found 2026-06-22):**
The TCP port is open (so "reachable" passes), but the thing answering it is **not
the manager**. The classic trigger: a stray `python -m http.server 8080` (often
started to share the `.pkg` from `dist/`) binds **IPv4 `127.0.0.1:8080`**, while
Docker's manager publishes on `*:8080`. When the agent connects to
`127.0.0.1:8080`, the **IPv4 loopback bind wins**, so every telemetry POST hits
the static file server and gets a 404. The agent's sender treats 404 (a 4xx
client error) as unrecoverable and **drops the payload** — silent data loss, and
nothing reaches the dashboard.

Tell-tale signature:
```bash
curl -sI http://127.0.0.1:8080/health      # Server: SimpleHTTP/0.6 Python/3.13.7  ← NOT uvicorn
lsof -nP -iTCP:8080 -sTCP:LISTEN
#   Python    27355 ... TCP 127.0.0.1:8080 (LISTEN)   ← rogue, shadows the manager (IPv4)
#   com.docke 69558 ... TCP *:8080 (LISTEN)            ← the real manager forward
```

**Fix — kill the squatter (it's your own process; no sudo needed):**
```bash
kill 27355                                 # the non-Docker PID from lsof above
curl -s http://127.0.0.1:8080/health       # must now return {"status":"ok",...}
```
The agent auto-recovers within seconds (the sender probes `/health`, sees it
healthy, and resumes delivering). **Never run `python -m http.server` on the
manager's port** — use a different port (e.g. 8000) to share files.

`sudo attacklens-service doctor` detects this automatically and prints the exact
offending PID + `kill` command (verdict: `rogue_server`). The self-heal daemon
escalates it too, but deliberately does **not** auto-kill a process (it could be
a server you started on purpose) — it surfaces the fix instead.

Alternative if you can't free the port: point the agent at the manager's other
front door (Caddy on port 80):
```bash
sudo attacklens-service set-manager http://127.0.0.1
```

---

### Issue 4 — `Send queue full — dropped oldest item`

**What you saw:**
```
agent WARNING Send queue full — dropped oldest item
(repeated ~20+ times per second)
```

**Root cause:**  
The in-memory send queue hit its capacity (`max_queue_size = 500` by default).

Timeline of what happened:
1. Manager goes offline (Connection refused)
2. Sender correctly spools items to `/Library/AttackLens/spool/unsent.ndjson`
3. BUT the spooling itself has a brief lock; if the orchestrator produces items
   faster than the spool thread writes them, the queue fills
4. When `queue.qsize() >= max_queue_size`, the orchestrator drops the oldest item

With 20+ sections collecting every 30–120 seconds and the sender unable to drain
them (manager offline), the queue saturates in ~3–5 minutes.

**Update — overflow no longer drops data (verified against the current
core.py):** when the in-memory queue is full, the Orchestrator now evicts the
oldest item and hands it to the Sender's disk spool instead of discarding it
(`overflow_sink` / `Sender.spool_envelope`) — it's replayed once the backlog
drains, same as any other spooled payload. The log line changed accordingly:
`"Send queue full (max=N) — spilled oldest section=X to disk spool"`. The
"dropped oldest item" message below is from the historical, now-fixed bug —
if you see that exact message, you're running an old agent build and should
rebuild/reinstall, not just tune `max_queue_size`.

**Fix A — increase queue size in `/Library/AttackLens/agent.toml`:**
```toml
[manager]
url           = "http://localhost"
max_queue_size = 2000              # default 500 — raise for longer outage tolerance
```

**Fix B — reduce collection frequency for volatile sections while manager is down.**
The agent detects offline state and skips the 3× retry loop (spools directly),
but collectors keep running at full speed regardless.

```toml
[collection.sections]
# Slow down high-volume sections — reduces queue pressure
ports       = { enabled = true, interval_sec = 120, send = true }
processes   = { enabled = true, interval_sec = 120, send = true }
connections = { enabled = true, interval_sec = 120, send = true }
metrics     = { enabled = true, interval_sec = 120, send = true }
```

**Fix C (code) — in `core.py`, spool directly when `_online` is False.**  
This already exists in `sender.py` (`if not self._online: self._spool.write(envelope); continue`),
but the orchestrator still enqueues to the in-memory queue first.
A future improvement: bypass the in-memory queue entirely when offline and write
straight to spool from the orchestrator thread.

**Check spool size:**
```bash
ls -lh /Library/AttackLens/spool/
# If unsent.ndjson grows over 50 MB the spool auto-trims (drops oldest 10%)
```

---

### Issue 5b — Agent never starts after reboot, exit code 78 OR a silent restart loop

**What you'd see:**
```
$ attacklens-service status
Agent:         stopped  (last exit: 2)
```
or, watching `launchctl print system/com.attacklens.agent` across a few seconds,
the PID changing every ~10s (ThrottleInterval) forever — KeepAlive restarting
a process that exits immediately every single time.

**Root cause (found 2026-06-19, fixed in this build):**
The agent binary/`run_agent.py` is built around `agent_entry.py`, whose CLI is
**subcommand-based** (`run`, `start`, `stop`, `status`, ...). Every plist
generator in this tree (`launchd.py`, `install.sh`, `build_pkg.sh`,
`attacklens-service`'s macOS-15+ auto-patcher) used to invoke it as:
```
<binary-or-run_agent.py> --config /Library/AttackLens/agent.toml
```
With no subcommand, argparse treats `--config` as having no matching
subcommand and tries to parse the config path itself as the subcommand →
`error: argument COMMAND: invalid choice: '/Library/AttackLens/agent.toml'`
→ exit 2 → KeepAlive restarts it → exit 2 again, forever. The agent **never
actually starts**, on first boot or after any reboot. This is the most
severe possible failure of capability #1 (auto-launch persistence): launchd
faithfully restarts the process every 10 seconds exactly as designed, while
the agent itself never runs even once.

Confirmed by direct reproduction:
```bash
python3 -c "
import sys; sys.argv = ['attacklens-agent', '--config', '/x.toml']
from agent.agent_entry import _parser
_parser().parse_args()"
# SystemExit(2): invalid choice: '/x.toml'
```

**Fix:** every plist generator now inserts the `run` subcommand:
```
<binary-or-run_agent.py> run --config /Library/AttackLens/agent.toml
```
`run_watchdog.py` is unaffected — it calls `watchdog.main()` directly, which
uses a plain (non-subcommand) `argparse` and already accepted `--config`
correctly.

**If you're on an older install:** reinstall the `.pkg`, or manually patch the
two plists at `/Library/LaunchDaemons/com.attacklens.agent.plist` (NOT the
watchdog plist) to insert `<string>run</string>` before `<string>--config</string>`
in `ProgramArguments`, then `sudo attacklens-service restart`.

---

### Issue 5c — Agent process runs after reboot but delivers NO telemetry (keychain locked at boot)

**What you'd see:**
```
$ sudo attacklens-service status
Agent:         running            # process is up — launchd/KeepAlive happy
```
…but the dashboard shows the agent offline / no fresh data, and
`/Library/AttackLens/logs/agent.log` repeats lines like:
```
No API key in keystore or config — starting first-run enrollment...
Enrollment failed (manager unreachable?) ... Starting with temporary key
```
or repeated `401` / re-enrollment churn. The agent is alive but can't authenticate.

**Root cause (fixed 2026-07-23):**
The pkg config used `keystore = "keychain"`. The agent runs as a **root
LaunchDaemon that starts at boot with no user login session**, so the macOS
**login keychain is locked** and the `keyring` library can't read the key back.
On interactive install the key went into the login keychain; after a reboot the
root daemon `load_key()` finds nothing (login keychain locked, System keychain +
file backend empty) → no key → enrollment loop / silent non-delivery. The
process stays up (nothing crashes, so KeepAlive never fires) while delivering
zero telemetry.

**Fix (in this build):**
- Fresh installs now generate `keystore = "file"` — the ACL-restricted file
  (`/Library/AttackLens/security/<agent-id>.key`, 0600, root-only) is the only
  storage guaranteed readable by a root daemon at boot.
- `store_key()` now **always mirrors the key to that file** even when the
  configured backend is `keychain` (defensive backstop).
- On startup, a key loaded from the Keychain is mirrored to the file too, so
  **upgrades from older keychain-only installs self-heal on the first run**.
- The pkg postinstall now verifies the daemon reached `running` and prints the
  last agent stderr lines if it didn't — so this surfaces at install time.

**If you're on an older install (recover now):**
```bash
# Point the keystore at the boot-safe file backend and re-run:
sudo sed -i '' 's/keystore = "keychain"/keystore = "file"/' /Library/AttackLens/agent.toml
sudo attacklens-service restart          # loads key from keychain, mirrors to file
sudo attacklens-service status
# verify the boot-safe key file now exists (root-only, 0600):
sudo ls -l /Library/AttackLens/security/
```
Then reboot to confirm the agent comes back delivering data.

---

### Issue 5 — `✗ TOML library — run: pip3 install tomli` (diagnose false-fail)

**What you saw:**
```
✗  TOML library    run: pip3 install tomli
```

**Root cause:**  
The `diagnose` command uses the system Python 3 (`/Library/Frameworks/Python.framework/.../python3.13`)
to test `import tomllib`. Python 3.13 has `tomllib` built-in, so this should
pass — it's likely a false-fail from the diagnose script finding a different
Python on `$PATH` than the bundled agent binary uses.

The agent itself runs fine (PID 72027, PID 73583 — running), so this does NOT
affect operation.

**Verify the agent's Python actually has tomllib:**
```bash
/Library/Frameworks/Python.framework/Versions/3.13/bin/python3.13 -c "import tomllib; print('OK')"
```

**If you still want to silence the warning:**
```bash
pip3 install tomli   # installs the backport (harmless on 3.13)
```

---

## Complete Fix Sequence for Your Situation

Run these in order from a valid directory:

```bash
# 1. Move to a valid directory first (fixes getcwd noise)
cd /

# 2. Start the manager (adjust command to your setup)
cd /Users/rutikmangale/Downloads/macbook_data
docker-compose up -d

# 3. Wait ~10 seconds, then verify manager health
curl -s http://localhost/health || curl -s http://localhost:8080/health

# 4. Stop the agent cleanly
sudo attacklens-service stop

# 5. Edit config to fix rate-limiting and queue issues
sudo nano /Library/AttackLens/agent.toml
# — Set max_queue_size = 2000
# — Stagger section intervals (see Issue 2 fix above)

# 6. Start the agent again
cd /
sudo attacklens-service start

# 7. Watch the log for 30 seconds
sudo attacklens-service logs   # Ctrl+C to stop

# 8. Full health check
attacklens-service diagnose
```

**Healthy log output should look like:**
```
agent INFO  API key ready (keystore backend=keychain, agent_id=mac-...)
agent INFO  Crypto keys derived (tail=...xxxx)
agent INFO  Orchestrator started — N sections, circuit breakers active
agent INFO  Manager connection restored
agent.sender DEBUG Sent metrics → 200
agent.sender DEBUG Sent processes → 200
```

---

## Reference — All Log Messages Explained

| Log message | Severity | Meaning | Action needed |
|---|---|---|---|
| `Send queue full (max=N) — spilled oldest section=X to disk spool` | WARNING | Manager offline; in-memory queue saturated; oldest item spilled to spool, NOT lost | Start manager — spool auto-drains; raise `max_queue_size` to reduce spill frequency |
| `HTTP 429 rate-limited ... (attempt N/3)` | WARNING | Manager rate-limited this send; treated as transient, retried with backoff, spooled if all retries fail | Space out collection intervals if persistent |
| `Send failed (attempt N/3): Connection refused` | WARNING | Manager TCP port closed | Start manager |
| `Spooling X to disk` | WARNING | Manager unreachable; data queued to disk spool | Start manager — spool auto-drains on reconnect |
| `Manager back online — draining spool` | INFO | Manager recovered; spooled data replaying | Normal — no action |
| `HTTP 401 (count=N) section=X — spooling for re-auth` | WARNING | API key rejected by manager | Run `sudo attacklens-service enroll` |
| `Persistent 401 — triggering re-enrollment` | WARNING | Key invalid after 3 consecutive 401s; auto re-enrolling | Usually auto-resolved; if not: `enroll` |
| `Shutting down (signal 15)` | INFO | Clean SIGTERM shutdown (stop command) | Normal |
| `Collector X failed: ...` | WARNING | One section's data collector threw an error | Check specific error message; usually permission |
| `[X] circuit open — skipping` | DEBUG | Section X failed 3× and is in cooldown | Auto-recovers after 60 s |
| `Config reloaded on SIGHUP` | INFO | Hot reload succeeded | Normal |
| `Enrollment failed (manager unreachable?)` | WARNING | Can't reach manager on first boot | Start manager first, then restart agent |
| `error: argument COMMAND: invalid choice` (in `agent-stderr.log`, repeating every ~10s) | — | Plist invokes the binary without the `run` subcommand — agent never starts, ever (see Issue 5b) | Reinstall/rebuild — fixed in this build's plist generators |

---

## Diagnosing Connectivity

```bash
# Is the manager port open?
nc -zv localhost 80        # nginx / reverse proxy
nc -zv localhost 8080      # direct FastAPI

# HTTP health endpoint
curl -v http://localhost/health
curl -v http://localhost:8080/health

# What's listening on those ports?
sudo lsof -i :80 -i :8080 | grep LISTEN

# Can the LaunchDaemon reach it? (run as root = same context as daemon)
sudo curl -s http://localhost/health

# Check for firewall blocking loopback (rare but possible)
sudo /usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate
```

---

## Inspecting the Disk Spool

```bash
# How much data is spooled?
ls -lh /Library/AttackLens/spool/

# Count how many payloads are waiting
wc -l /Library/AttackLens/spool/unsent.ndjson

# Peek at the sections in the spool (non-destructive)
cut -d'"' -f4 /Library/AttackLens/spool/unsent.ndjson | sort | uniq -c | sort -rn

# Clear the spool manually (if data is stale/corrupt)
sudo rm /Library/AttackLens/spool/unsent.ndjson
```

---

## Resetting the Agent (Last Resort)

```bash
# Full reset: stop, clear key, force re-enrollment on next start
sudo attacklens-service stop
sudo attacklens-service enroll       # clears Keychain entry
sudo rm -f /Library/AttackLens/spool/unsent.ndjson   # clear stale spool

# Update manager URL if it changed
sudo attacklens-service set-manager <NEW_IP_OR_URL>  # stops, updates, restarts

# Regenerate agent.toml (preserves identity + manager URL)
sudo attacklens-service update-config

# Start fresh
cd /
sudo attacklens-service start
attacklens-service diagnose
```

---

## agent.toml Recommended Settings

```toml
[agent]
id   = "mac-e33b9d33-d7fa-5950-8da6-bea73ae1df79"  # keep as-is
name = "Rutik_attacklens_arm64"

[manager]
url            = "http://localhost"    # or your manager IP
tls_verify     = false                 # true for https with valid cert
timeout_sec    = 30
retry_attempts = 3
retry_delay_sec = 5
max_queue_size  = 2000                 # raised from default 500

[collection]
tick_sec = 5

[collection.sections]
# Staggered intervals — prevents startup burst that triggers 429
ports       = { enabled = true, interval_sec = 45,  send = true }
metrics     = { enabled = true, interval_sec = 75,  send = true }
processes   = { enabled = true, interval_sec = 90,  send = true }
connections = { enabled = true, interval_sec = 60,  send = true }
network     = { enabled = true, interval_sec = 120, send = true }
arp         = { enabled = true, interval_sec = 120, send = true }
battery     = { enabled = true, interval_sec = 120, send = true }
services    = { enabled = true, interval_sec = 300, send = true }
storage     = { enabled = true, interval_sec = 600, send = true }
security    = { enabled = true, interval_sec = 3600, send = true }
apps        = { enabled = true, interval_sec = 86400, send = true }
packages    = { enabled = true, interval_sec = 86400, send = true }

[logging]
level   = "INFO"    # change to "DEBUG" for deep troubleshooting
file    = "/Library/AttackLens/logs/agent.log"
max_mb  = 10
backups = 3

[enrollment]
keystore = "keychain"

[watchdog]
enabled            = true
check_interval_sec = 30
max_restarts       = 5
restart_window_sec = 300
```

After editing:
```bash
sudo attacklens-service reload   # hot-reload (no restart)
# or
sudo attacklens-service restart  # full restart
```

---

## Service Commands Reference

| Command | Root? | What it does |
|---|---|---|
| `attacklens-service status` | No | Service state, config summary, last 8 log lines |
| `attacklens-service logs` | No | Live `tail -f` of agent.log |
| `attacklens-service config` | No | Print agent.toml |
| `attacklens-service version` | No | Version + Python info |
| `attacklens-service diagnose` | No | Full connectivity + install health check (incl. known-fault scan) |
| `sudo attacklens-service repair` | Yes | Auto-fix all known install faults, then reload + verify services |
| `sudo attacklens-service doctor` | No* | Deep diagnosis: decode logs, name a rogue server on the manager port (by PID), spool-storm trend (*sudo for full log access) |
| `sudo attacklens-service start` | Yes | Start agent + watchdog + self-heal LaunchDaemons |
| `sudo attacklens-service stop` | Yes | Stop agent + watchdog |
| `sudo attacklens-service restart` | Yes | Stop then start |
| `sudo attacklens-service reload` | Yes | SIGHUP — reload config with no restart |
| `sudo attacklens-service set-manager <URL>` | Yes | Update manager URL + clear key + restart |
| `sudo attacklens-service enroll` | Yes | Clear API key, force re-enrollment on next start |
| `sudo attacklens-service update-config` | Yes | Regenerate agent.toml (keeps identity) |

---

*Generated 2026-05-15 · Updated 2026-06-18 · AttackLens v2.1.0 · macOS arm64*  
*Reference: `agent/os/macos/AGENT_CHANGES.md` · Install guide: `agent/os/macos/pkg/INSTALL_GUIDE.md`*
