# AttackLens macOS Agent — Troubleshoot Guide

**Agent v2.0.0 · macOS 15+ (Sequoia / Tahoe)**

---

## Quick Diagnosis

Always start here:

```bash
attacklens-service diagnose        # no sudo needed
attacklens-service status          # no sudo needed
sudo attacklens-service logs       # live log tail
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

**Note: HTTP 4xx responses are permanently dropped by the sender — they are NOT
retried and NOT spooled to disk.** This means those telemetry payloads are lost.

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

**Dropped items are gone — they are NOT recoverable from the spool.**
The spool only contains items that were successfully dequeued and written.

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
| `Send queue full — dropped oldest item` | WARNING | Manager offline; in-memory queue saturated; data lost | Start manager; raise `max_queue_size` |
| `Manager rejected (HTTP 429) section=X — dropping` | ERROR | Manager rate-limited this section; payload permanently lost | Space out collection intervals |
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
| `attacklens-service diagnose` | No | Full connectivity + install health check |
| `sudo attacklens-service start` | Yes | Start agent + watchdog LaunchDaemons |
| `sudo attacklens-service stop` | Yes | Stop agent + watchdog |
| `sudo attacklens-service restart` | Yes | Stop then start |
| `sudo attacklens-service reload` | Yes | SIGHUP — reload config with no restart |
| `sudo attacklens-service set-manager <URL>` | Yes | Update manager URL + clear key + restart |
| `sudo attacklens-service enroll` | Yes | Clear API key, force re-enrollment on next start |
| `sudo attacklens-service update-config` | Yes | Regenerate agent.toml (keeps identity) |

---

*Generated 2026-05-15 · AttackLens v2.0.0 · macOS arm64*
