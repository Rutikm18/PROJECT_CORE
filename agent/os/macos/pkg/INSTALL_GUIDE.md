# AttackLens macOS Agent — Install, Diagnosis & Troubleshooting Guide

Applies to the **binary PKG install** (v2.1.0+, built by `pkg/build_pkg.sh`).

Layout after install:

```
/Library/AttackLens/bin/attacklens-agent       PyInstaller binary (SCA policies bundled)
/Library/AttackLens/bin/attacklens-watchdog    PyInstaller binary
/Library/AttackLens/agent.toml                 config (generated on first install)
/Library/AttackLens/logs/                      agent + watchdog logs
/Library/LaunchDaemons/com.attacklens.agent.plist
/Library/LaunchDaemons/com.attacklens.watchdog.plist
/usr/local/bin/attacklens-service              management CLI (+ attacklens-ctl symlink)
```

---

## 1. Build the PKG (on your dev Mac)

```bash
cd /path/to/macbook_data
MANAGER_IP=<your-manager-ip> MANAGER_PORT=8080 VERSION=2.1.0 ARCH=arm64 \
  bash agent/os/macos/pkg/build_pkg.sh
```

Output: `agent/os/macos/pkg/dist/attacklens-agent-2.1.0-arm64.pkg`

Notes:
- Omit `MANAGER_IP` to build a generic PKG; set the URL in `agent.toml` after install.
- Intel Macs: `ARCH=x86_64`. Both: `ARCH=universal2`.
- The macOS CIS SCA policy (57 checks) is bundled inside the agent binary — no
  extra files needed on the endpoint.

## 2. Install

```bash
sudo installer -pkg agent/os/macos/pkg/dist/attacklens-agent-2.1.0-arm64.pkg -target /
```

The postinstall automatically:
- derives a stable agent ID from the hardware UUID (`mac-<uuid>`),
- generates `/Library/AttackLens/agent.toml` (preserved on upgrades),
- removes the quarantine attribute from the binaries,
- loads both LaunchDaemons (bootout-first, so reinstalls never hit
  "Bootstrap failed: 5").

## 3. Verify (60 seconds)

```bash
sudo attacklens-service status        # both services should show ● running
sudo attacklens-service diagnose      # full health check incl. manager reachability
tail -f /Library/AttackLens/logs/agent.log
```

On the manager, the agent should appear in the dashboard within ~1 minute
(open enrollment) with posture, inventory and `sca` sections in its payloads.

---

## 4. Management CLI reference

```bash
sudo attacklens-service status      # service state + agent self-report
sudo attacklens-service start       # start both daemons (handles already-loaded)
sudo attacklens-service stop        # stop both (watchdog first, so agent stays down)
sudo attacklens-service restart
sudo attacklens-service logs 100    # last 100 lines of agent/watchdog logs
sudo attacklens-service config      # print agent.toml
sudo attacklens-service diagnose    # files, services, exit codes, manager connectivity
sudo attacklens-service repair      # AUTO-FIX all known install faults, reload, verify
sudo attacklens-service uninstall   # complete removal
```

The binaries also self-serve:

```bash
sudo /Library/AttackLens/bin/attacklens-agent status
sudo attacklens-watchdog status|start|stop|restart|logs   # if /Library/AttackLens/bin is on PATH
```

---

## 5. Troubleshooting

**Start with the one-shot auto-fix — it resolves everything below except a
missing CLI:**
```bash
sudo attacklens-service repair
```
It fixes: stale `[binaries]` paths in agent.toml, agent plist missing the
`run` subcommand (exit-code-2 crash loop), missing `run_agent.sh` wrapper,
missing `/usr/local/bin` tools, lost exec bits / quarantine flags, and stuck
services (Bootstrap error 5). Idempotent — safe to run any time.

### "attacklens-service: command not found"
You installed a pre-2.1.0 PKG, which didn't ship the CLI. Rebuild the PKG from
this repo (v2.1.0+) and reinstall — or manage directly with `launchctl`:
```bash
sudo launchctl kickstart -k system/com.attacklens.agent
```

### "Bootstrap failed: 5: Input/output error"
The service is **already loaded** — this is not a real failure. Either:
```bash
sudo launchctl kickstart -k system/com.attacklens.agent    # restart in place
```
or bootout first, then bootstrap:
```bash
sudo launchctl bootout system/com.attacklens.agent
sudo launchctl bootstrap system /Library/LaunchDaemons/com.attacklens.agent.plist
```
`attacklens-service start` and the v2.1.0 postinstall do this automatically.

### "attacklens-watchdog start: unrecognized arguments"
Pre-2.1.0 watchdog binary — it only accepted `--config`. Rebuild + reinstall;
the new binary supports `status|start|stop|restart|logs`.

### Agent loaded but not running / restart-looping
```bash
sudo launchctl print system/com.attacklens.agent | grep -E "state|last exit"
tail -50 /Library/AttackLens/logs/agent-stderr.log
```
- **last exit code = 78 (or launchd status 19968)** → config error: bad or
  missing `agent.toml`. Regenerate: `sudo bash /Library/AttackLens/generate_config.sh`
- **crash on start** → check stderr log; a missing keystore is normal on first
  run (it enrolls automatically).

### Agent runs but never appears on the manager
```bash
sudo attacklens-service diagnose          # section 4 tests /health on the manager
grep url /Library/AttackLens/agent.toml
curl -sk http://<manager-ip>:8080/health
```
- Wrong scheme is the most common cause: manager listens on **http://…:8080**
  unless you fronted it with TLS. Fix `url` in agent.toml, then
  `sudo attacklens-service restart`.
- Firewall between endpoint and manager: test with `nc -vz <ip> 8080`.

### SCA section missing from payloads
The policy is bundled in the binary from v2.1.0. On older installs the frozen
binary shipped without policy files. Rebuild + reinstall. To add custom
policies without rebuilding, drop `.yml` files into `/Library/AttackLens/sca/`
(picked up automatically) and restart the agent.

### Clean reinstall
```bash
sudo attacklens-service uninstall     # or manually:
sudo launchctl bootout system/com.attacklens.watchdog
sudo launchctl bootout system/com.attacklens.agent
sudo rm -f /Library/LaunchDaemons/com.attacklens.{agent,watchdog}.plist
sudo rm -rf /Library/AttackLens
sudo pkgutil --forget com.attacklens.agent
# then reinstall the PKG
```

### Leftovers from old installs
- `/usr/local/bin/attacklens-control` (dangling symlink) — removed
  automatically by the v2.1.0 postinstall; safe to `sudo rm -f` manually.
- `/Library/AttackLens/src/` (old source-based layout) — safe to delete once
  the binary install is running.
