# macOS Agent Installation and Lifecycle Guide

This guide explains how to install the macOS agent, manage it as a `launchd` service, and uninstall it safely.

## 1) Prerequisites

1. Open Terminal.
2. Go to the project root:
   ```bash
   cd /path/to/macbook_data
   ```
3. Make sure Python is available:
   ```bash
   python3 --version
   ```
4. Install manager dependencies (needed for key generation):
   ```bash
   pip3 install -r manager/requirements.txt
   ```
5. Install agent dependencies:
   ```bash
   pip3 install -r agent/requirements.txt
   ```

## 2) Generate API key (Manager side)

1. From project root, run:
   ```bash
   python3 manager/scripts/keygen.py
   ```
2. Copy the printed API key.

## 3) Configure the agent

1. Create agent config from example:
   ```bash
   cp agent/config/agent.toml.example agent/config/agent.toml
   ```
2. Edit `agent/config/agent.toml` and update:
   - `agent.id` (unique machine ID)
   - `agent.name` (friendly machine name)
   - `manager.url` (example: `https://127.0.0.1:8443`)
   - `manager.api_key` (paste generated key)
   - `manager.tls_verify` (`false` only for self-signed local dev)

## 4) Install agent as macOS service

1. Run the installer:
   ```bash
   cd agent
   bash scripts/install.sh
   ```
2. The script will:
   - Verify Python
   - Ensure dependencies are installed
   - Validate `config/agent.toml`
   - Create `~/Library/LaunchAgents/com.mac-intel.agent.plist`
   - Load service with `launchctl`
3. Confirm service is loaded:
   ```bash
   launchctl list | rg com.mac-intel.agent
   ```

## 5) Start manager (required for data ingestion)

Run manager from project root (example local TLS startup):

```bash
API_KEY="PASTE_YOUR_KEY_HERE" PYTHONPATH=. python3 -m uvicorn manager.manager.server:app \
  --host 0.0.0.0 \
  --port 8443 \
  --ssl-certfile certs/server.crt \
  --ssl-keyfile certs/server.key \
  --log-level info
```

## 6) Manage agent service (day-to-day)

Use plist path:

```bash
PLIST="$HOME/Library/LaunchAgents/com.mac-intel.agent.plist"
```

- **Check status**
  ```bash
  launchctl list | rg com.mac-intel.agent
  ```
- **Start**
  ```bash
  launchctl load "$PLIST"
  ```
- **Stop**
  ```bash
  launchctl unload "$PLIST"
  ```
- **Restart**
  ```bash
  launchctl unload "$PLIST" && launchctl load "$PLIST"
  ```
- **View logs**
  ```bash
  tail -f agent/logs/agent.log
  tail -f agent/logs/agent-err.log
  ```
- **Reload config without full restart**
  ```bash
  kill -HUP "$(pgrep -f agent.core)"
  ```

## 7) Verify agent connectivity

1. Check manager health:
   ```bash
   curl -k https://localhost:8443/health
   ```
2. Confirm agent appears:
   ```bash
   curl -k https://localhost:8443/api/v1/agents
   ```
3. Open dashboard:
   - `https://localhost:8443`

## 8) Uninstall agent from macOS

1. Stop and unload the service:
   ```bash
   launchctl unload "$HOME/Library/LaunchAgents/com.mac-intel.agent.plist" 2>/dev/null || true
   ```
2. Remove launch agent plist:
   ```bash
   rm -f "$HOME/Library/LaunchAgents/com.mac-intel.agent.plist"
   ```
3. Stop any leftover running process (if any):
   ```bash
   pkill -f agent.core || true
   ```
4. (Optional) Remove local agent logs:
   ```bash
   rm -f agent/logs/agent.log agent/logs/agent-err.log
   ```
5. (Optional) Remove local agent config:
   ```bash
   rm -f agent/config/agent.toml
   ```

## 9) Troubleshooting quick checks

- `401 Unauthorized`: manager `API_KEY` and agent `manager.api_key` do not match.
- Agent not sending: verify manager is reachable at `manager.url`.
- TLS errors in local dev: use `tls_verify = false` with self-signed certs only.
- Empty/partial sections: run with proper permissions and check `agent/logs/agent-err.log`.
