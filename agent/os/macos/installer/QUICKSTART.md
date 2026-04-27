# AttackLens Agent — Quick Start

## Connect to AWS Manager (port 8080, HTTP)

```bash
sudo bash install.sh --manager-url http://YOUR_AWS_IP:8080 --agent-name "My Mac"
```

## Connect to Local Manager (localhost)

1. Start the manager:
   ```bash
   cd /path/to/macbook_data
   docker compose up -d
   ```

2. Install agent pointing to localhost:
   ```bash
   sudo bash install.sh --manager-url http://localhost:8080 --agent-name "My Mac"
   ```

## Service Management

```bash
sudo attacklens-ctl status    # show agent + watchdog status
sudo attacklens-ctl start     # start services
sudo attacklens-ctl stop      # stop services
sudo attacklens-ctl restart   # restart services
sudo attacklens-ctl reload    # hot reload config (no restart)
sudo attacklens-ctl logs      # tail live log
sudo attacklens-ctl enroll    # force re-enrollment (clears key)
```

## Change Manager IP After Install

1. Edit config:
   ```bash
   sudo nano /Library/AttackLens/agent.toml
   # Change: url = "http://NEW_IP:8080"
   ```

2. Force re-enrollment and restart:
   ```bash
   sudo attacklens-ctl enroll
   sudo attacklens-ctl restart
   ```

## View Dashboard

- AWS: `http://YOUR_AWS_IP` (port 80 via Caddy) or `http://YOUR_AWS_IP:8080`
- Local: `http://localhost:8080`

## Troubleshoot

```bash
# Check agent is running
sudo attacklens-ctl status

# Watch logs live
sudo attacklens-ctl logs

# Test manager reachability from Mac
curl -v http://YOUR_MANAGER_IP:8080/health

# Check if data arrived on manager
curl http://YOUR_MANAGER_IP:8080/api/v1/agents
```
