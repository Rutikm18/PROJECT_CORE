# AttackLens — Quick Start Reference

## Default Dashboard Credentials

| Field | Value |
|---|---|
| **Email** | `admin@attacklens.ai` |
| **Password** | `!HLwS=f73fHo$?p!#M77XA*M` |

> ⚠️ Change these immediately after first login in production deployments.

---

## Getting Your ADMIN_TOKEN

The **ADMIN_TOKEN** is the API key for managing agent keys and platform access. It's displayed **once at startup** in the Docker logs.

### Option 1: Extract from logs (recommended)

```bash
# Copy directly to clipboard
docker compose logs manager | grep "ADMIN TOKEN" | awk -F': ' '{print $NF}' | pbcopy

# Or just view it
docker compose logs manager | grep -A1 "ADMIN TOKEN"
```

### Option 2: Save for reuse

```bash
# Extract and save to .env
TOKEN=$(docker compose logs manager | grep "ADMIN TOKEN" | awk -F': ' '{print $NF}')
echo "ADMIN_TOKEN=$TOKEN" >> .env

# Now reference it anytime
cat .env | grep ADMIN_TOKEN
```

---

## First-Time Setup Checklist

- [ ] Launch EC2 instance (Ubuntu 22.04 LTS, t3.large)
- [ ] Run `bash install.sh --doctor` to verify all dependencies
- [ ] Run `bash install.sh` to build and start the stack
- [ ] Open dashboard: `https://YOUR_EC2_IP:8443` (accept self-signed cert warning)
- [ ] Login with `admin@attacklens.ai` / `!HLwS=f73fHo$?p!#M77XA*M`
- [ ] Extract ADMIN_TOKEN: `docker compose logs manager | grep "ADMIN TOKEN"`
- [ ] Build macOS agent PKG: `VERSION=2.1.0 MANAGER_IP=YOUR_EC2_IP bash agent/os/macos/pkg/build_pkg.sh`
- [ ] Install PKG on test Mac: `sudo installer -pkg attacklens-agent-2.1.0-arm64.pkg -target /`
- [ ] Verify agent: `sudo attacklens-service status` on the Mac
- [ ] Check dashboard for agent (should appear within ~1 minute)

---

## Key Commands (on manager server)

```bash
# Check all services healthy
./attacklens doctor

# View full manager logs
docker compose logs -f manager

# Restart a service
docker compose restart manager

# Get ADMIN_TOKEN
docker compose logs manager | grep -A1 "ADMIN TOKEN"

# List enrolled agents
curl http://localhost:8080/api/v1/agents
```

---

## macOS Agent Commands (on endpoint)

```bash
# Check agent status
sudo attacklens-service status

# Full health diagnostic
sudo attacklens-service diagnose

# View recent logs
sudo attacklens-service logs 100

# Restart
sudo attacklens-service restart

# Retrieve the agent's API key metadata
sudo /Library/AttackLens/bin/attacklens-agent status --dir /Library/AttackLens
```

---

## Security Notes

| Item | How to keep it safe |
|---|---|
| **Dashboard password** | Change immediately from default |
| **ADMIN_TOKEN** | Treat like an AWS access key — revoke & rotate regularly |
| **Manager URL** | Use Elastic IP on EC2 so agents don't need reconfiguration on reboot |
| **Self-signed cert** | Fine for demos; use Let's Encrypt for production (update `env.sh` with domain) |

---

## Troubleshooting

**Agent appears in Dashboard but no data?**
```bash
# On the Mac
sudo attacklens-service diagnose
# Section 4 will test manager reachability and show any connection errors
```

**Manager not healthy?**
```bash
./attacklens doctor
# or check logs:
docker compose logs manager --tail=50
```

**Buildx version too old?**
```bash
bash install.sh --repair
# Auto-upgrades Docker, Compose, and Buildx
```

---

## Keep These Safe

1. **ADMIN_TOKEN** — Shown once at startup. Save it immediately.
2. **EC2 Elastic IP** — Prevents IP changes that break agent configs.
3. **Dashboard password** — First thing to change from default.
4. **Backup .env** — Contains all secrets for rebuilding the stack.

---

## Next Steps

- [ ] Deploy 2nd macOS agent to verify multi-agent setup
- [ ] Configure threat-intel feeds (OTX, AbuseIPDB, GreyNoise) in `.env`
- [ ] Set up daily backups to S3
- [ ] Enable domain + Let's Encrypt for production
- [ ] Enable enrollment tokens to gate new agent enrollment
