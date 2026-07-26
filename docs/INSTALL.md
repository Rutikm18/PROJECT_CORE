# AttackLens — Start Here (canonical install router)

This is the **single authoritative entry point** for installing AttackLens. It exists
because setup docs had drifted across four overlapping quick-starts with no signpost for
which one to trust. Follow the path for your role below; every other doc is either a
detail reference linked here or deprecated.

---

## The one golden path

```
1. Stand up the Manager   →  root  install.sh   (Docker Compose stack)
2. Get your credentials   →  docs/QUICK_START.md (admin login + ADMIN_TOKEN)
3. Install a macOS agent  →  agent/os/macos/pkg/  (binary PKG, v2.1.0+)  ← current
4. Verify end-to-end      →  docs/installation/quick-start.md
```

### 1. Manager (server)
Run the one-command installer from the repo root:
```bash
bash install.sh          # interactive; --repair to auto-fix deps
```
> ⚠️ Before running, set `REPO_URL` (and, for remote installs, your server IP). The
> shipped defaults are placeholders — see friction.md §1.

### 2. Credentials
Default dashboard login and how to retrieve the one-time `ADMIN_TOKEN`:
**→ [docs/QUICK_START.md](QUICK_START.md)** (credentials + token reference).

### 3. macOS agent — **use the binary PKG**
The **current, supported** agent package is built by `agent/os/macos/pkg/build_pkg.sh`
and documented in **→ [agent/os/macos/pkg/INSTALL_GUIDE.md](../agent/os/macos/pkg/INSTALL_GUIDE.md)**
(v2.1.0+). Install the latest pkg from `agent/os/macos/pkg/dist/`:
```bash
sudo installer -pkg attacklens-agent-<latest>-arm64.pkg -target /
sudo attacklens-service status
```

### 4. End-to-end verification
Full Mac→Manager→Dashboard walkthrough:
**→ [docs/installation/quick-start.md](installation/quick-start.md)**.

---

## Which doc is which (disambiguation)

| Doc | Purpose | Status |
|-----|---------|--------|
| **docs/INSTALL.md** (this file) | Start-here router | ✅ canonical |
| `agent/os/macos/pkg/INSTALL_GUIDE.md` | macOS agent install + diagnosis | ✅ current (v2.1.0+) |
| `docs/installation/quick-start.md` | End-to-end stack setup | ✅ reference |
| `docs/QUICK_START.md` | Dashboard credentials + ADMIN_TOKEN | ✅ reference |
| `agent/os/macos/installer/QUICKSTART.md` | Old `installer/` pkg path (v2.0.0) | ⛔ deprecated → use `pkg/` |

> Naming cleanup still pending: the older `installer/` packaging path and the legacy
> `macintel-*` pkg name should be retired in favour of `pkg/` + `attacklens-agent`.
> Tracked in friction.md §2.
