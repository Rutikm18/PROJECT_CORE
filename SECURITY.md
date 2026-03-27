# Security Policy

## Reporting a Vulnerability

**Do NOT open a public GitHub issue for security vulnerabilities.**

Send a private report to the project maintainer with:
- Component affected (`agent`, `manager`, `crypto`, wire format)
- Steps to reproduce
- Potential impact assessment

Expected response: within 48 hours.

---

## Security Architecture

### Defense-in-Depth Layers

| Layer | Mechanism | Where |
|-------|-----------|-------|
| Transport | TLS 1.3 minimum (`ssl.TLSVersion.TLSv1_3`) | `agent/sender.py` |
| Confidentiality | AES-256-GCM — every payload | `shared/crypto.py` |
| Integrity | GCM authentication tag (16-byte) | `shared/crypto.py` |
| Authenticity | HMAC-SHA256 envelope signature | `shared/crypto.py` |
| Key derivation | HKDF-SHA256, domain-separated | `shared/crypto.py` |
| Replay prevention | ±5 min timestamp window + per-nonce dedup | `manager/auth.py` |
| Verification order | schema → timestamp → nonce → HMAC → decrypt | `manager/auth.py` |

### Key Material

- The **API key never travels on the wire** — only HKDF-derived child keys are used.
- The `enc_key` (AES) and `mac_key` (HMAC) are **domain-separated** via distinct HKDF `info` strings — compromise of one does not imply compromise of the other.
- The nonce is **randomly generated per message** (12 bytes / 96 bits per NIST SP 800-38D). Expected nonce collision probability is negligible at realistic message volumes.

### Verification Order (cheap → expensive)

```
1. Schema check          (O(1) field presence)
2. Timestamp window      (O(1) arithmetic — rejects stale/future without crypto)
3. Nonce dedup           (O(1) hash lookup — rejects replays without crypto)
4. HMAC verify           (constant-time comparison — reject tampering)
5. AES-256-GCM decrypt   (only reached on authenticated messages)
```

### Agent Configuration Security

- `agent.toml` is in `.gitignore` — **never commit it** (contains the API key).
- `tls_verify = false` disables certificate validation — for dev/self-signed certs only. The agent logs a warning when this is set.
- `API_KEY` on the manager is supplied via environment variable, never in code.

### Manager Hardening

- All error responses use generic messages (`"Verification failed"`) — never leak crypto failure reasons to callers.
- Nonce dedup cache is evicted every 60 s (background task) to prevent unbounded memory growth.
- CORS is configurable via `CORS_ORIGINS` environment variable — default `*` logs a warning; set to specific origins in production.
- Docker image runs as a non-root user (uid 1000).

---

## Dependency Hygiene

Run weekly (or on every PR):

```bash
make security   # bandit SAST + pip-audit CVE scan
```

The CI pipeline (`ci.yml`) runs both scans automatically.

---

## Known Limitations

| Limitation | Severity | Mitigation / Roadmap |
|------------|----------|----------------------|
| Single shared API key — no per-agent keys | Medium | Planned: per-agent JWT with rotation |
| SQLite — no encryption at rest | Low | Use encrypted filesystem or PostgreSQL |
| WebSocket token in URL query param (logged by proxies) | Low | Migrate to `Authorization` header |
| `tls_verify = false` silently weakens TLS | Low | Warning logged; document clearly |
| No rate limiting on `/api/v1/ingest` | Low | Add middleware or reverse-proxy rate limit |

---

## Hardening Checklist (Before Production)

- [ ] Replace self-signed cert with a CA-signed or Let's Encrypt cert
- [ ] Set `CORS_ORIGINS` to specific dashboard domain(s)
- [ ] Rotate API key — run `make keygen` and update both sides
- [ ] Set `tls_verify = true` in `agent.toml`
- [ ] Run `make security` — confirm no HIGH/CRITICAL findings
- [ ] Use an encrypted volume for `manager/data/`
- [ ] Enable network-level firewall — allow 8443 only from known agent IPs
- [ ] Set up log forwarding (ship `logs/` to a SIEM)
