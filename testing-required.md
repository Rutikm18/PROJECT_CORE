# AttackLens — Complete Testing Requirements

> **Scope**: mac_intel / AttackLens platform — agent → manager pipeline, detection engine, dashboard UI, multi-tenancy, concurrent sessions.
> **Audience**: QA / Security test engineers. Covers every discipline — not just pytest.

---

## 1. Backend Unit Tests (pytest)

| # | Area | Test Case | File / Location | Priority |
|---|------|-----------|-----------------|----------|
| 1.1 | Detection engine | Rule fires on expected telemetry payload | `tests/unit/test_detection_executor.py` | P0 |
| 1.2 | Detection engine | Rule does NOT fire on clean payload (false-positive guard) | `tests/unit/test_wildcard_bind_fp.py` | P0 |
| 1.3 | Detection engine | All detection categories have at least one passing test | `tests/unit/test_detection_coverage.py` | P0 |
| 1.4 | Incident lifecycle | `first_detected_at` never overwritten on re-upsert (dedup) | `manager/tests/unit/test_auto_resolve.py` | P0 |
| 1.5 | Incident lifecycle | `closed_at` stamped for SOC close, auto-resolve, mark_resolved | New — `test_incident_timestamps.py` | P0 |
| 1.6 | Incident lifecycle | `is_active` flips 1→0 on auto-resolve; re-upsert restores it | `test_auto_resolve.py` | P0 |
| 1.7 | Time window filter | Interval-overlap: old finding re-detected recently shows in 1h window | `tests/integration/test_findings_window.py` | P0 |
| 1.8 | Time window filter | Offline-agent findings appear in historical window query | New — `test_stale_agent_filtering.py` | P0 |
| 1.9 | Time window filter | Historical `active_only` view includes closed findings within window | New — `test_findings_window.py` | P0 |
| 1.10 | Time window filter | `live_agent_ids` bypassed when `window_start`/`window_end` are set | New — `test_stale_agent_filtering.py` | P0 |
| 1.11 | Fingerprinting | Changed evidence → new fingerprint → `last_detected_at` updated | `manager/tests/unit/test_payload_ledger.py` | P1 |
| 1.12 | Fingerprinting | Identical evidence → same fingerprint → `scan_count` incremented only | `test_payload_ledger.py` | P1 |
| 1.13 | AI Precision Validation | Validated finding has `precision_score` >= threshold in response | `tests/unit/test_validation_quality_floor.py` | P1 |
| 1.14 | AI Precision Validation | Below-threshold finding excluded when `validated_only=true` | `test_validation_page_visibility.py` | P1 |
| 1.15 | Finding query | `external_id_prefix` search uses index, returns only matching rows | `test_finding_query_contract.py` | P1 |
| 1.16 | Finding query | Advanced filter operators: is / contains / exists / not_exists | `test_finding_query_contract.py` | P1 |
| 1.17 | SLA | `sla_due` computed correctly per severity on insert | New — `test_sla_computation.py` | P1 |
| 1.18 | SLA | SLA status = `breached` when `now > sla_due` | `test_finding_query_contract.py` | P1 |
| 1.19 | Correlator | Correlation emitted when >= min_hosts trigger across agents | `test_custom_correlations.py` | P1 |
| 1.20 | Correlator | Fleet correlator excludes stale agents from host count | `test_stale_agent_filtering.py` | P1 |
| 1.21 | Terrain classification | Each category maps to exactly one canonical terrain | `tests/unit/test_terrain_classification.py` | P1 |
| 1.22 | Confidence scoring | Detection confidence >= 0.70 for rule-based sources | `test_detection_confidence_priority.py` | P2 |
| 1.23 | Remediation | OS-aware recipe returns commands for macos / linux / windows | New — `test_remediation_recipe.py` | P2 |
| 1.24 | Data retention | Inactive findings older than cutoff are pruned; active are not | `tests/unit/test_retention.py` | P2 |

---

## 2. Backend Integration Tests (pytest + real Postgres)

| # | Area | Test Case | File / Location | Priority |
|---|------|-----------|-----------------|----------|
| 2.1 | Full pipeline | Agent payload → detect → upsert → `GET /api/v1/detection/all` returns finding | `tests/integration/test_attacklens_pipeline.py` | P0 |
| 2.2 | Ingest | NDJSON+gzip batch ingested without data loss | `tests/integration/test_ingest.py` | P0 |
| 2.3 | Auth | Unauthenticated request returns 401 | `tests/unit/test_api_auth_coverage.py` | P0 |
| 2.4 | Auth | Expired token returns 401; valid token passes | `tests/unit/test_auth.py` | P0 |
| 2.5 | Auth | Concurrent sessions: limit enforced, oldest session evicted | New — `test_session_limits.py` | P0 |
| 2.6 | Auth | Role check: viewer cannot POST to triage endpoint | `tests/unit/test_auth_role_claim.py` | P0 |
| 2.7 | Multi-tenancy | Org-A user cannot see Org-B findings | `tests/unit/test_tenancy_model.py` | P0 |
| 2.8 | Multi-tenancy | Empty tenant tuple returns empty result set (not all findings) | `tests/unit/test_tenant_scope_middleware.py` | P0 |
| 2.9 | Window API | `/detection/all?window=1h` — recent finding in; old finding out | `tests/integration/test_findings_window.py` | P0 |
| 2.10 | Window API | `/detection/all?start=X&end=Y` — only findings in absolute range | `tests/integration/test_findings_window.py` | P0 |
| 2.11 | Window API | `/detection/all?window=7d` with offline agent — findings still returned | New — `test_findings_window.py` | P0 |
| 2.12 | Case management | Create case → link finding → update status — round-trip | `test_case_management_model.py` | P1 |
| 2.13 | Remediation API | `GET /api/v1/remediation/{id}/recipe?os_type=macos` returns steps | New — `test_remediation_recipe.py` | P1 |
| 2.14 | Agent enroll | Enroll → upsert → `GET /api/v1/agents` returns agent | `tests/unit/test_enroll_api.py` | P1 |
| 2.15 | Agent delete | Delete agent removes all findings, correlations, timeline | `tests/integration/test_delete_agents.py` | P1 |
| 2.16 | Portal | Portal user login → JWT → scoped findings only | `tests/integration/test_session_auth_end_to_end.py` | P1 |
| 2.17 | Concurrent writes | Parallel upserts of same (agent, category, item_key) — no deadlock | `tests/unit/test_shared_write_connection.py` | P1 |
| 2.18 | Write txn rollback | Failed batch → no partial rows committed | `tests/unit/test_write_txn_rollback.py` | P1 |
| 2.19 | Queue durability | DLQ replayer re-processes failed messages | `tests/unit/test_dlq_replayer.py` | P2 |
| 2.20 | Timeseries | `GET /api/v1/stats/trend?window=7d` returns 7 daily buckets | `tests/unit/test_timeseries.py` | P2 |

---

## 3. API Contract Tests (httpx / schemathesis)

| # | Area | Test Case | Tool | Priority |
|---|------|-----------|------|----------|
| 3.1 | Schema conformance | Every response matches OpenAPI schema definition | schemathesis fuzz against `/openapi.json` | P0 |
| 3.2 | Required fields | `/detection/all` always returns `id`, `external_id`, `first_detected_at`, `closed_at` | httpx assertion | P0 |
| 3.3 | Pagination | `offset + limit` cursor consistent across pages (no duplicate rows) | httpx loop | P0 |
| 3.4 | Bad input 422 | Invalid `window` key → 422 with error detail | httpx | P0 |
| 3.5 | Bad input 422 | `start >= end` → 422 | httpx | P0 |
| 3.6 | Advanced filter injection | Injection attempt in `advanced` filter field → 422, no SQL error | httpx + fuzzer | P0 |
| 3.7 | Content-type | All JSON endpoints return `Content-Type: application/json` | httpx | P1 |
| 3.8 | CORS | OPTIONS preflight responds with correct `Allow-Origin` header | httpx | P1 |
| 3.9 | Response time | Large finding list (500 rows) returns within 2 s | httpx + timer | P1 |
| 3.10 | Versioning | `/api/v1/` prefix consistent — no endpoint returns 404 unexpectedly | schemathesis | P2 |

---

## 4. End-to-End (E2E) UI Tests (Playwright)

| # | Area | Test Case | Selector / Flow | Priority |
|---|------|-----------|-----------------|----------|
| 4.1 | Login | Valid credentials → dashboard loads, sidebar visible | `data-testid="sidebar"` | P0 |
| 4.2 | Login | Wrong password → error message shown | `data-testid="login-error"` | P0 |
| 4.3 | All Incidents | Table loads with at least one row when agent has findings | `data-testid="incidents-table"` | P0 |
| 4.4 | Time window | Change window to 7d → table re-fetches, row count changes | Click `7d` button, assert fetch | P0 |
| 4.5 | Time window | Custom absolute range → only incidents in range shown | Date picker, apply, assert | P0 |
| 4.6 | Time window | Agent offline during window → incidents still visible in that window | Seed offline agent data, select window | P0 |
| 4.7 | Remediation copy | Click copy icon on command → clipboard contains command text | `navigator.clipboard` mock assertion | P0 |
| 4.8 | Remediation copy | On HTTP (non-HTTPS) — copy still works via execCommand fallback | Serve on HTTP, click copy, assert | P0 |
| 4.9 | Remediation copy | Copy icon shows checkmark after successful copy | Assert icon class change to CheckCircle2 | P0 |
| 4.10 | Remediation copy | AI remediation step copy button works (AI panel) | Click AI tab → copy command | P0 |
| 4.11 | Finding detail | `closed_at` field displayed (in red) when finding is closed | Open closed finding, assert row present | P1 |
| 4.12 | Finding detail | `first_detected_at` and `last_detected_at` both present | Open finding panel, assert rows | P1 |
| 4.13 | Terrain tabs | Click "vector" tab → only vector-terrain findings shown | Tab click, assert category column | P1 |
| 4.14 | Status filter | Click "Triaging" → only status=triaging findings shown | Status tab, assert | P1 |
| 4.15 | Triage action | Click "Close" on finding → status changes to closed | Triage button, assert badge | P1 |
| 4.16 | Closed view | Switch to `view=closed` → previously closed findings appear | View toggle, assert rows | P1 |
| 4.17 | Severity badge | Critical finding has red badge; info has grey | Assert badge color class | P1 |
| 4.18 | OS switch | Switch remediation OS from macOS to Linux → commands update | Click "switch OS", select Linux | P2 |
| 4.19 | Pagination | Click next page → different findings, no duplicates | Scroll / next button | P2 |
| 4.20 | Sidebar badge | Badge count on "Incidents" matches `/detection/all` total | Assert badge number | P2 |

---

## 5. Security Tests

| # | Category | Test Case | Tool / Method | Priority |
|---|----------|-----------|---------------|----------|
| 5.1 | Authentication | No endpoint accessible without valid JWT | pytest + httpx, no auth header | P0 |
| 5.2 | Authorization | Org-A token cannot read Org-B findings even with valid JWT | httpx cross-tenant request | P0 |
| 5.3 | SQL Injection | `?search='; DROP TABLE findings;--` → no DB error, 200 empty | sqlmap / manual | P0 |
| 5.4 | SQLi via advanced filter | `advanced=[{"field":"title","op":"contains","value":"' OR 1=1 --"}]` → safe | httpx | P0 |
| 5.5 | XSS | `<script>` in finding title → escaped in UI, not executed | Playwright, assert no alert | P0 |
| 5.6 | JWT tampering | Modified JWT signature → 401, no data returned | httpx with forged token | P0 |
| 5.7 | JWT expiry | Expired JWT → 401 on all endpoints | httpx | P0 |
| 5.8 | Session fixation | Old session token after logout → 401 | httpx + logout sequence | P0 |
| 5.9 | Brute force | 10+ failed logins → rate-limit or lockout response | httpx loop | P0 |
| 5.10 | Default credentials | No default admin password in production config | `test_default_credential_exposure.py` | P0 |
| 5.11 | Secrets in responses | API responses never include `password_hash`, `license_key` | grep API response bodies | P0 |
| 5.12 | HTTPS enforcement | HTTP redirects to HTTPS; Caddy TLS config correct | `curl -I http://` | P0 |
| 5.13 | mTLS agent comms | Agent without valid cert rejected by manager | `openssl s_client` without cert | P1 |
| 5.14 | CORS | Arbitrary origin not reflected in `Access-Control-Allow-Origin` | httpx with `Origin: evil.com` | P1 |
| 5.15 | Clickjacking | `X-Frame-Options: DENY` or CSP `frame-ancestors` present | httpx header check | P1 |
| 5.16 | Path traversal | `/api/v1/remediation/../../../etc/passwd` → 404 or 422 | httpx | P1 |
| 5.17 | IDOR | `GET /api/v1/detection/finding/{id}` with another org's ID → 404 | httpx cross-org | P1 |
| 5.18 | Mass assignment | POST body with extra fields (e.g. `is_admin: true`) ignored | httpx | P2 |
| 5.19 | Dependency audit | No known CVEs in Python dependencies | `pip-audit` / `safety` | P2 |
| 5.20 | Container hardening | Manager container runs as non-root user | `docker inspect` | P2 |

---

## 6. Performance Tests (k6 / Locust)

| # | Scenario | Target | Metric | Priority |
|---|----------|--------|--------|----------|
| 6.1 | Dashboard load | 50 concurrent users | `GET /api/v1/detection/all` p95 < 500 ms | P0 |
| 6.2 | Ingest burst | 500 events/sec for 60 s | Zero 5xx; queue depth < 1 000 | P0 |
| 6.3 | Agent heartbeat | 200 agents reporting simultaneously | Upsert latency p99 < 200 ms | P0 |
| 6.4 | Full-text search | Search on 50 k findings | p95 < 300 ms | P1 |
| 6.5 | Pagination cursor | Cursor through 10 000 findings (1 000 pages) | No OOM; consistent ordering | P1 |
| 6.6 | Concurrent sessions | 100 simultaneous portal logins | Session creation p99 < 1 s | P1 |
| 6.7 | Remediation API | 100 RPS against recipe endpoint | p95 < 200 ms; cache hit > 80% | P2 |
| 6.8 | DB retention pruning | Prune 1 M inactive rows | Completes < 60 s; no lock contention | P2 |

---

## 7. Smoke Tests (post-deploy sanity, ~2 min)

| # | Check | Command / URL | Expected | Priority |
|---|-------|--------------|----------|----------|
| 7.1 | Manager health | `GET /health` | `{"status":"ok"}` | P0 |
| 7.2 | DB connectivity | `GET /api/v1/stats/summary` | 200 with counts | P0 |
| 7.3 | Agent enroll endpoint | `POST /api/v1/enroll` with dummy cert | 200 or 400 (not 500) | P0 |
| 7.4 | Dashboard SPA loads | `GET /` | HTML with `<div id="root">` | P0 |
| 7.5 | Auth endpoint alive | `POST /api/v1/auth/login` wrong creds | 401 (not 500) | P0 |
| 7.6 | Detection endpoint | `GET /api/v1/detection/all?window=1h` with token | 200 JSON | P0 |
| 7.7 | Remediation endpoint | `GET /api/v1/remediation/1/recipe` with token | 200 or 404 (not 500) | P0 |
| 7.8 | TLS cert valid | `curl --fail https://<host>/health` | No cert error | P0 |

---

## 8. Regression Tests (guard specific fixed bugs)

| # | Bug | Regression Test | File | Priority |
|---|-----|-----------------|------|----------|
| 8.1 | Offline-agent findings hidden in time window | `window=7d` + stale agent → findings present | `test_stale_agent_filtering.py` | P0 |
| 8.2 | `closed_at` NULL for auto-resolved findings | After auto-resolve, `closed_at IS NOT NULL` | New — `test_incident_timestamps.py` | P0 |
| 8.3 | Closed findings missing from historical view | `active_only=True` + past window → closed finding included | `test_findings_window.py` | P0 |
| 8.4 | Copy button crash on HTTP (no clipboard API) | `navigator.clipboard` undefined → execCommand fallback works | Playwright on HTTP | P0 |
| 8.5 | "Copied" shown even when clipboard blocked | Copy fails → no checkmark shown | Playwright with clipboard denied | P0 |
| 8.6 | AI remediation copy crash | `navigator.clipboard.writeText` without optional chaining → crash | Unit test / Playwright | P0 |
| 8.7 | FTS5 search crash on wrong DB | `search=suspicious` → no 500 | `test_stale_agent_filtering.py::test_search_path_does_not_crash` | P0 |
| 8.8 | `first_detected_at` overwritten on re-upsert | Same key, new scan → `first_detected_at` unchanged | `test_auto_resolve.py` | P0 |
| 8.9 | Empty live_agent_ids returns all rows | `live_agent_ids=[]` → empty result, not all findings | `test_stale_agent_filtering.py` | P0 |
| 8.10 | Concurrent session limit bypass | Enroll 11th session → oldest evicted, total <= limit | `test_session_limits.py` | P1 |

---

## 9. Accessibility Tests (axe-core / Playwright)

| # | Page | Check | Tool | Priority |
|---|------|-------|------|----------|
| 9.1 | Login | No axe violations | axe-core + Playwright | P1 |
| 9.2 | Incidents / All Incidents | No axe violations; table has `role="grid"` | axe-core | P1 |
| 9.3 | Finding detail panel | All icons have `aria-label` or `title` | axe-core | P1 |
| 9.4 | Remediation copy button | `title="Copy"` present; keyboard-accessible | Keyboard nav test | P1 |
| 9.5 | Color contrast | Severity badges meet WCAG AA (4.5:1) | axe-core | P2 |
| 9.6 | Time range picker | Dropdown keyboard-navigable (arrow keys, Escape) | Playwright keyboard | P2 |

---

## 10. Agent Tests (macOS / Linux / Windows)

| # | Platform | Test Case | Method | Priority |
|---|----------|-----------|--------|----------|
| 10.1 | macOS | Agent installs, enrolls, sends first payload within 60 s | Manual / Ansible smoke | P0 |
| 10.2 | macOS | Agent reconnects after network interruption — no duplicate findings | Network cutoff test | P0 |
| 10.3 | macOS | Agent goes offline → finding auto-resolved after `stale_agent_sec` | Wait + assert DB | P0 |
| 10.4 | Linux | Same as 10.1–10.3 on Ubuntu 22.04 | Manual / VM | P0 |
| 10.5 | Windows | Same as 10.1–10.3 on Windows 11 | Manual / VM | P0 |
| 10.6 | All | Agent version mismatch → graceful rejection or upgrade prompt | Send old agent payload | P1 |
| 10.7 | macOS | arm64 `.pkg` installs on Apple Silicon (M1/M2) | Install on Apple Silicon device | P1 |
| 10.8 | All | Agent sender retries on 5xx; drops duplicate telemetry | Kill manager mid-send | P1 |
| 10.9 | macOS | SIP-protected path not scanned without SIP bypass | Verify no `csrutil` requirement | P2 |

---

## 11. Data Integrity Tests

| # | Area | Test Case | Method | Priority |
|---|------|-----------|--------|----------|
| 11.1 | Dedup | Same telemetry sent 100x → exactly 1 finding row | Script + DB row count | P0 |
| 11.2 | Timeline | Every state change (created/modified/closed) has a `change_timeline` row | DB audit query | P0 |
| 11.3 | `actions_log` | `system.created` entry present on every new finding | `SELECT actions_log FROM findings` | P0 |
| 11.4 | `external_id` | Every finding has unique `external_id` in `AL-F-NNNNNNNN` format | DB select + regex | P0 |
| 11.5 | Timestamps | `first_detected_at <= last_detected_at`; if closed: `<= closed_at` | DB constraint query | P0 |
| 11.6 | Terrain FK | `terrain_id` in finding always references `terrains(id)` | DB foreign key check | P1 |
| 11.7 | Pruning safety | Prune does not delete active findings regardless of age | Insert old active row, prune, assert present | P1 |
| 11.8 | Finding UID | `finding_uid` is a valid 32-char hex UUIDv4 on every row | DB regex check | P2 |

---

## 12. Docker / Infrastructure Tests

| # | Check | Command | Expected | Priority |
|---|-------|---------|----------|----------|
| 12.1 | All containers start | `docker compose up -d && docker compose ps` | All services `Up` | P0 |
| 12.2 | No secrets in images | `docker history manager:latest` | No ENV with passwords visible | P0 |
| 12.3 | Health endpoints | `./attacklens status` | All green | P0 |
| 12.4 | Volume persistence | Restart manager → findings still present | `docker compose restart manager` + query | P0 |
| 12.5 | Caddy TLS | Certificate valid, HTTPS reachable | `curl --fail https://<host>/health` | P0 |
| 12.6 | Memory limits | Manager stays < 512 MB under load | `docker stats` during k6 run | P1 |
| 12.7 | Log rotation | Logs don't fill disk after 24 h | `docker logs --tail 10 manager` | P2 |

---

## Priority Legend

| Priority | Meaning |
|----------|---------|
| **P0** | Must pass before every release — blocks deploy |
| **P1** | Must pass before every release — severity determines block |
| **P2** | Run on main branch — failures tracked but do not block release |

---

## How to Run

```bash
# Backend unit tests
cd manager && python3 -m pytest tests/unit/ -v --tb=short

# Backend integration tests (requires Postgres)
docker compose up -d postgres
python3 -m pytest manager/tests/integration/ -v

# API schema fuzz (schemathesis)
schemathesis run http://localhost:8080/openapi.json --auth "Bearer $TOKEN"

# Performance load test (k6)
k6 run scripts/k6_dashboard_load.js --vus 50 --duration 60s

# E2E UI tests (Playwright)
cd "manager/dashboard/templates/Build Smart AttackLens Platform"
npx playwright test

# Accessibility (axe-core)
npx playwright test --grep accessibility

# Security dependency scan
pip-audit
safety check

# Post-deploy smoke
./attacklens status
curl --fail https://<host>/health
```
