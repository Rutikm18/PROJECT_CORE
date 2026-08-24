# AttackLens Test Catalog — Agent + Manager

What exists today, what each layer covers, how to run it, and where the gaps are.

**Inventory as of this snapshot**
- 1,540 Python test functions across 144 test files
- 114 frontend test cases across 20 `.test.ts` files
- Agent: 38 unit files + 2 integration files
- Manager: 79 unit files + 5 integration files + 1 accuracy harness
- Cross-cutting root suite: 19 unit files + 1 validation harness

---

## Tier 0 — Static gates (no runtime, run on every change)

| Check | Command | Scope |
|---|---|---|
| Lint | `make lint` | ruff (E,F,W,I,N,UP,B,S) + mypy over `agent/agent/`, `manager/manager/`, `shared/` |
| Auto-fix | `make lint-fix` | ruff `--fix` |
| SAST | `make security` | bandit `-ll` over agent + manager + shared |
| Dependency CVEs | `make security` | pip-audit against both `requirements.txt` |
| Weekly drift | `.github/workflows/security.yml` | Monday 06:00 UTC, uploads JSON artifacts, 90-day retention |

---

## Tier 1 — Unit tests

### Agent (`agent/tests/unit/` — 38 files)

**Identity, crypto, transport**
- `test_crypto.py`, `test_keystore.py`, `test_macos_keystore.py`, `test_windows_keystore.py` — key material at rest, Keychain / DPAPI paths
- `test_enrollment.py` — token exchange, agent-id binding
- `test_tls.py` — cert verification, pinning, self-signed handling
- `test_manifest.py`, `test_restamp.py` — payload manifest integrity and re-stamping
- `test_sender_status_handling.py`, `test_sender_reenroll_single_flight.py` — HTTP status semantics, no thundering-herd re-enroll

**Collection**
- `test_collectors.py`, `test_collector_overlap.py`, `test_collector_timeout.py`, `test_collector_accuracy_fixes.py`
- `test_macos_normalizer.py`, `test_windows_normalizer.py` — per-OS normalization into the shared schema
- `test_macos_developer_security_collector.py` — dev-security surface (MCP servers, coding agents, inference servers)
- `test_posture_collector_cis.py` — CIS posture items
- `test_metrics_collector_accuracy.py`, `test_sca_engine.py`, `test_section_merge.py`

**Durability + lifecycle**
- `test_spool.py`, `test_spool_disk_full.py`, `test_overflow_spill.py` — disk spool under pressure
- `test_circuit_breaker_recovery.py`, `test_link_state.py`, `test_clock_skew.py`
- `test_watchdog.py`, `test_supervision.py`, `test_single_instance.py`, `test_boot_persistence.py`, `test_launchd_plist.py`
- `test_config_engine.py`, `test_config_robustness.py`, `test_policy.py`, `test_obs.py`, `test_status_file.py`

Run: `make test-agent` · macOS-only subset: `make test-macos` · Windows-only subset: `make test-windows` (both importable on any OS)

### Manager (`manager/tests/unit/` — 79 files)

**AuthN / AuthZ / tenancy** — the security boundary; treat as must-pass
- `test_auth.py`, `test_auth_role_claim.py`, `test_manager_roles.py`, `test_api_auth_coverage.py`
- `test_tenancy_model.py`, `test_tenant_scope_middleware.py`
- `test_portal_isolation.py`, `test_portal_trust_boundary.py`
- `test_enroll_api.py`, `test_crypto_limits.py`, `test_licensing.py`, `test_customers_api.py`

**Ingest & storage integrity**
- `test_payload_schema.py`, `test_payload_storage.py`, `test_payload_ledger.py`
- `test_telemetry_worker_durability.py`, `test_write_txn_rollback.py`, `test_db_single_agent.py`
- `test_ingest_health.py`, `test_dlq_replayer.py`, `test_queue_topology.py`, `test_reconciler.py`
- `test_retention.py`, `test_data_retention_settings.py`, `test_intel_db_retention.py`

**Detection engine**
- `test_detection_executor.py`, `test_engine_module_routing.py`, `test_detection_coverage.py`
- `test_detection_workflow_integrity.py`, `test_detection_failure_semantics.py`
- `test_source_contract_detectors.py` — detector input contracts
- `test_developer_security_rules.py`, `test_devsec_composite_schema.py`
- `test_openfiles_detection.py`, `test_posture_cis.py`, `test_posture_criteria_emitter_shapes.py`
- False-positive guards: `test_user_account_fp.py`, `test_wildcard_bind_fp.py`, `test_stale_agent_filtering.py`

**Correlation & findings lifecycle**
- `test_correlation_coalescing.py`, `test_custom_correlations.py`, `test_fleet_correlator.py`
- `test_finding_lifecycle.py`, `test_finding_query_contract.py`, `test_auto_resolve.py`
- `test_case_management_model.py`, `test_all_incidents_filter.py`

**Validation pipeline** (the terrain/reachability area)
- `test_validation_error_policy.py`, `test_validation_observability.py`, `test_validation_persistence.py`
- `test_validation_quality_floor.py`, `test_validation_recompute_jobs.py`, `test_validation_run_persistence.py`
- `test_validation_page_visibility.py`, `test_validation_pipeline_api.py`, `test_validation_pipeline_inventory.py`
- `test_terrain_classification.py`, `test_terrain_catalog_routes.py`, `test_mesh_terrain.py`, `test_mesh_backfill.py`
- `test_reachability_enrichment.py`

**Threat intel**
- `test_ti_corroboration.py`, `test_corroboration_provenance.py`, `test_provenance.py`
- `test_nvd_rejected_filter.py`, `test_feed_health_honesty.py`

**API surface / read paths**
- `test_raw_search.py`, `test_raw_coverage.py`, `test_raw_deepmesh.py`
- `test_link_status_api.py`, `test_timeseries.py`, `test_timewindow.py`, `test_timewindow_adoption.py`
- `test_dashboard_stats_perf.py` — read-path perf assertions
- `test_notifications_integrations.py`, `test_integration_retry_after.py`, `test_investigation_graph.py`

Run: `make test-manager`

### Cross-cutting (`tests/unit/` — 19 files)
AI provider plumbing (`test_ai_*`, `test_openrouter_provider.py`), detection rule verification, rulepack detection, threat-intel integrity, validation model/accuracy, dashboard SPA fallback, version pinning.

---

## Tier 2 — Integration tests (need live infrastructure)

**Prerequisite:** Postgres reachable at `postgresql://attacklens:attacklens@localhost:5432/postgres` (override with `TEST_POSTGRES_ADMIN_DSN`). `manager/tests/conftest.py` creates and drops a real database per test — 12 manager test files depend on this fixture. Bring it up with the `postgres` service in `docker-compose.yml` (bound to `127.0.0.1:5432`).

- `agent/tests/integration/test_enrollment_flow.py` — full enroll handshake
- `agent/tests/integration/test_offline_online_replay.py` — spool → reconnect → replay without loss or duplication
- `manager/tests/integration/test_ingest.py` — NDJSON+gzip ingest path
- `manager/tests/integration/test_attacklens_pipeline.py` — ingest → detection → finding
- `manager/tests/integration/test_queue_runtime.py` — RabbitMQ producer/consumer
- `manager/tests/integration/test_endpoints_window.py`, `test_findings_window.py` — time-window read contracts

Run: `make test-integration`

---

## Tier 3 — Phase acceptance suites (curated cross-tier gates)

| Suite | Command | Documented in |
|---|---|---|
| Phase 1 — telemetry → dashboard | `make test-pipeline-validation` | `docs/validation/phase-1-pipeline-acceptance.md` |
| Phase 2 — detection logic | `make test-detection-validation` | `docs/validation/phase-2-detection-verification.md` |
| Phase 3 — AI / LangGraph | `make test-ai-validation` | `docs/validation/phase-3-ai-langgraph-acceptance.md` |
| Phase 4 — durable email | `make test-email-validation` | `docs/validation/phase-4-email-acceptance.md` |

Phase 2 additionally executes 17 detection modules as `__main__` self-tests (`app_vulnerability`, `arp_spoofing`, `binary_integrity`, `container_security`, `covert_channel`, `defense_evasion`, `exfiltration`, `lateral_movement`, `package_vulnerability`, `persistence`, `port_listener`, `privilege_escalation`, `sbom_posture`, `scheduled_task`, `service_monitor`, `sysctl_monitor`, `user_account`).

---

## Tier 4 — Detection accuracy / quality (not pass-fail logic — measured quality)

- `manager/tests/accuracy/test_detection_accuracy.py` + `harness.py` — labeled-corpus detection accuracy
- `tests/validation/test_detection_accuracy.py` — exploitability band accuracy, ranking correctness, KEV/EPSS escalation floors, no benign-over-critical inversion
- Standalone: `PYTHONPATH=. python3 tests/validation/test_detection_accuracy.py`

Track these as trend metrics (precision/recall/FP rate per rule), not just green/red.

---

## Tier 5 — Frontend (dashboard)

`cd "manager/dashboard/templates/Build Smart AttackLens Platform" && npm test` (vitest 2.1, 20 files / 114 cases)

Covers RBAC context, refresh context, portal client, sidebar + threat-queue validation states, responsive app shell, case client, time-range and terrain-catalog helpers, brightness/theme utils.

Also worth doing manually after `make build-dashboard`: verify the emitted `static/assets/*` hashes actually match `static/index.html` — the current working tree has a full set of deleted asset files, which is exactly the class of drift that ships a blank dashboard.

---

## Tier 6 — End-to-end / system (manual or scripted, not yet automated)

1. `make up` — full stack (postgres, rabbitmq, caddy, manager, threat-intel)
2. `make certs && make keygen && make enroll-token`
3. `make run-agent` against it; confirm enrollment, first payload, and `/health`
4. Verify the payload lands in raw storage, produces findings, and renders on the dashboard
5. Kill the manager mid-send → confirm agent spools → restart → confirm replay
6. `make check-kev-findings` — KEV-flagged findings surface end-to-end
7. Multi-OS: repeat with a Windows agent and a Linux agent against the same manager

---

## Tier 7 — Performance / load

`scripts/perf/loadtest.py` — p50/p90/p95/p99/max latency, req/s, error rate, bytes+rows/sec. Exits non-zero when error rate or p95 breaches thresholds, so it can gate a CD stage.

```
python3 scripts/perf/loadtest.py --url https://localhost:8443 --insecure \
  --endpoint /api/v1/detection/all --concurrency 50 --requests 5000 \
  --slo-p95-ms 500 --max-error-rate 0.01
```

Self-test the harness math with `--selftest`. Worth adding: sustained ingest-path throughput at target fleet size, and a soak run (hours, not minutes) to catch connection/memory leaks.

---

## Tier 8 — Security testing (beyond SAST)

Automated today: auth coverage, role claims, tenant scope middleware, portal isolation and trust boundary, crypto limits, enroll API.

Worth performing manually / adding:
- Cross-tenant IDOR sweep — every `/api/v1/*` route with tenant A's token against tenant B's ids
- Unauthenticated sweep of the full route table (`test_api_auth_coverage.py` is the right place to extend)
- Enrollment token replay, expiry, and revocation
- Ingest abuse: oversized payloads, gzip bombs, malformed NDJSON, schema-violating rows
- Prompt injection through telemetry into the AI analyst / LangGraph path (attacker-controlled process names, file paths)
- API key rotation and revocation propagation
- TLS: cert expiry, hostname mismatch, downgrade attempts
- Secret hygiene: confirm nothing from `.env` / `agent.toml` leaks into logs or API responses

---

## Tier 9 — Platform / packaging / install

**macOS:** `make build-macos` → `make install-macos-agent` → verify launchd plist loaded, watchdog running, single-instance lock held, boot persistence survives reboot → `make uninstall-macos-agent` leaves no residue.
Binary path: `make build-binaries` (agent + watchdog) → `make build-pkg` → `make install-pkg`.

**Windows:** `make build-windows` → `make build-msi` (or `build-msi-signed`) → `make install-msi` with `MANAGER_URL` + `ENROLL_TOKEN` → verify services → `make uninstall-windows-agent`.

Test both fresh-install and upgrade-over-existing, plus install with the manager unreachable (agent must spool, not crash).

---

## Tier 10 — Resilience / chaos

Partly covered by unit tests; the system-level versions are manual:
- Manager down for hours → agent spool growth, disk-full behaviour, no data loss on recovery
- RabbitMQ down → producer backpressure, DLQ fill, `dlq_replayer` drain
- Postgres failover / connection-pool exhaustion under load
- Clock skew on the agent host (already unit-tested; verify end-to-end timestamp handling)
- Partial payload corruption in flight → manifest rejection, not silent acceptance
- Agent process killed repeatedly → watchdog + supervision recovery loop

---

## Tier 11 — Ops / deploy

- `make build && make up && make ps && make logs` — stack smoke
- Postgres init scripts (`manager/postgres-init/`) run cleanly on a fresh volume
- `scripts/backup.sh` → restore into an empty instance → data intact
- `scripts/monitor.py` / `monitor.sh` — alerting fires on a synthetic failure
- Deploy workflow (`.github/workflows/deploy.yml`) dry-run
- Post-deploy canary + `/health` probe

---

## Known gaps — fix these first

**1. CI enforces almost none of the suite.**
`.github/workflows/ci.yml` runs only `tests/unit/` and `tests/integration/`. The 117 unit files and 7 integration files under `agent/tests/` and `manager/tests/` — the overwhelming majority of the 1,540 tests — never run in CI. They only run via `make`, locally, by hand.

**2. CI references a directory that does not exist.**
`tests/integration/` is not in the repo. `pytest tests/integration/ -v` exits 4 (file or directory not found), so that CI step cannot pass as written.

**3. No Postgres service in CI.**
The 12 manager test files using the `pg_manager_dsn` fixture need a live Postgres. CI has no `services: postgres:` block, so those tests cannot run there even if the paths were fixed. (`manager/tests/conftest.py:21` and `manager/manager/server.py:151` both reference a `docker-compose.postgres.yml` that isn't in the repo — the `postgres` service in `docker-compose.yml` is the working stand-in.)

**4. Frontend tests are not in CI.** `npm test` (114 cases) runs only manually.

**5. No coverage floor.** `make test-coverage` exists but nothing enforces a minimum, so coverage can silently regress.

**6. No automated end-to-end.** Tier 6 is entirely manual. A single scripted agent→manager→finding→API assertion against `make up` would catch most integration-level regressions before deploy.

### Suggested CI fix (smallest change with the largest effect)

```yaml
services:
  postgres:
    image: postgres:16-alpine
    env:
      POSTGRES_USER: attacklens
      POSTGRES_PASSWORD: attacklens
      POSTGRES_DB: manager
    ports: ["5432:5432"]
    options: >-
      --health-cmd "pg_isready -U attacklens -d manager"
      --health-interval 5s --health-timeout 5s --health-retries 10
```

then replace the two test steps with:

```
python -m pytest tests/unit/ agent/tests/ manager/tests/ -v --tb=short
```

---

## Recommended cadence

| When | Run |
|---|---|
| Every commit | `make lint`, `make test-unit` |
| Every PR | full `make test` + `npm test` + `make security` |
| Before merge to main | all four phase-acceptance suites |
| Before a release | Tier 6 E2E, Tier 7 load, Tier 9 install/uninstall on both platforms |
| Weekly | `security.yml`, accuracy-trend review (Tier 4) |
| Quarterly | Tier 8 manual security sweep, Tier 10 chaos |
