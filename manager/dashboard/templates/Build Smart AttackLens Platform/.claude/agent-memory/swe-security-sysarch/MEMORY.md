# Memory Index

- [Project: AttackLens Platform](project_attacklens.md) — AI-powered EDR/XDR, agent->manager (HMAC+AES-GCM), three-tier NDJSON+gzip store, dual SQLite DBs
- [Test Suite State](project_test_state.md) — 67 tests; 6 unit pass; 8 enroll unit FAIL (mock signature drift); 51 integration ERROR (aio_pika missing)
- [Architecture Quirks](architecture_quirks.md) — IntelDB writes via single _conn shared with pool, API layer reaches into private `_conn`/`_fetchall`
