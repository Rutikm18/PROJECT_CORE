---
name: project-test-state
description: Current pytest state on 2026-05-18 — what passes/fails and why
metadata:
  type: project
---

`python3 -m pytest manager/tests/` on 2026-05-18 collected 67 tests:
- **6 PASS**: all of `tests/unit/test_auth.py` plus a few `test_enroll_api.py` validation cases.
- **8 FAIL** in `tests/unit/test_enroll_api.py`: the test `MockDB.upsert_agent_key` signature has not been updated to accept `expires_at=` / `label=` kwargs that the real router now passes. Every 500 in the test output is this TypeError; not a security regression.
- **51 ERROR** at collect time in `tests/integration/`: `ModuleNotFoundError: No module named 'aio_pika'`. The integration suite imports `manager.manager.server` which unconditionally imports `manager.queue.producer` → `aio_pika`. requirements.txt lists `aio-pika>=9.0.0` but it's not installed in the local Python 3.13 environment.

**Why:** Diagnosing the test suite for the AttackLens audit; these two failure modes are environmental/staleness, not behavior bugs.

**How to apply:** Before re-running tests, either `pip install aio-pika` or guard the producer import behind `if RABBITMQ_URL`. Fix the MockDB by adding `**kwargs` to `upsert_agent_key`. The unit auth tests are the only ones currently exercising real crypto behavior.
