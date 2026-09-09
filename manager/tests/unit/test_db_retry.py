import pytest

from manager.manager.db_retry import is_retryable_lock_error, run_with_deadlock_retry


class DeadlockDetectedError(Exception):
    """Stand-in with the same class name asyncpg uses."""


def test_is_retryable_matches_deadlock_class_and_messages():
    assert is_retryable_lock_error(DeadlockDetectedError("deadlock detected"))
    assert is_retryable_lock_error(Exception("deadlock detected\nDETAIL: ..."))
    assert is_retryable_lock_error(Exception("database is locked"))
    assert not is_retryable_lock_error(ValueError("bad value"))


@pytest.mark.asyncio
async def test_retries_transient_deadlock_then_succeeds():
    calls = {"n": 0}

    async def txn():
        calls["n"] += 1
        if calls["n"] < 3:
            raise DeadlockDetectedError("deadlock detected")
        return "ok"

    result = await run_with_deadlock_retry(txn, base_delay=0)
    assert result == "ok"
    assert calls["n"] == 3


@pytest.mark.asyncio
async def test_non_retryable_error_propagates_immediately():
    calls = {"n": 0}

    async def txn():
        calls["n"] += 1
        raise ValueError("permanent")

    with pytest.raises(ValueError):
        await run_with_deadlock_retry(txn, base_delay=0)
    assert calls["n"] == 1  # not retried


@pytest.mark.asyncio
async def test_exhausts_attempts_and_reraises():
    calls = {"n": 0}

    async def txn():
        calls["n"] += 1
        raise DeadlockDetectedError("deadlock detected")

    with pytest.raises(DeadlockDetectedError):
        await run_with_deadlock_retry(txn, attempts=3, base_delay=0)
    assert calls["n"] == 3
