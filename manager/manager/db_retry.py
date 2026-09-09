"""Retry helper for transient Postgres lock failures (deadlock / serialization).

A deadlock aborts one of the two competing transactions; Postgres has already
rolled the loser back, so simply re-running the whole transaction almost always
succeeds once the other writer (e.g. live ingest for the same agent) has moved
on. Matched by exception *class name* so this stays free of a hard asyncpg
dependency and still recognises SQLite's "database is locked".

Usage:
    async def _txn():
        async with pool.write() as db:
            ...
            await db.commit()
        return result
    return await run_with_deadlock_retry(_txn)

The callable MUST run the entire transaction (open → mutate → commit) so a retry
re-does the whole thing on a fresh transaction — retrying a single statement of
an already-aborted transaction only re-fails.
"""
from __future__ import annotations

import asyncio
import logging
from typing import Awaitable, Callable, TypeVar

log = logging.getLogger(__name__)

T = TypeVar("T")

# asyncpg raises these class names; SerializationError covers SERIALIZABLE/
# REPEATABLE READ conflicts, which are retryable for the same reason.
_RETRYABLE_NAMES = {"DeadlockDetectedError", "SerializationError"}


def is_retryable_lock_error(exc: BaseException) -> bool:
    """True for a transient lock conflict that a retry can clear."""
    if type(exc).__name__ in _RETRYABLE_NAMES:
        return True
    msg = str(exc).lower()
    return "deadlock detected" in msg or "database is locked" in msg


async def run_with_deadlock_retry(
    txn: Callable[[], Awaitable[T]],
    *,
    attempts: int = 5,
    base_delay: float = 0.2,
) -> T:
    """Run `txn()`, retrying the whole thing on a transient lock error with
    exponential backoff (base_delay * 2**i). Non-retryable errors propagate
    immediately; the last attempt's error is re-raised."""
    for i in range(attempts):
        try:
            return await txn()
        except Exception as exc:  # noqa: BLE001 — re-raised below unless retryable
            if is_retryable_lock_error(exc) and i < attempts - 1:
                delay = base_delay * (2 ** i)
                log.warning(
                    "transient lock error (%s); retry %d/%d in %.1fs",
                    type(exc).__name__, i + 1, attempts - 1, delay,
                )
                await asyncio.sleep(delay)
                continue
            raise
    raise RuntimeError("unreachable: loop returns or raises")  # pragma: no cover
