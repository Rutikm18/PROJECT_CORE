"""
manager/manager/integrations/client.py — Resilient async HTTP client.

One call path for every external integration, composing the resilience
primitives so behaviour and observability are identical everywhere:

    client = ResilientHTTPClient("nvd", retry=CRITICAL, timeout_s=20)
    data = await client.request_json("GET", url, params=...)

Guarantees:
  • Timeouts        — connect + total, always set (no unbounded hangs)
  • Retries         — transient only (429/5xx/network), backoff + jitter,
                      honours Retry-After; 4xx fails fast (no wasted retries)
  • Circuit breaker — trips after repeated failures; rejects fast while open
  • Fallback        — optional async callable invoked when all attempts fail
  • Observability   — every call updates the IntegrationRegistry metrics

The transport is aiohttp, but callers can also wrap arbitrary async callables
via `call()` to get the same retry/breaker/metrics for non-HTTP integrations.
"""
from __future__ import annotations

import asyncio
import logging
import time
from typing import Any, Awaitable, Callable, Optional

import aiohttp

from .resilience import (
    registry, RetryPolicy, FAST_API,
    IntegrationError, TransientError, PermanentError,
    RateLimitedError, CircuitOpenError,
)

log = logging.getLogger("manager.integrations.client")

# HTTP statuses that are worth retrying.
_RETRYABLE_STATUS = {429, 500, 502, 503, 504}


class ResilientHTTPClient:
    def __init__(
        self,
        name: str,
        *,
        retry: RetryPolicy = FAST_API,
        timeout_s: float = 20.0,
        connect_timeout_s: float = 5.0,
        breaker_threshold: int = 5,
        breaker_reset_s: float = 60.0,
    ) -> None:
        self.name = name
        self._retry = retry
        self._timeout = aiohttp.ClientTimeout(total=timeout_s, connect=connect_timeout_s)
        self._breaker = registry.breaker(
            name, failure_threshold=breaker_threshold, reset_timeout=breaker_reset_s
        )
        self._metrics = registry.metrics(name)

    # ── HTTP JSON ─────────────────────────────────────────────────────────────

    async def request_json(
        self,
        method: str,
        url: str,
        *,
        headers: Optional[dict] = None,
        params: Optional[dict] = None,
        json_body: Optional[dict] = None,
        fallback: Optional[Callable[[], Awaitable[Any]]] = None,
        ok_404: bool = False,
    ) -> Any:
        """
        Perform an HTTP request with retries/breaker/metrics, returning parsed
        JSON. Raises a typed IntegrationError on final failure unless `fallback`
        is provided (then the fallback's result is returned).
        `ok_404=True` returns None on 404 instead of raising.
        """
        async def _do() -> Any:
            async with aiohttp.ClientSession(timeout=self._timeout) as session:
                async with session.request(
                    method, url, headers=headers, params=params, json=json_body
                ) as resp:
                    if resp.status == 404 and ok_404:
                        return None
                    if resp.status == 429:
                        ra = _parse_retry_after(resp.headers.get("Retry-After"))
                        raise RateLimitedError(self.name, f"429 from {url}", retry_after=ra)
                    if resp.status in _RETRYABLE_STATUS:
                        raise TransientError(self.name, f"HTTP {resp.status} from {url}", status=resp.status)
                    if resp.status >= 400:
                        body = (await resp.text())[:200]
                        raise PermanentError(self.name, f"HTTP {resp.status} from {url}: {body}", status=resp.status)
                    return await resp.json(content_type=None)

        return await self.call(_do, fallback=fallback)

    # ── Generic async call wrapper ────────────────────────────────────────────

    async def call(
        self,
        fn: Callable[[], Awaitable[Any]],
        *,
        fallback: Optional[Callable[[], Awaitable[Any]]] = None,
    ) -> Any:
        """
        Run an arbitrary async callable through the same resilience machinery.
        Used for non-HTTP integrations (SDK calls, file downloads) so they share
        the breaker + metrics + retry behaviour.
        """
        m = self._metrics

        if not self._breaker.allow():
            m.breaker_rejections += 1
            if fallback is not None:
                return await self._run_fallback(fallback)
            raise CircuitOpenError(self.name, "circuit open — rejecting request")

        m.calls += 1
        last_exc: BaseException = TransientError(self.name, "no attempt made")

        for attempt in range(self._retry.max_attempts):
            start = time.monotonic()
            try:
                result = await fn()
                m.record_latency((time.monotonic() - start) * 1000)
                m.successes += 1
                m.last_success_at = time.time()
                self._breaker.on_success()
                return result

            except PermanentError as exc:
                # Do not retry client errors — fail fast.
                m.record_latency((time.monotonic() - start) * 1000)
                m.failures += 1
                m.last_error = str(exc); m.last_error_at = time.time()
                self._breaker.on_failure(exc)
                if fallback is not None:
                    return await self._run_fallback(fallback)
                raise

            except (TransientError, asyncio.TimeoutError, aiohttp.ClientError) as exc:
                last_exc = exc
                if isinstance(exc, asyncio.TimeoutError):
                    m.timeouts += 1
                    exc = TransientError(self.name, "request timed out")
                if isinstance(exc, RateLimitedError):
                    m.rate_limited += 1

                is_last = attempt == self._retry.max_attempts - 1
                if is_last:
                    break
                retry_after = getattr(exc, "retry_after", None)
                delay = self._retry.backoff(attempt, retry_after=retry_after)
                m.retries += 1
                log.info("integration[%s] retry %d/%d in %.2fs: %s",
                         self.name, attempt + 1, self._retry.max_attempts - 1, delay, exc)
                await asyncio.sleep(delay)

            except asyncio.CancelledError:
                raise

            except Exception as exc:  # unexpected — treat as transient once, then give up
                last_exc = exc
                m.record_latency((time.monotonic() - start) * 1000)
                break

        # All attempts exhausted.
        m.failures += 1
        m.last_error = str(last_exc); m.last_error_at = time.time()
        self._breaker.on_failure(last_exc)
        if fallback is not None:
            return await self._run_fallback(fallback)
        if isinstance(last_exc, IntegrationError):
            raise last_exc
        raise TransientError(self.name, f"all {self._retry.max_attempts} attempts failed: {last_exc}")

    async def _run_fallback(self, fallback: Callable[[], Awaitable[Any]]) -> Any:
        try:
            log.info("integration[%s] using fallback", self.name)
            return await fallback()
        except Exception as exc:
            log.warning("integration[%s] fallback failed: %s", self.name, exc)
            raise TransientError(self.name, f"fallback failed: {exc}")


def _parse_retry_after(value: Optional[str]) -> Optional[float]:
    """Parse a Retry-After header (seconds form; HTTP-date form ignored)."""
    if not value:
        return None
    try:
        return float(value)
    except (ValueError, TypeError):
        return None
