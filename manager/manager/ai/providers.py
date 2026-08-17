"""
manager/manager/ai/providers.py — Concrete provider implementations.

Four providers, all sharing the same interface:
  AnthropicProvider  — Claude (Haiku 4.5 default, cost-efficient)
  OpenAIProvider     — GPT-4o-mini default
  GeminiProvider     — gemini-1.5-flash default
  OllamaProvider     — local LLM, no API key needed
"""
from __future__ import annotations

import json
import logging
import os
import time
from collections import deque
from typing import Optional

import aiohttp

from . import catalog
from .base import AIProvider, AIResponse, ProviderConfig, SYSTEM_PROMPT
from ..integrations.resilience import PermanentError, RateLimitedError, TransientError

log = logging.getLogger("manager.ai.providers")

_TIMEOUT = aiohttp.ClientTimeout(total=60)


def _allow_training_models() -> bool:
    """Whether free, train-on-input models may receive endpoint telemetry.

    Read per call rather than at import so an operator can flip it without a
    redeploy, matching the OpenRouter kill switch.
    """
    return os.environ.get(
        "ATTACKLENS_AI_ALLOW_TRAINING_MODELS", "false",
    ).lower() in {"1", "true", "yes", "on"}


class _OpenRouterUsageGuard:
    """Process-local org guard; durable cost remains in validation_runs."""

    def __init__(self) -> None:
        self.calls: deque[float] = deque()
        self.day = ""
        self.cost_usd = 0.0

    def check(self) -> None:
        if os.environ.get("ATTACKLENS_OPENROUTER_ENABLED", "true").lower() not in {
            "1", "true", "yes", "on",
        }:
            raise PermanentError(
                "ai:openrouter", "OpenRouter kill switch is disabled",
                error_type="kill_switch",
            )
        now = time.time()
        while self.calls and now - self.calls[0] >= 60:
            self.calls.popleft()
        try:
            rate_limit = max(1, int(os.environ.get(
                "ATTACKLENS_OPENROUTER_MAX_CALLS_PER_MINUTE", "60",
            )))
        except ValueError:
            rate_limit = 60
        if len(self.calls) >= rate_limit:
            raise RateLimitedError(
                "ai:openrouter", "AttackLens organization rate budget exhausted",
                retry_after=max(0.1, 60 - (now - self.calls[0])),
                error_type="local_rate_budget",
            )
        day = time.strftime("%Y-%m-%d", time.gmtime(now))
        if day != self.day:
            self.day = day
            self.cost_usd = 0.0
        try:
            daily_budget = max(0.0, float(os.environ.get(
                "ATTACKLENS_OPENROUTER_DAILY_BUDGET_USD", "25",
            )))
        except ValueError:
            daily_budget = 25.0
        if daily_budget and self.cost_usd >= daily_budget:
            raise PermanentError(
                "ai:openrouter", "AttackLens organization daily cost budget exhausted",
                error_type="local_cost_budget",
            )
        self.calls.append(now)

    def charge(self, cost_usd: float) -> None:
        self.cost_usd += max(0.0, float(cost_usd or 0.0))

    def reset(self) -> None:
        self.calls.clear()
        self.day = ""
        self.cost_usd = 0.0


_openrouter_usage_guard = _OpenRouterUsageGuard()


# ── Anthropic ─────────────────────────────────────────────────────────────────

class AnthropicProvider(AIProvider):
    """Uses the Anthropic Messages API directly via aiohttp (no SDK needed)."""

    _BASE = "https://api.anthropic.com/v1"

    async def chat(self, user_prompt: str, *, max_tokens: int = 1500) -> AIResponse:
        t0 = time.monotonic()
        headers = {
            "x-api-key":         self._cfg.api_key,
            "anthropic-version": "2023-06-01",
            "content-type":      "application/json",
        }
        payload = {
            "model":      self._cfg.model,
            "max_tokens": max_tokens,
            "system":     SYSTEM_PROMPT,
            "messages":   [{"role": "user", "content": user_prompt}],
        }
        body = await self._http.request_json(
            "POST", f"{self._BASE}/messages", headers=headers, json_body=payload
        )
        text = ""
        for block in body.get("content", []):
            if block.get("type") == "text":
                text += block["text"]

        usage = body.get("usage", {})
        return AIResponse(
            text=text,
            model=self._cfg.model,
            provider="anthropic",
            input_tokens=usage.get("input_tokens", 0),
            output_tokens=usage.get("output_tokens", 0),
            latency_ms=(time.monotonic() - t0) * 1000,
        )

    async def health_check(self) -> tuple[bool, str]:
        try:
            resp = await self.chat(
                "Reply with JSON: {\"status\": \"ok\"}",
                max_tokens=20,
            )
            parsed = self.parse_json(resp.text)
            if parsed.get("status") == "ok":
                return True, f"Connected — model {self._cfg.model} ({resp.total_tokens} tokens)"
            return True, f"Connected — model {self._cfg.model}"
        except Exception as exc:
            return False, str(exc)


# ── OpenAI ────────────────────────────────────────────────────────────────────

class OpenAIProvider(AIProvider):
    """Uses OpenAI Chat Completions API. Also compatible with Azure OpenAI."""

    _DEFAULT_BASE = "https://api.openai.com/v1"

    @property
    def _base(self) -> str:
        return self._cfg.base_url.rstrip("/") or self._DEFAULT_BASE

    async def chat(self, user_prompt: str, *, max_tokens: int = 1500) -> AIResponse:
        t0 = time.monotonic()
        headers = {
            "Authorization": f"Bearer {self._cfg.api_key}",
            "Content-Type":  "application/json",
        }
        payload = {
            "model":       self._cfg.model,
            "max_tokens":  max_tokens,
            "messages": [
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user",   "content": user_prompt},
            ],
            "response_format": {"type": "json_object"},
        }
        body = await self._http.request_json(
            "POST", f"{self._base}/chat/completions", headers=headers, json_body=payload
        )
        text = body["choices"][0]["message"]["content"]
        usage = body.get("usage", {})
        return AIResponse(
            text=text,
            model=self._cfg.model,
            provider="openai",
            input_tokens=usage.get("prompt_tokens", 0),
            output_tokens=usage.get("completion_tokens", 0),
            latency_ms=(time.monotonic() - t0) * 1000,
        )

    async def health_check(self) -> tuple[bool, str]:
        try:
            resp = await self.chat(
                "Reply with JSON: {\"status\": \"ok\"}",
                max_tokens=20,
            )
            return True, f"Connected — model {self._cfg.model} ({resp.total_tokens} tokens)"
        except Exception as exc:
            return False, str(exc)


# ── Google Gemini ─────────────────────────────────────────────────────────────

class GeminiProvider(AIProvider):
    """Uses Google Generative Language REST API (Gemini)."""

    _BASE = "https://generativelanguage.googleapis.com/v1beta"

    async def chat(self, user_prompt: str, *, max_tokens: int = 1500) -> AIResponse:
        t0 = time.monotonic()
        url = (
            f"{self._BASE}/models/{self._cfg.model}:generateContent"
            f"?key={self._cfg.api_key}"
        )
        payload = {
            "system_instruction": {
                "parts": [{"text": SYSTEM_PROMPT}]
            },
            "contents": [
                {"role": "user", "parts": [{"text": user_prompt}]}
            ],
            "generationConfig": {
                "maxOutputTokens": max_tokens,
                "responseMimeType": "application/json",
            },
        }
        body = await self._http.request_json("POST", url, json_body=payload)

        cand = body.get("candidates", [{}])[0]
        text = ""
        for part in cand.get("content", {}).get("parts", []):
            text += part.get("text", "")

        meta = body.get("usageMetadata", {})
        return AIResponse(
            text=text,
            model=self._cfg.model,
            provider="gemini",
            input_tokens=meta.get("promptTokenCount", 0),
            output_tokens=meta.get("candidatesTokenCount", 0),
            latency_ms=(time.monotonic() - t0) * 1000,
        )

    async def health_check(self) -> tuple[bool, str]:
        try:
            resp = await self.chat(
                "Reply with JSON: {\"status\": \"ok\"}",
                max_tokens=20,
            )
            return True, f"Connected — model {self._cfg.model}"
        except Exception as exc:
            return False, str(exc)


# ── Ollama (local) ────────────────────────────────────────────────────────────

class OllamaProvider(AIProvider):
    """Ollama REST API — runs locally, free, no API key needed."""

    _DEFAULT_BASE = "http://localhost:11434"

    @property
    def _base(self) -> str:
        return self._cfg.base_url.rstrip("/") or self._DEFAULT_BASE

    async def chat(self, user_prompt: str, *, max_tokens: int = 1500) -> AIResponse:
        t0 = time.monotonic()
        payload = {
            "model":  self._cfg.model,
            "prompt": f"{SYSTEM_PROMPT}\n\n{user_prompt}",
            "stream": False,
            "options": {"num_predict": max_tokens},
            "format": "json",
        }
        body = await self._http.request_json(
            "POST", f"{self._base}/api/generate", json_body=payload
        )
        text = body.get("response", "")
        return AIResponse(
            text=text,
            model=self._cfg.model,
            provider="ollama",
            input_tokens=body.get("prompt_eval_count", 0),
            output_tokens=body.get("eval_count", 0),
            latency_ms=(time.monotonic() - t0) * 1000,
        )

    async def health_check(self) -> tuple[bool, str]:
        try:
            # Check /api/tags to list available models
            timeout = aiohttp.ClientTimeout(total=5)
            async with aiohttp.ClientSession(timeout=timeout) as session:
                async with session.get(f"{self._base}/api/tags") as resp:
                    if resp.status != 200:
                        return False, f"Ollama returned {resp.status}"
                    body = await resp.json()
                    models = [m["name"] for m in body.get("models", [])]
                    if self._cfg.model not in models:
                        return False, (
                            f"Model '{self._cfg.model}' not found. "
                            f"Available: {', '.join(models[:5])}"
                        )
                    return True, f"Ollama connected — model {self._cfg.model} ready"
        except Exception as exc:
            return False, f"Cannot reach Ollama at {self._base}: {exc}"


# ── Factory ───────────────────────────────────────────────────────────────────

# ── OpenRouter ────────────────────────────────────────────────────────────────

class OpenRouterProvider(OpenAIProvider):
    """OpenRouter — OpenAI-compatible gateway to 200+ models.

    Uses the OpenAI Chat Completions schema with an OpenRouter base URL.
    Free models are identified by the `:free` suffix in the model ID.

    Optional attribution headers:
      HTTP-Referer        — identifies your app
      X-OpenRouter-Title  — human-readable app name shown in OpenRouter
    """

    _DEFAULT_BASE = "https://openrouter.ai/api/v1"

    async def chat(self, user_prompt: str, *, max_tokens: int = 1500) -> AIResponse:
        return await self._chat(user_prompt, max_tokens=max_tokens, schema=None)

    async def chat_structured(
        self,
        user_prompt: str,
        *,
        schema: dict,
        max_tokens: int = 1500,
    ) -> AIResponse:
        return await self._chat(user_prompt, max_tokens=max_tokens, schema=schema)

    async def _chat(
        self,
        user_prompt: str,
        *,
        max_tokens: int,
        schema: Optional[dict],
    ) -> AIResponse:
        _openrouter_usage_guard.check()
        t0 = time.monotonic()
        headers = {
            "Authorization": f"Bearer {self._cfg.api_key}",
            "Content-Type":  "application/json",
            # OpenRouter returns route/provider diagnostics only when this is
            # explicitly requested. This is metadata-only; prompts are never
            # logged by AttackLens telemetry.
            "X-OpenRouter-Metadata": "true",
        }
        app_url = os.environ.get("OPENROUTER_APP_URL", "https://attacklens.ai").strip()
        app_title = os.environ.get("OPENROUTER_APP_TITLE", "AttackLens").strip()
        if app_url:
            headers["HTTP-Referer"] = app_url
        if app_title:
            headers["X-OpenRouter-Title"] = app_title
        model_id = self._cfg.model
        is_free = catalog.is_free_model(model_id)

        # Privacy gate. Free tiers generally train on submitted prompts, and the
        # prompts here carry endpoint telemetry — process names, package lists,
        # finding evidence. Sending that to a training-on-input model is a
        # decision an operator has to make explicitly, so it is opt-in.
        if is_free and not _allow_training_models():
            raise PermanentError(
                "ai:openrouter",
                f"Model '{model_id}' is a free tier, which generally trains on "
                "submitted prompts. AttackLens prompts contain endpoint "
                "telemetry. Set ATTACKLENS_AI_ALLOW_TRAINING_MODELS=true to "
                "accept this, or choose a paid model.",
                error_type="privacy_policy",
            )

        payload = {
            "model":       model_id,
            "max_tokens":  max_tokens,
            "messages": [
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user",   "content": user_prompt},
            ],
        }
        if schema is not None:
            # Capability check. require_parameters=True with allow_fallbacks=False
            # tells OpenRouter to route only to providers supporting every
            # parameter sent — so handing a strict json_schema to a model that
            # cannot do structured output yields zero eligible providers and the
            # whole call fails. Most free models are in that category.
            supports = catalog.supports_structured_output(model_id)
            if supports is False:
                log.info(
                    "Model %s does not support structured outputs — falling back "
                    "to prompt-based JSON.", model_id,
                )
            else:
                payload["response_format"] = {
                    "type": "json_schema",
                    "json_schema": {
                        "name": "attacklens_validation",
                        "strict": True,
                        "schema": schema,
                    },
                }
                provider_prefs: dict = {
                    "require_parameters": True,
                    "allow_fallbacks": False,
                }
                # data_collection=deny and zdr exclude free providers by
                # definition, so requesting them alongside a free model
                # guarantees an empty route. The operator has already opted in
                # to training-on-input above; asking for the opposite here would
                # just turn that into an unexplained routing failure.
                if not is_free:
                    provider_prefs["data_collection"] = "deny"
                    provider_prefs["zdr"] = True
                payload["provider"] = provider_prefs
        body = await self._http.request_json(
            "POST", f"{self._base}/chat/completions", headers=headers, json_body=payload
        )
        # OpenRouter wraps errors in {"error": {...}} even on 200
        if "error" in body:
            err = body["error"]
            try:
                code = int(err.get("code"))
            except (TypeError, ValueError):
                code = 0
            message = str(err.get("message") or err)
            metadata = err.get("metadata") if isinstance(err, dict) else None
            error_type = str(metadata.get("error_type") or "") if isinstance(metadata, dict) else ""
            if code == 429:
                raise RateLimitedError(
                    "ai:openrouter", message, error_type=error_type or None,
                )
            if code in {408, 500, 502, 503, 504}:
                raise TransientError(
                    "ai:openrouter", message, status=code or None,
                    error_type=error_type or None,
                )
            raise PermanentError(
                "ai:openrouter", message, status=code or None,
                error_type=error_type or None,
            )
        choices = body.get("choices")
        if not isinstance(choices, list) or not choices:
            raise PermanentError(
                "ai:openrouter", "response missing a non-empty choice array",
            )
        choice = choices[0]
        message = choice.get("message") if isinstance(choice, dict) else None
        text = message.get("content") if isinstance(message, dict) else None
        if not isinstance(text, str) or not text.strip():
            raise PermanentError(
                "ai:openrouter", "response choice has no text content",
            )
        usage = body.get("usage", {})
        cost_usd = float(usage.get("cost") or 0.0)
        _openrouter_usage_guard.charge(cost_usd)
        return AIResponse(
            text=text,
            model=body.get("model") or self._cfg.model,
            provider="openrouter",
            input_tokens=usage.get("prompt_tokens", 0),
            output_tokens=usage.get("completion_tokens", 0),
            latency_ms=(time.monotonic() - t0) * 1000,
            generation_id=str(body.get("id") or ""),
            upstream_provider=str(body.get("provider") or ""),
            finish_reason=str(choice.get("finish_reason") or ""),
            cost_usd=cost_usd,
        )

    async def health_check(self) -> tuple[bool, str]:
        try:
            resp = await self.chat(
                'Reply with valid JSON only: {"status": "ok"}',
                max_tokens=30,
            )
            return True, f"OpenRouter connected — model {self._cfg.model} ({resp.total_tokens} tokens)"
        except Exception as exc:
            return False, str(exc)


_PROVIDER_MAP = {
    "anthropic":  AnthropicProvider,
    "openai":     OpenAIProvider,
    "gemini":     GeminiProvider,
    "ollama":     OllamaProvider,
    "openrouter": OpenRouterProvider,
}


def build_provider(config: ProviderConfig) -> AIProvider:
    """Instantiate the correct provider from a ProviderConfig."""
    cls = _PROVIDER_MAP.get(config.provider)
    if cls is None:
        raise ValueError(
            f"Unknown provider '{config.provider}'. "
            f"Valid: {list(_PROVIDER_MAP)}"
        )
    return cls(config)
