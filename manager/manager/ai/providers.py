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
import time
from typing import Optional

import aiohttp

from .base import AIProvider, AIResponse, ProviderConfig, SYSTEM_PROMPT

log = logging.getLogger("manager.ai.providers")

_TIMEOUT = aiohttp.ClientTimeout(total=60)


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

_PROVIDER_MAP = {
    "anthropic": AnthropicProvider,
    "openai":    OpenAIProvider,
    "gemini":    GeminiProvider,
    "ollama":    OllamaProvider,
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
