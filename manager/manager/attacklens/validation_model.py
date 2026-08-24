"""Provider-neutral, strict structured-output port for finding validation."""
from __future__ import annotations

from dataclasses import dataclass, field
import re
from typing import Protocol

from ..ai.base import AIProvider
from ..ai.registry import build_task_provider

VALIDATION_RESPONSE_SCHEMA_VERSION = "validation-response-v1"
VALIDATION_PROMPT_VERSION = "validation-v2"
_FIELDS = {"verdict", "confidence", "reasoning", "key_evidence", "risk_factors"}
VALIDATION_JSON_SCHEMA = {
    "type": "object",
    "properties": {
        "verdict": {"type": "string", "enum": ["tp", "fp", "uncertain"]},
        "confidence": {"type": "number", "minimum": 0.0, "maximum": 1.0},
        "reasoning": {"type": "string", "minLength": 1, "maxLength": 600},
        "key_evidence": {
            "type": "array", "maxItems": 6,
            "items": {"type": "string", "minLength": 1, "maxLength": 300},
        },
        "risk_factors": {
            "type": "array", "maxItems": 6,
            "items": {"type": "string", "minLength": 1, "maxLength": 300},
        },
    },
    "required": sorted(_FIELDS),
    "additionalProperties": False,
}


class ValidationResponseError(ValueError):
    """A model returned output that does not satisfy the verdict contract."""


@dataclass(frozen=True)
class ValidationModelVerdict:
    label: str
    confidence: float
    reasoning: str
    key_evidence: list[str] = field(default_factory=list)
    risk_factors: list[str] = field(default_factory=list)
    provider: str = ""
    model: str = ""
    generation_id: str = ""
    upstream_provider: str = ""
    finish_reason: str = ""
    tokens_used: int = 0
    cost_usd: float = 0.0
    prompt_version: str = VALIDATION_PROMPT_VERSION
    schema_version: str = VALIDATION_RESPONSE_SCHEMA_VERSION


class ValidationModel(Protocol):
    async def evaluate(self, prompt: str) -> ValidationModelVerdict: ...


def _string_list(value, field_name: str) -> list[str]:
    if not isinstance(value, list) or len(value) > 6:
        raise ValidationResponseError(f"{field_name} must be an array of at most 6 strings")
    if any(not isinstance(item, str) or not item.strip() for item in value):
        raise ValidationResponseError(f"{field_name} contains an invalid item")
    return [item.strip()[:300] for item in value]


class ProviderValidationModel:
    """Adapter from the shared AIProvider interface to ValidationModel."""

    def __init__(self, provider: AIProvider) -> None:
        self._provider = provider

    @property
    def model_id(self) -> str:
        """Configured model id, or '' when the provider cannot report one.

        Empty is meaningful: the verdict cache treats an unknown model as
        uncacheable rather than risking a verdict from one model being served
        for another. Test fakes that implement only `chat` land here.
        """
        return str(getattr(self._provider, "model_id", "") or "")

    async def evaluate(self, prompt: str) -> ValidationModelVerdict:
        if isinstance(self._provider, AIProvider):
            response = await self._provider.chat_structured(
                prompt, schema=VALIDATION_JSON_SCHEMA, max_tokens=900,
            )
        else:
            # Lightweight fakes used in deterministic contract tests only need
            # to implement the original provider interface.
            response = await self._provider.chat(prompt, max_tokens=900)
        parsed = AIProvider.parse_json(response.text) if response.text.strip() else {}
        if not isinstance(parsed, dict) or set(parsed) != _FIELDS:
            raise ValidationResponseError(
                "validation response must contain exactly the approved schema fields"
            )
        label = parsed.get("verdict")
        if label not in {"tp", "fp", "uncertain"}:
            raise ValidationResponseError("verdict must be tp, fp, or uncertain")
        confidence = parsed.get("confidence")
        if isinstance(confidence, bool) or not isinstance(confidence, (int, float)):
            raise ValidationResponseError("confidence must be a number")
        confidence = float(confidence)
        if not 0.0 <= confidence <= 1.0:
            raise ValidationResponseError("confidence must be between 0 and 1")
        reasoning = parsed.get("reasoning")
        if not isinstance(reasoning, str) or not reasoning.strip():
            raise ValidationResponseError("reasoning must be a non-empty string")
        key_evidence = _string_list(parsed.get("key_evidence"), "key_evidence")
        allowed_refs = set(re.findall(r"evidence_ref=([^\s]+)", prompt))
        invalid_refs = [reference for reference in key_evidence if reference not in allowed_refs]
        if invalid_refs:
            raise ValidationResponseError(
                "key_evidence must contain only evidence_ref identifiers from the prompt"
            )
        return ValidationModelVerdict(
            label=label,
            confidence=confidence,
            reasoning=reasoning.strip()[:600],
            key_evidence=key_evidence,
            risk_factors=_string_list(parsed.get("risk_factors"), "risk_factors"),
            provider=response.provider,
            model=response.model,
            generation_id=response.generation_id,
            upstream_provider=response.upstream_provider,
            finish_reason=response.finish_reason,
            tokens_used=response.total_tokens,
            cost_usd=response.cost_usd,
        )


def resolve_validation_model(legacy_analyst=None) -> ValidationModel | None:
    """Resolve the saved validation-task provider, with a legacy bridge.

    The saved provider is authoritative. The bridge only supports deployments
    that have not configured the shared provider store yet.
    """
    provider = build_task_provider("validation")
    if provider is not None:
        return ProviderValidationModel(provider)
    if (
        legacy_analyst is not None
        and getattr(legacy_analyst, "enabled", False)
        and callable(getattr(legacy_analyst, "_get_provider", None))
    ):
        return ProviderValidationModel(legacy_analyst._get_provider())
    return None
