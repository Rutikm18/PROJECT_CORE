"""Durable, human-gated investigations for findings that already exist.

Detection remains deterministic. This workflow starts only after a finding has
been persisted, gathers read-only evidence, uses the configured AI provider to
evaluate a bounded set of hypotheses, and pauses for an analyst decision before
drafting remediation.
"""
from __future__ import annotations

import asyncio
import ipaddress
import json
import logging
import os
import re
import time
import uuid
from typing import Any, Literal, TypedDict

from langgraph.graph import END, START, StateGraph
from langgraph.types import Command, interrupt

from ..attacklens.remediation_kb import recipe_for_finding
from .base import AIProvider, AIResponseError
from .finding_analyzer import FindingAnalyzer
from .key_store import load_config
from .providers import build_provider

log = logging.getLogger("manager.ai.investigation")

MAX_HYPOTHESES = 5
MAX_CONTEXT_ITEMS = 30
MAX_REVIEW_ROUNDS = 2
MAX_TEXT = 2_000
ALLOWED_VERDICTS = {"confirmed", "likely", "inconclusive", "unlikely", "false_positive"}
ALLOWED_DECISIONS = {"approve", "reject", "request_more"}

HYPOTHESES_SCHEMA = {
    "type": "object",
    "properties": {
        "hypotheses": {
            "type": "array",
            "minItems": 1,
            "maxItems": MAX_HYPOTHESES,
            "items": {
                "type": "object",
                "properties": {
                    "statement": {"type": "string"},
                    "supporting_ids": {"type": "array", "items": {"type": "string"}},
                    "contradicting_ids": {"type": "array", "items": {"type": "string"}},
                    "confidence": {"type": "number", "minimum": 0, "maximum": 1},
                    "status": {
                        "type": "string",
                        "enum": ["supported", "contradicted", "unresolved"],
                    },
                },
                "required": [
                    "statement",
                    "supporting_ids",
                    "contradicting_ids",
                    "confidence",
                    "status",
                ],
            },
        },
    },
    "required": ["hypotheses"],
}

VERDICT_SCHEMA = {
    "type": "object",
    "properties": {
        "verdict": {"type": "string", "enum": sorted(ALLOWED_VERDICTS)},
        "confidence": {"type": "number", "minimum": 0, "maximum": 1},
        "summary": {"type": "string"},
        "evidence_ids": {"type": "array", "items": {"type": "string"}},
        "gaps": {"type": "array", "items": {"type": "string"}},
    },
    "required": ["verdict", "confidence", "summary", "evidence_ids", "gaps"],
}


class StructuredResponseError(ValueError):
    """A provider replied, but its response failed the local output contract."""

    def __init__(self, message: str, audit: dict) -> None:
        super().__init__(message)
        self.audit = audit


class InvestigationState(TypedDict, total=False):
    run_id: str
    finding_id: int
    finding: dict
    evidence: list[dict]
    history: list[dict]
    related_findings: list[dict]
    correlations: list[dict]
    intel: list[dict]
    hypotheses: list[dict]
    verification: list[dict]
    verdict: dict
    review_round: int
    analyst_decision: str
    analyst_feedback: str
    analyst_actor: str
    remediation: dict
    result: dict
    status: str
    errors: list[str]
    model_calls: list[dict]
    started_at: float
    completed_at: float


def _text(value: Any, limit: int = MAX_TEXT) -> str:
    return str(value or "").replace("<untrusted>", "").replace("</untrusted>", "")[:limit]


def _json_safe(value: Any, *, depth: int = 0) -> Any:
    """Produce a small checkpoint-safe representation of untrusted endpoint data."""
    if depth >= 4:
        return _text(value, 300)
    if value is None or isinstance(value, (bool, int, float)):
        return value
    if isinstance(value, str):
        return _text(value)
    if isinstance(value, dict):
        return {
            _text(key, 100): _json_safe(item, depth=depth + 1)
            for key, item in list(value.items())[:40]
        }
    if isinstance(value, (list, tuple, set)):
        return [_json_safe(item, depth=depth + 1) for item in list(value)[:40]]
    return _text(value)


def _record(record_id: str, source: str, data: Any) -> dict:
    return {"id": record_id, "source": source, "data": _json_safe(data)}


def _extract_cves(value: Any) -> list[str]:
    encoded = json.dumps(_json_safe(value), default=str)
    return sorted(set(re.findall(r"CVE-\d{4}-\d{4,7}", encoded, flags=re.IGNORECASE)))[:10]


def _extract_iocs(value: Any) -> list[tuple[str, str]]:
    encoded = json.dumps(_json_safe(value), default=str)
    found: list[tuple[str, str]] = []
    for candidate in re.findall(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])", encoded):
        try:
            ipaddress.ip_address(candidate)
        except ValueError:
            continue
        found.append(("ip", candidate))
    for candidate in re.findall(r"(?i)\b[a-f0-9]{64}\b", encoded):
        found.append(("hash", candidate.lower()))
    # Domains are only accepted from fields whose names identify them as such;
    # broad extraction from descriptions creates too many false indicators.
    if isinstance(value, dict):
        for key, item in value.items():
            if "domain" not in str(key).lower() and "hostname" not in str(key).lower():
                continue
            for candidate in re.findall(r"(?i)\b(?:[a-z0-9-]+\.)+[a-z]{2,63}\b", str(item)):
                found.append(("domain", candidate.lower()))
    return list(dict.fromkeys(found))[:20]


def _citations(value: Any, allowed: set[str]) -> list[str]:
    kept, _fabricated = _ground_citations(value, allowed)
    return kept


def _ground_citations(value: Any, allowed: set[str]) -> tuple[list[str], int]:
    """Keep only citations that name real evidence, and count the invented ones.

    Dropping fabricated IDs is the grounding guard. Counting them is what makes
    the fabrication visible: a verdict citing one real ID out of five otherwise
    looks identical to one citing five out of five, and an analyst reviewing
    the run has no way to tell that the model was inventing evidence.
    """
    if not isinstance(value, list):
        return [], 0
    kept: list[str] = []
    fabricated = 0
    for item in value:
        text = str(item)
        if text in allowed:
            if text not in kept:
                kept.append(text)
        else:
            fabricated += 1
    return kept[:10], fabricated


def _usage_totals(model_calls: Any) -> dict:
    """Roll per-call spend up to the run.

    The per-stage audits already carry cost, but nothing summed them, so
    answering "what did this investigation cost" meant every consumer
    re-implementing the loop — and a stage that reports zero (as remediation
    once did) stays invisible unless the total is shown next to the calls.
    """
    calls = model_calls if isinstance(model_calls, list) else []
    total_in = total_out = total_attempts = 0
    total_cost = 0.0
    billed = 0
    for call in calls:
        if not isinstance(call, dict):
            continue
        billed += 1
        total_in += int(call.get("input_tokens") or 0)
        total_out += int(call.get("output_tokens") or 0)
        total_attempts += int(call.get("attempts") or 1)
        total_cost += float(call.get("cost_usd") or 0.0)
    return {
        "model_calls": billed,
        # attempts > model_calls means corrective retries were billed.
        "provider_requests": total_attempts,
        "input_tokens": total_in,
        "output_tokens": total_out,
        "total_tokens": total_in + total_out,
        "cost_usd": round(total_cost, 8),
    }


class InvestigationService:
    """Owns graph compilation, durable checkpoints, and run lifecycle metadata."""

    def __init__(
        self,
        intel_db,
        feeds=None,
        *,
        dsn: str = "",
        provider: AIProvider | None = None,
        analyzer: FindingAnalyzer | None = None,
        checkpointer=None,
        max_review_rounds: int = MAX_REVIEW_ROUNDS,
    ) -> None:
        self._db = intel_db
        self._feeds = feeds
        self._dsn = dsn or getattr(intel_db, "_dsn", "")
        self._provider = provider
        self._analyzer = analyzer or FindingAnalyzer(provider)
        self._injected_checkpointer = checkpointer
        self._checkpointer = None
        self._checkpointer_context = None
        self._graph = None
        self._start_lock = asyncio.Lock()
        self._max_review_rounds = max(1, min(int(max_review_rounds), 5))
        self._lifecycle_notification_handler = None

    @property
    def ready(self) -> bool:
        return self._graph is not None

    @property
    def provider_configured(self) -> bool:
        return self._provider is not None or getattr(self._analyzer, "_provider", None) is not None or load_config() is not None

    def set_lifecycle_notification_handler(self, handler) -> None:
        """Attach a best-effort durable workflow-notification callback."""
        self._lifecycle_notification_handler = handler

    async def start(self) -> None:
        if self._graph is not None:
            return
        async with self._start_lock:
            if self._graph is not None:
                return
            if self._injected_checkpointer is not None:
                self._checkpointer = self._injected_checkpointer
            else:
                if not self._dsn.startswith(("postgres://", "postgresql://")):
                    raise RuntimeError("LangGraph investigations require a PostgreSQL INTEL_DATABASE_URL")
                from langgraph.checkpoint.postgres.aio import AsyncPostgresSaver

                self._checkpointer_context = AsyncPostgresSaver.from_conn_string(self._dsn)
                self._checkpointer = await self._checkpointer_context.__aenter__()
                await self._checkpointer.setup()
            self._graph = self._build_graph().compile(checkpointer=self._checkpointer)
            log.info("LangGraph investigation service started with durable checkpoints")

    async def stop(self) -> None:
        self._graph = None
        self._checkpointer = None
        if self._checkpointer_context is not None:
            await self._checkpointer_context.__aexit__(None, None, None)
            self._checkpointer_context = None

    def _build_graph(self) -> StateGraph:
        graph = StateGraph(InvestigationState)
        graph.add_node("freeze_evidence", self._freeze_evidence)
        graph.add_node("gather_history", self._gather_history)
        graph.add_node("query_intel", self._query_intel)
        graph.add_node("generate_hypotheses", self._generate_hypotheses)
        graph.add_node("verify_hypotheses", self._verify_hypotheses)
        graph.add_node("draft_verdict", self._draft_verdict)
        graph.add_node("analyst_review", self._analyst_review)
        graph.add_node("expand_context", self._expand_context)
        graph.add_node("draft_remediation", self._draft_remediation)
        graph.add_node("finalize_approved", self._finalize_approved)
        graph.add_node("finalize_rejected", self._finalize_rejected)

        graph.add_edge(START, "freeze_evidence")
        graph.add_edge("freeze_evidence", "gather_history")
        graph.add_edge("gather_history", "query_intel")
        graph.add_edge("query_intel", "generate_hypotheses")
        graph.add_edge("generate_hypotheses", "verify_hypotheses")
        graph.add_edge("verify_hypotheses", "draft_verdict")
        graph.add_edge("draft_verdict", "analyst_review")
        graph.add_conditional_edges(
            "analyst_review",
            self._route_decision,
            {
                "approve": "draft_remediation",
                "request_more": "expand_context",
                "reject": "finalize_rejected",
            },
        )
        graph.add_edge("expand_context", "generate_hypotheses")
        graph.add_edge("draft_remediation", "finalize_approved")
        graph.add_edge("finalize_approved", END)
        graph.add_edge("finalize_rejected", END)
        return graph

    async def start_investigation(self, finding_id: int, *, force: bool = False) -> dict:
        if not self.ready:
            raise RuntimeError("Investigation service is not running")
        if not self.provider_configured:
            raise RuntimeError("AI provider is not configured")
        finding = await self._db.get_finding_by_id(int(finding_id))
        if not finding:
            raise LookupError("Finding not found")
        if not force:
            existing = await self._db.get_open_investigation_run(int(finding_id))
            if existing:
                return existing

        run_id = uuid.uuid4().hex
        thread_id = f"finding:{finding_id}:investigation:{run_id}"
        await self._db.create_investigation_run(run_id, int(finding_id), thread_id)
        state: InvestigationState = {
            "run_id": run_id,
            "finding_id": int(finding_id),
            "finding": _json_safe(finding),
            "review_round": 0,
            "errors": [],
            "model_calls": [],
            "status": "running",
            "started_at": time.time(),
        }
        try:
            await self._graph.ainvoke(state, config=self._config(thread_id))
            return await self._sync_run(run_id, thread_id)
        except Exception as exc:
            log.exception("Investigation failed for finding=%s run=%s", finding_id, run_id)
            previous = await self._db.get_investigation_run(run_id)
            updated = await self._db.update_investigation_run(
                run_id, status="failed", current_node="error", error=_text(exc, 1000), completed=True,
            ) or {}
            await self._notify_lifecycle(previous, updated, state)
            raise

    async def get_run(self, run_id: str) -> dict | None:
        return await self._db.get_investigation_run(run_id)

    async def get_latest_run(self, finding_id: int) -> dict | None:
        return await self._db.get_latest_investigation_run(finding_id)

    async def resume_investigation(
        self,
        run_id: str,
        *,
        decision: Literal["approve", "reject", "request_more"],
        actor: str,
        feedback: str = "",
    ) -> dict:
        if not self.ready:
            raise RuntimeError("Investigation service is not running")
        decision = _text(decision, 30).lower()
        if decision not in ALLOWED_DECISIONS:
            raise ValueError("decision must be approve, reject, or request_more")
        run = await self._db.get_investigation_run(run_id)
        if not run:
            raise LookupError("Investigation run not found")
        if run.get("status") != "pending_review":
            raise ValueError("Investigation is not awaiting analyst review")
        review_payload = run.get("review_payload") or {}
        if decision not in review_payload.get("allowed_decisions", []):
            raise ValueError(f"Decision {decision} is not allowed at this review stage")

        actor = _text(actor or "analyst", 100)
        feedback = _text(feedback, 1000)
        await self._db.record_investigation_decision(
            int(run["finding_id"]), run_id, decision, actor, feedback,
        )
        await self._db.update_investigation_run(
            run_id, status="running", analyst_actor=actor, analyst_decision=decision,
            review_payload={}, current_node="analyst_review",
        )
        try:
            await self._graph.ainvoke(
                Command(resume={"decision": decision, "actor": actor, "feedback": feedback}),
                config=self._config(run["thread_id"]),
            )
            return await self._sync_run(run_id, run["thread_id"])
        except Exception as exc:
            log.exception("Investigation resume failed for run=%s", run_id)
            previous = await self._db.get_investigation_run(run_id)
            updated = await self._db.update_investigation_run(
                run_id, status="failed", current_node="error", error=_text(exc, 1000), completed=True,
            ) or {}
            finding = await self._db.get_finding_by_id(int(run["finding_id"])) or {}
            failure_state: InvestigationState = {
                "finding": _json_safe(finding),
                "run_id": run_id,
                "finding_id": int(run["finding_id"]),
                "analyst_actor": actor,
                "analyst_decision": decision,
                "analyst_feedback": feedback,
            }
            await self._notify_lifecycle(previous, updated, failure_state)
            raise

    async def handle_finding_event(self, finding: dict, event: str) -> None:
        """Auto-start eligible investigations from the post-persist notification hook."""
        if os.environ.get("LANGGRAPH_AUTO_INVESTIGATE", "true").lower() in {"0", "false", "no", "off"}:
            return
        if event not in {"created", "escalated"} or not self.provider_configured or not self.ready:
            return
        severities = {
            item.strip().lower()
            for item in os.environ.get("LANGGRAPH_AUTO_SEVERITIES", "critical,high").split(",")
            if item.strip()
        }
        if str(finding.get("severity") or "").lower() not in severities:
            return
        try:
            await self.start_investigation(int(finding["id"]))
        except Exception:
            log.exception("Automatic investigation failed for finding=%s", finding.get("id"))

    async def _freeze_evidence(self, state: InvestigationState) -> dict:
        finding = state.get("finding") or {}
        evidence = [_record("E-FINDING", "finding", finding)]
        raw_evidence = finding.get("evidence")
        if isinstance(raw_evidence, dict):
            for index, (key, value) in enumerate(list(raw_evidence.items())[:MAX_CONTEXT_ITEMS], start=1):
                evidence.append(_record(f"E-{index:03d}", f"finding.evidence.{_text(key, 80)}", value))
        elif raw_evidence:
            evidence.append(_record("E-001", "finding.evidence", raw_evidence))
        return {"evidence": evidence, "status": "running"}

    async def _gather_history(self, state: InvestigationState) -> dict:
        finding = state.get("finding") or {}
        finding_id = int(state["finding_id"])
        errors = list(state.get("errors") or [])
        timeline: list[dict] = []
        related: list[dict] = []
        correlations: list[dict] = []
        try:
            timeline = await self._db.get_finding_timeline(finding_id)
        except Exception as exc:
            errors.append(f"timeline: {_text(exc, 300)}")
        try:
            candidates = await self._db.get_soc_findings(
                agent_id=finding.get("agent_id") or None, active_only=False, limit=100,
            )
            finding_cves = set(_extract_cves(finding))
            item_key = str(finding.get("item_key") or "")
            category = str(finding.get("category") or "")
            for candidate in candidates:
                if int(candidate.get("id") or 0) == finding_id:
                    continue
                candidate_cves = set(_extract_cves(candidate))
                if (
                    (item_key and candidate.get("item_key") == item_key)
                    or (finding_cves and candidate_cves & finding_cves)
                    or (category and candidate.get("category") == category)
                ):
                    related.append(candidate)
                if len(related) >= MAX_CONTEXT_ITEMS:
                    break
        except Exception as exc:
            errors.append(f"related_findings: {_text(exc, 300)}")
        try:
            if finding.get("agent_id"):
                correlations = await self._db.get_correlations(str(finding["agent_id"]))
        except Exception as exc:
            errors.append(f"correlations: {_text(exc, 300)}")
        return {
            "history": [_record(f"H-{i:03d}", "timeline", row) for i, row in enumerate(timeline[-MAX_CONTEXT_ITEMS:], 1)],
            "related_findings": [_record(f"R-{i:03d}", "related_finding", row) for i, row in enumerate(related[:MAX_CONTEXT_ITEMS], 1)],
            "correlations": [_record(f"C-{i:03d}", "correlation", row) for i, row in enumerate(correlations[:MAX_CONTEXT_ITEMS], 1)],
            "errors": errors,
        }

    async def _query_intel(self, state: InvestigationState) -> dict:
        finding = state.get("finding") or {}
        errors = list(state.get("errors") or [])
        intel: list[dict] = []
        for cve_id in _extract_cves(finding):
            cve_id = cve_id.upper()
            try:
                local = await self._db.get_nvd_local_by_id(cve_id) or await self._db.get_cve_by_id(cve_id)
                if local:
                    intel.append(_record(f"I-NVD-{cve_id}", "nvd", local))
            except Exception as exc:
                errors.append(f"nvd:{cve_id}: {_text(exc, 300)}")
            try:
                epss = await self._feeds.get_epss(cve_id) if self._feeds else await self._db.get_epss(cve_id)
                if epss:
                    intel.append(_record(f"I-EPSS-{cve_id}", "epss", epss))
            except Exception as exc:
                errors.append(f"epss:{cve_id}: {_text(exc, 300)}")
            try:
                is_kev = bool(self._feeds and self._feeds.is_kev_cve(cve_id))
                intel.append(_record(f"I-KEV-{cve_id}", "cisa_kev", {"cve_id": cve_id, "known_exploited": is_kev}))
            except Exception as exc:
                errors.append(f"kev:{cve_id}: {_text(exc, 300)}")
            try:
                news = await self._db.search_news_by_cve(cve_id)
                for index, item in enumerate(news[:3], 1):
                    intel.append(_record(f"I-NEWS-{cve_id}-{index}", "security_news", item))
            except Exception as exc:
                errors.append(f"news:{cve_id}: {_text(exc, 300)}")

        for ioc_type, value in _extract_iocs(finding):
            details = None
            malicious = False
            try:
                if self._feeds:
                    if ioc_type == "ip":
                        malicious, details = self._feeds.is_malicious_ip(value), self._feeds.get_details(value)
                    elif ioc_type == "domain":
                        malicious, details = self._feeds.is_malicious_domain(value), self._feeds.get_domain_details(value)
                    elif ioc_type == "hash":
                        malicious, details = self._feeds.is_malicious_hash(value), self._feeds.get_hash_details(value)
                intel.append(_record(
                    f"I-IOC-{len(intel) + 1:03d}", "ioc_feed",
                    {"type": ioc_type, "value": value, "malicious": malicious, "details": details or {}},
                ))
            except Exception as exc:
                errors.append(f"ioc:{ioc_type}: {_text(exc, 300)}")
        return {"intel": intel[:MAX_CONTEXT_ITEMS], "errors": errors}

    def _get_provider(self) -> AIProvider:
        if self._provider is not None:
            return self._provider
        analyzer_provider = getattr(self._analyzer, "_provider", None)
        if analyzer_provider is not None:
            return analyzer_provider
        config = load_config()
        if config is None:
            raise RuntimeError("AI provider is not configured")
        return build_provider(config)

    @staticmethod
    def _response_audit(stage: str, response) -> dict:
        return {
            "stage": stage,
            "contract_version": "investigation.v1",
            "status": "succeeded",
            "provider": _text(getattr(response, "provider", "unknown"), 100),
            "model": _text(getattr(response, "model", "unknown"), 200),
            "upstream_provider": _text(
                getattr(response, "upstream_provider", ""), 100,
            ),
            "generation_id": _text(getattr(response, "generation_id", ""), 200),
            "finish_reason": _text(getattr(response, "finish_reason", ""), 100),
            "input_tokens": int(getattr(response, "input_tokens", 0) or 0),
            "output_tokens": int(getattr(response, "output_tokens", 0) or 0),
            "latency_ms": round(float(getattr(response, "latency_ms", 0.0) or 0.0), 1),
            "cost_usd": round(float(getattr(response, "cost_usd", 0.0) or 0.0), 8),
            # >1 means a corrective retry was billed for this stage.
            "attempts": int(getattr(response, "attempts", 1) or 1),
            "recorded_at": time.time(),
        }

    def _failure_audit(self, stage: str, exc: Exception) -> dict:
        if isinstance(exc, StructuredResponseError):
            return dict(exc.audit)
        provider_name = "unconfigured"
        model = ""
        try:
            provider = self._get_provider()
            config = getattr(provider, "_cfg", None)
            provider_name = _text(
                getattr(config, "provider", "") or provider.__class__.__name__, 100,
            )
            model = _text(getattr(config, "model", ""), 200)
        except Exception:
            pass
        return {
            "stage": stage,
            "contract_version": "investigation.v1",
            "status": "provider_error",
            "provider": provider_name,
            "model": model,
            "error_type": type(exc).__name__,
            "recorded_at": time.time(),
        }

    @staticmethod
    def _validate_structured_response(stage: str, parsed: dict) -> None:
        if stage == "hypothesis_generation":
            hypotheses = parsed.get("hypotheses")
            if not isinstance(hypotheses, list) or not hypotheses:
                raise ValueError("hypotheses must be a non-empty array")
            for hypothesis in hypotheses[:MAX_HYPOTHESES]:
                if not isinstance(hypothesis, dict):
                    raise ValueError("each hypothesis must be an object")
                if not isinstance(hypothesis.get("statement"), str):
                    raise ValueError("hypothesis.statement must be a string")
                for field in ("supporting_ids", "contradicting_ids"):
                    citations = hypothesis.get(field)
                    if not isinstance(citations, list) or not all(
                        isinstance(item, str) for item in citations
                    ):
                        raise ValueError(f"hypothesis.{field} must be a string array")
                confidence = hypothesis.get("confidence")
                if (
                    isinstance(confidence, bool)
                    or not isinstance(confidence, (int, float))
                    or not 0 <= confidence <= 1
                ):
                    raise ValueError("hypothesis.confidence must be between 0 and 1")
                if hypothesis.get("status") not in {
                    "supported", "contradicted", "unresolved",
                }:
                    raise ValueError("hypothesis.status is invalid")
            return

        if stage == "verdict_generation":
            if parsed.get("verdict") not in ALLOWED_VERDICTS:
                raise ValueError("verdict is invalid")
            confidence = parsed.get("confidence")
            if (
                isinstance(confidence, bool)
                or not isinstance(confidence, (int, float))
                or not 0 <= confidence <= 1
            ):
                raise ValueError("verdict.confidence must be between 0 and 1")
            if not isinstance(parsed.get("summary"), str):
                raise ValueError("verdict.summary must be a string")
            for field in ("evidence_ids", "gaps"):
                values = parsed.get(field)
                if not isinstance(values, list) or not all(
                    isinstance(item, str) for item in values
                ):
                    raise ValueError(f"verdict.{field} must be a string array")

    async def _ask_json(
        self,
        prompt: str,
        *,
        stage: str,
        schema: dict,
        required_fields: tuple[str, ...],
        max_tokens: int,
    ) -> tuple[dict, dict]:
        provider = self._get_provider()

        def _check(parsed: dict) -> None:
            missing = [field for field in required_fields if field not in parsed]
            if missing:
                raise ValueError(
                    "AI provider response is missing required fields: "
                    + ", ".join(missing)
                )
            self._validate_structured_response(stage, parsed)

        # chat_json runs _check inside its retry loop, so a missing field or a
        # bad enum earns one corrective attempt instead of aborting the whole
        # investigation — cheap models drop out of format intermittently, and
        # every node here is a hard dependency for the next one.
        chat_json = getattr(provider, "chat_json", None)
        if callable(chat_json):
            try:
                parsed, response = await chat_json(
                    prompt, max_tokens=max_tokens, schema=schema, validate=_check,
                )
            except AIResponseError as exc:
                # The audit trail is the point of this module, so record which
                # model produced the bad reply rather than losing it with the
                # exception.
                audit = (
                    self._response_audit(stage, exc.response)
                    if exc.response is not None
                    else self._failure_audit(stage, exc)
                )
                audit["status"] = "invalid_response"
                audit["error_type"] = type(exc).__name__
                raise StructuredResponseError(str(exc), audit) from exc
            except Exception as exc:
                raise StructuredResponseError(
                    str(exc), self._failure_audit(stage, exc),
                ) from exc
            return parsed, self._response_audit(stage, response)

        # Minimal injected providers (tests, alternative implementations) may
        # implement only chat/chat_structured. They get the original
        # single-attempt path rather than being rejected outright.
        structured_chat = getattr(provider, "chat_structured", None)
        try:
            if callable(structured_chat):
                response = await structured_chat(
                    prompt, schema=schema, max_tokens=max_tokens,
                )
            else:
                response = await provider.chat(prompt, max_tokens=max_tokens)
        except Exception as exc:
            raise StructuredResponseError(
                str(exc), self._failure_audit(stage, exc),
            ) from exc

        audit = self._response_audit(stage, response)
        try:
            parsed = provider.parse_json(response.text)
            if not isinstance(parsed, dict):
                raise ValueError("AI provider returned a non-object response")
            _check(parsed)
        except Exception as exc:
            audit["status"] = "invalid_response"
            audit["error_type"] = type(exc).__name__
            raise StructuredResponseError(str(exc), audit) from exc
        return parsed, audit

    def _context_payload(self, state: InvestigationState) -> dict:
        return {
            "finding": state.get("finding") or {},
            "evidence": state.get("evidence") or [],
            "history": state.get("history") or [],
            "related_findings": state.get("related_findings") or [],
            "correlations": state.get("correlations") or [],
            "intel": state.get("intel") or [],
        }

    async def _generate_hypotheses(self, state: InvestigationState) -> dict:
        context = json.dumps(self._context_payload(state), default=str)[:60_000]
        feedback = _text(state.get("analyst_feedback"), 1000)
        prompt = f"""Generate at most {MAX_HYPOTHESES} bounded security hypotheses for this existing finding.
Each hypothesis must be testable from the supplied records and must cite record IDs. Do not invent evidence.
Return JSON: {{"hypotheses":[{{"id":"HP-1","statement":"...","supporting_ids":["E-..."],"contradicting_ids":[],"confidence":0.0,"status":"supported|contradicted|unresolved"}}]}}.
Analyst feedback from a prior review, if any: <untrusted>{feedback}</untrusted>
Context: <untrusted>{context}</untrusted>"""
        try:
            parsed, call_audit = await self._ask_json(
                prompt,
                stage="hypothesis_generation",
                schema=HYPOTHESES_SCHEMA,
                required_fields=("hypotheses",),
                max_tokens=1400,
            )
        except Exception as exc:
            errors = list(state.get("errors") or [])
            errors.append(f"hypothesis_generation: {type(exc).__name__}")
            return {
                "hypotheses": [{
                    "id": "HP-1", "statement": "The available evidence requires analyst validation.",
                    "supporting_ids": ["E-FINDING"], "contradicting_ids": [],
                    "confidence": 0.0, "status": "unresolved",
                }],
                "errors": errors,
                "model_calls": [
                    *list(state.get("model_calls") or []),
                    self._failure_audit("hypothesis_generation", exc),
                ],
            }

        allowed = {
            record["id"]
            for key in ("evidence", "history", "related_findings", "correlations", "intel")
            for record in state.get(key, [])
        }
        hypotheses: list[dict] = []
        for index, raw in enumerate(parsed.get("hypotheses", [])[:MAX_HYPOTHESES], start=1):
            if not isinstance(raw, dict) or not _text(raw.get("statement"), 1000):
                continue
            status = str(raw.get("status") or "unresolved").lower()
            if status not in {"supported", "contradicted", "unresolved"}:
                status = "unresolved"
            try:
                confidence = max(0.0, min(float(raw.get("confidence", 0.0)), 1.0))
            except (TypeError, ValueError):
                confidence = 0.0
            supporting, fake_support = _ground_citations(raw.get("supporting_ids"), allowed)
            contradicting, fake_contra = _ground_citations(
                raw.get("contradicting_ids"), allowed,
            )
            fabricated = fake_support + fake_contra
            # A hypothesis whose support was entirely invented is unresolved,
            # not supported — otherwise a fabricated citation carries it into
            # the verdict stage as though it had evidence behind it.
            if status == "supported" and not supporting:
                status, confidence = "unresolved", min(confidence, 0.3)
            hypotheses.append({
                "id": f"HP-{index}",
                "statement": _text(raw.get("statement"), 1000),
                "supporting_ids": supporting,
                "contradicting_ids": contradicting,
                "fabricated_citations": fabricated,
                "confidence": confidence,
                "status": status,
            })
        if not hypotheses:
            hypotheses.append({
                "id": "HP-1", "statement": "The available evidence is insufficient for a bounded hypothesis.",
                "supporting_ids": [], "contradicting_ids": [], "confidence": 0.0, "status": "unresolved",
            })
        return {
            "hypotheses": hypotheses,
            "model_calls": [*list(state.get("model_calls") or []), call_audit],
        }

    async def _verify_hypotheses(self, state: InvestigationState) -> dict:
        record_map = {
            record["id"]: record
            for key in ("evidence", "history", "related_findings", "correlations", "intel")
            for record in state.get(key, [])
        }
        verification = []
        for hypothesis in state.get("hypotheses", [])[:MAX_HYPOTHESES]:
            support = [record_map[item] for item in hypothesis.get("supporting_ids", []) if item in record_map]
            contradict = [record_map[item] for item in hypothesis.get("contradicting_ids", []) if item in record_map]
            status = hypothesis.get("status", "unresolved")
            if not support and status == "supported":
                status = "unresolved"
            verification.append({
                "hypothesis_id": hypothesis.get("id"),
                "status": status,
                "support_count": len(support),
                "contradiction_count": len(contradict),
                "verified_citations": [item["id"] for item in support + contradict],
            })
        return {"verification": verification}

    async def _draft_verdict(self, state: InvestigationState) -> dict:
        allowed = {
            record["id"]
            for key in ("evidence", "history", "related_findings", "correlations", "intel")
            for record in state.get(key, [])
        }
        prompt = f"""Assess the bounded hypotheses for an existing security finding.
Return JSON: {{"verdict":"confirmed|likely|inconclusive|unlikely|false_positive","confidence":0.0,"summary":"...","evidence_ids":["E-..."],"gaps":["..."]}}.
Use only supplied record IDs. A lack of evidence must produce inconclusive, not confirmed.
Data: <untrusted>{json.dumps({"hypotheses": state.get("hypotheses", []), "verification": state.get("verification", [])}, default=str)[:30_000]}</untrusted>"""
        try:
            parsed, call_audit = await self._ask_json(
                prompt,
                stage="verdict_generation",
                schema=VERDICT_SCHEMA,
                required_fields=("verdict", "confidence", "summary", "evidence_ids", "gaps"),
                max_tokens=900,
            )
        except Exception as exc:
            errors = list(state.get("errors") or [])
            errors.append(f"verdict_generation: {type(exc).__name__}")
            return {
                "verdict": {"verdict": "inconclusive", "confidence": 0.0, "summary": "AI verdict unavailable; analyst review is required.", "evidence_ids": [], "gaps": ["AI provider response unavailable"]},
                "errors": errors,
                "model_calls": [
                    *list(state.get("model_calls") or []),
                    self._failure_audit("verdict_generation", exc),
                ],
            }
        verdict = str(parsed.get("verdict") or "inconclusive").lower()
        if verdict not in ALLOWED_VERDICTS:
            verdict = "inconclusive"
        try:
            confidence = max(0.0, min(float(parsed.get("confidence", 0.0)), 1.0))
        except (TypeError, ValueError):
            confidence = 0.0
        evidence_ids, fabricated = _ground_citations(parsed.get("evidence_ids"), allowed)
        if not evidence_ids and verdict in {"confirmed", "likely", "unlikely", "false_positive"}:
            verdict, confidence = "inconclusive", 0.0

        # A verdict is only as grounded as the evidence it can actually point
        # at. When most of the citations were invented, damp confidence by the
        # share that survived rather than presenting a partly-fabricated
        # verdict at face value. The counts are recorded either way so the
        # reviewing analyst — and the audit trail — can see it.
        cited_total = len(evidence_ids) + fabricated
        grounding_ratio = (len(evidence_ids) / cited_total) if cited_total else 0.0
        if fabricated and grounding_ratio < 0.5:
            confidence = round(confidence * grounding_ratio, 4)
            log.warning(
                "Investigation verdict cited %d fabricated evidence id(s) of %d; "
                "confidence damped to %.4f", fabricated, cited_total, confidence,
            )
        if fabricated:
            call_audit = {**call_audit, "fabricated_citations": fabricated}

        return {
            "verdict": {
                "verdict": verdict,
                "confidence": confidence,
                "summary": _text(parsed.get("summary"), 1500),
                "evidence_ids": evidence_ids,
                "fabricated_citations": fabricated,
                "grounding_ratio": round(grounding_ratio, 4),
                "gaps": [_text(item, 500) for item in parsed.get("gaps", [])[:10]],
            },
            "model_calls": [*list(state.get("model_calls") or []), call_audit],
        }

    def _analyst_review(self, state: InvestigationState) -> dict:
        review_round = int(state.get("review_round") or 0)
        allowed = ["approve", "reject"]
        if review_round < self._max_review_rounds:
            allowed.append("request_more")
        decision = interrupt({
            "type": "analyst_approval",
            "finding_id": state.get("finding_id"),
            "run_id": state.get("run_id"),
            "review_round": review_round + 1,
            "verdict": state.get("verdict") or {},
            "hypotheses": state.get("hypotheses") or [],
            "verification": state.get("verification") or [],
            "errors": state.get("errors") or [],
            "model_calls": state.get("model_calls") or [],
            "allowed_decisions": allowed,
        })
        if not isinstance(decision, dict):
            raise ValueError("Analyst decision payload must be an object")
        choice = _text(decision.get("decision"), 30).lower()
        if choice not in allowed:
            raise ValueError(f"Decision {choice} is not allowed at this review stage")
        return {
            "analyst_decision": choice,
            "analyst_actor": _text(decision.get("actor") or "analyst", 100),
            "analyst_feedback": _text(decision.get("feedback"), 1000),
            "review_round": review_round + 1,
        }

    def _route_decision(self, state: InvestigationState) -> str:
        decision = state.get("analyst_decision") or "reject"
        if decision == "request_more" and int(state.get("review_round") or 0) <= self._max_review_rounds:
            return "request_more"
        return decision if decision in {"approve", "reject"} else "reject"

    async def _expand_context(self, state: InvestigationState) -> dict:
        finding = state.get("finding") or {}
        errors = list(state.get("errors") or [])
        related = list(state.get("related_findings") or [])
        try:
            candidates = await self._db.get_soc_findings(active_only=False, limit=200)
            existing_ids = {str(item.get("data", {}).get("id")) for item in related}
            cves = set(_extract_cves(finding))
            for candidate in candidates:
                candidate_id = str(candidate.get("id") or "")
                if candidate_id in existing_ids or int(candidate.get("id") or 0) == int(state["finding_id"]):
                    continue
                if (
                    (cves and cves & set(_extract_cves(candidate)))
                    or candidate.get("rule_id") == finding.get("rule_id")
                    or candidate.get("item_key") == finding.get("item_key")
                ):
                    related.append(_record(f"R-{len(related) + 1:03d}", "fleet_related_finding", candidate))
                if len(related) >= MAX_CONTEXT_ITEMS:
                    break
        except Exception as exc:
            errors.append(f"expanded_context: {_text(exc, 300)}")
        return {"related_findings": related[:MAX_CONTEXT_ITEMS], "errors": errors}

    async def _draft_remediation(self, state: InvestigationState) -> dict:
        finding = state.get("finding") or {}
        errors = list(state.get("errors") or [])
        try:
            plan = await self._analyzer.remediate(
                int(state["finding_id"]), finding,
                os_type=str(finding.get("agent_os") or "unknown"), force=True, intel_db=self._db,
            )
            remediation = plan.to_dict() if hasattr(plan, "to_dict") else _json_safe(plan)
            remediation["source"] = "ai_provider"
            # These used to be hardcoded 0 because the plan carried only a
            # summed tokens_used and no cost at all, so the remediation stage —
            # the most expensive call in the run — reported as free and made
            # every per-run cost total wrong.
            call_audit = {
                "stage": "remediation_generation",
                "contract_version": "investigation.v1",
                "status": "succeeded",
                "provider": _text(remediation.get("provider") or "unknown", 100),
                "model": _text(remediation.get("model") or "unknown", 200),
                "upstream_provider": _text(
                    remediation.get("upstream_provider") or "", 100,
                ),
                "generation_id": _text(remediation.get("generation_id") or "", 200),
                "input_tokens": int(remediation.get("input_tokens") or 0),
                "output_tokens": int(remediation.get("output_tokens") or 0),
                "attempts": int(remediation.get("attempts") or 1),
                "latency_ms": round(float(remediation.get("latency_ms") or 0.0), 1),
                "cost_usd": round(float(remediation.get("cost_usd") or 0.0), 8),
                "recorded_at": time.time(),
            }
        except Exception as exc:
            errors.append(f"remediation_generation: {type(exc).__name__}")
            remediation = _json_safe(recipe_for_finding(finding))
            remediation["source"] = "deterministic_knowledge_base"
            call_audit = self._failure_audit("remediation_generation", exc)
            call_audit["fallback"] = "deterministic_knowledge_base"
        remediation["execution_authorized"] = False
        remediation["approval_scope"] = "draft_only"
        return {
            "remediation": remediation,
            "errors": errors,
            "model_calls": [*list(state.get("model_calls") or []), call_audit],
        }

    def _finalize_approved(self, state: InvestigationState) -> dict:
        completed = time.time()
        result = self._result_payload(state, "completed", completed)
        return {"result": result, "status": "completed", "completed_at": completed}

    def _finalize_rejected(self, state: InvestigationState) -> dict:
        completed = time.time()
        result = self._result_payload(state, "rejected", completed)
        return {"result": result, "status": "rejected", "completed_at": completed}

    def _result_payload(self, state: InvestigationState, status: str, completed: float) -> dict:
        model_calls = state.get("model_calls") or []
        return {
            "run_id": state.get("run_id"),
            "finding_id": state.get("finding_id"),
            "status": status,
            "verdict": state.get("verdict") or {},
            "hypotheses": state.get("hypotheses") or [],
            "verification": state.get("verification") or [],
            "remediation": state.get("remediation") or {},
            "analyst": {
                "actor": state.get("analyst_actor") or "",
                "decision": state.get("analyst_decision") or "",
                "feedback": state.get("analyst_feedback") or "",
                "review_round": state.get("review_round") or 0,
            },
            "errors": state.get("errors") or [],
            "model_calls": model_calls,
            "usage": _usage_totals(model_calls),
            "completed_at": completed,
        }

    async def _sync_run(self, run_id: str, thread_id: str) -> dict:
        previous = await self._db.get_investigation_run(run_id)
        snapshot = await self._graph.aget_state(self._config(thread_id))
        state = dict(snapshot.values or {})
        interrupts = [item for task in snapshot.tasks for item in getattr(task, "interrupts", ())]
        if interrupts:
            payload = _json_safe(interrupts[0].value)
            updated = await self._db.update_investigation_run(
                run_id, status="pending_review", current_node="analyst_review", review_payload=payload,
                error="; ".join(state.get("errors") or [])[:1000],
            ) or {}
            await self._notify_lifecycle(previous, updated, state)
            return updated
        status = state.get("status") or "running"
        completed = status in {"completed", "rejected", "failed"}
        updated = await self._db.update_investigation_run(
            run_id,
            status=status,
            current_node="complete" if completed else "running",
            review_payload={},
            result=state.get("result") or {},
            analyst_actor=state.get("analyst_actor") or "",
            analyst_decision=state.get("analyst_decision") or "",
            error="; ".join(state.get("errors") or [])[:1000],
            completed=completed,
        ) or {}
        await self._notify_lifecycle(previous, updated, state)
        return updated

    async def _notify_lifecycle(
        self, previous: dict | None, updated: dict, state: InvestigationState,
    ) -> None:
        handler = self._lifecycle_notification_handler
        status = str(updated.get("status") or "")
        if (
            handler is None
            or status not in {"pending_review", "completed", "rejected", "failed"}
            or status == str((previous or {}).get("status") or "")
        ):
            return
        event = f"investigation_{status}"
        try:
            await handler(
                dict(state.get("finding") or {}),
                event,
                {
                    "run_id": updated.get("run_id") or state.get("run_id"),
                    "status": status,
                    "actor": state.get("analyst_actor") or "AttackLens",
                    "decision": state.get("analyst_decision") or "",
                    "feedback": state.get("analyst_feedback") or "",
                },
            )
        except Exception:
            log.exception("investigation lifecycle notification failed run=%s", updated.get("run_id"))

    @staticmethod
    def _config(thread_id: str) -> dict:
        return {"configurable": {"thread_id": thread_id}}
