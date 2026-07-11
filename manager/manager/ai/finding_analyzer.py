"""
manager/manager/ai/finding_analyzer.py — Provider-agnostic finding analysis.

Wraps any AIProvider and exposes three high-level operations:
  analyze(finding)     → AIFindingAnalysis   (threat context, risk narrative, urgency)
  remediate(finding)   → AIRemediationPlan   (OS-specific step-by-step plan)
  prioritize(findings) → list with ai_priority + ai_reason injected

The prompts are deliberately provider-neutral: structured JSON schemas with
clear field descriptions, so they work equally well with Claude, GPT-4o-mini,
Gemini Flash, and local Ollama models.

Cost strategy:
  • Short prompts (analysis) → use cheaper/faster model (Haiku, gpt-4o-mini)
  • Long prompts (remediation) → same model but more tokens
  • Batch prioritize → single call for up to 20 findings
  • All results cached in intel_db; force=True bypasses cache
"""
from __future__ import annotations

import json
import logging
import time
from dataclasses import dataclass, field
from typing import Optional

from .base import AIProvider, AIResponse
from .providers import build_provider
from .key_store import load_config

log = logging.getLogger("manager.ai.finding_analyzer")


# ── Result types ──────────────────────────────────────────────────────────────

@dataclass
class AIFindingAnalysis:
    finding_id:    int
    provider:      str
    model:         str
    analysis:      str           # 2-3 sentence expert narrative
    threat_context: str          # current threat landscape context
    risk_factors:  list[str]     # top 3 specific risk factors
    urgency:       str           # immediate|urgent|scheduled|informational
    confidence:    float         # 0.0–1.0 analyst confidence
    mitre_context: str           # MITRE ATT&CK mapping insight
    tokens_used:   int
    latency_ms:    float
    generated_at:  float = field(default_factory=time.time)

    def to_dict(self) -> dict:
        return {
            "finding_id":    self.finding_id,
            "provider":      self.provider,
            "model":         self.model,
            "analysis":      self.analysis,
            "threat_context": self.threat_context,
            "risk_factors":  self.risk_factors,
            "urgency":       self.urgency,
            "confidence":    self.confidence,
            "mitre_context": self.mitre_context,
            "tokens_used":   self.tokens_used,
            "latency_ms":    round(self.latency_ms, 1),
            "generated_at":  self.generated_at,
        }


@dataclass
class AIRemediationPlan:
    finding_id:   int
    provider:     str
    model:        str
    os_type:      str
    summary:      str
    effort:       str            # low|medium|high
    risk_level:   str            # low|medium|high (risk of the remediation itself)
    steps:        list[dict]     # [{step, title, description, command, verification, risk}]
    verification: list[str]      # post-remediation checks
    long_term:    list[str]      # strategic improvements
    compensating: str            # if immediate remediation not possible
    tokens_used:  int
    latency_ms:   float
    generated_at: float = field(default_factory=time.time)

    def to_dict(self) -> dict:
        return {
            "finding_id":   self.finding_id,
            "provider":     self.provider,
            "model":        self.model,
            "os_type":      self.os_type,
            "summary":      self.summary,
            "effort":       self.effort,
            "risk_level":   self.risk_level,
            "steps":        self.steps,
            "verification": self.verification,
            "long_term":    self.long_term,
            "compensating": self.compensating,
            "tokens_used":  self.tokens_used,
            "latency_ms":   round(self.latency_ms, 1),
            "generated_at": self.generated_at,
        }


# ── Analyzer ──────────────────────────────────────────────────────────────────

class FindingAnalyzer:
    """
    Provider-agnostic finding analysis service.

    Pass an explicit AIProvider for testing, or let it resolve from the
    customer-configured key store at call time (lazy resolution).
    """

    def __init__(self, provider: Optional[AIProvider] = None) -> None:
        self._provider = provider   # None → resolved lazily from key_store

    def _get_provider(self) -> AIProvider:
        if self._provider:
            return self._provider
        cfg = load_config()
        if cfg is None:
            raise RuntimeError(
                "AI provider not configured. "
                "POST /api/v1/ai/provider to configure your provider and API key."
            )
        return build_provider(cfg)

    @property
    def enabled(self) -> bool:
        cfg = load_config()
        return cfg is not None

    # ── Public operations ─────────────────────────────────────────────────────

    async def analyze(
        self,
        finding_id: int,
        finding: dict,
        *,
        force: bool = False,
        intel_db=None,
    ) -> AIFindingAnalysis:
        """
        Analyze a finding. Returns cached result unless force=True.
        If intel_db is provided, cache is read/written.
        """
        if not force and intel_db:
            cached = await _load_cached_analysis(intel_db, finding_id)
            if cached:
                return cached

        provider = self._get_provider()
        prompt   = _analysis_prompt(finding)

        resp: AIResponse = await provider.chat(prompt, max_tokens=800)
        parsed  = provider.parse_json(resp.text)

        result = AIFindingAnalysis(
            finding_id    = finding_id,
            provider      = resp.provider,
            model         = resp.model,
            analysis      = parsed.get("analysis", ""),
            threat_context = parsed.get("threat_context", ""),
            risk_factors  = parsed.get("risk_factors", [])[:5],
            urgency       = parsed.get("urgency", "scheduled"),
            confidence    = float(parsed.get("confidence", 0.5)),
            mitre_context = parsed.get("mitre_context", ""),
            tokens_used   = resp.total_tokens,
            latency_ms    = resp.latency_ms,
        )

        if intel_db:
            await _cache_analysis(intel_db, finding_id, result)

        return result

    async def remediate(
        self,
        finding_id: int,
        finding: dict,
        os_type: str = "macos",
        *,
        force: bool = False,
        intel_db=None,
    ) -> AIRemediationPlan:
        """Generate an OS-specific remediation plan."""
        if not force and intel_db:
            cached = await _load_cached_remediation(intel_db, finding_id, os_type)
            if cached:
                return cached

        provider = self._get_provider()
        prompt   = _remediation_prompt(finding, os_type)

        resp: AIResponse = await provider.chat(prompt, max_tokens=2000)
        parsed  = provider.parse_json(resp.text)

        result = AIRemediationPlan(
            finding_id  = finding_id,
            provider    = resp.provider,
            model       = resp.model,
            os_type     = os_type,
            summary     = parsed.get("summary", ""),
            effort      = parsed.get("effort", "medium"),
            risk_level  = parsed.get("remediation_risk", "low"),
            steps       = parsed.get("steps", []),
            verification = parsed.get("verification", []),
            long_term   = parsed.get("long_term_recommendations", []),
            compensating = parsed.get("compensating_controls", ""),
            tokens_used = resp.total_tokens,
            latency_ms  = resp.latency_ms,
        )

        if intel_db:
            await _cache_remediation(intel_db, finding_id, os_type, result)

        return result

    async def prioritize(
        self,
        findings: list[dict],
        *,
        top_n: int = 20,
    ) -> list[dict]:
        """
        AI-assisted prioritization — injects ai_priority + ai_reason into each
        finding dict and sorts by priority rank.
        """
        if not findings:
            return findings

        provider   = self._get_provider()
        candidates = sorted(findings, key=lambda f: -float(f.get("composite_score", 0)))[:top_n]
        prompt     = _prioritize_prompt(candidates)

        try:
            resp   = await provider.chat(prompt, max_tokens=1000)
            parsed = provider.parse_json(resp.text)
        except Exception as exc:
            log.warning("AI prioritization failed: %s", exc)
            return findings

        pmap: dict[str, dict] = {}
        for item in parsed.get("prioritized", []):
            key = str(item.get("item_key", ""))
            pmap[key] = {
                "ai_priority": int(item.get("priority_rank", 99)),
                "ai_reason":   str(item.get("reason", "")),
            }

        for f in findings:
            ai = pmap.get(str(f.get("item_key", "")), {})
            f["ai_priority"] = ai.get("ai_priority", 99)
            f["ai_reason"]   = ai.get("ai_reason", "")

        findings.sort(key=lambda f: (f.get("ai_priority", 99), -float(f.get("composite_score", 0))))
        return findings


# ── Prompt builders ───────────────────────────────────────────────────────────

def _wrap_untrusted(text: str) -> str:
    """
    Wrap endpoint-sourced free-text in <untrusted> tags so the model treats it
    as data, not instructions (paired with the SYSTEM_PROMPT injection guard).
    Any literal delimiter in the content is neutralized to prevent tag-breakout.
    """
    if text is None:
        return "<untrusted></untrusted>"
    safe = str(text).replace("<untrusted>", "‹untrusted›").replace("</untrusted>", "‹/untrusted›")
    return f"<untrusted>{safe}</untrusted>"


def _analysis_prompt(f: dict) -> str:
    cves  = f.get("cve_ids") or []
    if isinstance(cves, str):
        try:
            cves = json.loads(cves)
        except Exception:
            cves = []

    evid  = f.get("evidence") or {}
    if isinstance(evid, str):
        try:
            evid = json.loads(evid)
        except Exception:
            evid = {}

    # Untrusted, endpoint-sourced free-text is wrapped so the model treats it as
    # data (see SYSTEM_PROMPT injection guard), not instructions.
    title = _wrap_untrusted(f.get("title", "Untitled"))
    desc  = _wrap_untrusted((f.get("description") or "")[:400])
    evid_s = _wrap_untrusted(json.dumps(evid, default=str)[:400])

    return f"""Analyze this endpoint security finding as a senior SOC analyst. Be concise and specific.

FINDING:
- Title:         {title}
- Severity:      {f.get("severity", "unknown")}
- Category:      {f.get("category", "unknown")}
- Risk Score:    {f.get("composite_score", 0)}/10
- CVE IDs:       {json.dumps(cves)}
- MITRE:         {f.get("mitre_technique", "N/A")} / {f.get("mitre_tactic", "N/A")}
- Description:   {desc}
- Evidence:      {evid_s}
- KEV (active):  {f.get("kev", False)}
- EPSS Score:    {f.get("epss_score", "N/A")}
- CVSS Score:    {f.get("cvss_score", "N/A")}
- Exploit:       {f.get("exploit_available", False)}

Reply ONLY with this JSON (no other text):
{{
  "analysis": "2-3 sentence expert analysis — what this finding means and its real-world impact on an endpoint",
  "threat_context": "1-2 sentences on current threat landscape relevance — active campaigns, ransomware relevance, nation-state usage",
  "risk_factors": ["specific risk factor 1", "specific risk factor 2", "specific risk factor 3"],
  "mitre_context": "1 sentence on how this maps to ATT&CK and what technique the attacker uses",
  "urgency": "immediate",
  "confidence": 0.85
}}

urgency values: immediate (KEV/active exploit/critical), urgent (high risk, patch soon), scheduled (medium, plan remediation), informational (low/info)
confidence: 0.0-1.0, your confidence in this assessment"""


def _remediation_prompt(f: dict, os_type: str) -> str:
    os_labels = {"macos": "macOS", "windows": "Windows", "linux": "Linux"}
    os_label  = os_labels.get(os_type, os_type)

    cves = f.get("cve_ids") or []
    if isinstance(cves, str):
        try:
            cves = json.loads(cves)
        except Exception:
            cves = []

    evid = f.get("evidence") or {}
    if isinstance(evid, str):
        try:
            evid = json.loads(evid)
        except Exception:
            evid = {}

    # Untrusted, endpoint-sourced free-text is wrapped so the model treats it as
    # data (see SYSTEM_PROMPT injection guard), not instructions.
    title = _wrap_untrusted(f.get("title", ""))
    desc  = _wrap_untrusted((f.get("description") or "")[:400])
    evid_s = _wrap_untrusted(json.dumps(evid, default=str)[:300])
    rec   = _wrap_untrusted((f.get("recommendation") or "")[:200])

    return f"""Generate a detailed {os_label} remediation plan for this security finding.

FINDING:
- Title:       {title}
- Severity:    {f.get("severity", "")}
- Category:    {f.get("category", "")}
- Description: {desc}
- CVE IDs:     {json.dumps(cves)}
- MITRE:       {f.get("mitre_technique", "N/A")}
- KEV:         {f.get("kev", False)}
- Evidence:    {evid_s}
- Existing rec: {rec}

Reply ONLY with this JSON:
{{
  "summary": "One sentence describing the remediation approach",
  "effort": "low",
  "remediation_risk": "low",
  "steps": [
    {{
      "step": 1,
      "title": "Step title",
      "description": "What to do and why",
      "command": "exact {os_label} shell command or null",
      "verification": "how to verify this step succeeded",
      "risk": "risk of performing this step (or null)"
    }}
  ],
  "verification": ["final check 1", "final check 2"],
  "long_term_recommendations": ["strategic item 1", "strategic item 2"],
  "compensating_controls": "what to do if immediate fix is impossible"
}}

effort: low|medium|high  remediation_risk: low|medium|high
Use real {os_label} commands. For macOS: defaults, launchctl, codesign, security, brew. For Linux: systemctl, apt/yum, sysctl. Include verification after each step."""


def _prioritize_prompt(findings: list[dict]) -> str:
    items = []
    for f in findings:
        items.append({
            "item_key":        f.get("item_key", f.get("id", "")),
            "title":           f.get("title", ""),
            "severity":        f.get("severity", ""),
            "composite_score": f.get("composite_score", 0),
            "kev":             f.get("kev", False),
            "epss":            f.get("epss_score", 0),
            "exploit":         f.get("exploit_available", False),
            "category":        f.get("category", ""),
            "cve_ids":         f.get("cve_ids", []),
        })

    return f"""You are a CISO prioritizing {len(findings)} security findings for remediation. Rank by true business risk — not just CVSS. Factor in: active exploitation (KEV), exploit probability (EPSS), attack chain potential, and operational impact.

FINDINGS:
{json.dumps(items, indent=2)}

Reply ONLY with this JSON:
{{
  "prioritized": [
    {{
      "item_key": "exact item_key from input",
      "priority_rank": 1,
      "reason": "brief reason max 15 words"
    }}
  ],
  "summary": "one sentence CISO-level summary of overall risk posture"
}}

Rank ALL {len(findings)} findings. Priority 1 = highest risk / address immediately."""


# ── Cache helpers (best-effort, no exceptions to caller) ─────────────────────

async def _load_cached_analysis(idb, finding_id: int) -> Optional[AIFindingAnalysis]:
    try:
        data = await idb.get_ai_analysis(finding_id)
        if not data:
            return None
        return AIFindingAnalysis(
            finding_id    = finding_id,
            provider      = data.get("provider", "unknown"),
            model         = data.get("model", "unknown"),
            analysis      = data.get("analysis", ""),
            threat_context = data.get("threat_context", ""),
            risk_factors  = data.get("risk_factors", []),
            urgency       = data.get("urgency", "scheduled"),
            confidence    = float(data.get("confidence", 0.5)),
            mitre_context = data.get("mitre_context", ""),
            tokens_used   = int(data.get("tokens_used", 0)),
            latency_ms    = float(data.get("latency_ms", 0)),
            generated_at  = float(data.get("generated_at", 0)),
        )
    except Exception as exc:
        log.debug("Cache load failed for finding %d: %s", finding_id, exc)
        return None


async def _cache_analysis(idb, finding_id: int, result: AIFindingAnalysis) -> None:
    try:
        await idb.upsert_ai_analysis(finding_id, result.to_dict())
    except Exception as exc:
        log.debug("Cache write failed for finding %d: %s", finding_id, exc)


async def _load_cached_remediation(idb, finding_id: int, os_type: str) -> Optional[AIRemediationPlan]:
    try:
        data = await idb.get_remediation_plan(finding_id, os_type)
        if not data:
            return None
        return AIRemediationPlan(
            finding_id  = finding_id,
            provider    = data.get("provider", "unknown"),
            model       = data.get("model", "unknown"),
            os_type     = os_type,
            summary     = data.get("summary", ""),
            effort      = data.get("effort", "medium"),
            risk_level  = data.get("risk_level", "low"),
            steps       = data.get("steps", []),
            verification = data.get("verification", []),
            long_term   = data.get("long_term", []),
            compensating = data.get("compensating", ""),
            tokens_used = int(data.get("tokens_used", 0)),
            latency_ms  = float(data.get("latency_ms", 0)),
            generated_at = float(data.get("generated_at", 0)),
        )
    except Exception as exc:
        log.debug("Cache load (remediation) failed for finding %d: %s", finding_id, exc)
        return None


async def _cache_remediation(idb, finding_id: int, os_type: str, result: AIRemediationPlan) -> None:
    try:
        await idb.upsert_remediation_plan(
            finding_id, "", os_type, result.to_dict()
        )
    except Exception as exc:
        log.debug("Cache write (remediation) failed for finding %d: %s", finding_id, exc)
