"""
manager/manager/ai_analyst.py — AI-powered security analyst using Claude API.

Provides:
  • Finding analysis with expert security commentary
  • Threat actor / news correlation
  • OS-specific step-by-step remediation plans
  • Batch prioritization across multiple findings

All results are cached in intel.db (ai_analysis + remediation_plans tables).
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
from typing import Any, Optional

from .ai.base import (
    SYSTEM_PROMPT,
    coerce_confidence,
    coerce_enum,
    coerce_str_list,
)

log = logging.getLogger("manager.ai_analyst")

_EFFORT_LEVELS = {"trivial", "low", "medium", "high", "significant"}
_RISK_LEVELS   = {"none", "low", "medium", "high", "critical"}


def _wrap_untrusted(text: object, limit: int = 4000) -> str:
    """Wrap endpoint-sourced free text so the model treats it as DATA.

    The system prompt tells the model that anything inside these tags is data
    to analyse, never instructions. Without the tags that guard is inert: this
    path interpolated finding titles, descriptions, evidence and recommendations
    straight into the prompt, and it is the path that emits shell commands an
    analyst is expected to run. A compromised endpoint controls those strings.

    Literal tags in the source text are neutralised with look-alike characters
    so injected content cannot close the wrapper and escape the guard.
    """
    if text is None:
        return "<untrusted></untrusted>"
    safe = str(text)[:limit]
    safe = safe.replace("<untrusted>", "‹untrusted›").replace("</untrusted>", "‹/untrusted›")
    return f"<untrusted>{safe}</untrusted>"


def _text(value: object, limit: int = 4000) -> str:
    """Normalise a free-text field the model may return as a non-string."""
    if isinstance(value, str):
        return value.strip()[:limit]
    if isinstance(value, (list, tuple)):
        return " ".join(str(v).strip() for v in value if v)[:limit]
    if value is None or isinstance(value, bool):
        return ""
    return str(value)[:limit]

_MODEL   = os.environ.get("AI_ANALYST_MODEL", "claude-sonnet-4-6")
_ENABLED = os.environ.get("AI_ANALYST_ENABLED", "true").lower() not in ("false", "0", "no")


class AIAnalyst:
    """
    Async AI security analyst.  Instantiate once at server startup.

    Usage:
        analyst = AIAnalyst(intel_db, feeds)
        result  = await analyst.analyze_finding(finding_id, finding)
        plan    = await analyst.generate_remediation(finding_id, finding, os_type="macos")
    """

    def __init__(self, intel_db, feeds=None) -> None:
        self._db    = intel_db
        self._feeds = feeds   # FeedManager — for context enrichment
        self._client = None
        self._api_key = os.environ.get("ANTHROPIC_API_KEY", "").strip()
        if _ENABLED and self._api_key:
            try:
                import anthropic
                self._client = anthropic.AsyncAnthropic(api_key=self._api_key)
                log.info("AI Analyst initialised (model=%s)", _MODEL)
            except ImportError:
                log.warning("anthropic package not installed — AI analysis disabled")
            except Exception as exc:
                log.warning("AI Analyst init failed: %s", exc)
        elif _ENABLED:
            log.info(
                "ANTHROPIC_API_KEY not set — AI Analyst will use the configured "
                "AI provider (Settings -> AI Provider) if one exists"
            )

    # ── Provider resolution ───────────────────────────────────────────────────

    def _store_provider(self):
        """Build a provider from the encrypted store, or None if unconfigured.

        Resolved per call rather than cached at startup: the provider is
        configured at runtime through the dashboard, so a cached "unconfigured"
        decision from boot would keep AI features dead until a restart.
        """
        try:
            from .ai.registry import build_task_provider
            return build_task_provider("remediation")
        except Exception as exc:
            log.warning("Could not resolve AI provider from store: %s", exc)
            return None

    @property
    def enabled(self) -> bool:
        """True when either credential path can serve a call.

        Checks the store on each access so configuring a provider in the
        dashboard takes effect immediately, with no manager restart.
        """
        if not _ENABLED:
            return False
        if self._client is not None and self._api_key:
            return True
        try:
            from .ai.key_store import load_config
            return load_config() is not None
        except Exception:
            return False

    # ── Public API ────────────────────────────────────────────────────────────

    async def analyze_finding(self, finding_id: int, finding: dict,
                              force: bool = False) -> Optional[dict]:
        """
        Analyze a finding with AI. Returns cached result if available.
        Set force=True to regenerate even if cached.
        """
        if not self.enabled:
            return None
        if not force:
            cached = await self._db.get_ai_analysis(finding_id)
            if cached:
                return cached

        context = await self._build_context(finding)
        prompt  = self._analysis_prompt(finding, context)
        try:
            result = await self._call_claude(prompt, max_tokens=1500)
            parsed = self._parse_json_response(result)
            data = {
                "model":         result.get("model", _MODEL),
                "analysis":      _text(parsed.get("analysis")),
                "threat_context": _text(parsed.get("threat_context")),
                "risk_factors":  coerce_str_list(parsed.get("risk_factors"), limit=8),
                "ioc_matches":   context.get("ioc_matches", []),
                "news_context":  context.get("news_items", []),
                "actor_context": context.get("actors", []),
                "confidence":    coerce_confidence(parsed.get("confidence")),
                "tokens_used":   result.get("tokens_used", 0),
            }
            await self._db.upsert_ai_analysis(finding_id, data)
            return data
        except Exception as exc:
            log.warning("AI analysis failed for finding %d: %s", finding_id, exc)
            return None

    async def generate_remediation(self, finding_id: int, finding: dict,
                                   os_type: str = "macos",
                                   force: bool = False) -> Optional[dict]:
        """
        Generate step-by-step remediation plan. Cached per finding+OS.
        """
        if not self.enabled:
            return None
        if not force:
            cached = await self._db.get_remediation_plan(finding_id, os_type)
            if cached:
                return cached

        prompt = self._remediation_prompt(finding, os_type)
        try:
            result = await self._call_claude(prompt, max_tokens=2000)
            parsed = self._parse_json_response(result)
            data = {
                "model":        result.get("model", _MODEL),
                "summary":      _text(parsed.get("summary")),
                # steps carry structured command objects, so they are length-
                # capped rather than flattened to strings like the prose lists.
                "steps":        parsed.get("steps", []) if isinstance(parsed.get("steps"), list) else [],
                "verification": coerce_str_list(parsed.get("verification"), limit=10),
                "long_term":    coerce_str_list(parsed.get("long_term_recommendations"), limit=10),
                "effort":       coerce_enum(parsed.get("effort"), _EFFORT_LEVELS, "medium"),
                "risk_level":   coerce_enum(parsed.get("remediation_risk"), _RISK_LEVELS, "low"),
            }
            if not data["summary"] and not data["steps"]:
                raise ValueError(
                    "model returned no summary and no steps — "
                    f"keys present: {sorted(parsed)[:8]}"
                )
            await self._db.upsert_remediation_plan(finding_id,
                                                   finding.get("agent_id", ""),
                                                   os_type, data)
            return data
        except Exception as exc:
            log.warning("Remediation generation failed for finding %d: %s", finding_id, exc)
            return None

    async def prioritize_findings(self, findings: list[dict]) -> list[dict]:
        """
        AI-assisted prioritization: returns findings sorted with AI priority
        scores and brief reasoning. Input findings must have composite_score set.
        """
        if not self.enabled or not findings:
            return findings
        # Only send top candidates to AI to control cost
        candidates = sorted(findings, key=lambda f: -float(f.get("composite_score", 0)))[:20]
        prompt = self._prioritization_prompt(candidates)
        try:
            result = await self._call_claude(prompt, max_tokens=1000)
            parsed = self._parse_json_response(result)
            priority_map: dict[str, dict] = {}
            for item in parsed.get("prioritized", []):
                key = str(item.get("item_key", ""))
                priority_map[key] = {
                    "ai_priority": int(item.get("priority_rank", 99)),
                    "ai_reason":   str(item.get("reason", "")),
                }
            for f in findings:
                ai = priority_map.get(str(f.get("item_key", "")), {})
                f["ai_priority"] = ai.get("ai_priority", 99)
                f["ai_reason"]   = ai.get("ai_reason", "")
            findings.sort(key=lambda f: (f.get("ai_priority", 99),
                                         -float(f.get("composite_score", 0))))
        except Exception as exc:
            log.warning("AI prioritization failed: %s", exc)
        return findings

    async def enrich_findings_batch(self, findings: list[dict]) -> None:
        """
        Background enrichment: analyze unanalysed active findings.
        Limits to 10 per call to avoid excessive API usage.
        """
        if not self.enabled:
            return
        pending = [f for f in findings if not f.get("ai_analysed")][:10]
        for f in pending:
            fid = f.get("id")
            if fid:
                await self.analyze_finding(int(fid), f)
                await asyncio.sleep(1)  # rate limit courtesy pause

    # ── Context enrichment ────────────────────────────────────────────────────

    async def _build_context(self, finding: dict) -> dict:
        """Gather threat intel context for a finding."""
        context: dict[str, Any] = {
            "ioc_matches":  [],
            "kev_match":    False,
            "news_items":   [],
            "actors":       [],
            "epss":         None,
        }
        # IOC match check
        try:
            if self._feeds:
                for cve_id in (finding.get("cve_ids") or []):
                    if isinstance(cve_id, str) and self._feeds.is_kev_cve(cve_id):
                        context["kev_match"] = True
                        context["ioc_matches"].append({"type": "kev", "value": cve_id})
        except Exception:
            pass

        # News correlation by CVE
        try:
            for cve_id in (finding.get("cve_ids") or []):
                if isinstance(cve_id, str):
                    news = await self._db.search_news_by_cve(cve_id)
                    for n in news[:3]:
                        context["news_items"].append({
                            "title":  n.get("title", ""),
                            "source": n.get("source", ""),
                            "url":    n.get("url", ""),
                        })
        except Exception:
            pass

        # EPSS score for first CVE
        try:
            cve_ids = finding.get("cve_ids") or []
            if cve_ids and isinstance(cve_ids, list) and self._feeds:
                epss_data = await self._feeds.get_epss(cve_ids[0])
                if epss_data:
                    context["epss"] = epss_data
        except Exception:
            pass

        # Active threat actors
        try:
            actors = await self._db.get_threat_actors(active_only=True, limit=5)
            context["actors"] = [{"name": a["name"], "last_active": a.get("last_active", "")}
                                 for a in actors[:5]]
        except Exception:
            pass

        return context

    # ── Prompt builders ───────────────────────────────────────────────────────

    def _analysis_prompt(self, finding: dict, context: dict) -> str:
        sev   = finding.get("severity", "unknown")
        title = _wrap_untrusted(finding.get("title", "Untitled Finding"), 300)
        cat   = finding.get("category", "unknown")
        desc  = _wrap_untrusted(finding.get("description", ""), 800)
        evid  = finding.get("evidence", {})
        cves  = finding.get("cve_ids", [])
        mitre = finding.get("mitre_technique", "")
        score = finding.get("composite_score", 0)
        kev   = finding.get("kev", False) or context.get("kev_match", False)
        epss  = context.get("epss", {})
        news  = context.get("news_items", [])
        actors = context.get("actors", [])

        return f"""You are an expert security analyst. Analyze this endpoint security finding and provide a structured JSON response.

FINDING:
- Title: {title}
- Severity: {sev}
- Category: {cat}
- Composite Risk Score: {score}/10
- CVE IDs: {json.dumps(cves)}
- MITRE Technique: {mitre}
- Description: {desc}
- Evidence: {_wrap_untrusted(json.dumps(evid, default=str), 800)}
- CISA KEV (active exploit): {kev}
- EPSS Score: {epss.get('epss', 'N/A') if epss else 'N/A'} (exploit probability)

THREAT INTEL CONTEXT:
- Recent related news: {json.dumps([n['title'] for n in news[:3]])}
- Active ransomware groups (last 30 days): {json.dumps([a['name'] for a in actors[:5]])}

Respond ONLY with valid JSON in this exact structure:
{{
  "analysis": "2-3 sentence expert security analysis of what this finding means and its real-world impact",
  "threat_context": "1-2 sentence assessment of current threat landscape relevance (active exploitation, ransomware relevance, etc.)",
  "risk_factors": ["specific risk factor 1", "specific risk factor 2", "specific risk factor 3"],
  "confidence": 0.85,
  "urgency": "immediate|urgent|scheduled|informational"
}}"""

    def _remediation_prompt(self, finding: dict, os_type: str) -> str:
        title  = _wrap_untrusted(finding.get("title", "Untitled Finding"), 300)
        sev    = finding.get("severity", "unknown")
        cat    = finding.get("category", "unknown")
        desc   = _wrap_untrusted(finding.get("description", ""), 800)
        evid   = finding.get("evidence", {})
        cves   = finding.get("cve_ids", [])
        mitre  = finding.get("mitre_technique", "")
        rec    = _wrap_untrusted(finding.get("recommendation", ""), 400)
        kev    = finding.get("kev", False)
        os_map = {"macos": "macOS", "windows": "Windows", "linux": "Linux"}
        os_label = os_map.get(os_type, os_type)

        return f"""You are an expert security engineer. Generate a detailed, actionable remediation plan for this security finding on {os_label}.

FINDING:
- Title: {title}
- Severity: {sev}
- Category: {cat}
- Description: {desc}
- Evidence: {_wrap_untrusted(json.dumps(evid, default=str), 600)}
- CVE IDs: {json.dumps(cves)}
- MITRE Technique: {mitre}
- CISA KEV (active exploitation): {kev}
- Existing recommendation: {rec}

Generate a complete remediation plan. Respond ONLY with valid JSON:
{{
  "summary": "One sentence describing the remediation approach",
  "effort": "low|medium|high",
  "remediation_risk": "low|medium|high",
  "steps": [
    {{
      "step": 1,
      "title": "Step title",
      "description": "What to do and why",
      "command": "exact shell command for {os_label} or null",
      "verification": "How to verify this step succeeded",
      "risk": "Any risk from performing this step"
    }}
  ],
  "verification": [
    "Final verification step 1",
    "Final verification step 2"
  ],
  "long_term_recommendations": [
    "Strategic improvement 1",
    "Strategic improvement 2"
  ],
  "compensating_controls": "What to do if immediate remediation is not possible"
}}

Be specific with actual {os_label} commands. For macOS use Terminal commands (defaults, launchctl, security, etc.). Include verification steps after each remediation action."""

    def _prioritization_prompt(self, findings: list[dict]) -> str:
        items = []
        for f in findings:
            items.append({
                "item_key":       f.get("item_key", ""),
                "title":          f.get("title", ""),
                "severity":       f.get("severity", ""),
                "composite_score": f.get("composite_score", 0),
                "kev":            f.get("kev", False),
                "epss":           f.get("epss_score", 0),
                "category":       f.get("category", ""),
                "cve_ids":        f.get("cve_ids", []),
            })

        return f"""You are a CISO prioritizing security findings for remediation. Given these findings, rank them by true business risk (not just CVSS score). Consider: active exploitation (KEV), exploitability (EPSS), attack chain potential, and operational impact.

FINDINGS:
{_wrap_untrusted(json.dumps(items, indent=2), 20000)}

Respond ONLY with valid JSON:
{{
  "prioritized": [
    {{
      "item_key": "exact item_key from input",
      "priority_rank": 1,
      "reason": "Brief reason for this priority rank (max 20 words)"
    }}
  ],
  "summary": "One sentence CISO-level summary of the overall risk posture"
}}

Rank all {len(findings)} findings. Priority 1 = highest risk, address immediately."""

    # ── Claude API call ───────────────────────────────────────────────────────

    async def _call_claude(self, prompt: str, max_tokens: int = 1500) -> dict:
        """Single call choke point for both credential paths.

        ANTHROPIC_API_KEY keeps its original direct-SDK behaviour so existing
        deployments are unaffected. Otherwise the call goes through the shared
        provider abstraction, which is what makes the encrypted store (and every
        non-Anthropic provider, including Claude via OpenRouter) work here.
        """
        if self._client is not None:
            message = await self._client.messages.create(
                model=_MODEL,
                max_tokens=max_tokens,
                # Same hardened system prompt as the provider abstraction, so
                # the injection guard does not depend on which credential path
                # happens to be configured.
                system=SYSTEM_PROMPT,
                messages=[{"role": "user", "content": prompt}],
            )
            content = message.content[0].text if message.content else "{}"
            return {
                "text":        content,
                "tokens_used": message.usage.input_tokens + message.usage.output_tokens,
                "model":       _MODEL,
            }

        provider = self._store_provider()
        if provider is None:
            raise RuntimeError(
                "No AI provider configured. Set it in Settings -> AI Provider, "
                "or POST /api/v1/ai/provider."
            )
        resp = await provider.chat(prompt, max_tokens=max_tokens)
        return {
            "text":        resp.text,
            "tokens_used": resp.total_tokens,
            "model":       resp.model,
        }

    def _parse_json_response(self, result: dict) -> dict:
        """Parse the model's JSON, raising when it is unusable.

        Delegates to the shared strict parser so this path gets the same
        balanced-brace extraction as the ai/ package. It used to return {} on
        failure, which the callers below then turned into a fully-default
        record and wrote to the cache — a blank analysis that reads as "the
        model had nothing to say" and is never retried because it is cached.
        Raising instead lets the existing handlers log the failure and skip the
        write.
        """
        from .ai.base import AIProvider
        return AIProvider.parse_json_strict(result.get("text", ""))
