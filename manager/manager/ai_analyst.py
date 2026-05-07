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

import json
import logging
import os
import time
from typing import Any, Optional

log = logging.getLogger("manager.ai_analyst")

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
        elif _ENABLED and not self._api_key:
            log.info("AI Analyst disabled — set ANTHROPIC_API_KEY to enable")

    @property
    def enabled(self) -> bool:
        return self._client is not None and bool(self._api_key)

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
                "model":         _MODEL,
                "analysis":      parsed.get("analysis", ""),
                "threat_context": parsed.get("threat_context", ""),
                "risk_factors":  parsed.get("risk_factors", []),
                "ioc_matches":   context.get("ioc_matches", []),
                "news_context":  context.get("news_items", []),
                "actor_context": context.get("actors", []),
                "confidence":    float(parsed.get("confidence", 0.5)),
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
                "model":        _MODEL,
                "summary":      parsed.get("summary", ""),
                "steps":        parsed.get("steps", []),
                "verification": parsed.get("verification", []),
                "long_term":    parsed.get("long_term_recommendations", []),
                "effort":       parsed.get("effort", "medium"),
                "risk_level":   parsed.get("remediation_risk", "low"),
            }
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
        title = finding.get("title", "Untitled Finding")
        cat   = finding.get("category", "unknown")
        desc  = finding.get("description", "")
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
- Evidence: {json.dumps(evid, default=str)[:800]}
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
        title  = finding.get("title", "Untitled Finding")
        sev    = finding.get("severity", "unknown")
        cat    = finding.get("category", "unknown")
        desc   = finding.get("description", "")
        evid   = finding.get("evidence", {})
        cves   = finding.get("cve_ids", [])
        mitre  = finding.get("mitre_technique", "")
        rec    = finding.get("recommendation", "")
        kev    = finding.get("kev", False)
        os_map = {"macos": "macOS", "windows": "Windows", "linux": "Linux"}
        os_label = os_map.get(os_type, os_type)

        return f"""You are an expert security engineer. Generate a detailed, actionable remediation plan for this security finding on {os_label}.

FINDING:
- Title: {title}
- Severity: {sev}
- Category: {cat}
- Description: {desc}
- Evidence: {json.dumps(evid, default=str)[:600]}
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
{json.dumps(items, indent=2)}

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
        import anthropic
        message = await self._client.messages.create(
            model=_MODEL,
            max_tokens=max_tokens,
            system="You are an expert cybersecurity analyst. Always respond with valid JSON only — no markdown, no explanation outside the JSON.",
            messages=[{"role": "user", "content": prompt}],
        )
        content = message.content[0].text if message.content else "{}"
        return {
            "text":        content,
            "tokens_used": message.usage.input_tokens + message.usage.output_tokens,
        }

    def _parse_json_response(self, result: dict) -> dict:
        text = result.get("text", "{}")
        # Strip markdown code fences if present
        text = text.strip()
        if text.startswith("```"):
            text = text.split("```")[1]
            if text.startswith("json"):
                text = text[4:]
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            # Try to extract JSON object from text
            start = text.find("{")
            end   = text.rfind("}") + 1
            if start >= 0 and end > start:
                try:
                    return json.loads(text[start:end])
                except json.JSONDecodeError:
                    pass
        return {}


# asyncio import needed for enrich_findings_batch
import asyncio
