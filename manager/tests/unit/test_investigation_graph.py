from __future__ import annotations

import json
import time

import pytest
from langgraph.checkpoint.memory import InMemorySaver

from manager.manager.ai.base import AIResponse
from manager.manager.ai.investigation_graph import InvestigationService
from manager.manager.indexer import IntelDB


class FakeProvider:
    async def chat(self, prompt: str, *, max_tokens: int = 1500) -> AIResponse:
        if "Generate at most" in prompt:
            payload = {
                "hypotheses": [
                    {
                        "statement": f"bounded hypothesis {index}",
                        "supporting_ids": ["E-FINDING", "NOT-A-RECORD"],
                        "contradicting_ids": [],
                        "confidence": 0.75,
                        "status": "supported",
                    }
                    for index in range(7)
                ]
            }
        else:
            payload = {
                "verdict": "likely",
                "confidence": 0.8,
                "summary": "The persisted evidence supports analyst review.",
                "evidence_ids": ["E-FINDING", "MADE-UP"],
                "gaps": ["Endpoint process ancestry is unavailable."],
            }
        return AIResponse(text=json.dumps(payload), model="fake", provider="fake")

    @staticmethod
    def parse_json(text: str) -> dict:
        return json.loads(text)


class MalformedProvider(FakeProvider):
    async def chat(self, prompt: str, *, max_tokens: int = 1500) -> AIResponse:
        if "Generate at most" in prompt:
            text = '{"hypotheses": "not-an-array"}'
        else:
            text = json.dumps({
                "verdict": "likely",
                "confidence": "high",
                "summary": "wrong confidence type",
                "evidence_ids": "E-FINDING",
                "gaps": [],
            })
        return AIResponse(
            text=text,
            model="malformed-model",
            provider="malformed-provider",
            input_tokens=11,
            output_tokens=3,
            latency_ms=12.5,
        )


class FailingProvider(FakeProvider):
    async def chat(self, prompt: str, *, max_tokens: int = 1500) -> AIResponse:
        raise RuntimeError("provider unavailable")


class FakePlan:
    def to_dict(self) -> dict:
        return {"summary": "Contain and validate", "steps": [{"title": "Validate"}]}


class FakeAnalyzer:
    def __init__(self, provider) -> None:
        self._provider = provider
        self.calls = 0

    async def remediate(self, *args, **kwargs):
        self.calls += 1
        return FakePlan()


class FailingAnalyzer(FakeAnalyzer):
    async def remediate(self, *args, **kwargs):
        self.calls += 1
        raise RuntimeError("remediation provider unavailable")


class FakeIntelDB:
    def __init__(self) -> None:
        self.finding = {
            "id": 42,
            "agent_id": "agent-1",
            "agent_os": "linux",
            "severity": "critical",
            "category": "package",
            "rule_id": "vulnerable-package",
            "item_key": "openssl",
            "title": "OpenSSL vulnerability CVE-2025-12345",
            "evidence": {"cve_id": "CVE-2025-12345", "remote_ip": "203.0.113.10"},
        }
        self.runs: dict[str, dict] = {}
        self.decisions: list[dict] = []

    async def get_finding_by_id(self, finding_id: int):
        return dict(self.finding) if finding_id == 42 else None

    async def create_investigation_run(self, run_id, finding_id, thread_id):
        now = time.time()
        self.runs[run_id] = {
            "run_id": run_id,
            "finding_id": finding_id,
            "thread_id": thread_id,
            "status": "running",
            "review_payload": {},
            "result": {},
            "created_at": now,
            "updated_at": now,
        }
        return dict(self.runs[run_id])

    async def get_investigation_run(self, run_id):
        run = self.runs.get(run_id)
        return dict(run) if run else None

    async def get_latest_investigation_run(self, finding_id):
        matches = [run for run in self.runs.values() if run["finding_id"] == finding_id]
        return dict(matches[-1]) if matches else None

    async def get_open_investigation_run(self, finding_id):
        for run in reversed(list(self.runs.values())):
            if run["finding_id"] == finding_id and run["status"] in {"running", "pending_review"}:
                return dict(run)
        return None

    async def update_investigation_run(self, run_id, **changes):
        run = self.runs[run_id]
        completed = changes.pop("completed", False)
        for key, value in changes.items():
            if value is not None:
                run[key] = value
        run["updated_at"] = time.time()
        if completed:
            run["completed_at"] = time.time()
        return dict(run)

    async def record_investigation_decision(self, finding_id, run_id, decision, actor, feedback):
        self.decisions.append({
            "finding_id": finding_id, "run_id": run_id, "decision": decision,
            "actor": actor, "feedback": feedback,
        })

    async def get_finding_timeline(self, finding_id):
        return [{"action": "created", "actor": "system", "created_at": 1.0}]

    async def get_soc_findings(self, **kwargs):
        return [self.finding, {**self.finding, "id": 43, "status": "closed"}]

    async def get_correlations(self, agent_id):
        return [{"rule_id": "execution-chain", "score": 80}]

    async def get_nvd_local_by_id(self, cve_id):
        return {"cve_id": cve_id, "cvss_score": 9.8, "vuln_status": "Analyzed"}

    async def get_cve_by_id(self, cve_id):
        return None

    async def get_epss(self, cve_id):
        return {"cve_id": cve_id, "epss": 0.92}

    async def search_news_by_cve(self, cve_id):
        return []


class FakeFeeds:
    async def get_epss(self, cve_id):
        return {"cve_id": cve_id, "epss": 0.92}

    def is_kev_cve(self, cve_id):
        return True

    def is_malicious_ip(self, value):
        return True

    def get_details(self, value):
        return {"source": "test", "confidence": 90}


@pytest.fixture
async def service():
    db = FakeIntelDB()
    provider = FakeProvider()
    analyzer = FakeAnalyzer(provider)
    instance = InvestigationService(
        db,
        FakeFeeds(),
        provider=provider,
        analyzer=analyzer,
        checkpointer=InMemorySaver(),
        max_review_rounds=1,
    )
    await instance.start()
    try:
        yield instance, db, analyzer
    finally:
        await instance.stop()


@pytest.mark.asyncio
async def test_investigation_pauses_and_approval_only_drafts_remediation(service):
    graph, db, analyzer = service

    pending = await graph.start_investigation(42)

    assert pending["status"] == "pending_review"
    assert pending["review_payload"]["allowed_decisions"] == ["approve", "reject", "request_more"]
    assert len(pending["review_payload"]["hypotheses"]) == 5
    assert pending["review_payload"]["hypotheses"][0]["supporting_ids"] == ["E-FINDING"]
    assert pending["review_payload"]["verdict"]["evidence_ids"] == ["E-FINDING"]
    assert [call["stage"] for call in pending["review_payload"]["model_calls"]] == [
        "hypothesis_generation",
        "verdict_generation",
    ]
    assert {call["status"] for call in pending["review_payload"]["model_calls"]} == {
        "succeeded",
    }
    assert {call["provider"] for call in pending["review_payload"]["model_calls"]} == {
        "fake",
    }

    duplicate = await graph.start_investigation(42)
    assert duplicate["run_id"] == pending["run_id"]

    completed = await graph.resume_investigation(
        pending["run_id"], decision="approve", actor="soc@example.com", feedback="Evidence checked",
    )

    assert completed["status"] == "completed"
    # "ai_direct_sdk" was accurate when this path called the Anthropic SDK
    # directly. It now resolves through the shared provider abstraction, so
    # the audit trail must not claim a transport that is no longer used.
    assert completed["result"]["remediation"]["source"] == "ai_provider"
    assert completed["result"]["remediation"]["execution_authorized"] is False
    assert completed["result"]["analyst"]["actor"] == "soc@example.com"
    assert len(completed["result"]["model_calls"]) == 3
    assert completed["result"]["model_calls"][-1]["stage"] == "remediation_generation"
    assert analyzer.calls == 1
    assert db.decisions[0]["decision"] == "approve"


@pytest.mark.asyncio
async def test_rejection_completes_without_remediation(service):
    graph, _, analyzer = service
    pending = await graph.start_investigation(42)

    rejected = await graph.resume_investigation(
        pending["run_id"], decision="reject", actor="analyst", feedback="Known maintenance",
    )

    assert rejected["status"] == "rejected"
    assert rejected["result"]["remediation"] == {}
    assert analyzer.calls == 0


@pytest.mark.asyncio
async def test_remediation_failure_uses_deterministic_fallback_and_records_it():
    db = FakeIntelDB()
    provider = FakeProvider()
    analyzer = FailingAnalyzer(provider)
    graph = InvestigationService(
        db,
        FakeFeeds(),
        provider=provider,
        analyzer=analyzer,
        checkpointer=InMemorySaver(),
    )
    await graph.start()
    try:
        pending = await graph.start_investigation(42)
        completed = await graph.resume_investigation(
            pending["run_id"], decision="approve", actor="fallback-test",
        )
    finally:
        await graph.stop()

    assert completed["status"] == "completed"
    assert completed["result"]["remediation"]["source"] == (
        "deterministic_knowledge_base"
    )
    remediation_call = completed["result"]["model_calls"][-1]
    assert remediation_call["stage"] == "remediation_generation"
    assert remediation_call["status"] == "provider_error"
    assert remediation_call["fallback"] == "deterministic_knowledge_base"
    assert completed["result"]["remediation"]["execution_authorized"] is False


@pytest.mark.asyncio
async def test_investigation_lifecycle_emits_review_and_completion_events(service):
    graph, _, _ = service
    events: list[tuple[dict, str, dict]] = []

    async def capture(finding, event, run):
        events.append((finding, event, run))

    graph.set_lifecycle_notification_handler(capture)
    pending = await graph.start_investigation(42)
    await graph.resume_investigation(
        pending["run_id"], decision="approve", actor="soc@example.test",
    )

    assert [event for _, event, _ in events] == [
        "investigation_pending_review",
        "investigation_completed",
    ]
    assert events[0][0]["id"] == 42
    assert events[1][2]["actor"] == "soc@example.test"


@pytest.mark.asyncio
async def test_request_more_is_bounded_by_review_round_limit(service):
    graph, _, analyzer = service
    first = await graph.start_investigation(42)

    second = await graph.resume_investigation(
        first["run_id"], decision="request_more", actor="analyst", feedback="Check fleet history",
    )

    assert second["status"] == "pending_review"
    assert second["review_payload"]["review_round"] == 2
    assert second["review_payload"]["allowed_decisions"] == ["approve", "reject"]
    with pytest.raises(ValueError, match="not allowed"):
        await graph.resume_investigation(
            first["run_id"], decision="request_more", actor="analyst",
        )
    assert analyzer.calls == 0


@pytest.mark.asyncio
async def test_auto_trigger_applies_event_and_severity_gates(service, monkeypatch):
    graph, db, _ = service
    monkeypatch.setenv("LANGGRAPH_AUTO_INVESTIGATE", "true")
    monkeypatch.setenv("LANGGRAPH_AUTO_SEVERITIES", "critical,high")

    await graph.handle_finding_event({**db.finding, "severity": "medium"}, "created")
    assert not db.runs

    await graph.handle_finding_event(db.finding, "updated")
    assert not db.runs

    await graph.handle_finding_event(db.finding, "created")
    assert len(db.runs) == 1
    assert next(iter(db.runs.values()))["status"] == "pending_review"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("provider", "expected_status"),
    [
        (MalformedProvider(), "invalid_response"),
        (FailingProvider(), "provider_error"),
    ],
)
async def test_provider_failures_fall_back_and_are_auditable(provider, expected_status):
    db = FakeIntelDB()
    analyzer = FakeAnalyzer(provider)
    graph = InvestigationService(
        db,
        FakeFeeds(),
        provider=provider,
        analyzer=analyzer,
        checkpointer=InMemorySaver(),
    )
    await graph.start()
    try:
        pending = await graph.start_investigation(42)
    finally:
        await graph.stop()

    assert pending["status"] == "pending_review"
    review = pending["review_payload"]
    assert review["verdict"]["verdict"] == "inconclusive"
    assert review["verdict"]["confidence"] == 0.0
    assert len(review["errors"]) == 2
    assert [call["stage"] for call in review["model_calls"]] == [
        "hypothesis_generation",
        "verdict_generation",
    ]
    assert {call["status"] for call in review["model_calls"]} == {expected_status}
    assert all("error_type" in call for call in review["model_calls"])


@pytest.mark.asyncio
async def test_investigation_run_index_round_trips_json(pg_intel_dsn):
    db = IntelDB(pg_intel_dsn)
    await db.init()
    try:
        created = await db.create_investigation_run("run-1", 42, "thread-1")
        assert created["status"] == "running"

        updated = await db.update_investigation_run(
            "run-1",
            status="pending_review",
            current_node="analyst_review",
            review_payload={"allowed_decisions": ["approve", "reject"]},
        )
        assert updated["review_payload"]["allowed_decisions"] == ["approve", "reject"]
        assert (await db.get_open_investigation_run(42))["run_id"] == "run-1"

        completed = await db.update_investigation_run(
            "run-1", status="completed", result={"verdict": "likely"}, completed=True,
        )
        assert completed["result"] == {"verdict": "likely"}
        assert completed["completed_at"] > 0
        assert await db.get_open_investigation_run(42) is None
    finally:
        await db.close()


@pytest.mark.asyncio
async def test_postgres_checkpoint_resumes_after_service_restart(pg_intel_dsn):
    db = FakeIntelDB()
    provider = FakeProvider()
    analyzer = FakeAnalyzer(provider)

    first_service = InvestigationService(
        db, FakeFeeds(), dsn=pg_intel_dsn, provider=provider, analyzer=analyzer,
    )
    await first_service.start()
    pending = await first_service.start_investigation(42)
    await first_service.stop()

    second_service = InvestigationService(
        db, FakeFeeds(), dsn=pg_intel_dsn, provider=provider, analyzer=analyzer,
    )
    await second_service.start()
    try:
        completed = await second_service.resume_investigation(
            pending["run_id"], decision="approve", actor="restart-test",
        )
        assert completed["status"] == "completed"
        assert completed["result"]["analyst"]["actor"] == "restart-test"
        assert analyzer.calls == 1
    finally:
        await second_service.stop()
