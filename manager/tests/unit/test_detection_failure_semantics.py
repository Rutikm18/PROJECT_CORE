"""Required detector failures must leave payloads pending, never completed."""
from __future__ import annotations

import asyncio

import pytest

from manager.manager.attacklens import engine as engine_module
from manager.manager.attacklens import rulepack as rulepack_module
from manager.manager.attacklens.behavioral import BehavioralAnalyzer
from manager.manager.attacklens.engine import AttackLensEngine, _DeferredDetectionState
from manager.manager.attacklens.rulepack import RulePackDetector, RulePackRule
from manager.manager.attacklens.signals import Signal


def _run(coro):
    return asyncio.run(coro)


class _EmptyRulepack:
    async def analyze(self, *_args):
        return []


def test_rich_module_exception_fails_the_dispatch(monkeypatch):
    async def broken(*_args):
        raise RuntimeError("detector offline")

    eng = object.__new__(AttackLensEngine)
    eng._idb = object()
    eng._feeds = None
    eng._rulepack = _EmptyRulepack()
    monkeypatch.setitem(engine_module._DETECTION_MODULE_ROUTES, "sca", [broken])
    monkeypatch.setitem(engine_module.ENGINE_CONFIG, "use_detection_modules", True)

    with pytest.raises(RuntimeError, match="detector path"):
        _run(eng._dispatch("agent-1", "sca", {"policies": []}))


def test_rulepack_evaluator_exception_fails_the_payload(monkeypatch):
    rule = RulePackRule(
        id="TEST-FAIL", section="metrics", title="test", description="",
        severity="medium", mitre_attack=[], detection={}, false_positives=[],
        enrichment_sources=[], response_actions=[], status="test", source_file="test",
    )
    detector = RulePackDetector({"metrics": [rule]})

    def broken(*_args):
        raise ValueError("bad evaluator")

    monkeypatch.setitem(rulepack_module._RULE_EVALUATORS, "TEST-FAIL", broken)
    with pytest.raises(rulepack_module.RulePackEvaluationError, match="TEST-FAIL"):
        _run(detector.analyze("agent-1", "metrics", {"cpu_pct": 1}))


def test_behavioral_db_exception_is_not_converted_to_no_findings():
    class BrokenDB:
        async def get_baseline(self, *_args):
            raise RuntimeError("baseline unavailable")

    analyzer = BehavioralAnalyzer(BrokenDB())
    with pytest.raises(RuntimeError, match="baseline unavailable"):
        _run(analyzer.analyze("agent-1", "metrics", {"cpu_pct": 1}))


def test_signal_persistence_failure_does_not_mark_ledger_processed():
    class BrokenIntelDB:
        async def get_baseline(self, *_args):
            return None

        async def upsert_baseline(self, *_args):
            return None

        async def upsert_signal(self, _signal):
            raise RuntimeError("signal database unavailable")

    class LedgerDB:
        def __init__(self):
            self.processed = []

        async def ledger_processed(self, *args, **kwargs):
            self.processed.append((args, kwargs))

    class Behavior:
        async def analyze(self, *_args):
            return []

        async def analyze_as_signals(self, *_args, **_kwargs):
            return []

    eng = object.__new__(AttackLensEngine)
    eng._source_coverage = {"metrics": ("inline",)}
    eng._ready = True
    eng._idb = BrokenIntelDB()
    eng._db = LedgerDB()
    eng._behav = Behavior()

    async def dispatch(*_args, **_kwargs):
        return []

    async def to_signals(*_args, **_kwargs):
        return [Signal(
            rule_id="test", layer="behavior", data_point="metrics",
            entity_key="metric:test", agent_id="agent-1",
            severity_hint="medium", evidence={}, weight=0.5, strength=0.5,
        )]

    eng._dispatch = dispatch
    eng._dispatch_to_signals = to_signals

    with pytest.raises(RuntimeError, match="signal database unavailable"):
        _run(eng.process("agent-1", "metrics", {"cpu_pct": 1}, collected_at=1000))
    assert eng._db.processed == []


def test_detector_state_is_not_written_before_explicit_commit():
    class StateDB:
        def __init__(self):
            self.entity = {}
            self.baselines = {}

        async def get_entity_state(self, agent, category, key):
            return self.entity.get((agent, category, key))

        async def set_entity_state(self, agent, category, key, fingerprint, ts):
            self.entity[(agent, category, key)] = {
                "fingerprint": fingerprint, "seen_at": ts,
            }

        async def get_baseline(self, agent, metric):
            return self.baselines.get((agent, metric))

        async def upsert_baseline(self, agent, metric, data):
            self.baselines[(agent, metric)] = dict(data)

    db = StateDB()
    state = _DeferredDetectionState(db)

    async def exercise():
        await state.set_entity_state("a", "hardware", "base", "new", 10)
        await state.upsert_baseline("a", "cpu", {"sample_count": 2})
        assert (await state.get_entity_state("a", "hardware", "base"))["fingerprint"] == "new"
        assert (await state.get_baseline("a", "cpu"))["sample_count"] == 2
        assert db.entity == {}
        assert db.baselines == {}
        await state.commit()

    _run(exercise())
    assert db.entity[("a", "hardware", "base")]["fingerprint"] == "new"
    assert db.baselines[("a", "cpu")]["sample_count"] == 2


def test_required_correlation_failure_propagates_for_queue_retry():
    class BrokenCorrelation:
        async def correlate(self, _agent_id):
            raise RuntimeError("correlation database unavailable")

    class EmptyCustom:
        async def correlate(self, _agent_id):
            return []

    eng = object.__new__(AttackLensEngine)
    eng._corr = BrokenCorrelation()
    eng._custom_corr = EmptyCustom()
    eng._idb = object()

    with pytest.raises(RuntimeError, match="correlation path"):
        _run(eng.run_correlations("agent-1"))
