from manager.manager.attacklens.validation_error_policy import decide_validation_error


def test_terrain_engine_failure_is_fail_closed() -> None:
    decision = decide_validation_error("terrain", "critical", "evaluation_error")

    assert decision.state == "error"
    assert decision.action == "fail_closed"


def test_model_failure_requires_review_for_high_impact_finding() -> None:
    decision = decide_validation_error("model", "high", "llm_timeout")

    assert decision.state == "needs_review"
    assert decision.action == "degrade_to_review"


def test_authoritative_evidence_survives_model_failure() -> None:
    decision = decide_validation_error(
        "model", "critical", "llm_timeout", authoritative_evidence=True,
    )

    assert decision.state == "continue"
    assert decision.action == "deterministic_continue"


def test_corroborator_outage_does_not_turn_absence_into_negative_evidence() -> None:
    decision = decide_validation_error("corroboration", "medium", "nvd_unavailable")

    assert decision.state == "continue"
    assert decision.action == "inconclusive_continue"


def test_unknown_validation_stage_defaults_to_review() -> None:
    decision = decide_validation_error("new_stage", "low", "unknown")

    assert decision.state == "needs_review"
    assert decision.action == "degrade_to_review"
