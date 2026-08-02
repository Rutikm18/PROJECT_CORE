"""Manager responsibilities can be split without ambiguous process behavior."""
from __future__ import annotations

import pytest

from manager.manager.server import _parse_manager_roles


def test_roles_default_to_single_process_compatibility():
    assert _parse_manager_roles(None) == frozenset({
        "api", "telemetry", "detection", "maintenance", "intel",
    })


def test_roles_are_normalized_and_deduplicated():
    assert _parse_manager_roles(" API, detection,api ") == frozenset({
        "api", "detection",
    })


@pytest.mark.parametrize("raw", ["unknown", "api,worker", ",,,"])
def test_invalid_roles_fail_fast(raw):
    with pytest.raises(ValueError):
        _parse_manager_roles(raw)
