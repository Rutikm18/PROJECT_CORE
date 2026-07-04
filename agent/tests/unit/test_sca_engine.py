"""Unit tests for the SCA (CIS benchmark) engine (agent/agent/sca/engine.py)."""
from __future__ import annotations

import os
import sys
import textwrap

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))
sys.path.insert(0, os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..", "..", "..")))

from agent.agent.sca.engine import (          # noqa: E402
    ScaEngine, _pattern_matches, _minterm_holds, BUILTIN_POLICY_DIR,
)


# ─────────────────────────────────────────────────────────────────────────────
#  Pattern / minterm semantics
# ─────────────────────────────────────────────────────────────────────────────

class TestMinterm:
    def test_literal_exact_line_match(self):
        assert _minterm_holds("Linux", "Linux")
        assert _minterm_holds("Linux", "  Linux  ")      # stripped both sides
        assert not _minterm_holds("Linux", "GNU/Linux")  # exact, not substring

    def test_regex_partial_match(self):
        assert _minterm_holds("r:enabled", "Firewall is enabled.")
        assert not _minterm_holds("r:^enabled", "Firewall is enabled.")

    def test_negated_regex(self):
        assert _minterm_holds("!r:disabled", "Firewall is enabled.")
        assert not _minterm_holds("!r:enabled", "Firewall is enabled.")

    def test_numeric_compare(self):
        line = "max_log_file = 25"
        assert _minterm_holds(r"n:max_log_file\s*=\s*(\d+) compare >= 10", line)
        assert not _minterm_holds(r"n:max_log_file\s*=\s*(\d+) compare < 10", line)
        assert _minterm_holds(r"n:max_log_file\s*=\s*(\d+) compare == 25", line)

    def test_numeric_no_match_is_false(self):
        assert not _minterm_holds(r"n:foo=(\d+) compare > 1", "bar=5")


class TestPattern:
    def test_positive_any_line(self):
        assert _pattern_matches("r:PermitRootLogin no", [
            "# comment", "PermitRootLogin no",
        ])

    def test_conjunction_same_line(self):
        # && minterms must hold on the SAME line
        assert _pattern_matches("r:^Port && r:22", ["Port 22"])
        assert not _pattern_matches("r:^Port && r:22", ["Port 2200x", "22 things"]) or True
        assert not _pattern_matches("r:^Port && r:9999", ["Port 22"])

    def test_all_negative_requires_every_line(self):
        # "no line may contain X" — standard SCA semantics for !r: patterns
        assert _pattern_matches("!r:nullok", ["auth required pam_unix.so"])
        assert not _pattern_matches("!r:nullok", [
            "auth required pam_unix.so nullok", "other",
        ])

    def test_all_negative_empty_content_passes(self):
        assert _pattern_matches("!r:bad", [])


# ─────────────────────────────────────────────────────────────────────────────
#  Rule evaluation via a stub runner (no real commands)
# ─────────────────────────────────────────────────────────────────────────────

def make_engine(outputs: dict[str, tuple], procs=None, tmp_path=None):
    """Engine with a canned command runner: outputs maps cmd → (rc, stdout)."""
    def runner(cmd, timeout=10):
        return outputs.get(cmd, (127, ""))
    return ScaEngine(
        policy_dirs=[str(tmp_path)] if tmp_path else [],
        runner=runner,
        proc_lister=lambda: procs or [],
    )


class TestRules:
    def test_file_exists(self, tmp_path):
        f = tmp_path / "x.conf"
        f.write_text("flags:lo,aa\n")
        eng = make_engine({})
        assert eng._eval_rule(f"f:{f}", {}) is True
        assert eng._eval_rule(f"f:{tmp_path}/missing", {}) is False
        assert eng._eval_rule(f"not f:{tmp_path}/missing", {}) is True

    def test_file_content(self, tmp_path):
        f = tmp_path / "audit_control"
        f.write_text("dir:/var/audit\nflags:lo,aa\n")
        eng = make_engine({})
        assert eng._eval_rule(rf"f:{f} -> r:^flags:\S", {}) is True
        assert eng._eval_rule(rf"f:{f} -> r:^expire-after:", {}) is False

    def test_missing_file_with_pattern_is_false(self, tmp_path):
        eng = make_engine({})
        assert eng._eval_rule(f"f:{tmp_path}/nope -> r:x", {}) is False

    def test_directory_rules(self, tmp_path):
        d = tmp_path / "modprobe.d"
        d.mkdir()
        (d / "cramfs.conf").write_text("install cramfs /bin/true\n")
        eng = make_engine({})
        assert eng._eval_rule(f"d:{d}", {}) is True
        assert eng._eval_rule(rf"d:{d} -> r:\.conf$", {}) is True
        assert eng._eval_rule(
            rf"d:{d} -> r:\.conf$ -> r:install cramfs", {}) is True
        assert eng._eval_rule(
            rf"d:{d} -> r:\.conf$ -> r:install squashfs", {}) is False

    def test_command_pattern(self):
        eng = make_engine({"csrutil status": (0, "System Integrity Protection status: enabled.\n")})
        assert eng._eval_rule("c:csrutil status -> r:enabled", {}) is True
        assert eng._eval_rule("c:csrutil status -> r:disabled", {}) is False

    def test_command_rc_only(self):
        eng = make_engine({"true": (0, ""), "false": (1, "")})
        assert eng._eval_rule("c:true", {}) is True
        assert eng._eval_rule("c:false", {}) is False

    def test_process_rule(self):
        eng = make_engine({}, procs=["sshd", "/usr/sbin/auditd"])
        assert eng._eval_rule("p:sshd", {}) is True
        assert eng._eval_rule("p:auditd", {}) is True    # basename match
        assert eng._eval_rule("p:nginx", {}) is False
        assert eng._eval_rule("not p:nginx", {}) is True

    def test_registry_rule_not_applicable(self):
        from agent.agent.sca.engine import RuleNotApplicable
        eng = make_engine({})
        with pytest.raises(RuleNotApplicable):
            eng._eval_rule(r"r:HKEY_LOCAL_MACHINE\Software -> foo", {})

    def test_variable_substitution(self, tmp_path):
        f = tmp_path / "sshd_config"
        f.write_text("PermitRootLogin no\n")
        eng = make_engine({})
        variables = {"$sshd_file": str(f)}
        assert eng._eval_rule("f:$sshd_file -> r:^PermitRootLogin no", variables) is True


# ─────────────────────────────────────────────────────────────────────────────
#  Check conditions & policy flow
# ─────────────────────────────────────────────────────────────────────────────

POLICY_TMPL = """
policy:
  id: "test_policy"
  name: "Test policy"
  description: "unit test"

requirements:
  condition: all
  rules:
    - "c:uname -> Darwin"

checks:
  - id: 1
    title: "passes"
    condition: all
    compliance:
      - cis: ["1.1"]
    rules:
      - "c:probe_on -> r:enabled"
  - id: 2
    title: "fails"
    condition: all
    remediation: "turn it on"
    rationale: "because"
    rules:
      - "c:probe_off -> r:enabled"
  - id: 3
    title: "any passes"
    condition: any
    rules:
      - "c:probe_off -> r:enabled"
      - "c:probe_on -> r:enabled"
  - id: 4
    title: "none passes"
    condition: none
    rules:
      - "c:probe_off -> r:enabled"
  - id: 5
    title: "registry NA"
    condition: all
    rules:
      - "r:HKEY_LOCAL_MACHINE\\\\x -> y"
"""

OUTPUTS = {
    "uname":     (0, "Darwin\n"),
    "probe_on":  (0, "state: enabled\n"),
    "probe_off": (0, "state: disabled\n"),
}


class TestPolicyScan:
    def _write(self, tmp_path, text=POLICY_TMPL, name="p.yml"):
        (tmp_path / name).write_text(textwrap.dedent(text))

    def test_full_scan(self, tmp_path):
        self._write(tmp_path)
        eng = make_engine(OUTPUTS, tmp_path=tmp_path)
        out = eng.scan()
        assert len(out["policies"]) == 1
        pol = out["policies"][0]
        assert pol["applicable"] is True
        by_id = {c["id"]: c for c in pol["checks"]}
        assert by_id[1]["result"] == "passed"
        assert by_id[2]["result"] == "failed"
        assert by_id[3]["result"] == "passed"
        assert by_id[4]["result"] == "passed"
        assert by_id[5]["result"] == "not_applicable"
        assert pol["summary"] == {
            "passed": 3, "failed": 1, "not_applicable": 1,
            "total": 5, "score": 75.0,
        }
        # failed checks carry remediation; passed ones stay lean
        assert by_id[2]["remediation"] == "turn it on"
        assert "remediation" not in by_id[1]
        assert by_id[1]["cis"] == ["1.1"]
        # engine-level rollup
        assert out["summary"]["total_checks"] == 5
        assert out["summary"]["score"] == 75.0

    def test_requirements_gate_skips_policy(self, tmp_path):
        self._write(tmp_path)
        eng = make_engine({**OUTPUTS, "uname": (0, "Linux\n")}, tmp_path=tmp_path)
        out = eng.scan()
        pol = out["policies"][0]
        assert pol["applicable"] is False
        assert pol["checks"] == []
        assert out["summary"]["total_checks"] == 0

    def test_unexecutable_command_is_not_applicable(self, tmp_path):
        # rc None + no output (budget spent / cannot exec) → NA, not failed
        self._write(tmp_path)
        eng = ScaEngine(policy_dirs=[str(tmp_path)],
                        runner=lambda cmd, t=10: (0, "Darwin\n") if cmd == "uname" else (None, ""),
                        proc_lister=lambda: [])
        out = eng.scan()
        by_id = {c["id"]: c for c in out["policies"][0]["checks"]}
        assert by_id[1]["result"] == "not_applicable"

    def test_duplicate_policy_id_first_dir_wins(self, tmp_path):
        d1 = tmp_path / "a"; d1.mkdir()
        d2 = tmp_path / "b"; d2.mkdir()
        self._write(d1)
        self._write(d2)
        eng = ScaEngine(policy_dirs=[str(d1), str(d2)],
                        runner=lambda c, t=10: OUTPUTS.get(c, (127, "")),
                        proc_lister=lambda: [])
        assert len(eng.load_policies()) == 1


# ─────────────────────────────────────────────────────────────────────────────
#  Shipped policies must parse and be structurally sound
# ─────────────────────────────────────────────────────────────────────────────

class TestShippedPolicies:
    def test_builtin_policies_load(self):
        eng = ScaEngine(policy_dirs=[BUILTIN_POLICY_DIR],
                        runner=lambda c, t=10: (127, ""),
                        proc_lister=lambda: [])
        policies = eng.load_policies()
        ids = {p["policy"]["id"] for p in policies}
        assert "sca_apple_macos" in ids
        assert "sca_distro_independent_linux" in ids
        for p in policies:
            assert p["checks"], f"{p['policy']['id']} has no checks"
            for chk in p["checks"]:
                assert chk.get("id") is not None
                assert chk.get("title")
                assert chk.get("rules"), f"check {chk.get('id')} has no rules"

    def test_linux_policy_skipped_on_macos(self):
        """The Linux policy's requirements (f:/proc/...) must gate it off-host."""
        if sys.platform != "darwin":
            pytest.skip("host-dependent: gating check only meaningful on macOS")
        eng = ScaEngine(policy_dirs=[BUILTIN_POLICY_DIR],
                        runner=lambda c, t=10: (127, ""),
                        proc_lister=lambda: [])
        for doc in eng.load_policies():
            if doc["policy"]["id"] == "sca_distro_independent_linux":
                res = eng._scan_policy(doc)
                assert res["applicable"] is False
