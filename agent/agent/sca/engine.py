"""
agent/agent/sca/engine.py — Security Configuration Assessment (SCA) engine.

Evaluates SCA policy files (CIS benchmarks) against the local host and
produces per-check pass/fail results with compliance mappings. The policy
schema follows the de-facto industry format for SCA policies, so existing
public CIS policy files run unmodified.

Policy format (YAML):

    policy:        {id, name, description, references}
    requirements:  {condition, rules}     — host-applicability gate
    variables:     {"$var": "value"}      — substituted into rule strings
    checks:        [{id, title, condition, rules, compliance, ...}]

Rule grammar (one string per rule):

    ["not "] TYPE ":" BODY
      f:/path                      file exists
      f:/path -> PATTERN           any line of the file satisfies PATTERN
      d:/dir                       directory exists
      d:/dir -> FPAT               dir contains a file matching FPAT
      d:/dir -> FPAT -> PATTERN    ...whose content satisfies PATTERN
      c:command                    command exits 0
      c:command -> PATTERN         any output line satisfies PATTERN
      p:name                       process with that name is running
      r:HKEY...                    Windows registry — not applicable on POSIX

    PATTERN := MINTERM (" && " MINTERM)*
    MINTERM := ["!"] ( "r:" regex                      partial regex match
                     | "n:" regex " compare " OP NUM   numeric capture compare
                     | literal )                       exact line match

A line satisfies a PATTERN when every minterm holds for that line ("!" inverts
one minterm). A rule with at least one positive minterm passes if ANY line
satisfies; a rule whose minterms are ALL negative passes only if EVERY line
does (i.e. no line matches the forbidden form) — the standard SCA semantics
for "ensure no line has X" rules.

Check result: passed / failed / not_applicable (rule type unusable on this OS,
or evaluation could not run — e.g. section budget exhausted).

The engine is OS-agnostic: command execution is delegated to an injectable
`runner(cmd: str, timeout: float) -> (returncode | None, stdout: str)` so each
platform's collector supplies its own budget/timeout policy. Policies are
root-owned files shipped inside the agent's source tree (same trust domain as
the agent code itself); `c:` rules therefore execute with the agent's
privileges by design.
"""
from __future__ import annotations

import logging
import os
import re
import subprocess
import sys

log = logging.getLogger(__name__)

try:
    import yaml
    _HAVE_YAML = True
except ImportError:          # policies can still ship as .json
    _HAVE_YAML = False

# Built-in policies live next to this file; a drop-in dir lets operators add
# custom policies on a host without rebuilding the agent.
BUILTIN_POLICY_DIR = os.path.join(os.path.dirname(__file__), "policies")
CUSTOM_POLICY_DIRS = (
    "/Library/AttackLens/sca",          # macOS
    "/etc/attacklens/sca",              # linux
)

_CMD_TIMEOUT_SEC = 10        # per c: rule command
_FILE_READ_LIMIT = 1 << 20   # 1 MiB cap per f:/d: content read
_TEXT_TRUNC      = 400       # rationale/remediation cap in the payload

_NUM_COMPARE_RE = re.compile(r"^n:(?P<rx>.+?)\s+compare\s+(?P<op>[<>=!]+)\s*(?P<val>-?\d+)\s*$")

_OPS = {
    "<":  lambda a, b: a < b,
    "<=": lambda a, b: a <= b,
    "==": lambda a, b: a == b,
    "=":  lambda a, b: a == b,
    ">":  lambda a, b: a > b,
    ">=": lambda a, b: a >= b,
    "!=": lambda a, b: a != b,
}


class RuleNotApplicable(Exception):
    """Rule type cannot be evaluated on this host (e.g. registry on POSIX)."""


def _default_runner(cmd: str, timeout: float = _CMD_TIMEOUT_SEC):
    """Run a `c:` rule command through the shell. Returns (rc, stdout).
    rc is None when the command could not be executed at all."""
    try:
        p = subprocess.run(
            ["/bin/sh", "-c", cmd],
            capture_output=True, text=True, errors="replace", timeout=timeout,
        )
        return p.returncode, p.stdout
    except subprocess.TimeoutExpired:
        log.warning("SCA command timed out after %.0fs: %s", timeout, cmd)
        return None, ""
    except Exception as exc:
        log.debug("SCA command failed [%s]: %s", cmd, exc)
        return None, ""


def _default_proc_lister() -> list[str]:
    """Names of running processes (comm) — used by p: rules."""
    rc, out = _default_runner("ps -axo comm=")
    if rc != 0:
        return []
    return [os.path.basename(l.strip()) for l in out.splitlines() if l.strip()]


# ─────────────────────────────────────────────────────────────────────────────
#  Pattern evaluation
# ─────────────────────────────────────────────────────────────────────────────

def _minterm_holds(minterm: str, line: str) -> bool:
    negate = minterm.startswith("!")
    if negate:
        minterm = minterm[1:]

    if minterm.startswith("r:"):
        hit = re.search(minterm[2:], line) is not None
    elif minterm.startswith("n:"):
        m = _NUM_COMPARE_RE.match(minterm)
        if not m:
            hit = False
        else:
            g = re.search(m.group("rx"), line)
            if g and g.groups():
                try:
                    hit = _OPS.get(m.group("op"), lambda a, b: False)(
                        int(g.group(1)), int(m.group("val")))
                except (ValueError, IndexError):
                    hit = False
            else:
                hit = False
    else:
        hit = line.strip() == minterm.strip()

    return (not hit) if negate else hit


def _split_minterms(pattern: str) -> list[str]:
    return [p.strip() for p in pattern.split(" && ") if p.strip()]


def _pattern_matches(pattern: str, lines: list[str]) -> bool:
    minterms = _split_minterms(pattern)
    if not minterms:
        return False
    all_negative = all(m.startswith("!") for m in minterms)
    if all_negative:
        # "no line may match the forbidden form(s)" — vacuously true when empty
        return all(all(_minterm_holds(m, l) for m in minterms) for l in lines)
    return any(all(_minterm_holds(m, l) for m in minterms) for l in lines)


def _read_lines(path: str) -> list[str] | None:
    try:
        with open(path, errors="replace") as f:
            return f.read(_FILE_READ_LIMIT).splitlines()
    except OSError:
        return None


# ─────────────────────────────────────────────────────────────────────────────
#  Engine
# ─────────────────────────────────────────────────────────────────────────────

class ScaEngine:
    def __init__(self, policy_dirs: list[str] | None = None,
                 runner=None, proc_lister=None):
        if policy_dirs is None:
            policy_dirs = [BUILTIN_POLICY_DIR] + [
                d for d in CUSTOM_POLICY_DIRS if os.path.isdir(d)
            ]
        self.policy_dirs = policy_dirs
        self.runner = runner or _default_runner
        self.proc_lister = proc_lister or _default_proc_lister
        self._procs: list[str] | None = None   # lazy, once per scan

    # ── policy loading ───────────────────────────────────────────────────────

    def load_policies(self) -> list[dict]:
        policies: list[dict] = []
        seen_ids: set[str] = set()
        for d in self.policy_dirs:
            try:
                names = sorted(os.listdir(d))
            except OSError:
                continue
            for name in names:
                if not name.endswith((".yml", ".yaml", ".json")):
                    continue
                path = os.path.join(d, name)
                doc = self._load_policy_file(path)
                if not doc or "policy" not in doc or "checks" not in doc:
                    continue
                pid = str(doc["policy"].get("id") or name)
                if pid in seen_ids:      # custom dir overrides builtin
                    continue
                seen_ids.add(pid)
                doc["_path"] = path
                policies.append(doc)
        return policies

    @staticmethod
    def _load_policy_file(path: str) -> dict | None:
        try:
            with open(path, errors="replace") as f:
                text = f.read()
        except OSError as exc:
            log.warning("SCA policy unreadable %s: %s", path, exc)
            return None
        try:
            if path.endswith(".json"):
                import json
                return json.loads(text)
            if not _HAVE_YAML:
                log.warning("SCA: PyYAML unavailable — skipping %s", path)
                return None
            return yaml.safe_load(text)
        except Exception as exc:
            log.warning("SCA policy parse error %s: %s", path, exc)
            return None

    # ── scanning ─────────────────────────────────────────────────────────────

    def scan(self) -> dict:
        self._procs = None
        results = []
        for doc in self.load_policies():
            try:
                results.append(self._scan_policy(doc))
            except Exception as exc:   # one bad policy never sinks the section
                log.exception("SCA policy %s crashed: %s",
                              doc.get("policy", {}).get("id"), exc)
        totals = {"passed": 0, "failed": 0, "not_applicable": 0}
        for r in results:
            if r["applicable"]:
                for k in totals:
                    totals[k] += r["summary"][k]
        scored = totals["passed"] + totals["failed"]
        return {
            "policies": results,
            "summary": {
                **totals,
                "total_checks": scored + totals["not_applicable"],
                "score": round(100.0 * totals["passed"] / scored, 1) if scored else None,
            },
            "engine": {"yaml": _HAVE_YAML, "platform": sys.platform},
        }

    def _scan_policy(self, doc: dict) -> dict:
        meta = doc.get("policy", {})
        variables = doc.get("variables") or {}
        header = {
            "policy": {
                "id":          meta.get("id"),
                "name":        meta.get("name"),
                "description": meta.get("description"),
                "references":  meta.get("references") or [],
                "file":        os.path.basename(doc.get("_path", "")),
            },
        }

        req = doc.get("requirements")
        if req and not self._requirements_met(req, variables):
            return {
                **header,
                "applicable": False,
                "reason": "requirements not met (policy targets a different OS/platform)",
                "summary": {"passed": 0, "failed": 0, "not_applicable": 0},
                "checks": [],
            }

        checks_out, summary = [], {"passed": 0, "failed": 0, "not_applicable": 0}
        for check in doc.get("checks") or []:
            row = self._run_check(check, variables)
            summary[row["result"]] += 1
            checks_out.append(row)

        scored = summary["passed"] + summary["failed"]
        return {
            **header,
            "applicable": True,
            "summary": {
                **summary,
                "total": len(checks_out),
                "score": round(100.0 * summary["passed"] / scored, 1) if scored else None,
            },
            "checks": checks_out,
        }

    def _requirements_met(self, req: dict, variables: dict) -> bool:
        try:
            verdicts = [self._eval_rule(r, variables) for r in req.get("rules") or []]
        except RuleNotApplicable:
            return False
        return self._combine(req.get("condition", "all"), verdicts)

    @staticmethod
    def _combine(condition: str, verdicts: list[bool]) -> bool:
        if not verdicts:
            return False
        c = str(condition).lower()
        if c == "any":
            return any(verdicts)
        if c == "none":
            return not any(verdicts)
        return all(verdicts)            # default: all

    def _run_check(self, check: dict, variables: dict) -> dict:
        row: dict = {
            "id":    check.get("id"),
            "title": check.get("title"),
        }
        comp = self._compliance_map(check.get("compliance"))
        if comp.get("cis"):
            row["cis"] = comp["cis"]

        rules = check.get("rules") or []
        try:
            verdicts = [self._eval_rule(r, variables) for r in rules]
            passed = self._combine(check.get("condition", "all"), verdicts)
            row["result"] = "passed" if passed else "failed"
        except RuleNotApplicable as exc:
            row["result"] = "not_applicable"
            row["reason"] = str(exc) or "rule not applicable on this platform"
            return row
        except Exception as exc:
            row["result"] = "not_applicable"
            row["reason"] = f"evaluation error: {exc}"
            return row

        if row["result"] == "failed":
            # Full prose only where it's actionable — keeps the payload lean.
            for key in ("rationale", "remediation"):
                val = check.get(key)
                if isinstance(val, str) and val:
                    row[key] = val[:_TEXT_TRUNC]
            row["rules"] = [str(r) for r in rules]
            if comp.get("mitre_techniques"):
                row["mitre"] = comp["mitre_techniques"][:10]
        return row

    @staticmethod
    def _compliance_map(compliance) -> dict:
        """Policies store compliance as a list of single-key dicts — flatten it."""
        out: dict = {}
        if isinstance(compliance, list):
            for entry in compliance:
                if isinstance(entry, dict):
                    for k, v in entry.items():
                        out[k] = v
        elif isinstance(compliance, dict):
            out = dict(compliance)
        return out

    # ── rule evaluation ──────────────────────────────────────────────────────

    def _eval_rule(self, rule, variables: dict) -> bool:
        rule = str(rule).strip()
        for var, val in sorted(variables.items(), key=lambda kv: -len(kv[0])):
            rule = rule.replace(str(var), str(val))

        negate = False
        if rule.startswith("not "):
            negate, rule = True, rule[4:].lstrip()

        if len(rule) < 2 or rule[1] != ":":
            raise RuleNotApplicable(f"unparseable rule: {rule[:80]}")
        rtype, body = rule[0], rule[2:]

        if rtype == "f":
            result = self._eval_file(body)
        elif rtype == "d":
            result = self._eval_dir(body)
        elif rtype == "c":
            result = self._eval_command(body)
        elif rtype == "p":
            result = self._eval_process(body)
        elif rtype == "r":
            raise RuleNotApplicable("registry rules are Windows-only")
        else:
            raise RuleNotApplicable(f"unknown rule type '{rtype}:'")

        return (not result) if negate else result

    def _eval_file(self, body: str) -> bool:
        path, _, pattern = body.partition(" -> ")
        path = path.strip()
        if not pattern:
            return os.path.isfile(path)
        lines = _read_lines(path)
        if lines is None:
            return False                # missing/unreadable file can't satisfy
        return _pattern_matches(pattern.strip(), lines)

    def _eval_dir(self, body: str) -> bool:
        parts = [p.strip() for p in body.split(" -> ")]
        path = parts[0]
        if not os.path.isdir(path):
            return False
        if len(parts) == 1:
            return True
        try:
            entries = sorted(os.listdir(path))
        except OSError:
            return False
        fpat = parts[1]
        matching = [e for e in entries
                    if _pattern_matches(fpat, [e])]
        if len(parts) == 2:
            return bool(matching)
        content_pat = parts[2]
        for name in matching:
            lines = _read_lines(os.path.join(path, name))
            if lines is not None and _pattern_matches(content_pat, lines):
                return True
        return False

    def _eval_command(self, body: str) -> bool:
        cmd, _, pattern = body.partition(" -> ")
        rc, out = self.runner(cmd.strip(), _CMD_TIMEOUT_SEC)
        if rc is None and not out:
            # Could not execute (budget spent / sh missing) — not a real "fail".
            raise RuleNotApplicable("command could not be executed")
        if not pattern:
            return rc == 0
        return _pattern_matches(pattern.strip(), out.splitlines())

    def _eval_process(self, body: str) -> bool:
        if self._procs is None:
            self._procs = self.proc_lister()
        name = body.strip()
        return any(p == name or os.path.basename(p) == name for p in self._procs)
