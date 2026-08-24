#!/usr/bin/env python3
"""Measure developer_security rule precision against real fleet telemetry.

Detection tuning done against imagined inputs optimises for the rule author's
mental model of a developer laptop. This replays the snapshots the fleet
actually sent — read from the three-tier NDJSON store, which keeps more history
than the payloads table — and reports, per rule:

  fires/snapshot  how much queue volume the rule produces
  distinct objects  how many *things* it is really talking about (rollup check)
  churn             finding-set stability; a rule that re-keys every snapshot
                    floods the queue even when every finding is correct

Usage:
    python3 manager/scripts/rule_precision.py [--data-dir data] [--rule AL-DEV-007]

Labelling precision requires a human: pass --labels FILE where FILE is a JSON
list of paths/object keys known to be true positives, and the script will score
precision and recall for the rules that emit them.
"""
from __future__ import annotations

import argparse
import asyncio
import glob
import gzip
import json
import os
import sys
from collections import Counter, defaultdict

_REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if _REPO not in sys.path:
    sys.path.insert(0, _REPO)

from manager.manager.attacklens.detections.developer_security import (  # noqa: E402,I001
    RULE_SPECS, analyze,
)

SECTION = "developer_security"


def load_snapshots(data_dir: str) -> list[dict]:
    """Read every unique snapshot across the hot/warm/cold tiers."""
    pattern = os.path.join(data_dir, "*", "*", SECTION, "**", "*.ndjson.gz")
    unique: dict = {}
    for path in sorted(glob.glob(pattern, recursive=True)):
        with gzip.open(path, "rt") as handle:
            for line in handle:
                line = line.strip()
                if not line:
                    continue
                try:
                    record = json.loads(line)
                except ValueError:
                    continue
                key = record.get("event_id") or (record.get("agent_id"), record.get("ts"))
                unique[key] = record
    return sorted(unique.values(), key=lambda record: record.get("ts") or 0)


def finding_paths(hit: dict) -> list[str]:
    evidence = hit.get("evidence") or {}
    paths = list(evidence.get("sample_paths") or [])
    for field in ("path", "object"):
        if evidence.get(field):
            paths.append(str(evidence[field]))
    return paths


async def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--data-dir", default=os.path.join(_REPO, "data"))
    parser.add_argument("--rule", help="restrict output to one rule id")
    parser.add_argument("--labels", help="JSON list of known true-positive paths")
    parser.add_argument("--verbose", action="store_true")
    args = parser.parse_args()

    snapshots = load_snapshots(args.data_dir)
    if not snapshots:
        print(f"no {SECTION} snapshots under {args.data_dir}", file=sys.stderr)
        return 2

    truth = set(json.load(open(args.labels))) if args.labels else None

    fires: Counter = Counter()
    objects: dict[str, set] = defaultdict(set)
    per_snapshot: dict[str, list] = defaultdict(list)
    covered: dict[str, set] = defaultdict(set)

    for snapshot in snapshots:
        hits = await analyze("replay", SECTION, snapshot.get("data") or {}, object())
        by_rule: dict[str, set] = defaultdict(set)
        for hit in hits:
            rule = hit["rule_id"]
            fires[rule] += 1
            objects[rule].add(hit["item_key"])
            by_rule[rule].add(hit["item_key"])
            covered[rule].update(finding_paths(hit))
        for rule in RULE_SPECS:
            per_snapshot[rule].append(frozenset(by_rule.get(rule, ())))

    count = len(snapshots)
    print(f"replayed {count} {SECTION} snapshots from {args.data_dir}\n")
    header = f"{'rule':11} {'fires/snap':>10} {'objects':>8} {'churn':>6}"
    if truth is not None:
        header += f" {'precision':>10} {'recall':>7}"
    print(header)
    print("-" * len(header))

    for rule in sorted(RULE_SPECS):
        if args.rule and rule != args.rule:
            continue
        churn = len(set(per_snapshot[rule]))
        line = (f"{rule:11} {fires[rule] / count:>10.1f} "
                f"{len(objects[rule]):>8} {churn:>6}")
        if truth is not None:
            found = covered[rule] & truth
            # Only rules that touched the labelled surface are scorable.
            if covered[rule]:
                hit_count = fires[rule] / count
                precision = len(found) / hit_count if hit_count else 0.0
                line += f" {min(precision, 1.0):>9.0%} {len(found) / len(truth):>6.0%}"
            else:
                line += f" {'-':>10} {'-':>7}"
        print(line)

    if args.verbose:
        print("\nboundaries (what each rule promises to stay silent about):")
        for rule in sorted(RULE_SPECS):
            if args.rule and rule != args.rule:
                continue
            print(f"  {rule}: {RULE_SPECS[rule]['boundary']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
