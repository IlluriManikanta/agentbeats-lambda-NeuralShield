#!/usr/bin/env python3
"""
Record a winning attacker strategy from a result directory into simulation/successful_strategies.json.

Use after a run where the attacker won. Does not modify any existing arena/orchestrator code.
Reads result.json from the given results dir; if winner is attacker, appends the winning
round's attack to simulation/successful_strategies.json (by scenario_type).

Usage:
    uv run python scenarios/security_arena/simulation/record_winning_strategy.py <results_dir>

Example:
    uv run python scenarios/security_arena/simulation/record_winning_strategy.py scenarios/security_arena/bulk_scenarios/results/medical_example
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path


SIMULATION_DIR = Path(__file__).resolve().parent
STRATEGIES_FILE = SIMULATION_DIR / "successful_strategies.json"
MAX_ENTRIES_PER_TYPE = 5
SUMMARY_LEN = 400


def slug_from_path(results_dir: Path) -> str:
    """Infer scenario slug from results path (e.g. .../results/medical_example -> medical_example)."""
    name = results_dir.name
    return name or "unknown"


def make_summary(attack_output: str) -> str:
    """Short summary of the attack for the strategies log."""
    if not attack_output:
        return ""
    cleaned = re.sub(r"\s+", " ", attack_output).strip()
    return (cleaned[: SUMMARY_LEN] + "…") if len(cleaned) > SUMMARY_LEN else cleaned


def main() -> int:
    parser = argparse.ArgumentParser(description="Record winning attacker strategy from a result dir")
    parser.add_argument("results_dir", type=Path, help="Path to scenario results (contains result.json)")
    args = parser.parse_args()
    results_dir = args.results_dir.resolve()
    result_path = results_dir / "result.json"
    if not result_path.exists():
        print(f"Not found: {result_path}", file=sys.stderr)
        return 1
    data = json.loads(result_path.read_text(encoding="utf-8"))
    winner = data.get("winner")
    if winner != "attacker":
        print(f"Winner is '{winner}', not attacker. Nothing to record.", file=sys.stderr)
        return 0
    scenario_type = data.get("scenario_type") or slug_from_path(results_dir)
    manipulation_round = data.get("manipulation_round")
    battle_log = data.get("battle_log") or []
    winning_entry = None
    for entry in battle_log:
        if entry.get("round") == manipulation_round:
            winning_entry = entry
            break
    if not winning_entry:
        print("Winning round not found in battle_log.", file=sys.stderr)
        return 1
    attack_output = winning_entry.get("attack_output") or ""
    summary = make_summary(attack_output)
    strategies = {"strategies": []}
    if STRATEGIES_FILE.exists():
        strategies = json.loads(STRATEGIES_FILE.read_text(encoding="utf-8"))
    strategies["strategies"].append({
        "scenario_type": scenario_type,
        "round": manipulation_round,
        "attack_output": attack_output,
        "summary": summary,
    })
    by_type = [e for e in strategies["strategies"] if e.get("scenario_type") == scenario_type]
    if len(by_type) > MAX_ENTRIES_PER_TYPE:
        to_keep = by_type[-MAX_ENTRIES_PER_TYPE:]
        strategies["strategies"] = [
            e for e in strategies["strategies"] if e.get("scenario_type") != scenario_type
        ] + to_keep
    STRATEGIES_FILE.parent.mkdir(parents=True, exist_ok=True)
    STRATEGIES_FILE.write_text(json.dumps(strategies, indent=2), encoding="utf-8")
    print(f"Recorded winning strategy for scenario_type={scenario_type} to {STRATEGIES_FILE}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
