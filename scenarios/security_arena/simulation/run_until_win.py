#!/usr/bin/env python3
"""
Run a scenario with many rounds (simulate "talk till attacker wins") then record winning strategy.

Does not modify any existing files. Creates a temporary TOML with num_rounds overridden,
runs agentbeats-run, then runs record_winning_strategy.py on the results dir.

Usage:
    uv run python scenarios/security_arena/simulation/run_until_win.py <scenario.toml> [--num-rounds 20] [--results-dir DIR]

Example:
    uv run python scenarios/security_arena/simulation/run_until_win.py scenarios/security_arena/scenario_medical_example.toml --num-rounds 20
"""

from __future__ import annotations

import argparse
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path


SIMULATION_DIR = Path(__file__).resolve().parent
RUNS_DIR = SIMULATION_DIR / "runs"
RECORD_SCRIPT = SIMULATION_DIR / "record_winning_strategy.py"


def slug_from_toml(path: Path) -> str:
    name = path.stem
    if name.startswith("scenario_"):
        return name[len("scenario_") :]
    return name


def make_toml_with_rounds(toml_path: Path, num_rounds: int, temp_dir: Path) -> Path:
    """Copy TOML and set num_rounds to the given value."""
    text = toml_path.read_text(encoding="utf-8")
    text = re.sub(r"num_rounds\s*=\s*\d+", f"num_rounds = {num_rounds}", text, count=1)
    out = temp_dir / toml_path.name
    out.write_text(text, encoding="utf-8")
    return out


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Run scenario with many rounds, then record winning strategy if attacker wins"
    )
    parser.add_argument("toml", type=Path, help="Scenario TOML (e.g. scenario_medical_example.toml)")
    parser.add_argument(
        "--num-rounds",
        type=int,
        default=20,
        help="Override num_rounds (default 20; max allowed by arena is 20)",
    )
    parser.add_argument(
        "--results-dir",
        type=Path,
        default=None,
        help="Directory for results (default: simulation/runs/<slug>)",
    )
    args = parser.parse_args()
    toml_path = args.toml.resolve()
    if not toml_path.exists():
        print(f"Not found: {toml_path}", file=sys.stderr)
        return 1
    slug = slug_from_toml(toml_path)
    results_dir = args.results_dir
    if results_dir is None:
        results_dir = RUNS_DIR / slug
    results_dir = results_dir.resolve()
    results_dir.mkdir(parents=True, exist_ok=True)
    env = os.environ.copy()
    env["AGENTBEATS_RESULTS_DIR"] = str(results_dir)
    with tempfile.TemporaryDirectory(prefix="sim_until_win_") as temp_dir:
        temp_toml = make_toml_with_rounds(toml_path, args.num_rounds, Path(temp_dir))
        cmd = ["uv", "run", "agentbeats-run", str(temp_toml)]
        print(f"Running: {' '.join(cmd)} (results -> {results_dir})", file=sys.stderr)
        proc = subprocess.run(cmd, env=env)
        if proc.returncode != 0:
            print(f"agentbeats-run exited with {proc.returncode}", file=sys.stderr)
            return proc.returncode
    record_cmd = [sys.executable, str(RECORD_SCRIPT), str(results_dir)]
    print(f"Recording strategy: {' '.join(record_cmd)}", file=sys.stderr)
    rec = subprocess.run(record_cmd)
    return rec.returncode


if __name__ == "__main__":
    sys.exit(main())
