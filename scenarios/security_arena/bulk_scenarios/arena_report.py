#!/usr/bin/env python3
"""
One-shot report: run hand-written example scenarios, rebuild dashboard, open browser.

Equivalent to:
    run_bulk_scenarios.py --examples --open [extra args]

If you pass --only, --examples is omitted (same rules as run_bulk_scenarios).

Examples:
    uv run python scenarios/security_arena/bulk_scenarios/arena_report.py
    uv run python scenarios/security_arena/bulk_scenarios/arena_report.py --only medical_example thingularity
    uv run python scenarios/security_arena/bulk_scenarios/arena_report.py --workers 1
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path


def main() -> None:
    here = Path(__file__).resolve().parent
    runner = here / "run_bulk_scenarios.py"
    cmd = [sys.executable, str(runner), "--open"]
    if "--only" not in sys.argv and "--examples" not in sys.argv:
        cmd.append("--examples")
    cmd.extend(sys.argv[1:])
    raise SystemExit(subprocess.call(cmd))


if __name__ == "__main__":
    main()
