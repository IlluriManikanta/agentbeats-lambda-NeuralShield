#!/usr/bin/env python3
"""
Run scenario TOML files and store results in bulk_scenarios/results/<slug>.

Modes:
  - **Bulk (default):** Run all auto-generated scenarios from generated_tomls/
    (e.g. 424 scenarios). Requires running scrape_and_generate_tomls.py first.
  - **Examples:** Run all example scenarios from scenarios/security_arena/
    (scenario_medical_example.toml, scenario_thingularity.toml, …) — **not** generated bulk.
  - **Subset:** `--only medical_example gymjailbreak` runs just those two TOMLs from
    scenarios/security_arena/.

Each run invokes:
    uv run agentbeats-run <toml>

Runs can be parallelized with --workers N. Each worker uses a separate port set
(9010/9020/9021/9022, 9110/9120/9121/9122, ...) so multiple agentbeats-run
processes can run at once without port conflicts.

Results are written to:
    scenarios/security_arena/bulk_scenarios/results/<slug>

After running, generate the dashboard and open it in a browser:
    uv run python scenarios/security_arena/bulk_scenarios/run_bulk_scenarios.py --examples --open
    # or: uv run python scenarios/security_arena/bulk_scenarios/arena_report.py

Usage:
    # Run all bulk (424) scenarios
    uv run python scenarios/security_arena/bulk_scenarios/run_bulk_scenarios.py
    uv run python scenarios/security_arena/bulk_scenarios/run_bulk_scenarios.py --workers 8

    # Run all example TOMLs under scenarios/security_arena/ (not generated bulk)
    uv run python scenarios/security_arena/bulk_scenarios/run_bulk_scenarios.py --examples

    # Run only specific examples (slugs = filename without scenario_ prefix)
    uv run python scenarios/security_arena/bulk_scenarios/run_bulk_scenarios.py --only medical_example gymjailbreak

    # Run the same scenario set 3 times (results under results/<slug>/repeat_001..003/)
    uv run python scenarios/security_arena/bulk_scenarios/run_bulk_scenarios.py --examples --repeat 3

    # Run examples, build dashboard, open browser (one step)
    uv run python scenarios/security_arena/bulk_scenarios/run_bulk_scenarios.py --examples --open

    # Or use the convenience wrapper (same as --examples --open; add --only … as needed)
    uv run python scenarios/security_arena/bulk_scenarios/arena_report.py
    uv run python scenarios/security_arena/bulk_scenarios/arena_report.py --only medical_example gymjailbreak
"""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from pathlib import Path
from typing import List, Tuple


BASE_DIR = Path(__file__).resolve().parent
ARENA_DIR = BASE_DIR.parent  # scenarios/security_arena
TOML_DIR = BASE_DIR / "generated_tomls"
RESULTS_BASE = BASE_DIR / "results"

# Default ports for worker 0; each worker gets base + worker_id * 100
ORCHESTRATOR_PORT = 9010
DEFENDER_PORT = 9020
ATTACKER_PORT = 9021
NORMAL_USER_PORT = 9022
PORT_STEP = 100


@dataclass
class RunResult:
    slug: str
    toml_path: Path
    returncode: int
    worker_id: int


def resolve_example_tomls_only(slugs: List[str]) -> List[Path]:
    """Paths to scenario_<slug>.toml under ARENA_DIR; exit with error if any missing."""
    paths: List[Path] = []
    for slug in slugs:
        p = ARENA_DIR / f"scenario_{slug}.toml"
        if not p.is_file():
            print(f"ERROR: Example scenario not found: {p}", file=sys.stderr)
            print(f"  (expected slug '{slug}' → scenario_{slug}.toml under {ARENA_DIR})", file=sys.stderr)
            sys.exit(1)
        paths.append(p)
    return sorted(paths, key=lambda x: x.name)


def find_tomls(examples_only: bool = False) -> List[Path]:
    """Return paths to scenario TOMLs. If examples_only, use example scenarios from arena dir; else use generated_tomls."""
    if examples_only:
        # Example scenarios: scenario_*.toml in scenarios/security_arena/ (one level up from bulk_scenarios)
        paths = sorted(ARENA_DIR.glob("scenario_*.toml"))
        if not paths:
            print(f"No example TOMLs found in {ARENA_DIR}. Expected scenario_medical_example.toml, etc.", file=sys.stderr)
        return paths
    if not TOML_DIR.exists():
        print(f"No TOML directory found at {TOML_DIR}. Run scrape_and_generate_tomls.py first.", file=sys.stderr)
        return []
    return sorted(TOML_DIR.glob("scenario_*.toml"))


def slug_from_toml(path: Path) -> str:
    name = path.stem
    if name.startswith("scenario_"):
        return name[len("scenario_") :]
    return name


def ports_for_worker(worker_id: int) -> Tuple[int, int, int, int]:
    """Return (orchestrator, defender, attacker, normal_user) ports for this worker."""
    base = ORCHESTRATOR_PORT + worker_id * PORT_STEP
    return (
        base,
        base + (DEFENDER_PORT - ORCHESTRATOR_PORT),
        base + (ATTACKER_PORT - ORCHESTRATOR_PORT),
        base + (NORMAL_USER_PORT - ORCHESTRATOR_PORT),
    )


def make_toml_for_worker(toml_path: Path, worker_id: int, temp_dir: Path) -> Path:
    """
    Read the scenario TOML and write a copy with ports substituted for this worker.
    Returns path to the temporary TOML file.
    """
    text = toml_path.read_text(encoding="utf-8")
    orch, def_, att, norm = ports_for_worker(worker_id)
    # Replace default ports with worker-specific ones (order: longest first to avoid partial matches)
    text = text.replace("9022", str(norm))
    text = text.replace("9021", str(att))
    text = text.replace("9020", str(def_))
    text = text.replace("9010", str(orch))
    out = temp_dir / f"scenario_worker{worker_id}_{toml_path.name}"
    out.write_text(text, encoding="utf-8")
    return out


def run_one(args: Tuple[Path, int, int, int, int], retries: int = 0) -> RunResult:
    """Run a single scenario. args = (toml_path, worker_id, scenario_index, trial_num, total_repeats)."""
    toml_path, worker_id, _, trial_num, total_repeats = args
    slug = slug_from_toml(toml_path)
    if total_repeats <= 1:
        scenario_results_dir = RESULTS_BASE / slug
    else:
        scenario_results_dir = RESULTS_BASE / slug / f"repeat_{trial_num:03d}"
    scenario_results_dir.mkdir(parents=True, exist_ok=True)

    env = os.environ.copy()
    env["AGENTBEATS_RESULTS_DIR"] = str(scenario_results_dir)

    last_returncode = -1
    trial_tag = f" trial {trial_num}/{total_repeats}" if total_repeats > 1 else ""
    for attempt in range(retries + 1):
        with tempfile.TemporaryDirectory(prefix="bulk_scenario_") as temp_dir:
            temp_toml = make_toml_for_worker(toml_path, worker_id, Path(temp_dir))
            cmd = ["uv", "run", "agentbeats-run", str(temp_toml)]
            proc = subprocess.run(cmd, env=env)
        last_returncode = proc.returncode
        if proc.returncode == 0:
            break
        if attempt < retries:
            time.sleep(5)
            print(
                f"[w{worker_id}] {slug}{trial_tag}: exit {proc.returncode}, retrying ({attempt + 2}/{retries + 1})...",
                file=sys.stderr,
            )

    print(f"[w{worker_id}] {slug}{trial_tag}: exit {last_returncode}", file=sys.stderr)
    return RunResult(slug=slug, toml_path=toml_path, returncode=last_returncode, worker_id=worker_id)


def run_dashboard(open_browser: bool = False) -> None:
    """Generate dashboard.html from results in RESULTS_BASE; optionally open in browser."""
    dashboard_script = BASE_DIR / "dashboard.py"
    if not dashboard_script.exists():
        print(f"Dashboard script not found: {dashboard_script}", file=sys.stderr)
        return
    cmd = [sys.executable, str(dashboard_script)]
    if open_browser:
        cmd.append("--open")
    proc = subprocess.run(cmd, cwd=str(BASE_DIR))
    if proc.returncode == 0 and not open_browser:
        print(f"Dashboard written to {BASE_DIR / 'dashboard.html'}. Open it in a browser.", file=sys.stderr)
    elif proc.returncode != 0:
        print(f"Dashboard script exited with {proc.returncode}", file=sys.stderr)


def main() -> None:
    parser = argparse.ArgumentParser(description="Run scenario TOMLs (bulk or examples, optionally in parallel)")
    parser.add_argument(
        "--examples",
        action="store_true",
        help="Run every scenario_*.toml in scenarios/security_arena/ (the hand-written examples). Default without --examples/--only: run bulk scenarios from generated_tomls/.",
    )
    parser.add_argument(
        "--only",
        nargs="+",
        metavar="SLUG",
        default=None,
        help="Run only these example scenarios: slugs are the TOML name without 'scenario_' and '.toml', e.g. medical_example gymjailbreak thingularity. Uses files under scenarios/security_arena/ only (not generated bulk).",
    )
    parser.add_argument(
        "--workers",
        type=int,
        default=8,
        help="Number of scenarios to run in parallel (default 8). Each uses a separate port set.",
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=0,
        help="If set, only run this many scenarios (for testing). 0 = run all.",
    )
    parser.add_argument(
        "--retries",
        type=int,
        default=2,
        help="On non-zero exit (e.g. 'Server disconnected'), retry this many times (default 2).",
    )
    parser.add_argument(
        "--dashboard",
        action="store_true",
        help="After running scenarios, generate dashboard.html from results (run dashboard.py).",
    )
    parser.add_argument(
        "--open",
        action="store_true",
        help="After runs, regenerate dashboard and open it in the default browser (implies --dashboard).",
    )
    parser.add_argument(
        "--repeat",
        type=int,
        default=1,
        metavar="N",
        help="Run the full selected scenario set N times in sequence (default 1). Results go to "
        "results/<slug>/repeat_001/… for N>1; dashboard aggregates trials per slug.",
    )
    args = parser.parse_args()
    if args.open:
        args.dashboard = True
    if args.only is not None and args.examples:
        print("NOTE: --only takes precedence; ignoring --examples.", file=sys.stderr)

    workers = max(1, args.workers)
    limit = args.limit
    retries = max(0, args.retries)

    if args.only is not None:
        tomls = resolve_example_tomls_only(args.only)
    else:
        tomls = find_tomls(examples_only=args.examples)
    if not tomls:
        sys.exit(1)

    if limit > 0:
        tomls = tomls[:limit]
    total = len(tomls)
    if total == 0:
        sys.exit(1)

    if args.only is not None:
        mode = "example (subset)"
    elif args.examples:
        mode = "example (all)"
    else:
        mode = "bulk"
    repeats = max(1, args.repeat)
    if repeats > 1:
        mode = f"{mode} × {repeats} trials"
    print(f"Running {total} {mode} scenario(s) with {workers} parallel worker(s)...", file=sys.stderr)

    results: List[RunResult] = []
    for trial in range(1, repeats + 1):
        if repeats > 1:
            print(f"\n--- Trial {trial}/{repeats} (full scenario set) ---", file=sys.stderr)
        # Each task gets a worker_id so we don't exceed `workers` concurrent runs with same port set.
        task_args: List[Tuple[Path, int, int, int, int]] = [
            (path, i % workers, i, trial, repeats) for i, path in enumerate(tomls)
        ]

        with ThreadPoolExecutor(max_workers=workers) as executor:
            futures = {executor.submit(run_one, a, retries): a for a in task_args}
            for fut in as_completed(futures):
                try:
                    results.append(fut.result())
                except Exception as e:
                    a = futures[fut]
                    slug = slug_from_toml(a[0])
                    print(f"Scenario '{slug}' raised: {e}", file=sys.stderr)
                    results.append(RunResult(slug=slug, toml_path=a[0], returncode=-1, worker_id=a[1]))

    # Sort by slug for stable summary
    results.sort(key=lambda r: r.slug)

    print("\n=== Summary ===", file=sys.stderr)
    ok = [r for r in results if r.returncode == 0]
    failed = [r for r in results if r.returncode != 0]

    print(f"Total scenarios: {len(results)}", file=sys.stderr)
    print(f"  Succeeded:     {len(ok)}", file=sys.stderr)
    print(f"  Failed:        {len(failed)}", file=sys.stderr)

    if failed:
        print("\nFailures:", file=sys.stderr)
        for r in failed:
            print(f"  - {r.slug}: exit code {r.returncode}", file=sys.stderr)

    if args.dashboard:
        print("", file=sys.stderr)
        run_dashboard(open_browser=args.open)


if __name__ == "__main__":
    main()

