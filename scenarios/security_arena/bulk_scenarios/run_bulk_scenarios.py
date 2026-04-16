#!/usr/bin/env python3
"""
Run scenario TOML files and store results in bulk_scenarios/results/<slug>.

Modes:
  - **Bulk (default):** Run all auto-generated scenarios from generated_tomls/
    (e.g. 424 scenarios). Requires running scrape_and_generate_tomls.py first.
  - **Examples:** Run only the example scenarios (medical_records, thingularity,
    gymjailbreak, resume_downgrade, portfolioiq) from scenarios/security_arena/.

Each run invokes:
    uv run agentbeats-run <toml>

Local Ollama (recommended on a single machine): set repo-root `.env` (see `.env.example`
  Profile B) or export:
  OPENAI_BASE_URL=http://127.0.0.1:11434/v1
  OPENAI_API_KEY=ollama
  ARENA_OLLAMA_MODEL=<tag from `ollama list`, e.g. llama3.2:3b>
  uv run python .../run_bulk_scenarios.py --limit 3

  --model <name> overrides ARENA_OLLAMA_MODEL and rewrites --model in each temp TOML
  (generated TOMLs use openai/gpt-oss-20b otherwise).

Runs can be parallelized with --workers N. Each worker uses a separate port set
(9010/9020/9021/9022, 9110/9120/9121/9122, ...) so multiple agentbeats-run
processes can run at once without port conflicts.

Results are written to:
    scenarios/security_arena/bulk_scenarios/results/<slug>

After running, generate the dashboard and open it in a browser:
    uv run python scenarios/security_arena/bulk_scenarios/dashboard.py
    # then open: scenarios/security_arena/bulk_scenarios/dashboard.html

Usage:
    # Run all bulk (424) scenarios (local Ollama: set OPENAI_* and ARENA_OLLAMA_MODEL; prefer --workers 1)
    uv run python scenarios/security_arena/bulk_scenarios/run_bulk_scenarios.py
    uv run python scenarios/security_arena/bulk_scenarios/run_bulk_scenarios.py --workers 2

    # Run only example scenarios (5 scenarios)
    uv run python scenarios/security_arena/bulk_scenarios/run_bulk_scenarios.py --examples

    # Run examples then build dashboard
    uv run python scenarios/security_arena/bulk_scenarios/run_bulk_scenarios.py --examples --dashboard
"""

from __future__ import annotations

import argparse
import os
import re
import shlex
import socket
import subprocess
import sys
import tempfile
import tomllib
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional, Tuple


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


def ports_for_worker_with_offset(
    worker_id: int,
    run_port_offset: int,
) -> Tuple[int, int, int, int]:
    """Return worker ports shifted by a run-specific offset."""
    orch, def_, att, norm = ports_for_worker(worker_id)
    return (orch + run_port_offset, def_ + run_port_offset, att + run_port_offset, norm + run_port_offset)


def _can_bind(port: int, host: str = "127.0.0.1") -> bool:
    """Return True when the TCP port is currently available on host."""
    if port < 1 or port > 65535:
        return False
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            sock.bind((host, port))
            return True
        except OSError:
            return False


def choose_run_port_offset(workers: int, explicit_offset: Optional[int]) -> int:
    """
    Pick a run-specific port offset that keeps this bulk run isolated from
    other overlapping runs on the same machine.
    """
    if explicit_offset is not None:
        return explicit_offset

    # Spread candidates across high user ports; PID-derived start reduces collision
    # when two bulk runs are launched close together.
    slot_step = 1000
    max_slot = 50  # up to ~59010 base for worker 0 orchestrator
    start_slot = os.getpid() % (max_slot + 1)
    candidate_offsets = [((start_slot + i) % (max_slot + 1)) * slot_step for i in range(max_slot + 1)]

    for offset in candidate_offsets:
        required_ports: set[int] = set()
        for worker_id in range(workers):
            required_ports.update(ports_for_worker_with_offset(worker_id, offset))
        if all(_can_bind(port) for port in required_ports):
            return offset

    raise RuntimeError(
        "Unable to find a free port range for this bulk run. "
        "Close other local scenario runs or pass --port-offset explicitly."
    )


# Default model string embedded in generated TOMLs (vLLM-style); replaced when using Ollama.
_DEFAULT_TOML_MODEL = "openai/gpt-oss-20b"


def make_toml_for_worker(
    toml_path: Path,
    worker_id: int,
    temp_dir: Path,
    model_override: Optional[str] = None,
    run_port_offset: int = 0,
) -> Path:
    """
    Read the scenario TOML and write a copy with ports substituted for this worker.
    If model_override is set, replace each --model <...> in participant cmd lines
    (so attacker/defender/normal_user use your Ollama tag).
    """
    text = toml_path.read_text(encoding="utf-8")
    orch, def_, att, norm = ports_for_worker_with_offset(worker_id, run_port_offset)
    # Replace default ports with worker-specific ones (order: longest first to avoid partial matches)
    text = text.replace("9022", str(norm))
    text = text.replace("9021", str(att))
    text = text.replace("9020", str(def_))
    text = text.replace("9010", str(orch))
    if model_override:
        quoted = shlex.quote(model_override)
        # Token must not include the closing " on cmd lines. Using \S+ here eats that quote and
        # produces invalid TOML (tomllib: Illegal character '\\n' near end of the broken string).
        text = re.sub(r'--model\s+[^\s"]+', f"--model {quoted}", text)
    try:
        tomllib.loads(text)
    except tomllib.TOMLDecodeError as e:
        raise ValueError(
            f"Invalid TOML after substitutions in {toml_path} (check --model / ARENA_OLLAMA_MODEL): {e}"
        ) from e
    out = temp_dir / f"scenario_worker{worker_id}_{toml_path.name}"
    out.write_text(text, encoding="utf-8")
    return out


def run_one(
    args: Tuple[Path, int, int, Optional[str], int], retries: int = 0
) -> RunResult:
    """Run a single scenario. args = (toml_path, worker_id, scenario_index, model_override, run_port_offset)."""
    toml_path, worker_id, _, model_override, run_port_offset = args
    slug = slug_from_toml(toml_path)
    scenario_results_dir = RESULTS_BASE / slug
    scenario_results_dir.mkdir(parents=True, exist_ok=True)

    env = os.environ.copy()
    env["AGENTBEATS_RESULTS_DIR"] = str(scenario_results_dir)

    last_returncode = -1
    for attempt in range(retries + 1):
        with tempfile.TemporaryDirectory(prefix="bulk_scenario_") as temp_dir:
            temp_toml = make_toml_for_worker(
                toml_path,
                worker_id,
                Path(temp_dir),
                model_override=model_override,
                run_port_offset=run_port_offset,
            )
            cmd = ["uv", "run", "agentbeats-run", str(temp_toml)]
            proc = subprocess.run(cmd, env=env)
        last_returncode = proc.returncode
        if proc.returncode == 0:
            break
        if attempt < retries:
            time.sleep(5)
            print(f"[w{worker_id}] {slug}: exit {proc.returncode}, retrying ({attempt + 2}/{retries + 1})...", file=sys.stderr)

    print(f"[w{worker_id}] {slug}: exit {last_returncode}", file=sys.stderr)
    return RunResult(slug=slug, toml_path=toml_path, returncode=last_returncode, worker_id=worker_id)


def run_dashboard() -> None:
    """Generate dashboard.html from results in RESULTS_BASE."""
    dashboard_script = BASE_DIR / "dashboard.py"
    if not dashboard_script.exists():
        print(f"Dashboard script not found: {dashboard_script}", file=sys.stderr)
        return
    proc = subprocess.run([sys.executable, str(dashboard_script)], cwd=str(BASE_DIR))
    if proc.returncode == 0:
        print(f"Dashboard written to {BASE_DIR / 'dashboard.html'}. Open it in a browser.", file=sys.stderr)
    else:
        print(f"Dashboard script exited with {proc.returncode}", file=sys.stderr)


def main() -> None:
    try:
        from dotenv import load_dotenv

        # parents[0]=bulk_scenarios, [1]=security_arena, [2]=scenarios, [3]=repo root
        repo_root = Path(__file__).resolve().parents[3]
        load_dotenv(repo_root / ".env")
    except ImportError:
        pass

    parser = argparse.ArgumentParser(description="Run scenario TOMLs (bulk or examples, optionally in parallel)")
    parser.add_argument(
        "--examples",
        action="store_true",
        help="Run only example scenarios (medical_example, thingularity, gymjailbreak, resume_downgrade, portfolioiq) from scenarios/security_arena/. Default: run bulk scenarios from generated_tomls/.",
    )
    parser.add_argument(
        "--workers",
        type=int,
        default=1,
        help="Number of scenarios to run in parallel (default 1; use higher only if your LLM backend can take it). Each uses a separate port set.",
    )
    parser.add_argument(
        "--model",
        type=str,
        default=None,
        metavar="NAME",
        help=(
            "Override LLM model for all participants in the temp TOML (attacker, defender, normal_user). "
            "Default: env ARENA_OLLAMA_MODEL or OLLAMA_MODEL; if unset, TOML keeps %s."
            % _DEFAULT_TOML_MODEL
        ),
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
        "--port-offset",
        type=int,
        default=None,
        help=(
            "Optional run-level port offset applied to 9010/9020/9021/9022 (and worker variants). "
            "If omitted, a free offset is auto-selected."
        ),
    )
    args = parser.parse_args()
    workers = max(1, args.workers)
    limit = args.limit
    retries = max(0, args.retries)
    run_port_offset = choose_run_port_offset(workers, args.port_offset)

    model_override: Optional[str] = args.model or os.environ.get(
        "ARENA_OLLAMA_MODEL"
    ) or os.environ.get("OLLAMA_MODEL")
    if model_override:
        print(
            f"Using LLM model for all agents: {model_override!r} (Ollama tag or API model id)",
            file=sys.stderr,
        )
    else:
        print(
            f"No --model / ARENA_OLLAMA_MODEL / OLLAMA_MODEL: leaving TOML model as {_DEFAULT_TOML_MODEL!r}",
            file=sys.stderr,
        )

    print(
        f"Using run port offset: {run_port_offset} (worker 0 ports: {ORCHESTRATOR_PORT + run_port_offset}/"
        f"{DEFENDER_PORT + run_port_offset}/{ATTACKER_PORT + run_port_offset}/{NORMAL_USER_PORT + run_port_offset})",
        file=sys.stderr,
    )

    tomls = find_tomls(examples_only=args.examples)
    if not tomls:
        sys.exit(1)

    if limit > 0:
        tomls = tomls[:limit]
    total = len(tomls)
    if total == 0:
        sys.exit(1)

    mode = "example" if args.examples else "bulk"
    print(f"Running {total} {mode} scenario(s) with {workers} parallel worker(s)...", file=sys.stderr)

    # Each task gets a worker_id so we don't exceed `workers` concurrent runs with same port set.
    # Worker i uses ports 9010+i*100, 9020+i*100, etc.
    task_args: List[Tuple[Path, int, int, Optional[str], int]] = [
        (path, i % workers, i, model_override, run_port_offset) for i, path in enumerate(tomls)
    ]

    results: List[RunResult] = []
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
        run_dashboard()


if __name__ == "__main__":
    main()

