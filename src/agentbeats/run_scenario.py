import argparse
import asyncio
import os, sys, time, subprocess, shlex, signal
import socket
from pathlib import Path
import tomllib
import httpx
from dotenv import load_dotenv

from a2a.client import A2ACardResolver
from agentbeats.debug_runtime import append_debug_log


load_dotenv(override=True)


def _process_snapshot(procs: list[subprocess.Popen], proc_labels: dict[int, str]) -> list[dict]:
    return [
        {
            "pid": p.pid,
            "label": proc_labels.get(p.pid, "unknown"),
            "alive": p.poll() is None,
            "returncode": p.returncode,
        }
        for p in procs
    ]


def _dead_server_processes(
    procs: list[subprocess.Popen], proc_labels: dict[int, str]
) -> list[dict]:
    dead = []
    for proc in procs:
        label = proc_labels.get(proc.pid, "")
        if label.startswith("participant:") or label.startswith("green_agent:"):
            rc = proc.poll()
            if rc is not None:
                dead.append(
                    {
                        "pid": proc.pid,
                        "label": label,
                        "returncode": rc,
                    }
                )
    return dead


def _port_in_use(host: str, port: int, timeout: float = 0.3) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


async def wait_for_agents(
    cfg: dict,
    procs: list[subprocess.Popen],
    proc_labels: dict[int, str],
    run_id: str,
    timeout: int = 30,
) -> bool:
    """Wait for all agents to be healthy and responding."""
    endpoints = []

    # Collect all endpoints to check
    for p in cfg["participants"]:
        if p.get("cmd"):  # Only check if there's a command (agent to start)
            endpoints.append(f"http://{p['host']}:{p['port']}")

    if cfg["green_agent"].get("cmd"):  # Only check if there's a command (host to start)
        endpoints.append(f"http://{cfg['green_agent']['host']}:{cfg['green_agent']['port']}")

    if not endpoints:
        return True  # No agents to wait for

    print(f"Waiting for {len(endpoints)} agent(s) to be ready...")
    start_time = time.time()

    async def check_endpoint(endpoint: str) -> bool:
        """Check if an endpoint is responding by fetching the agent card."""
        try:
            async with httpx.AsyncClient(timeout=2) as client:
                resolver = A2ACardResolver(httpx_client=client, base_url=endpoint)
                await resolver.get_agent_card()
                return True
        except Exception:
            # Any exception means the agent is not ready
            return False

    while time.time() - start_time < timeout:
        dead_servers = _dead_server_processes(procs, proc_labels)
        if dead_servers:
            # region agent log
            append_debug_log(
                run_id=run_id,
                hypothesis_id="H1",
                location="src/agentbeats/run_scenario.py:wait_for_agents:server_exited",
                message="A server process exited before readiness",
                data={"dead_servers": dead_servers},
            )
            # endregion
            print(f"Error: Server process exited before readiness: {dead_servers}")
            return False

        ready_count = 0
        for endpoint in endpoints:
            if await check_endpoint(endpoint):
                ready_count += 1

        if ready_count == len(endpoints):
            return True

        print(f"  {ready_count}/{len(endpoints)} agents ready, waiting...")
        await asyncio.sleep(1)

    print(f"Timeout: Only {ready_count}/{len(endpoints)} agents became ready after {timeout}s")
    return False


def parse_toml(scenario_path: str) -> dict:
    path = Path(scenario_path)
    if not path.exists():
        print(f"Error: Scenario file not found: {path}")
        sys.exit(1)

    data = tomllib.loads(path.read_text())

    def host_port(ep: str):
        s = (ep or "")
        s = s.replace("http://", "").replace("https://", "")
        s = s.split("/", 1)[0]
        host, port = s.split(":", 1)
        return host, int(port)

    green_ep = data.get("green_agent", {}).get("endpoint", "")
    g_host, g_port = host_port(green_ep)
    green_cmd = data.get("green_agent", {}).get("cmd", "")

    parts = []
    for p in data.get("participants", []):
        if isinstance(p, dict) and "endpoint" in p:
            h, pt = host_port(p["endpoint"])
            parts.append({
                "role": str(p.get("role", "")),
                "host": h,
                "port": pt,
                "cmd": p.get("cmd", "")
            })

    cfg = data.get("config", {})
    return {
        "green_agent": {"host": g_host, "port": g_port, "cmd": green_cmd},
        "participants": parts,
        "config": cfg,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Run agent scenario")
    parser.add_argument("scenario", help="Path to scenario TOML file")
    parser.add_argument("--show-logs", action="store_true",
                        help="Show agent stdout/stderr")
    parser.add_argument("--serve-only", action="store_true",
                        help="Start agent servers only without running evaluation")
    parser.add_argument("--normal-user", action="store_true",
                        help="Run normal user helpfulness test instead of adversarial battle")
    args = parser.parse_args()
    run_id = os.getenv("AGENTBEATS_DEBUG_RUN_ID", "pre-fix")
    exit_code = 0

    cfg = parse_toml(args.scenario)

    # Set normal_user mode in config if flag provided
    if args.normal_user:
        cfg["config"]["normal_user"] = True

    sink = None if args.show_logs or args.serve_only else subprocess.DEVNULL
    parent_bin = str(Path(sys.executable).parent)
    base_env = os.environ.copy()
    base_env["PATH"] = parent_bin + os.pathsep + base_env.get("PATH", "")

    procs = []
    proc_labels: dict[int, str] = {}
    try:
        preflight_conflicts = []
        for participant in cfg["participants"]:
            if participant.get("cmd") and _port_in_use(participant["host"], participant["port"]):
                preflight_conflicts.append(
                    {
                        "label": f"participant:{participant['role']}",
                        "host": participant["host"],
                        "port": participant["port"],
                    }
                )
        if cfg["green_agent"].get("cmd") and _port_in_use(cfg["green_agent"]["host"], cfg["green_agent"]["port"]):
            preflight_conflicts.append(
                {
                    "label": "green_agent",
                    "host": cfg["green_agent"]["host"],
                    "port": cfg["green_agent"]["port"],
                }
            )
        if preflight_conflicts:
            # region agent log
            append_debug_log(
                run_id=run_id,
                hypothesis_id="H1",
                location="src/agentbeats/run_scenario.py:main:preflight_port_conflict",
                message="Port conflict detected before startup",
                data={"conflicts": preflight_conflicts},
            )
            # endregion
            print(
                "Error: Required agent port(s) already in use before startup. "
                f"Conflicts: {preflight_conflicts}"
            )
            exit_code = 1
            return exit_code

        # start participant agents
        for p in cfg["participants"]:
            cmd_args = shlex.split(p.get("cmd", ""))
            if cmd_args:
                print(f"Starting {p['role']} at {p['host']}:{p['port']}")
                proc = subprocess.Popen(
                    cmd_args,
                    env=base_env,
                    stdout=sink, stderr=sink,
                    text=True,
                    start_new_session=True,
                )
                procs.append(proc)
                proc_labels[proc.pid] = f"participant:{p['role']}@{p['host']}:{p['port']}"

        # start host
        green_cmd_args = shlex.split(cfg["green_agent"].get("cmd", ""))
        if green_cmd_args:
            print(f"Starting green agent at {cfg['green_agent']['host']}:{cfg['green_agent']['port']}")
            proc = subprocess.Popen(
                green_cmd_args,
                env=base_env,
                stdout=sink, stderr=sink,
                text=True,
                start_new_session=True,
            )
            procs.append(proc)
            proc_labels[proc.pid] = (
                f"green_agent:{cfg['green_agent']['host']}:{cfg['green_agent']['port']}"
            )

        # region agent log
        append_debug_log(
            run_id=run_id,
            hypothesis_id="H1",
            location="src/agentbeats/run_scenario.py:main:after_start",
            message="Started scenario subprocesses",
            data={
                "processes": _process_snapshot(procs, proc_labels),
            },
        )
        # endregion

        # Wait for all agents to be ready
        agents_ready = asyncio.run(wait_for_agents(cfg, procs, proc_labels, run_id))
        # region agent log
        append_debug_log(
            run_id=run_id,
            hypothesis_id="H5",
            location="src/agentbeats/run_scenario.py:main:after_wait_for_agents",
            message="wait_for_agents completed",
            data={
                "agents_ready": agents_ready,
                "processes": _process_snapshot(procs, proc_labels),
            },
        )
        # endregion
        if not agents_ready:
            print("Error: Not all agents became ready. Exiting.")
            exit_code = 1
            return exit_code

        print("Agents started. Press Ctrl+C to stop.")
        if args.serve_only:
            while True:
                for proc in procs:
                    if proc.poll() is not None:
                        print(f"Agent exited with code {proc.returncode}")
                        exit_code = proc.returncode or 1
                        return exit_code
                    time.sleep(0.5)
        else:
            dead_servers = _dead_server_processes(procs, proc_labels)
            if dead_servers:
                # region agent log
                append_debug_log(
                    run_id=run_id,
                    hypothesis_id="H1",
                    location="src/agentbeats/run_scenario.py:main:pre_client_dead_servers",
                    message="Refusing to start client because server process already exited",
                    data={"dead_servers": dead_servers},
                )
                # endregion
                print(
                    "Error: Server process exited before client start; likely port contention "
                    f"or startup failure: {dead_servers}"
                )
                exit_code = 1
                return exit_code

            client_cmd = [sys.executable, "-m", "agentbeats.client_cli", args.scenario]
            if args.normal_user:
                client_cmd.append("--normal-user")
            client_proc = subprocess.Popen(
                client_cmd,
                env=base_env,
                start_new_session=True,
            )
            procs.append(client_proc)
            proc_labels[client_proc.pid] = "client_cli"
            client_proc.wait()
            # region agent log
            append_debug_log(
                run_id=run_id,
                hypothesis_id="H3",
                location="src/agentbeats/run_scenario.py:main:after_client_wait",
                message="Client process exited",
                data={
                    "client_returncode": client_proc.returncode,
                    "processes": _process_snapshot(procs, proc_labels),
                },
            )
            # endregion
            if client_proc.returncode != 0:
                print(f"Error: Scenario client exited with code {client_proc.returncode}")
                exit_code = client_proc.returncode or 1
            dead_servers = _dead_server_processes(procs, proc_labels)
            if dead_servers:
                print(
                    "Error: One or more server processes exited during scenario run: "
                    f"{dead_servers}"
                )
                exit_code = exit_code or 1

    except KeyboardInterrupt:
        exit_code = 130

    finally:
        # region agent log
        append_debug_log(
            run_id=run_id,
            hypothesis_id="H1",
            location="src/agentbeats/run_scenario.py:main:shutdown_begin",
            message="Beginning scenario shutdown",
            data={
                "processes": _process_snapshot(procs, proc_labels),
            },
        )
        # endregion
        print("\nShutting down...")
        for p in procs:
            if p.poll() is None:
                try:
                    os.killpg(p.pid, signal.SIGTERM)
                except ProcessLookupError:
                    pass
        time.sleep(1)
        for p in procs:
            if p.poll() is None:
                try:
                    os.killpg(p.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass

    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
