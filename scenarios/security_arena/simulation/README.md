# Simulation: talk till attacker wins, then record strategy

This directory provides a **simulation environment** that uses only **new files**; it does not modify the orchestrator, plugin base, or attacker/defender code.

## What it does

1. **Run a scenario with many rounds** so the attacker has more chances to succeed.
2. **Record what worked** when the attacker wins: the winning round’s attack is appended to `successful_strategies.json` in this directory, keyed by scenario type.

You can then use `successful_strategies.json` as reference to update prompts or feed into a custom attacker (e.g. a wrapper that reads this file) without changing existing code.

## Usage

### 1. Run until win (run scenario with high rounds, then record if attacker won)

From the repo root:

```bash
uv run python scenarios/security_arena/simulation/run_until_win.py scenarios/security_arena/scenario_medical_example.toml --num-rounds 20
```

- Results are written to `simulation/runs/<slug>/` (e.g. `simulation/runs/medical_example/`).
- If the attacker won, the winning strategy is appended to `simulation/successful_strategies.json`.

Options:

- `--num-rounds N` — override `num_rounds` in the TOML (default 20; arena max is 20).
- `--results-dir DIR` — use this directory for results instead of `simulation/runs/<slug>`.

### 2. Record from an existing result directory

If you already ran a scenario (e.g. via bulk or single run) and the attacker won:

```bash
uv run python scenarios/security_arena/simulation/record_winning_strategy.py <results_dir>
```

Example:

```bash
uv run python scenarios/security_arena/simulation/record_winning_strategy.py scenarios/security_arena/bulk_scenarios/results/medical_example
```

This reads `result.json` from that dir; if `winner == "attacker"`, it appends the winning round’s attack to `simulation/successful_strategies.json`.

## Output: `successful_strategies.json`

Stored in this directory. Format:

```json
{
  "strategies": [
    {
      "scenario_type": "medical_records",
      "round": 3,
      "attack_output": "...",
      "summary": "..."
    }
  ]
}
```

Up to 5 entries per `scenario_type` are kept (oldest dropped when over limit).

## Using the recorded strategies

- **Manual:** Copy from `successful_strategies.json` into your attacker prompt or scenario docs.
- **Custom attacker:** You can build a separate attacker entrypoint (in this directory or elsewhere) that reads `simulation/successful_strategies.json` and injects prior strategies into the prompt; the existing orchestrator and attacker code stay unchanged.

## Requirements

- Run from repo root so `uv run agentbeats-run` and imports resolve.
- Orchestrator and agents are **not** modified; this simulation layer only runs the existing pipeline and records results.
