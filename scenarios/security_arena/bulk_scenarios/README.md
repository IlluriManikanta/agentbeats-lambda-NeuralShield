# Bulk scenario runner and dashboard

## Run example scenarios (hand-written TOMLs in `scenarios/security_arena/`)

These are **not** the generated bulk library (`generated_tomls/`). They are the top-level `scenario_*.toml` files, for example:

- `medical_example`, `thingularity`, `gymjailbreak`, `resume_downgrade`, `portfolioiq`

```bash
# From repo root — run every example TOML in that folder
uv run python scenarios/security_arena/bulk_scenarios/run_bulk_scenarios.py --examples
```

**Only some examples** (slugs = filename without `scenario_` and `.toml`):

```bash
uv run python scenarios/security_arena/bulk_scenarios/run_bulk_scenarios.py --only medical_example gymjailbreak thingularity
```

**One scenario, no helper script** — results default to `results/<scenario_type>/` unless you set `AGENTBEATS_RESULTS_DIR`:

```bash
uv run agentbeats-run scenarios/security_arena/scenario_gymjailbreak.toml
```

With a single worker (sequential):

```bash
uv run python scenarios/security_arena/bulk_scenarios/run_bulk_scenarios.py --examples --workers 1
```

Run the **same** scenario set multiple times (outputs go to `results/<slug>/repeat_001/`, `repeat_002/`, …; the dashboard **aggregates** trials per slug):

```bash
uv run python scenarios/security_arena/bulk_scenarios/run_bulk_scenarios.py --examples --repeat 3 --dashboard
```

## Run all bulk scenarios (~424)

Requires generated TOMLs from `scrape_and_generate_tomls.py` in `generated_tomls/`.

```bash
uv run python scenarios/security_arena/bulk_scenarios/run_bulk_scenarios.py
uv run python scenarios/security_arena/bulk_scenarios/run_bulk_scenarios.py --workers 8
uv run python scenarios/security_arena/bulk_scenarios/run_bulk_scenarios.py --limit 10   # test with 10 only
```

## Dashboard (after runs)

Results are written to `bulk_scenarios/results/<slug>/result.json`. To build and view the dashboard:

```bash
# Generate dashboard.html from results
uv run python scenarios/security_arena/bulk_scenarios/dashboard.py
```

Then open in a browser:

```
scenarios/security_arena/bulk_scenarios/dashboard.html
```

Run examples, regenerate the dashboard (with outcome + prompt-improvement columns), and **open the dashboard in your browser**:

```bash
uv run python scenarios/security_arena/bulk_scenarios/run_bulk_scenarios.py --examples --open
```

Shortcut (same as `--examples --open`; add `--only …` or `--workers 1` as needed):

```bash
uv run python scenarios/security_arena/bulk_scenarios/arena_report.py
```

To refresh the dashboard **without** re-running scenarios:

```bash
uv run python scenarios/security_arena/bulk_scenarios/dashboard.py --open
```
