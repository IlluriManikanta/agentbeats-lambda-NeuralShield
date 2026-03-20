# Bulk scenario runner and dashboard

## Run example scenarios (5 scenarios)

Runs only the example scenarios in `scenarios/security_arena/`:
- medical_example, thingularity, gymjailbreak, resume_downgrade, portfolioiq

```bash
# From repo root
uv run python scenarios/security_arena/bulk_scenarios/run_bulk_scenarios.py --examples
```

With a single worker (sequential):

```bash
uv run python scenarios/security_arena/bulk_scenarios/run_bulk_scenarios.py --examples --workers 1
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

Or run examples and build the dashboard in one go:

```bash
uv run python scenarios/security_arena/bulk_scenarios/run_bulk_scenarios.py --examples --dashboard
```
