# Bulk scenario runner and dashboard

## Scenario plugin resolution (generated TOMLs)

Generated TOMLs use `scenario_type` values from the public scenario index. The registry still includes a small set of **canonical** plugins (`portfolioiq`, `thingularity`, `medical_records`, `resume_downgrade`, `gymjailbreak`). For local bulk evaluation:

1. **Exact match** — uses the real plugin (faithful behavior where implemented).
2. **Aliases** — a few generated slugs map to a canonical name (e.g. `resumedowngrade` → `resume_downgrade`). See `SCENARIO_ALIASES` in [`plugins/registry.py`](../plugins/registry.py).
3. **Fallback** — any other slug loads `GenericLocalEvalPlugin`: DIRECT-style prompts built from `scenario_catalog.json` when available. Attack **success detection is disabled** in the fallback (`check_success` always false); `winner` / defender “hold” outcomes are **not** competition-faithful. `result.json` includes `evaluation_provenance`, and `battle_log.md` / HTML add a banner for alias/fallback runs.

Disable fallback (restore strict unknown-type errors) with:

```bash
export SECURITY_ARENA_ALLOW_FALLBACK_PLUGINS=0
```

## Local Ollama (MacBook / single machine)

Agents and the defender use the **OpenAI Python client** (`AsyncOpenAI` / `OpenAI`) with `OPENAI_BASE_URL` and `OPENAI_API_KEY`. Pointing `OPENAI_BASE_URL` at Ollama’s **`/v1`** endpoint makes those calls hit your local server instead of OpenAI—**no code fork**; cloud runs use the same variables with `https://api.openai.com/v1` and a real key.

1. **Install & run Ollama** (menu bar app or `ollama serve`). If port 11434 is already in use, the server is up.

2. **Model:** Set `ARENA_OLLAMA_MODEL` to a tag from `ollama list` (or pull first, e.g. `ollama pull llama3.2:3b`). The bulk runner injects that tag into generated TOMLs (`--model` overrides env). **Change the model** by editing `.env`, exporting `ARENA_OLLAMA_MODEL`, or passing `--model <tag>`.

3. **Config:** From the repo root, copy [`.env.example`](../../.env.example) to `.env` and use the “Profile B” Ollama block, **or** use the tracked template values. `load_dotenv()` in agents, orchestrator, and `run_bulk_scenarios.py` loads `repo_root/.env` when you run from `uv`.

4. **Check Ollama:**

```bash
ollama --version
ollama list
curl -s http://127.0.0.1:11434/api/tags | head
```

5. **Smoke test** (examples, one scenario, one worker — default):

```bash
cd /path/to/agentbeats-lambda-NeuralShield
uv run python scenarios/security_arena/bulk_scenarios/run_bulk_scenarios.py --examples --limit 1
```

6. **Small bulk test** (first N generated scenarios; requires `generated_tomls/`):

```bash
uv run python scenarios/security_arena/bulk_scenarios/run_bulk_scenarios.py --limit 10
```

7. **Full bulk run** (all generated TOMLs; still default `--workers 1`):

```bash
uv run python scenarios/security_arena/bulk_scenarios/run_bulk_scenarios.py
```

**Failure signs:** HTTP errors to `127.0.0.1:11434`, `model ... not found` (pull the tag or fix `ARENA_OLLAMA_MODEL`), timeouts or OOM/swap thrash (use a smaller model or keep `--workers 1`).

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
# With Ollama env set (see "Local Ollama" above)
uv run python scenarios/security_arena/bulk_scenarios/run_bulk_scenarios.py
uv run python scenarios/security_arena/bulk_scenarios/run_bulk_scenarios.py --workers 1
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
