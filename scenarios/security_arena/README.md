# Security Arena

Adversarial security battles between AI attacker and defender agents. All agents use [openai/gpt-oss-20b](https://huggingface.co/openai/gpt-oss-20b).

## Local evaluation (Ollama)

Use a repo-root `.env` with `OPENAI_BASE_URL=http://127.0.0.1:11434/v1`, `OPENAI_API_KEY=ollama`, and `ARENA_OLLAMA_MODEL` set to a small pulled model (see [`.env.example`](../../.env.example)). The same OpenAI-compatible client is used for cloud and local; switch the URL/key back for OpenAI. Bulk runs: [bulk_scenarios/README.md](bulk_scenarios/README.md) (section **Local Ollama**).

## Documentation

- **[Phase 2: Attack & Defend](docs/phase2.md)** — Build attacker/defender agents, submit, and compete on the leaderboard
- **[Phase 1: Scenario Implementation](docs/phase1.md)** — Framework architecture, plugin system, and scenario creation
