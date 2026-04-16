#!/usr/bin/env python3
"""
Simple dashboard generator for bulk scenario runs.

Scans:
    scenarios/security_arena/bulk_scenarios/results/<slug>/result.json

and produces:
    scenarios/security_arena/bulk_scenarios/dashboard.html

The dashboard shows:
  - Per-scenario winner (attacker/defender)
  - Rounds defended / total rounds
  - Inferred "reason" based on manipulation_round and basic heuristics
  - Aggregate totals for attacker vs defender wins

Usage:
    uv run python scenarios/security_arena/bulk_scenarios/dashboard.py
    # then open scenarios/security_arena/bulk_scenarios/dashboard.html in a browser
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional


BASE_DIR = Path(__file__).resolve().parent
RESULTS_BASE = BASE_DIR / "results"
DASHBOARD_HTML = BASE_DIR / "dashboard.html"


@dataclass
class ScenarioResult:
    slug: str
    scenario_type: str
    winner: str
    manipulation_round: Optional[int]
    rounds_defended: int
    total_rounds: int
    reason: str


def load_single_result(slug: str, folder: Path) -> Optional[ScenarioResult]:
    result_path = folder / "result.json"
    if not result_path.exists():
        return None

    try:
        data = json.loads(result_path.read_text(encoding="utf-8"))
    except Exception:
        return None

    scenario_type = data.get("scenario_type", slug)
    winner = data.get("winner", "unknown")
    manipulation_round = data.get("manipulation_round")
    rounds_defended = int(data.get("rounds_defended", 0))
    total_rounds = int(data.get("total_rounds", 0))

    # Simple heuristic "reason" inference.
    if winner == "attacker":
        if manipulation_round is not None:
            reason = f"Attacker successfully manipulated defender in round {manipulation_round}."
        else:
            reason = "Attacker succeeded (manipulation detected), round unknown."
    elif winner == "defender":
        reason = f"Defender resisted all {total_rounds or '?'} rounds; no manipulation detected."
    else:
        reason = "Outcome unknown (no clear winner recorded)."

    return ScenarioResult(
        slug=slug,
        scenario_type=scenario_type,
        winner=winner,
        manipulation_round=manipulation_round,
        rounds_defended=rounds_defended,
        total_rounds=total_rounds,
        reason=reason,
    )


def collect_results() -> List[ScenarioResult]:
    results: List[ScenarioResult] = []
    if not RESULTS_BASE.exists():
        return results

    for folder in sorted(RESULTS_BASE.iterdir()):
        if not folder.is_dir():
            continue
        slug = folder.name
        sr = load_single_result(slug, folder)
        if sr:
            results.append(sr)
    return results


def render_dashboard_html(results: List[ScenarioResult]) -> str:
    attacker_wins = sum(1 for r in results if r.winner == "attacker")
    defender_wins = sum(1 for r in results if r.winner == "defender")
    unknown = sum(1 for r in results if r.winner not in ("attacker", "defender"))

    rows = []
    for r in results:
        rows.append(
            f"<tr>"
            f"<td>{r.slug}</td>"
            f"<td>{r.scenario_type}</td>"
            f"<td>{r.winner}</td>"
            f"<td>{r.rounds_defended}/{r.total_rounds}</td>"
            f"<td>{(r.manipulation_round or '')}</td>"
            f"<td>{r.reason}</td>"
            f"</tr>"
        )

    rows_html = "\n".join(rows) if rows else "<tr><td colspan='6'>No results found.</td></tr>"

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <title>Security Arena Bulk Scenario Dashboard</title>
  <style>
    body {{
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
      margin: 20px;
      background: #0f172a;
      color: #e5e7eb;
    }}
    h1 {{
      margin-bottom: 0.25rem;
    }}
    .summary {{
      margin-bottom: 1.5rem;
    }}
    .summary span {{
      margin-right: 1.5rem;
      font-weight: 600;
    }}
    table {{
      border-collapse: collapse;
      width: 100%;
      background: #020617;
      border-radius: 8px;
      overflow: hidden;
    }}
    th, td {{
      border-bottom: 1px solid #1f2937;
      padding: 8px 10px;
      font-size: 0.9rem;
      vertical-align: top;
    }}
    th {{
      background: #111827;
      text-align: left;
      font-weight: 600;
    }}
    tr:nth-child(even) td {{
      background: #020617;
    }}
    tr:nth-child(odd) td {{
      background: #020617;
    }}
    .winner-attacker {{
      color: #f97316;
      font-weight: 600;
    }}
    .winner-defender {{
      color: #22c55e;
      font-weight: 600;
    }}
  </style>
</head>
<body>
  <h1>Security Arena Bulk Scenario Dashboard</h1>
  <div class="summary">
    <span>Attacker wins: {attacker_wins}</span>
    <span>Defender wins: {defender_wins}</span>
    <span>Unknown: {unknown}</span>
    <span>Total with results: {len(results)}</span>
  </div>

  <table>
    <thead>
      <tr>
        <th>Slug</th>
        <th>Scenario Type</th>
        <th>Winner</th>
        <th>Rounds Defended / Total</th>
        <th>Manipulation Round</th>
        <th>Inferred Reason</th>
      </tr>
    </thead>
    <tbody>
      {rows_html}
    </tbody>
  </table>
</body>
</html>
"""


def main() -> None:
    results = collect_results()
    html = render_dashboard_html(results)
    DASHBOARD_HTML.write_text(html, encoding="utf-8")
    print(f"Wrote dashboard to {DASHBOARD_HTML}")


if __name__ == "__main__":
    main()

