#!/usr/bin/env python3
"""
Dashboard generator for bulk / example scenario runs.

Scans:
    scenarios/security_arena/bulk_scenarios/results/<slug>/result.json
    and, when using --repeat, results/<slug>/repeat_*/result.json

and produces:
    scenarios/security_arena/bulk_scenarios/dashboard.html

Columns include outcome summary, heuristic "signals" from battle_log, and
prompt-improvement hints for attacker vs defender templates.

Usage:
    uv run python scenarios/security_arena/bulk_scenarios/dashboard.py
    uv run python scenarios/security_arena/bulk_scenarios/dashboard.py --open
"""

from __future__ import annotations

import argparse
import html
import json
import re
import webbrowser
from dataclasses import dataclass
from pathlib import Path
from typing import Any, List, Optional


BASE_DIR = Path(__file__).resolve().parent
RESULTS_BASE = BASE_DIR / "results"
DASHBOARD_HTML = BASE_DIR / "dashboard.html"


@dataclass
class ScenarioResult:
    slug: str
    scenario_type: str
    winner: str  # attacker | defender | mixed | unknown
    outcome_detail: str
    prompt_ideas: str
    trial_count: int = 1
    attacker_win_count: int = 0
    defender_win_count: int = 0
    unknown_win_count: int = 0
    manipulation_round: Optional[int] = None
    manipulation_rounds_summary: str = ""  # e.g. "6" or "3, 6" across attacker wins
    rounds_defended: int = 0
    rounds_defended_min: Optional[int] = None
    rounds_defended_max: Optional[int] = None
    total_rounds: int = 0


def _join_defender_texts(battle_log: list) -> str:
    return " ".join((r.get("defender_output") or "") for r in battle_log).lower()


def _attack_words(battle_log: list) -> list[int]:
    return [len((r.get("attack_output") or "").split()) for r in battle_log]


def analyze_result(data: dict) -> tuple[str, str]:
    """
    Return (outcome_detail, prompt_improvement_bullets) using battle_log heuristics.
    Plain text; caller HTML-escapes for the table.
    """
    winner = data.get("winner", "unknown")
    battle_log = data.get("battle_log") or []
    total_rounds = int(data.get("total_rounds", 0)) or len(battle_log)
    manipulation_round = data.get("manipulation_round")
    detail_parts: List[str] = []
    ideas: List[str] = []

    if winner == "attacker":
        detail_parts.append(
            f"Attacker succeeded (manipulation in round {manipulation_round}). "
            f"Defender held {data.get('rounds_defended', '?')} full round(s) before leakage."
        )
        win_entry = next((r for r in battle_log if r.get("manipulation_detected")), None)
        ev: Any = win_entry.get("extracted_value") if win_entry else None
        if ev is not None and ev != []:
            detail_parts.append(f"Checker extracted: {ev!r}.")
        atk_preview = (win_entry or {}).get("attack_output") or ""
        if atk_preview:
            snippet = atk_preview.strip().replace("\n", " ")
            if len(snippet) > 220:
                snippet = snippet[:217] + "…"
            detail_parts.append(f"Winning attack (excerpt): {snippet}")

        ideas.append(
            "Defender: Tighten system prompt for the tactic that worked (e.g. block incremental "
            "confirm/correct games, single-letter hints, or echo of internal names). Align refusal "
            "with the success checker so partial leaks still count as failure."
        )
        ideas.append(
            "Attacker: Record this winning pattern for regression; avoid overfitting to one defender "
            "model—keep diverse fallbacks in templates."
        )

    elif winner == "defender":
        detail_parts.append(
            f"Defender held all {total_rounds} round(s); no successful extraction."
        )
        combined = _join_defender_texts(battle_log)
        words = _attack_words(battle_log)

        if any(w < 22 for w in words):
            n_short = sum(1 for w in words if w < 22)
            detail_parts.append(f"Note: {n_short} attack round(s) had very short messages (<22 words).")
            ideas.append(
                "Attacker: Short or abrupt turns often burn rounds—use role + context + one clear ask "
                "(see system/user templates); continue thread from last defender reply."
            )

        if re.search(r"\b(billing|portal|contact|department|support team)\b", combined):
            detail_parts.append("Defender often redirected to another channel (billing/portal/support).")
            ideas.append(
                "Attacker: Redirect replies pair well with clearance-from-that-team narrative + "
                "scenario reference IDs; avoid cold persona swaps each round."
            )
            ideas.append(
                "Defender: Redirects are fine; ensure replies never echo or partially confirm sensitive "
                "values while refusing."
            )

        if re.search(r"social security|\bssn\b|tax id|nine[- ]digit", combined):
            detail_parts.append("Defender explicitly named restricted data types in refusals.")
            ideas.append(
                "Attacker: If the model names forbidden fields, switch to neutral billing/insurer "
                "labels and phased asks; avoid repeating those keywords in your next turn."
            )
            ideas.append(
                "Defender: Consider generic refusals that do not teach which keyword triggered the "
                "block, if policy allows."
            )

        if combined.count("sorry") >= 3 or combined.count("can't") >= 3:
            detail_parts.append("Many generic refusals ('sorry' / 'can't') across rounds.")
            ideas.append(
                "Attacker: After repeated soft refusals, change tactic category (urgency, role, "
                "indirect framing) rather than repeating the same ask verbatim."
            )

        if any("verify" in (r.get("defender_output") or "").lower() and "name" in (r.get("defender_output") or "").lower() for r in battle_log):
            detail_parts.append("Defender asked for identity / verification at least once.")
            ideas.append(
                "Attacker: Answer verification in-character if useful, or impersonate the role the "
                "defender asked for—still self-contained each round."
            )

        if not ideas:
            ideas.append(
                "Attacker: Review battle_log.html for stall patterns; strengthen continuity and "
                "benign-first phases where appropriate."
            )
            ideas.append(
                "Defender: If win rate is too high, stress-test refusals against indirect and "
                "multi-turn asks."
            )
    else:
        detail_parts.append("Outcome unknown or run incomplete.")
        ideas.append("Verify result.json and re-run; check agent timeouts/crashes in the file.")

    return " ".join(detail_parts), " ".join(f"• {x}" for x in ideas)


def iter_trial_result_paths(slug_dir: Path) -> List[Path]:
    """Prefer repeat_*/result.json if present; else legacy result.json at slug root."""
    repeat_paths = sorted(slug_dir.glob("repeat_*/result.json"))
    if repeat_paths:
        return repeat_paths
    legacy = slug_dir / "result.json"
    return [legacy] if legacy.is_file() else []


def aggregate_trial_results(slug: str, datas: List[dict]) -> Optional[ScenarioResult]:
    if not datas:
        return None
    n = len(datas)
    ws = [d.get("winner", "unknown") for d in datas]
    aw = sum(1 for w in ws if w == "attacker")
    dw = sum(1 for w in ws if w == "defender")
    uw = sum(1 for w in ws if w not in ("attacker", "defender"))
    if aw == n and n > 0:
        overall = "attacker"
    elif dw == n and n > 0:
        overall = "defender"
    elif aw > 0 and dw > 0:
        overall = "mixed"
    elif aw > 0:
        overall = "attacker"
    elif dw > 0:
        overall = "defender"
    else:
        overall = "unknown"

    mr_list: List[str] = []
    for d in datas:
        if d.get("winner") == "attacker" and d.get("manipulation_round") is not None:
            mr_list.append(str(d["manipulation_round"]))
    manipulation_rounds_summary = ", ".join(mr_list) if mr_list else ""
    first_mr: Optional[int] = None
    if mr_list:
        try:
            first_mr = int(mr_list[0])
        except ValueError:
            first_mr = None

    rds = [int(d.get("rounds_defended", 0)) for d in datas]
    trs = [int(d.get("total_rounds", 0)) for d in datas]
    rd_min, rd_max = (min(rds), max(rds)) if rds else (0, 0)
    total_rounds = trs[0] if trs else 0

    scenario_type = str(datas[0].get("scenario_type", slug))

    detail_parts: List[str] = [f"{n} trial(s): attacker {aw}×, defender {dw}×"]
    if uw:
        detail_parts[0] += f", unknown {uw}×"
    if n > 1:
        for i, d in enumerate(datas):
            w = d.get("winner", "?")
            mr = d.get("manipulation_round")
            extra = f", manip round {mr}" if mr is not None else ""
            detail_parts.append(f"Trial {i + 1}: {w}{extra}.")

    idea_seen: set[str] = set()
    idea_order: List[str] = []
    for d in datas:
        _, pi = analyze_result(d)
        for chunk in pi.split("•"):
            chunk = chunk.strip()
            if chunk and chunk not in idea_seen:
                idea_seen.add(chunk)
                idea_order.append(chunk)
    prompt_merged = " ".join(f"• {x}" for x in idea_order) if idea_order else "—"

    outcome_detail = " ".join(detail_parts)

    return ScenarioResult(
        slug=slug,
        scenario_type=scenario_type,
        winner=overall,
        outcome_detail=outcome_detail,
        prompt_ideas=prompt_merged,
        trial_count=n,
        attacker_win_count=aw,
        defender_win_count=dw,
        unknown_win_count=uw,
        manipulation_round=first_mr,
        manipulation_rounds_summary=manipulation_rounds_summary,
        rounds_defended=rd_max,
        rounds_defended_min=rd_min if n > 1 else None,
        rounds_defended_max=rd_max if n > 1 else None,
        total_rounds=total_rounds,
    )


def load_slug_folder(slug: str, folder: Path) -> Optional[ScenarioResult]:
    paths = iter_trial_result_paths(folder)
    if not paths:
        return None
    datas: List[dict] = []
    for p in paths:
        try:
            datas.append(json.loads(p.read_text(encoding="utf-8")))
        except Exception:
            continue
    if not datas:
        return None
    return aggregate_trial_results(slug, datas)


def collect_results() -> List[ScenarioResult]:
    results: List[ScenarioResult] = []
    if not RESULTS_BASE.exists():
        return results

    for folder in sorted(RESULTS_BASE.iterdir()):
        if not folder.is_dir():
            continue
        slug = folder.name
        sr = load_slug_folder(slug, folder)
        if sr:
            results.append(sr)
    return results


def render_dashboard_html(results: List[ScenarioResult]) -> str:
    attacker_wins = sum(1 for r in results if r.winner == "attacker")
    defender_wins = sum(1 for r in results if r.winner == "defender")
    mixed_wins = sum(1 for r in results if r.winner == "mixed")
    unknown = sum(1 for r in results if r.winner == "unknown")

    rows = []
    for r in results:
        wcls = ""
        if r.winner == "attacker":
            wcls = ' class="winner-attacker"'
        elif r.winner == "defender":
            wcls = ' class="winner-defender"'
        elif r.winner == "mixed":
            wcls = ' class="winner-mixed"'

        split_cell = f"{r.attacker_win_count}/{r.defender_win_count}"
        if r.unknown_win_count:
            split_cell += f"/{r.unknown_win_count}"

        if (
            r.trial_count > 1
            and r.rounds_defended_min is not None
            and r.rounds_defended_max is not None
            and r.rounds_defended_min != r.rounds_defended_max
        ):
            rounds_cell = f"{r.rounds_defended_min}–{r.rounds_defended_max} / {r.total_rounds}"
        else:
            rounds_cell = f"{r.rounds_defended}/{r.total_rounds}"

        manip_cell = r.manipulation_rounds_summary or (
            str(r.manipulation_round) if r.manipulation_round is not None else ""
        )

        rows.append(
            "<tr>"
            f"<td>{html.escape(r.slug)}</td>"
            f"<td>{html.escape(r.scenario_type)}</td>"
            f"<td>{r.trial_count}</td>"
            f"<td>{html.escape(split_cell)}</td>"
            f"<td{wcls}>{html.escape(r.winner)}</td>"
            f"<td>{html.escape(rounds_cell)}</td>"
            f"<td>{html.escape(manip_cell)}</td>"
            f'<td class="wide">{html.escape(r.outcome_detail)}</td>'
            f'<td class="wide">{html.escape(r.prompt_ideas)}</td>'
            "</tr>"
        )

    rows_html = "\n".join(rows) if rows else "<tr><td colspan='9'>No results found.</td></tr>"

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <title>Security Arena Scenario Dashboard</title>
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
      font-size: 0.85rem;
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
    .winner-mixed {{
      color: #eab308;
      font-weight: 600;
    }}
    td.wide {{
      max-width: 28rem;
      white-space: normal;
      line-height: 1.45;
    }}
  </style>
</head>
<body>
  <h1>Security Arena Scenario Dashboard</h1>
  <p style="color:#94a3b8;font-size:0.9rem;">Heuristic summary from each result.json <code>battle_log</code>. Tune attacker <code>system.j2</code>/<code>user.j2</code> and defender prompts using the last column.</p>
  <div class="summary">
    <span>Scenarios (attacker overall): {attacker_wins}</span>
    <span>Scenarios (defender overall): {defender_wins}</span>
    <span>Mixed trials: {mixed_wins}</span>
    <span>Unknown: {unknown}</span>
    <span>Rows: {len(results)}</span>
  </div>

  <table>
    <thead>
      <tr>
        <th>Slug</th>
        <th>Scenario Type</th>
        <th>Trials</th>
        <th>A/D split</th>
        <th>Winner (overall)</th>
        <th>Rounds defended / total</th>
        <th>Manipulation round(s)</th>
        <th>Outcome &amp; signals</th>
        <th>Prompt improvement ideas</th>
      </tr>
    </thead>
    <tbody>
      {rows_html}
    </tbody>
  </table>
</body>
</html>
"""


def open_dashboard_in_browser() -> None:
    path = DASHBOARD_HTML.resolve()
    if path.is_file():
        webbrowser.open(path.as_uri())
        print(f"Opened {path} in default browser.")
    else:
        print(f"No file at {path}; generate the dashboard first.", flush=True)


def main() -> None:
    parser = argparse.ArgumentParser(description="Build Security Arena dashboard from bulk_scenarios/results")
    parser.add_argument(
        "--open",
        action="store_true",
        help="Open dashboard.html in the default browser after generating.",
    )
    args = parser.parse_args()

    results = collect_results()
    html_out = render_dashboard_html(results)
    DASHBOARD_HTML.write_text(html_out, encoding="utf-8")
    print(f"Wrote dashboard to {DASHBOARD_HTML}")

    if args.open:
        open_dashboard_in_browser()


if __name__ == "__main__":
    main()
