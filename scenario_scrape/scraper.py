#!/usr/bin/env python3
"""
End-to-end AgentBeats scenario scraper.

Run from repo root:
  pip install -r scenario_scrape/requirements.txt
  python scenario_scrape/scraper.py

Or from this directory:
  pip install -r requirements.txt
  python scraper.py
"""

from __future__ import annotations

import json
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

import requests
from tqdm import tqdm

from parser import parse_scenario_page
from scenario_urls import get_all_scenario_urls
from utils import DEFAULT_HEADERS, html_body_utf8, log_progress

# Same directory as this file (works whether cwd is repo root or scenario_scrape/).
_ROOT = Path(__file__).resolve().parent
OUTPUT_PATH = _ROOT / "data" / "scenario_data.json"

MAX_WORKERS = 10
MAX_ATTEMPTS = 3
CONNECT_TIMEOUT = 10
READ_TIMEOUT = 45
BACKOFF_BASE_S = 0.5


def _fetch_html(url: str) -> str | None:
    """
    GET one scenario page with retries (timeouts, 5xx, connection errors).
    Returns HTML text or None after all attempts fail.
    """
    last_err: Exception | None = None
    for attempt in range(MAX_ATTEMPTS):
        try:
            resp = requests.get(
                url,
                headers=DEFAULT_HEADERS,
                timeout=(CONNECT_TIMEOUT, READ_TIMEOUT),
            )
            if resp.status_code >= 500:
                raise requests.HTTPError(f"HTTP {resp.status_code}")
            resp.raise_for_status()
            return html_body_utf8(resp)
        except (requests.Timeout, requests.ConnectionError, requests.HTTPError) as exc:
            last_err = exc
            if attempt < MAX_ATTEMPTS - 1:
                time.sleep(BACKOFF_BASE_S * (2**attempt))
        except requests.RequestException as exc:
            last_err = exc
            break
    print(f"[warn] giving up on {url}: {last_err}", file=sys.stderr)
    return None


def _process_url(url: str) -> dict | None:
    """Fetch and parse a single scenario URL."""
    html = _fetch_html(url)
    if html is None:
        return None
    try:
        return parse_scenario_page(html, url)
    except Exception as exc:  # noqa: BLE001 — keep pipeline resilient
        print(f"[warn] parse failed for {url}: {exc}", file=sys.stderr)
        return None


def main() -> None:
    # Step 1: discover URLs from the public index.
    print("[info] fetching scenario index…", flush=True)
    urls = get_all_scenario_urls()
    print(f"[info] {len(urls)} scenario URLs discovered", flush=True)
    if len(urls) != 424:
        print(
            f"[warn] expected 424 scenarios, found {len(urls)} — check index or network",
            file=sys.stderr,
        )

    scenarios: list[dict] = []
    total = len(urls)
    completed = 0

    # Step 2: concurrent fetch + parse with bounded workers.
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as pool:
        futures = {pool.submit(_process_url, u): u for u in urls}
        with tqdm(total=total, desc="Scenarios", unit="page") as bar:
            for fut in as_completed(futures):
                row = fut.result()
                if row is not None:
                    scenarios.append(row)
                completed += 1
                bar.update(1)
                log_progress(completed, total)

    # Stable order by slug / URL for reproducible diffs.
    scenarios.sort(key=lambda r: r.get("url", ""))

    payload = {
        "total_scenarios": len(scenarios),
        "scenarios": scenarios,
    }

    # Step 3: write UTF-8 JSON next to this package.
    OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT_PATH.write_text(
        json.dumps(payload, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    print(f"[info] wrote {OUTPUT_PATH} ({len(scenarios)} scenarios)", flush=True)


if __name__ == "__main__":
    main()
