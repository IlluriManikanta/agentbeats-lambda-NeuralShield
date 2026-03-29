"""
Discover all scenario detail URLs from the public index page.

Run after: `pip install -r scenario_scrape/requirements.txt`
"""

from __future__ import annotations

import re
from typing import List
from urllib.parse import urljoin, urlparse

import requests
from bs4 import BeautifulSoup

from utils import DEFAULT_HEADERS, INDEX_URL, S3_HOST, html_body_utf8

# Slug segment in /{slug}/index.html (letters, digits, underscore).
_SLUG_RE = re.compile(r"^[a-zA-Z0-9_]+$")

# Fallback: full URLs embedded anywhere in the HTML (robust if <a> layout changes).
_URL_FALLBACK_RE = re.compile(
    r"https://agentbeats-lambda\.s3\.us-east-1\.amazonaws\.com/([a-zA-Z0-9_]+)/index\.html"
)


def _is_scenario_url(absolute: str) -> bool:
    """True if URL points to a single-scenario index under the S3 host."""
    try:
        parsed = urlparse(absolute)
    except ValueError:
        return False
    if parsed.netloc.lower() != S3_HOST.lower():
        return False
    parts = [p for p in parsed.path.split("/") if p]
    if len(parts) != 2:
        return False
    slug, name = parts
    if name != "index.html":
        return False
    if not _SLUG_RE.match(slug):
        return False
    if slug.lower() == "index":
        return False
    return True


def get_all_scenario_urls(session: requests.Session | None = None) -> List[str]:
    """
    Fetch the main index, collect every link to `/<slug>/index.html`, dedupe, sort.

    Primary path: BeautifulSoup + urljoin on <a href>.
    Fallback: regex scan of raw HTML if link parsing yields too few rows (< 50).
    """
    sess = session or requests.Session()
    # Step A — download the shuffled scenario index (static HTML on S3).
    resp = sess.get(INDEX_URL, headers=DEFAULT_HEADERS, timeout=(10, 60))
    resp.raise_for_status()
    html = html_body_utf8(resp)

    found: set[str] = set()

    # Step B — resolve each <a href> to an absolute URL and keep scenario detail pages only.
    soup = BeautifulSoup(html, "html.parser")
    for tag in soup.find_all("a", href=True):
        absolute = urljoin(INDEX_URL, tag["href"])
        if _is_scenario_url(absolute):
            found.add(absolute.rstrip("/"))

    # Step C — if anchors are missing or the DOM changes, scrape full URLs from raw HTML.
    if len(found) < 50:
        for m in _URL_FALLBACK_RE.finditer(html):
            slug = m.group(1)
            if slug.lower() != "index":
                found.add(f"https://{S3_HOST}/{slug}/index.html")

    return sorted(found)
