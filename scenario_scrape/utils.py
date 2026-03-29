"""
Shared helpers: HTTP defaults, text cleaning, and progress logging.
"""

from __future__ import annotations

import re
import unicodedata
from typing import TYPE_CHECKING, Final

if TYPE_CHECKING:
    import requests

# Canonical URLs for the public AgentBeats scenario browser (S3 static site).
BASE_URL: Final[str] = "https://agentbeats-lambda.s3.us-east-1.amazonaws.com"
INDEX_URL: Final[str] = f"{BASE_URL}/index.html"
S3_HOST: Final[str] = "agentbeats-lambda.s3.us-east-1.amazonaws.com"

# Polite default for static fetches.
DEFAULT_HEADERS: Final[dict[str, str]] = {
    "User-Agent": (
        "AgentBeatsScenarioScraper/1.0 (+https://github.com/LambdaLabsML/agentbeats-lambda; research)"
    ),
    "Accept": "text/html,application/xhtml+xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.9",
}


def html_body_utf8(response: "requests.Response") -> str:
    """
    Decode HTML as UTF-8 from raw bytes.

    S3 static pages are UTF-8, but Content-Type charset is sometimes wrong; using
    ``response.text`` then corrupts emoji in section titles and breaks parsing.
    """
    return response.content.decode("utf-8", errors="replace")


def clean_text(text: str | None) -> str:
    """
    Normalize page text: NFKC, drop most control chars, collapse whitespace,
    and use Unix newlines.
    """
    if not text:
        return ""

    # Unicode compatibility normalization (e.g. full-width digits).
    s = unicodedata.normalize("NFKC", text)

    # Remove C0 controls except newline/tab; strip other exotic controls.
    def _keep(ch: str) -> bool:
        o = ord(ch)
        if ch in "\n\t":
            return True
        if o < 32:
            return False
        if o == 0x7F:
            return False
        if unicodedata.category(ch) == "Cc":
            return False
        return True

    s = "".join(ch for ch in s if _keep(ch))

    # Normalize newlines then collapse horizontal whitespace runs.
    s = s.replace("\r\n", "\n").replace("\r", "\n")
    s = re.sub(r"[ \t]+", " ", s)
    s = re.sub(r"\n{3,}", "\n\n", s)
    return s.strip()


def log_progress(done: int, total: int) -> None:
    """Print a line every 10 completed items (and on the last item)."""
    if done <= 0:
        return
    if done % 10 == 0 or done == total:
        print(f"[progress] {done}/{total} scenarios fetched and parsed", flush=True)
