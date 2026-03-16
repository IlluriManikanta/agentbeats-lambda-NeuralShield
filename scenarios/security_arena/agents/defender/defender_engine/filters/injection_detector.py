"""Prompt injection detector.

Version 1 is intentionally simple and purely keyword-based.
"""

from __future__ import annotations

from ..config import KEYWORDS


def detect(prompt: str) -> bool:
    """
    Return True if the prompt appears to contain prompt injection attempts.

    This is a lightweight, rule-based detector using case-insensitive
    keyword matching. It must not call any LLMs.
    """
    if not prompt:
        return False

    lower = prompt.lower()
    return any(keyword in lower for keyword in KEYWORDS.injection_keywords)


