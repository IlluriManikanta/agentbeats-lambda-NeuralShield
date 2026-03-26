"""Prompt injection detector.

Version 1 is intentionally simple and purely keyword-based.

NOTE: This module is currently NOT used by the main SecurityGateway.
The 2-pass LLM pipeline in main.py uses structural_analyzer + LLM analysis
instead. This is kept for potential future use or as a fast pre-filter.
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
    # Use injection_patterns from KeywordConfig
    return any(keyword in lower for keyword in KEYWORDS.injection_patterns)


