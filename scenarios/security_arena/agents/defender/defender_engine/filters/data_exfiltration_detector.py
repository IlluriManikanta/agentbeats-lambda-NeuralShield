"""Data exfiltration detector.

Detects obvious attempts to retrieve sensitive data such as passwords,
API keys, tokens, or other credentials using simple keyword rules.

NOTE: This module is currently NOT used by the main SecurityGateway.
The 2-pass LLM pipeline in main.py uses structural_analyzer + LLM analysis
instead. This is kept for potential future use or as a fast pre-filter.
"""

from __future__ import annotations

from ..config import KEYWORDS


def detect(prompt: str) -> bool:
    """
    Return True if the prompt appears to request sensitive data.

    Rule-based only: no LLM calls or external dependencies.
    """
    if not prompt:
        return False

    lower = prompt.lower()
    # Use exfiltration_patterns from KeywordConfig
    return any(keyword in lower for keyword in KEYWORDS.exfiltration_patterns)


