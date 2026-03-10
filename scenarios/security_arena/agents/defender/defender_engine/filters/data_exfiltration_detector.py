"""Data exfiltration detector.

Detects obvious attempts to retrieve sensitive data such as passwords,
API keys, tokens, or other credentials using simple keyword rules.
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
    return any(keyword in lower for keyword in KEYWORDS.data_exfiltration_keywords)


