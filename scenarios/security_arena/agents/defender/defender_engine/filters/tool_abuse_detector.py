"""Tool abuse detector.

Flags attempts to execute commands, access system files, or otherwise
abuse tools that the defender may have access to.

NOTE: This module is currently NOT used by the main SecurityGateway.
The 2-pass LLM pipeline in main.py uses structural_analyzer + LLM analysis
instead. This is kept for potential future use or as a fast pre-filter.
"""

from __future__ import annotations

from ..config import KEYWORDS


def detect(prompt: str) -> bool:
    """
    Return True if the prompt appears to request tool or system abuse.

    This detector is intentionally simple and only uses keyword checks.
    """
    if not prompt:
        return False

    lower = prompt.lower()
    # Use authority_patterns from KeywordConfig (closest match for tool abuse)
    return any(keyword in lower for keyword in KEYWORDS.authority_patterns)


