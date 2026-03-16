"""Tool abuse detector.

Flags attempts to execute commands, access system files, or otherwise
abuse tools that the defender may have access to.
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
    return any(keyword in lower for keyword in KEYWORDS.tool_abuse_keywords)


