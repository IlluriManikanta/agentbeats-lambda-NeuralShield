"""Output sanitizer for LLM responses.

Scans generated text for obvious sensitive information markers and
replaces unsafe outputs with a standard refusal message.
"""

from __future__ import annotations

from ..config import KEYWORDS, SAFE_REFUSAL_MESSAGE


def sanitize_output(text: str) -> str:
    """
    Sanitize model output.

    If the output appears to contain sensitive information (based on
    simple keyword checks), return the safe refusal message instead.
    Otherwise, return the original text unchanged.
    """
    if not text:
        return text

    lower = text.lower()
    if any(keyword in lower for keyword in KEYWORDS.output_sensitive_keywords):
        return SAFE_REFUSAL_MESSAGE

    return text


