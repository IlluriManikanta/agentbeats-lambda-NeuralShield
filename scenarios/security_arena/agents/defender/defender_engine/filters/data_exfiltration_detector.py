"""DEPRECATED: legacy exfiltration detector (unused)."""

from __future__ import annotations


def detect(prompt: str) -> bool:
    """Compatibility no-op. The active pipeline does not use this detector."""
    _ = prompt
    return False


