"""DEPRECATED: legacy intent classifier.

The redesigned defender performs semantic intent separation inside Pass 1
(`analyze_and_extract`) and no longer relies on this module for decisions.
Compatibility stubs are kept to avoid import breakage in external tooling.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import List, Tuple


class IntentType(Enum):
    DATA = "data"
    INSTRUCTION = "instruction"
    META = "meta"
    OVERRIDE = "override"
    MIXED = "mixed"


@dataclass
class IntentResult:
    primary_intent: IntentType
    confidence: float
    flags: List[str]
    instruction_spans: List[Tuple[int, int]]
    meta_claims: List[str]
    override_attempts: List[str]


def classify_intent(text: str, context: str = "") -> IntentResult:
    """Compatibility stub: returns neutral DATA intent."""
    _ = (text, context)
    return IntentResult(
        primary_intent=IntentType.DATA,
        confidence=1.0,
        flags=[],
        instruction_spans=[],
        meta_claims=[],
        override_attempts=[],
    )


def detect_embedded_instructions(text: str) -> List[Tuple[str, str, float]]:
    """Compatibility stub: no embedded instructions returned."""
    _ = text
    return []


def get_intent_risk_adjustment(result: IntentResult) -> float:
    """Compatibility stub: intent no longer contributes direct risk boost."""
    _ = result
    return 0.0


def classify_segments(segments: List[any], context: str = "") -> dict[str, IntentResult]:
    """Compatibility stub: classify all segments as DATA."""
    _ = context
    output: dict[str, IntentResult] = {}
    for seg in segments:
        seg_key = getattr(seg, "doc_id", None) or f"seg_{getattr(seg, 'start_idx', 0)}"
        output[seg_key] = classify_intent(getattr(seg, "content", ""))
    return output
