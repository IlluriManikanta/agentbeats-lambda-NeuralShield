"""Policy decision engine for the baseline defender."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class Decision(Enum):
    """High-level policy decision outcome."""

    ALLOW = "allow"
    BLOCK = "block"


@dataclass
class DetectionResult:
    """Aggregated results from rule-based detectors."""

    prompt_injection: bool
    data_exfiltration: bool
    tool_abuse: bool


class DecisionEngine:
    """
    Combine rule-based detector outputs into a final policy decision.

    Version 1 policy:
        If ANY detector flags malicious intent -> BLOCK
        Else                                     ALLOW
    """

    def decide(self, detections: DetectionResult) -> Decision:
        if (
            detections.prompt_injection
            or detections.data_exfiltration
            or detections.tool_abuse
        ):
            return Decision.BLOCK
        return Decision.ALLOW


