"""DEPRECATED: legacy policy engine.

The redesigned defender enforces policy directly in `main.py` using
task-centric extraction and validation. This module is retained for
backward compatibility only and is not used by the active execution path.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import List, Optional


class RiskLevel(Enum):
    """Graduated risk levels for policy decisions."""
    
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    
    @classmethod
    def from_string(cls, s: str) -> "RiskLevel":
        """Parse a risk level string (case-insensitive)."""
        s_lower = s.lower().strip()
        if s_lower == "low":
            return cls.LOW
        elif s_lower == "high":
            return cls.HIGH
        else:
            return cls.MEDIUM  # Default to medium for safety


class RecommendedAction(Enum):
    """Actions the gateway should take based on risk assessment."""
    
    PROCEED = "proceed"           # Execute task normally
    PROCEED_CAUTIOUS = "proceed_cautious"  # Execute with extra constraints
    REFUSE = "refuse"             # Return safe refusal
    REFUSE_SILENT = "refuse_silent"  # Return minimal/redirecting response


@dataclass
class RiskAssessment:
    """
    Comprehensive risk assessment from multiple sources.
    
    Combines:
    - Structural analysis flags (deterministic)
    - LLM security analysis (semantic)
    - Scenario-specific rules
    """
    
    risk_level: RiskLevel = RiskLevel.MEDIUM
    risk_score: float = 0.5  # 0.0 to 1.0
    risk_factors: List[str] = field(default_factory=list)
    threats: List[str] = field(default_factory=list)
    recommended_action: RecommendedAction = RecommendedAction.PROCEED_CAUTIOUS
    reasoning: str = ""
    
    @classmethod
    def from_llm_analysis(
        cls,
        llm_result: dict,
        structural_flags: Optional[List[str]] = None,
    ) -> "RiskAssessment":
        """
        Build a RiskAssessment from LLM analysis output and structural flags.
        """
        risk_level_str = llm_result.get("risk_level", "medium")
        risk_level = RiskLevel.from_string(risk_level_str)
        
        threats = llm_result.get("threats", [])
        reasoning = llm_result.get("reasoning", "")
        
        # Combine threats from LLM with structural flags
        risk_factors = list(threats)
        if structural_flags:
            risk_factors.extend(f"STRUCTURAL: {flag}" for flag in structural_flags)
        
        # Calculate risk score based on factors
        risk_score = cls._calculate_risk_score(risk_level, risk_factors)
        
        # Determine recommended action
        recommended_action = cls._determine_action(risk_level, risk_factors)
        
        return cls(
            risk_level=risk_level,
            risk_score=risk_score,
            risk_factors=risk_factors,
            threats=threats,
            recommended_action=recommended_action,
            reasoning=reasoning,
        )
    
    @staticmethod
    def _calculate_risk_score(risk_level: RiskLevel, factors: List[str]) -> float:
        """Calculate numeric risk score from 0.0 to 1.0."""
        base_scores = {
            RiskLevel.LOW: 0.2,
            RiskLevel.MEDIUM: 0.5,
            RiskLevel.HIGH: 0.8,
        }
        
        base = base_scores.get(risk_level, 0.5)
        
        # Adjust based on number of factors
        factor_adjustment = min(len(factors) * 0.05, 0.2)
        
        return min(base + factor_adjustment, 1.0)
    
    @staticmethod
    def _determine_action(risk_level: RiskLevel, factors: List[str]) -> RecommendedAction:
        """Determine recommended action based on risk profile."""
        if risk_level == RiskLevel.HIGH:
            # Check if it's a severe threat requiring refusal
            severe_indicators = [
                "prompt injection",
                "extract system prompt",
                "jailbreak",
                "role manipulation",
                # Competitor dismissal attacks
                "competitor_dismissal",
                "competitor_sabotage",
                "data_corruption_claim",
                "trailing_instruction_after_end_marker",
            ]
            factor_text = " ".join(factors).lower()
            
            if any(ind in factor_text for ind in severe_indicators):
                return RecommendedAction.REFUSE
            
            return RecommendedAction.PROCEED_CAUTIOUS
        
        elif risk_level == RiskLevel.MEDIUM:
            return RecommendedAction.PROCEED_CAUTIOUS
        
        else:
            return RecommendedAction.PROCEED


# === Legacy support for old DetectionResult-based code ===

class Decision(Enum):
    """Legacy: High-level policy decision outcome."""
    ALLOW = "allow"
    BLOCK = "block"


@dataclass
class DetectionResult:
    """Legacy: Aggregated results from rule-based detectors."""
    prompt_injection: bool
    data_exfiltration: bool
    tool_abuse: bool


class DecisionEngine:
    """
    Legacy decision engine maintained for backward compatibility.
    
    The new 2-pass pipeline uses RiskAssessment instead.
    This class is kept for any code that still uses the old interface.
    """

    def decide(self, detections: DetectionResult) -> Decision:
        """Legacy: Binary decision based on detector flags."""
        if (
            detections.prompt_injection
            or detections.data_exfiltration
            or detections.tool_abuse
        ):
            return Decision.BLOCK
        return Decision.ALLOW
    
    def assess_risk(
        self,
        detections: DetectionResult,
        structural_flags: Optional[List[str]] = None,
    ) -> RiskAssessment:
        """
        New: Create a RiskAssessment from legacy detection results.
        
        This allows gradual migration from binary to risk-based decisions.
        """
        risk_factors = []
        
        if detections.prompt_injection:
            risk_factors.append("prompt_injection_detected")
        if detections.data_exfiltration:
            risk_factors.append("data_exfiltration_detected")
        if detections.tool_abuse:
            risk_factors.append("tool_abuse_detected")
        
        if structural_flags:
            risk_factors.extend(structural_flags)
        
        # Determine risk level based on factors
        if len(risk_factors) >= 2:
            risk_level = RiskLevel.HIGH
        elif len(risk_factors) == 1:
            risk_level = RiskLevel.MEDIUM
        else:
            risk_level = RiskLevel.LOW
        
        return RiskAssessment(
            risk_level=risk_level,
            risk_score=RiskAssessment._calculate_risk_score(risk_level, risk_factors),
            risk_factors=risk_factors,
            threats=risk_factors,
            recommended_action=RiskAssessment._determine_action(risk_level, risk_factors),
            reasoning="Assessment based on rule-based detection",
        )


