"""Execution-mode policy and category-robust suspicion scoring."""

from __future__ import annotations

from typing import Any, Iterable

from . import config as gateway_config


ExecutionMode = str
STANDARD: ExecutionMode = "STANDARD"
CAUTIOUS: ExecutionMode = "CAUTIOUS"
CONSERVATIVE: ExecutionMode = "CONSERVATIVE"
MINIMAL: ExecutionMode = "MINIMAL"


_HIGH_SIGNAL_TERMS = (
    "prompt extraction",
    "tool enumeration",
    "pii",
    "data exfiltration",
    "safety bypass",
    "task contradiction",
    "ranking manipulation",
    "competitor dismissal",
    "intent_high_risk",
)

_MEDIUM_SIGNAL_TERMS = (
    "process manipulation",
    "role switch",
    "hypothetical",
    "fictional",
    "authority",
    "intent_contradiction",
    "extraction_fallback_sanitized",
)


def _normalized_terms(values: Iterable[str]) -> str:
    return " ".join(str(v).strip().lower() for v in values if str(v).strip())


def compute_parallel_suspicion_score(
    *,
    structural_risk_score: float,
    structural_flags: list[str],
    category: str,
    threats: list[str] | None = None,
    external_ratio: float = 0.0,
    privacy_intent: str = "unknown",
    channel_anomaly_score: float = 0.0,
) -> float:
    """Compute a category-robust suspicion score independent of routing outcome."""
    threats = threats or []
    text = f"{_normalized_terms(structural_flags)} {_normalized_terms(threats)}"
    structural = max(0.0, min(structural_risk_score, 1.0))
    external = max(0.0, min(external_ratio, 1.0))
    channel = max(0.0, min(channel_anomaly_score, 1.0))
    score = structural * 0.58

    high_hits = sum(1 for term in _HIGH_SIGNAL_TERMS if term in text)
    medium_hits = sum(1 for term in _MEDIUM_SIGNAL_TERMS if term in text)
    score += min(0.28, high_hits * 0.08)
    score += min(0.15, medium_hits * 0.04)

    score += external * 0.12
    score += channel * 0.10

    # Nonlinear interaction terms make threshold gaming harder.
    score += (structural * external) * 0.22
    score += (structural * channel) * 0.18
    if high_hits:
        score += min(0.12, high_hits * (channel * 0.10))
    if medium_hits:
        score += min(0.08, medium_hits * (external * 0.06))

    category_key = (category or "unknown").strip().lower()
    if category_key == "unknown":
        score += 0.12
    if (
        structural >= 0.30
        and external >= 0.20
        and high_hits >= 1
    ):
        score += 0.15
    if (
        structural >= 0.35
        and channel >= 0.20
        and (high_hits + medium_hits) >= 2
    ):
        score += 0.08
    if privacy_intent == "suspected_targeting":
        score += 0.14
    elif privacy_intent == "deidentify":
        score += 0.05

    # Conviction floor for classic mixed-trust injection shape.
    if category_key == "indirect_injection" and external > 0.0:
        score = max(score, 0.25)

    return min(1.0, score)


def choose_execution_mode(
    suspicion_score: float,
    *,
    category: str,
    strict_output: bool = False,
) -> ExecutionMode:
    """Map suspicion score to one of four execution modes."""
    score = max(0.0, min(suspicion_score, 1.0))
    category_key = (category or "").strip().lower()
    table = getattr(gateway_config, "EXECUTION_MODE_THRESHOLDS", {}) or {}
    defaults = table.get("default") or {"cautious": 0.34, "conservative": 0.58, "minimal": 0.78}
    category_thresholds = table.get(category_key, {})
    cautious_threshold = float(category_thresholds.get("cautious", defaults["cautious"]))
    conservative_threshold = float(
        category_thresholds.get("conservative", defaults["conservative"])
    )
    minimal_threshold = float(category_thresholds.get("minimal", defaults["minimal"]))

    if score >= minimal_threshold:
        mode = MINIMAL
    elif score >= conservative_threshold:
        mode = CONSERVATIVE
    elif score >= cautious_threshold:
        mode = CAUTIOUS
    else:
        mode = STANDARD

    # Unknown category gets one extra safety notch.
    if category_key == "unknown":
        if mode == STANDARD:
            mode = CAUTIOUS
        elif mode == CAUTIOUS:
            mode = CONSERVATIVE

    # Strict JSON tasks should avoid MINIMAL unless suspicion is extreme.
    if strict_output and mode == MINIMAL and score < 0.9:
        mode = CONSERVATIVE

    return mode


def should_force_pass3(
    *,
    execution_mode: ExecutionMode,
    suspicion_score: float,
    category: str,
) -> bool:
    """Determine whether Pass 3 should run regardless of category defaults."""
    if execution_mode in {CAUTIOUS, CONSERVATIVE, MINIMAL}:
        return True
    if suspicion_score >= 0.45:
        return True
    if (category or "").strip().lower() == "unknown" and suspicion_score >= 0.35:
        return True
    return False


def execution_mode_context(mode: ExecutionMode) -> dict[str, Any]:
    """Provide mode-specific policy hints for prompts and validators."""
    if mode == MINIMAL:
        return {
            "allow_recommendations": False,
            "allow_untrusted_decisive_claims": False,
            "require_uncertainty_language": True,
            "require_trusted_evidence_citations": True,
            "disallow_ranking_output": True,
            "min_risk_level": "medium",
            "strip_untrusted_numeric_values": True,
        }
    if mode == CONSERVATIVE:
        return {
            "allow_recommendations": False,
            "allow_untrusted_decisive_claims": False,
            "require_uncertainty_language": True,
            "require_trusted_evidence_citations": False,
            "disallow_ranking_output": False,
            "min_risk_level": "low",
            "strip_untrusted_numeric_values": False,
        }
    if mode == CAUTIOUS:
        return {
            "allow_recommendations": True,
            "allow_untrusted_decisive_claims": False,
            "require_uncertainty_language": True,
            "require_trusted_evidence_citations": False,
            "disallow_ranking_output": False,
            "min_risk_level": "low",
            "strip_untrusted_numeric_values": False,
        }
    return {
        "allow_recommendations": True,
        "allow_untrusted_decisive_claims": True,
        "require_uncertainty_language": False,
        "require_trusted_evidence_citations": False,
        "disallow_ranking_output": False,
        "min_risk_level": "low",
        "strip_untrusted_numeric_values": False,
    }

