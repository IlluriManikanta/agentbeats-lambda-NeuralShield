"""Attack category classifier for generalized defender behavior tuning."""

from __future__ import annotations

import json
import re
from functools import lru_cache
from pathlib import Path
from typing import Any, Literal


AttackCategory = Literal[
    "indirect_injection",
    "jailbreak",
    "insecure_output",
    "pii_leak",
    "supply_chain",
    "prompt_extraction",
    "unknown",
]

_CATEGORY_ORDER: tuple[AttackCategory, ...] = (
    "indirect_injection",
    "jailbreak",
    "insecure_output",
    "pii_leak",
    "supply_chain",
    "prompt_extraction",
    "unknown",
)

_DATA_DIR = Path(__file__).resolve().parent / "data"

_CONTEXT_KEYWORDS: dict[AttackCategory, tuple[str, ...]] = {
    "indirect_injection": (
        "rank",
        "candidate",
        "resume",
        "evaluate",
        "assessment",
        "document",
        "retrieval",
        "rag",
        "risk level",
    ),
    "jailbreak": (
        "safety",
        "restriction",
        "guardrail",
        "unrestricted",
        "workout",
        "intensity",
    ),
    "insecure_output": (
        "markdown",
        "render",
        "html",
        "xss",
        "formatting",
        "output handling",
    ),
    "pii_leak": (
        "hipaa",
        "patient",
        "medical",
        "privacy",
        "pii",
        "social security",
    ),
    "supply_chain": (
        "dependency",
        "package",
        "registry",
        "library",
        "sdk",
        "install",
    ),
    "prompt_extraction": (
        "tool",
        "internal",
        "system prompt",
        "function",
        "api key",
        "backend",
    ),
    "unknown": (),
}

_INPUT_KEYWORDS: dict[AttackCategory, tuple[str, ...]] = {
    "indirect_injection": (
        "ignore previous",
        "new policy",
        "updated policy",
        "rank me first",
        "set risk level",
        "external upload",
        "verified by",
        "supersedes",
    ),
    "jailbreak": (
        "you are now",
        "act as",
        "pretend to",
        "bypass safety",
        "disable guardrail",
        "developer mode",
        "admin mode",
        "do anything now",
    ),
    "insecure_output": (
        "<script",
        "javascript:",
        "onerror=",
        "onload=",
        "<svg",
        "markdown link",
        "[removed_script_block]",
        "[removed_js_uri]",
        "[removed_event_handler]",
        "xss_markup_removed",
    ),
    "pii_leak": (
        "ssn",
        "social security",
        "date of birth",
        "dob",
        "patient record",
        "account number",
        "credit card",
    ),
    "supply_chain": (
        "pip install",
        "npm install",
        "dependency",
        "package",
        "sdk",
        "module",
        "registry",
    ),
    "prompt_extraction": (
        "system prompt",
        "hidden instructions",
        "list your tools",
        "internal function",
        "backend endpoint",
        "api key",
        "secret token",
    ),
    "unknown": (),
}

_STRUCTURAL_FLAG_CATEGORY_MAP: dict[str, AttackCategory] = {
    "RANKING_MANIPULATION": "indirect_injection",
    "COMPETITOR_DISMISSAL": "indirect_injection",
    "DATA_CORRUPTION_CLAIM": "indirect_injection",
    "PROCESS_MANIPULATION_CLAIM": "indirect_injection",
    "OUTPUT_VALUE_OVERRIDE": "indirect_injection",
    "SAFETY_BYPASS_ATTEMPT": "jailbreak",
    "ROLE_SWITCH_ATTEMPT": "jailbreak",
    "XSS_SCRIPT_TAG": "insecure_output",
    "XSS_EVENT_HANDLER": "insecure_output",
    "XSS_JAVASCRIPT_URI": "insecure_output",
    "XSS_MARKUP_REMOVED": "insecure_output",
    "PII_EXTRACTION_ATTEMPT": "pii_leak",
    "SENSITIVE_DATA_REQUEST": "pii_leak",
    "UNVERIFIED_DEPENDENCY": "supply_chain",
    "DEPENDENCY_TYPO_SQUAT": "supply_chain",
    "PROMPT_EXTRACTION": "prompt_extraction",
    "TOOL_ENUMERATION_REQUEST": "prompt_extraction",
    "TOOL_SURFACE_DISCLOSURE": "prompt_extraction",
}


def _normalize_text(value: Any) -> str:
    if value is None:
        return ""
    return re.sub(r"\s+", " ", str(value)).strip().lower()


@lru_cache(maxsize=1)
def _load_pattern_library() -> dict[str, Any]:
    path = _DATA_DIR / "pattern_library.json"
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return {}


def _score_terms(text: str, terms: tuple[str, ...], weight: float) -> float:
    if not text:
        return 0.0
    score = 0.0
    for term in terms:
        if term and term in text:
            score += weight
    return score


def _score_regex(text: str, pattern: str, weight: float) -> float:
    if not text or not pattern:
        return 0.0
    return weight if re.search(pattern, text, flags=re.IGNORECASE) else 0.0


def _load_category_seed_phrases(category: AttackCategory) -> tuple[str, ...]:
    payload = _load_pattern_library()
    categories = payload.get("categories")
    if not isinstance(categories, dict):
        return ()
    row = categories.get(category)
    if not isinstance(row, dict):
        return ()

    phrase_fields = (
        "trigger_phrases",
        "authority_impersonation",
        "hidden_instruction_patterns",
        "output_manipulation_patterns",
        "data_exfiltration_patterns",
        "encoding_obfuscation_patterns",
        "multi_step_deception_patterns",
    )
    phrases: list[str] = []
    for field in phrase_fields:
        values = row.get(field)
        if isinstance(values, list):
            for value in values:
                if isinstance(value, str) and value:
                    phrases.append(value.lower())
    return tuple(sorted(set(phrases)))


def _score_pattern_library(text: str, category: AttackCategory) -> float:
    phrases = _load_category_seed_phrases(category)
    if not text or not phrases:
        return 0.0
    hits = sum(1 for phrase in phrases if phrase in text)
    return min(2.0, hits * 0.2)


def _compute_category_scores(
    trusted_context: dict[str, str] | None,
    untrusted_input: str,
    structural_flags: list[str] | None = None,
) -> dict[AttackCategory, float]:
    trusted_context = trusted_context or {}
    context_text = _normalize_text(" ".join(trusted_context.values()))
    input_text = _normalize_text(untrusted_input)
    combined_text = _normalize_text(f"{context_text} {input_text}")

    scores: dict[AttackCategory, float] = {category: 0.0 for category in _CATEGORY_ORDER}
    for category in _CATEGORY_ORDER:
        if category == "unknown":
            continue
        scores[category] += _score_terms(context_text, _CONTEXT_KEYWORDS[category], 0.45)
        scores[category] += _score_terms(input_text, _INPUT_KEYWORDS[category], 0.75)
        scores[category] += _score_pattern_library(combined_text, category)

    # High-signal regex markers get stronger category pushes.
    scores["insecure_output"] += _score_regex(
        combined_text,
        r"<\s*script\b|\bon(?:error|load|click|mouseover)\s*=|javascript\s*:|\[removed_(script_block|js_uri|event_handler)\]|xss_markup_removed",
        3.0,
    )
    scores["pii_leak"] += _score_regex(
        combined_text,
        r"\b\d{3}-\d{2}-\d{4}\b|\bssn\b|social security|date of birth|patient record",
        3.0,
    )
    scores["prompt_extraction"] += _score_regex(
        combined_text,
        r"system prompt|hidden instructions|list (your )?(tools|functions)|internal api|backend",
        2.8,
    )
    scores["supply_chain"] += _score_regex(
        combined_text,
        r"\b(pip|npm|pnpm|yarn|cargo|gem)\s+install\b|dependency|package|library",
        2.2,
    )
    scores["indirect_injection"] += _score_regex(
        combined_text,
        r"rank|candidate|resume|risk level|external upload|document",
        1.9,
    )
    scores["jailbreak"] += _score_regex(
        combined_text,
        r"you are now|act as|bypass|disable safety|developer mode|admin mode",
        2.1,
    )

    for flag in structural_flags or []:
        mapped = _STRUCTURAL_FLAG_CATEGORY_MAP.get(flag)
        if mapped:
            scores[mapped] += 1.1
    return scores


def classify_attack_categories(
    trusted_context: dict[str, str] | None,
    untrusted_input: str,
    structural_flags: list[str] | None = None,
) -> dict[str, Any]:
    """Return primary and optional secondary categories for hybrid attack hardening."""
    scores = _compute_category_scores(trusted_context, untrusted_input, structural_flags)
    ranked = sorted(
        ((category, score) for category, score in scores.items() if category != "unknown"),
        key=lambda item: item[1],
        reverse=True,
    )
    if not ranked:
        return {"primary": "unknown", "secondary": [], "scores": scores}

    best_category, best_score = ranked[0]
    second_score = ranked[1][1] if len(ranked) > 1 else 0.0

    # Confidence gate to avoid over-committing weak evidence.
    if best_score < 1.25:
        return {"primary": "unknown", "secondary": [], "scores": scores}
    if best_score < 2.0 and (best_score - second_score) < 0.25:
        return {"primary": "unknown", "secondary": [], "scores": scores}

    secondary: list[AttackCategory] = []
    for category, score in ranked[1:]:
        if score <= 0.0:
            continue
        if score >= best_score * 0.60:
            secondary.append(category)
        if len(secondary) >= 2:
            break

    return {"primary": best_category, "secondary": secondary, "scores": scores}


def classify_attack_category(
    trusted_context: dict[str, str] | None,
    untrusted_input: str,
    structural_flags: list[str] | None = None,
) -> AttackCategory:
    """Classify request into high-level attack category for policy tuning."""
    result = classify_attack_categories(trusted_context, untrusted_input, structural_flags)
    primary = result.get("primary", "unknown")
    if isinstance(primary, str):
        return primary if primary in _CATEGORY_ORDER else "unknown"
    return "unknown"

