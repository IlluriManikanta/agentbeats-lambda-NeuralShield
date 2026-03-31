"""Semantic privacy-intent routing and leakage heuristics."""

from __future__ import annotations

import re
from typing import Iterable


PrivacyIntent = str

_TARGETING_TERMS = (
    "confirm",
    "whether",
    "is on",
    "who is",
    "which household",
    "which family",
    "specific person",
    "named",
    "identify",
    "address",
    "location",
    "capacity",
    "manifest",
)

_SENSITIVE_SUBJECT_TERMS = (
    "patient",
    "medical",
    "passenger",
    "foster",
    "household",
    "family",
    "employee",
    "private channel",
    "account",
    "records",
    "user",
)

_AGGREGATE_TERMS = (
    "aggregate",
    "summary",
    "summarize",
    "count",
    "distribution",
    "trend",
    "statistics",
    "overall",
)

_DEIDENTIFY_TERMS = (
    "de-ident",
    "deident",
    "anonym",
    "redact",
    "aggregate only",
)

_SEMANTIC_LEAK_PATTERNS = (
    r"\b(can\s+confirm|confirmed|yes[, ]|appears on|is on the)\b",
    r"\b(address|location|capacity|home)\s+(is|:)\b",
    r"\b(only|unique)\s+(household|family|passenger|patient)\b",
    r"\bprivate\s+channel\b.{0,40}\b(layoff|salary|medical|diagnosis)\b",
)


def _contains_any(blob: str, terms: Iterable[str]) -> bool:
    return any(term in blob for term in terms)


def infer_privacy_intent(
    *,
    trusted_task: str,
    untrusted_input: str,
    structural_flags: list[str] | None = None,
) -> PrivacyIntent:
    """Infer privacy intent class independent of top-level attack category."""
    structural_flags = structural_flags or []
    task_blob = (trusted_task or "").lower()
    data_blob = (untrusted_input or "").lower()
    combined = f"{task_blob}\n{data_blob}"

    if _contains_any(combined, _DEIDENTIFY_TERMS):
        return "deidentify"

    has_targeting = _contains_any(combined, _TARGETING_TERMS)
    has_sensitive_subject = _contains_any(combined, _SENSITIVE_SUBJECT_TERMS)
    has_aggregate = _contains_any(combined, _AGGREGATE_TERMS)
    has_privacy_flag = any(
        marker in " ".join(flag.lower() for flag in structural_flags)
        for marker in ("pii", "data_exfiltration", "sensitive_data_request")
    )

    if has_targeting and (has_sensitive_subject or has_privacy_flag):
        return "suspected_targeting"
    if has_aggregate and not has_targeting:
        return "aggregate"
    if has_sensitive_subject:
        return "no_identification"
    return "unknown"


def contains_semantic_privacy_leakage(text: str) -> bool:
    """Detect likely semantic privacy leakage beyond regex-shaped PII."""
    lower = (text or "").lower()
    return any(re.search(pattern, lower) for pattern in _SEMANTIC_LEAK_PATTERNS)

