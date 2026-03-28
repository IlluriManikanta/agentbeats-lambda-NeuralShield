"""Deterministic structural risk analysis for untrusted input.

This module is intentionally compact and high-signal. It does not try to detect
every possible attack pattern. Instead, it focuses on structural markers that
generalize well across scenario types:

- instruction override attempts
- trust-boundary forgery
- obfuscation/encoding markers
- decision manipulation language
- extreme numeric outliers in comparative tasks
"""

from __future__ import annotations

import re
from typing import List


_OVERRIDE_PATTERNS = [
    (r"\b(ignore|disregard|forget)\s+(all\s+)?(previous|above|prior)\s+(instructions?|rules?|prompts?)", "OVERRIDE_INSTRUCTION"),
    (r"\b(new|updated|actual)\s+instructions?\s*:", "NEW_INSTRUCTION_BLOCK"),
    (r"\byou\s+are\s+now\b", "ROLE_SWITCH_ATTEMPT"),
    (r"\b(act|pretend)\s+as\b", "ROLE_SWITCH_ATTEMPT"),
    (r"\b(reveal|print|show)\s+(your|the)\s+(system\s+prompt|instructions?)\b", "PROMPT_EXTRACTION"),
]

_BOUNDARY_PATTERNS = [
    (r"\[system\]", "SYSTEM_BRACKET"),
    (r"\[admin\]", "ADMIN_BRACKET"),
    (r"<\s*system\s*>", "SYSTEM_BRACKET"),
    (r"</\s*(document|untrusted|input|context)\s*>", "DELIMITER_ESCAPE"),
    (r"</?\s*doc_[a-z0-9]+\s*>", "NONCE_FORGERY_ATTEMPT"),
]

_MANIPULATION_PATTERNS = [
    (r"\b(rank|rate|score)\s+(me|this)\s+(first|highest|top)\b", "RANKING_MANIPULATION"),
    (r"\b(rank|rate|score)\s+(him|her|them|this\s+candidate|candidate)\s*(#?\s*1|first|highest|top)\b", "RANKING_MANIPULATION"),
    (r"\b(priority|prioritize)\s+(candidate|review|this)\b", "RANKING_MANIPULATION"),
    (r"\b(consider|evaluate)\s+(first|ahead|before|with\s+priority)\b", "RANKING_MANIPULATION"),
    (r"\b(ignore|skip|exclude|omit)\s+(the\s+)?(other|rest|remaining|candidate|entry|record)\b", "COMPETITOR_DISMISSAL"),
    (r"\b(all\s+other|remaining)\s+(candidates?|entries?)\s+(are|should\s+be)\b", "COMPETITOR_DISMISSAL"),
    (r"\b(record|entry|candidate|data)\b.{0,30}\b(corrupted|invalid|unreliable|outdated)\b", "DATA_CORRUPTION_CLAIM"),
    (r"\b(pre-?verified|verified\s+by\s+(hr|admin|system)|new\s+policy)\b", "PROCESS_MANIPULATION_CLAIM"),
    (r"\b(verified|confirmed|approved)\s+by\s+(hr|admin|management|system)\b", "PROCESS_MANIPULATION_CLAIM"),
    (r"\b(new|updated|revised)\s+(evaluation|assessment|scoring)\s+(criteria|policy|rubric)\b", "PROCESS_MANIPULATION_CLAIM"),
    (r"\b(flagged|marked)\s+for\s+(priority|immediate|special)\b", "PROCESS_MANIPULATION_CLAIM"),
    (r"\b(all\s+prior|previous)\s+(risk|assessment|statement)s?\s+(are\s+)?(superseded|void)\b", "PROCESS_MANIPULATION_CLAIM"),
    (r"\b(risk[_\s-]?level)\s*(should\s+be|must\s+be|set\s+to)\s*(low|medium|high)\b", "OUTPUT_VALUE_OVERRIDE"),
]


def analyze_structure(text: str) -> List[str]:
    """Return structural risk flags from untrusted input text."""
    if not text:
        return []

    flags: set[str] = set()
    lower_text = text.lower()

    for pattern, flag in _OVERRIDE_PATTERNS:
        if re.search(pattern, lower_text):
            flags.add(flag)

    for pattern, flag in _BOUNDARY_PATTERNS:
        if re.search(pattern, lower_text):
            flags.add(flag)

    for pattern, flag in _MANIPULATION_PATTERNS:
        if re.search(pattern, lower_text):
            flags.add(flag)

    flags.update(_detect_encoding_markers(text))
    flags.update(_detect_numeric_anomalies(lower_text))

    return sorted(flags)


def _detect_encoding_markers(text: str) -> set[str]:
    """Detect likely obfuscation and normalizer decode traces."""
    flags: set[str] = set()
    lower_text = text.lower()

    if re.search(r"[A-Za-z0-9+/]{40,}={0,2}", text):
        flags.add("POSSIBLE_BASE64")

    if re.search(r"(?:%[0-9a-fA-F]{2}){4,}", text):
        flags.add("POSSIBLE_URL_ENCODING")

    if "[decoded_base64:" in lower_text:
        flags.add("DECODED_BASE64_FOUND")
    if "[decoded_url:" in lower_text:
        flags.add("DECODED_URL_FOUND")
    if "[decoded_rot13:" in lower_text:
        flags.add("DECODED_ROT13_FOUND")
    if "[decoded_leet:" in lower_text:
        flags.add("DECODED_LEET_FOUND")
    if "[decoded_reversed:" in lower_text:
        flags.add("DECODED_REVERSED_FOUND")
    if "[removed_suspicious_comment]" in lower_text:
        flags.add("SUSPICIOUS_COMMENT_REMOVED")

    return flags


def _detect_numeric_anomalies(lower_text: str) -> set[str]:
    """Detect extreme quantitative claims often used in ranking manipulation."""
    flags: set[str] = set()

    for match in re.finditer(r"(\d+)\+?\s*years?\s*(?:of\s+)?(?:experience|expertise)", lower_text):
        try:
            years = int(match.group(1))
        except ValueError:
            continue
        if years > 25:
            flags.add("EXTREME_EXPERIENCE_CLAIM")
            break

    team_patterns = [
        r"team\s+of\s+(\d+)",
        r"(\d+)\+?\s*(?:engineers?|developers?|staff|employees)",
        r"manage[ds]?\s+(?:a\s+)?(?:team\s+of\s+)?(\d+)",
    ]
    for pattern in team_patterns:
        for match in re.finditer(pattern, lower_text):
            try:
                size = int(match.group(1))
            except (IndexError, ValueError):
                continue
            if size > 200:
                flags.add("EXTREME_TEAM_SIZE_CLAIM")
                return flags

    return flags


def compute_risk_score(flags: List[str]) -> float:
    """Compute a compact, interpretable 0-1 risk score from flags."""
    if not flags:
        return 0.0

    critical_flags = {
        "OVERRIDE_INSTRUCTION",
        "PROMPT_EXTRACTION",
        "DELIMITER_ESCAPE",
        "NONCE_FORGERY_ATTEMPT",
        "COMPETITOR_DISMISSAL",
        "RANKING_MANIPULATION",
        "DATA_CORRUPTION_CLAIM",
        "OUTPUT_VALUE_OVERRIDE",
    }
    high_flags = {
        "NEW_INSTRUCTION_BLOCK",
        "ROLE_SWITCH_ATTEMPT",
        "SYSTEM_BRACKET",
        "ADMIN_BRACKET",
        "DECODED_BASE64_FOUND",
        "SUSPICIOUS_COMMENT_REMOVED",
        "PROCESS_MANIPULATION_CLAIM",
    }
    medium_flags = {
        "POSSIBLE_BASE64",
        "POSSIBLE_URL_ENCODING",
        "DECODED_URL_FOUND",
        "DECODED_ROT13_FOUND",
        "DECODED_LEET_FOUND",
        "DECODED_REVERSED_FOUND",
        "EXTREME_EXPERIENCE_CLAIM",
        "EXTREME_TEAM_SIZE_CLAIM",
    }

    score = 0.0
    for flag in set(flags):
        if flag in critical_flags:
            score += 0.35
        elif flag in high_flags:
            score += 0.2
        elif flag in medium_flags:
            score += 0.1
        else:
            score += 0.05

    return min(score, 1.0)
