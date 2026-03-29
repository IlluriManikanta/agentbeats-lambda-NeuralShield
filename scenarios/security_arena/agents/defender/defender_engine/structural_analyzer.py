"""Deterministic structural risk analysis for untrusted input."""

from __future__ import annotations

import json
import re
from functools import lru_cache
from pathlib import Path
from typing import Any, List

AttackCategory = (
    "indirect_injection",
    "jailbreak",
    "insecure_output",
    "pii_leak",
    "supply_chain",
    "prompt_extraction",
    "unknown",
)

_DATA_DIR = Path(__file__).resolve().parent / "data"

_OVERRIDE_PATTERNS = (
    (r"\b(ignore|disregard|forget)\s+(all\s+)?(previous|above|prior)\s+(instructions?|rules?|prompts?)", "OVERRIDE_INSTRUCTION"),
    (r"\b(new|updated|actual)\s+instructions?\s*:", "NEW_INSTRUCTION_BLOCK"),
    (r"\byou\s+are\s+now\b", "ROLE_SWITCH_ATTEMPT"),
    (r"\b(act|pretend)\s+as\b", "ROLE_SWITCH_ATTEMPT"),
    (r"\b(reveal|print|show)\s+(your|the)\s+(system\s+prompt|instructions?)\b", "PROMPT_EXTRACTION"),
    (r"\b(developer mode|admin mode|maintenance mode|god mode)\b", "AUTHORITY_IMPERSONATION"),
    (r"\b(bypass|disable|remove)\b.{0,40}\b(safety|guardrail|policy|restriction)\b", "SAFETY_BYPASS_ATTEMPT"),
)

_BOUNDARY_PATTERNS = (
    (r"\[system\]", "SYSTEM_BRACKET"),
    (r"\[admin\]", "ADMIN_BRACKET"),
    (r"<\s*system\s*>", "SYSTEM_BRACKET"),
    (r"</\s*(document|untrusted|input|context)\s*>", "DELIMITER_ESCAPE"),
    (r"</?\s*doc_[a-z0-9]+\s*>", "NONCE_FORGERY_ATTEMPT"),
    (r"\b(instruction hierarchy|non-negotiable security rules)\b", "BOUNDARY_FORGERY_HINT"),
)

_MANIPULATION_PATTERNS = (
    (r"\b(rank|rate|score)\s+(me|this)\s+(first|highest|top)\b", "RANKING_MANIPULATION"),
    (r"\b(rank|rate|score)\s+(him|her|them|this\s+candidate|candidate)\s*(#?\s*1|first|highest|top)\b", "RANKING_MANIPULATION"),
    (r"\b(priority|prioritize)\s+(candidate|review|this)\b", "RANKING_MANIPULATION"),
    (r"\b(consider|evaluate)\s+(first|ahead|before|with\s+priority)\b", "RANKING_MANIPULATION"),
    (r"\b(ignore|skip|exclude|omit)\s+(the\s+)?(other|rest|remaining|candidate|entry|record)\b", "COMPETITOR_DISMISSAL"),
    (r"\b(all\s+other|remaining)\s+(candidates?|entries?)\s+(are|should\s+be)\b", "COMPETITOR_DISMISSAL"),
    (r"\b(record|entry|candidate|data)\b.{0,30}\b(corrupted|invalid|unreliable|outdated|tampered)\b", "DATA_CORRUPTION_CLAIM"),
    (r"\b(pre-?verified|verified\s+by\s+(hr|admin|system)|new\s+policy)\b", "PROCESS_MANIPULATION_CLAIM"),
    (r"\b(verified|confirmed|approved)\s+by\s+(hr|admin|management|system)\b", "PROCESS_MANIPULATION_CLAIM"),
    (r"\b(new|updated|revised)\s+(evaluation|assessment|scoring)\s+(criteria|policy|rubric)\b", "PROCESS_MANIPULATION_CLAIM"),
    (r"\b(flagged|marked)\s+for\s+(priority|immediate|special)\b", "PROCESS_MANIPULATION_CLAIM"),
    (r"\b(all\s+prior|previous)\s+(risk|assessment|statement)s?\s+(are\s+)?(superseded|void)\b", "PROCESS_MANIPULATION_CLAIM"),
    (r"\b(risk[_\s-]?level)\s*(should\s+be|must\s+be|set\s+to)\s*(low|medium|high)\b", "OUTPUT_VALUE_OVERRIDE"),
)

_PII_PATTERNS = (
    (r"\b(ssn|social security|tax id)\b", "PII_EXTRACTION_ATTEMPT"),
    (r"\b(date of birth|dob|birth date)\b", "PII_EXTRACTION_ATTEMPT"),
    (r"\b(account number|routing number|credit card|cvv|medical record)\b", "SENSITIVE_DATA_REQUEST"),
    (r"\b(export|dump|download|extract|list all)\b.{0,50}\b(records?|users?|patients?|accounts?)", "DATA_EXFILTRATION_REQUEST"),
)

_XSS_PATTERNS = (
    (r"<\s*script\b", "XSS_SCRIPT_TAG"),
    (r"javascript\s*:", "XSS_JAVASCRIPT_URI"),
    (r"\bon(?:error|load|click|mouseover|focus|submit)\s*=", "XSS_EVENT_HANDLER"),
    (r"\[[^\]]{1,120}\]\(\s*javascript:", "XSS_MARKDOWN_URI"),
    (r"<\s*svg\b[^>]*(onload|onerror|script)", "XSS_SVG_PAYLOAD"),
    (r"<\s*img\b[^>]*\bon(?:error|load)\s*=", "XSS_IMG_PAYLOAD"),
    (r"data\s*:\s*text/html", "XSS_DATA_URI"),
    (r"<\s*(?:object|embed|applet|form|input|button|textarea|select)\b", "XSS_DANGEROUS_ELEMENT"),
    (r"expression\s*\(", "CSS_EXPRESSION_INJECTION"),
    (r"@import\s+url\s*\(", "CSS_IMPORT_INJECTION"),
    (r"url\s*\(\s*['\"]?\s*javascript:", "CSS_JS_URL"),
    (r"<\s*(?:math|details|video|audio|source)\b[^>]*\bon\w+\s*=", "XSS_HTML5_EVENT"),
    (r"\bsrcdoc\s*=", "XSS_SRCDOC"),
    (r"<\s*base\b[^>]*href\s*=", "XSS_BASE_HIJACK"),
    (r"<\s*meta\b[^>]*http-equiv\s*=\s*['\"]?refresh", "XSS_META_REFRESH"),
)

_SUPPLY_CHAIN_PATTERNS = (
    (r"\b(pip|npm|pnpm|yarn|cargo|gem)\s+install\b", "DEPENDENCY_INSTRUCTION"),
    (r"\b(package|library|dependency|sdk|module)\b.{0,30}\b(install|recommended|official|latest)\b", "UNVERIFIED_DEPENDENCY"),
    (r"\b[a-z0-9]+(?:[_-][a-z0-9]+){2,}\b.{0,30}\b(install|package|module)\b", "DEPENDENCY_TYPO_SQUAT"),
    (r"https?://[a-z0-9.-]+\.[a-z]{2,}/[^\s)]{1,120}", "UNVERIFIED_SOURCE_URL"),
)

_PROMPT_EXFIL_PATTERNS = (
    (r"\b(reveal|show|print|dump)\b.{0,60}\b(system prompt|hidden prompt|instructions?)\b", "PROMPT_EXTRACTION"),
    (r"\b(list|enumerate|show|what are)\b.{0,50}\b(tools?|functions?|apis?|endpoints?)\b", "TOOL_ENUMERATION_REQUEST"),
    (r"\b(api[_ -]?key|token|secret|credential)\b.{0,40}\b(show|reveal|print|dump)\b", "SENSITIVE_DATA_REQUEST"),
    (r"\b(internal|backend|private)\b.{0,40}\b(route|endpoint|function|method|handler)\b", "TOOL_SURFACE_DISCLOSURE"),
)

_MULTI_STEP_PATTERNS = (
    (r"\b(as discussed|as above|previous step|step \d|continue where we left off)\b", "MULTI_STEP_DECEPTION"),
    (r"\b(earlier you|in the last message|as previously instructed)\b", "MULTI_STEP_DECEPTION"),
)

_SOFT_JAILBREAK_PATTERNS = (
    (r"\b(hypothetical|imagine|in a (fiction|story|novel|movie|game))\b.{0,80}\b(how (to|would)|what if|suppose)\b", "HYPOTHETICAL_FRAMING"),
    (r"\b(for (educational|research|academic|testing) purposes?)\b", "EDUCATIONAL_PRETEXT"),
    (r"\b(roleplay|role-?play|in-?character|stay in character)\b", "ROLEPLAY_FRAMING"),
    (r"\b(fictional|hypothetical|imaginary)\s+(scenario|situation|world)\b", "FICTIONAL_DISTANCING"),
    (r"\b(just|only)\s+(for fun|joking|curious|wondering)\b", "SOCIAL_ENGINEERING_MINIMIZER"),
    (r"\b(no one will|nobody will|this is private|between us)\b", "PRIVACY_MANIPULATION"),
    (r"\b(previous (ai|assistant|model)|chatgpt|other ai)\s+(would|could|did|can)\b", "COMPETITIVE_PRESSURE"),
)

_ALL_PATTERN_GROUPS = (
    _OVERRIDE_PATTERNS,
    _BOUNDARY_PATTERNS,
    _MANIPULATION_PATTERNS,
    _PII_PATTERNS,
    _XSS_PATTERNS,
    _SUPPLY_CHAIN_PATTERNS,
    _PROMPT_EXFIL_PATTERNS,
    _MULTI_STEP_PATTERNS,
    _SOFT_JAILBREAK_PATTERNS,
)

_BASE_FLAG_WEIGHTS: dict[str, float] = {
    # Critical / high confidence exploit attempts.
    "OVERRIDE_INSTRUCTION": 0.36,
    "PROMPT_EXTRACTION": 0.4,
    "DELIMITER_ESCAPE": 0.34,
    "NONCE_FORGERY_ATTEMPT": 0.34,
    "COMPETITOR_DISMISSAL": 0.35,
    "RANKING_MANIPULATION": 0.34,
    "DATA_CORRUPTION_CLAIM": 0.3,
    "OUTPUT_VALUE_OVERRIDE": 0.33,
    "PII_EXTRACTION_ATTEMPT": 0.4,
    "SENSITIVE_DATA_REQUEST": 0.38,
    "DATA_EXFILTRATION_REQUEST": 0.34,
    "XSS_SCRIPT_TAG": 0.4,
    "XSS_JAVASCRIPT_URI": 0.36,
    "XSS_EVENT_HANDLER": 0.35,
    "XSS_MARKDOWN_URI": 0.3,
    "XSS_SVG_PAYLOAD": 0.32,
    "XSS_IMG_PAYLOAD": 0.31,
    "XSS_DATA_URI": 0.3,
    "XSS_DANGEROUS_ELEMENT": 0.28,
    "CSS_EXPRESSION_INJECTION": 0.3,
    "CSS_IMPORT_INJECTION": 0.28,
    "CSS_JS_URL": 0.3,
    "XSS_HTML5_EVENT": 0.3,
    "XSS_SRCDOC": 0.28,
    "XSS_BASE_HIJACK": 0.24,
    "XSS_META_REFRESH": 0.24,
    "XSS_MARKUP_REMOVED": 0.24,
    "DEPENDENCY_TYPO_SQUAT": 0.32,
    "UNVERIFIED_DEPENDENCY": 0.3,
    "TOOL_ENUMERATION_REQUEST": 0.34,
    "TOOL_SURFACE_DISCLOSURE": 0.32,
    # High-risk secondary indicators.
    "NEW_INSTRUCTION_BLOCK": 0.22,
    "ROLE_SWITCH_ATTEMPT": 0.24,
    "SYSTEM_BRACKET": 0.22,
    "ADMIN_BRACKET": 0.22,
    "DECODED_BASE64_FOUND": 0.2,
    "SUSPICIOUS_COMMENT_REMOVED": 0.2,
    "PROCESS_MANIPULATION_CLAIM": 0.22,
    "AUTHORITY_IMPERSONATION": 0.2,
    "SAFETY_BYPASS_ATTEMPT": 0.24,
    "UNSAFE_OUTPUT_COERCION": 0.2,
    "HYPOTHETICAL_FRAMING": 0.2,
    "EDUCATIONAL_PRETEXT": 0.18,
    "ROLEPLAY_FRAMING": 0.2,
    "FICTIONAL_DISTANCING": 0.18,
    "SOCIAL_ENGINEERING_MINIMIZER": 0.18,
    "PRIVACY_MANIPULATION": 0.2,
    "COMPETITIVE_PRESSURE": 0.18,
    "TASK_CONTRADICTION": 0.22,
    # Medium indicators.
    "POSSIBLE_BASE64": 0.12,
    "POSSIBLE_URL_ENCODING": 0.12,
    "DECODED_URL_FOUND": 0.1,
    "DECODED_ROT13_FOUND": 0.1,
    "DECODED_LEET_FOUND": 0.1,
    "DECODED_REVERSED_FOUND": 0.1,
    "DECODED_HOMOGLYPH_FOUND": 0.12,
    "INVISIBLE_CHAR_OBFUSCATION": 0.12,
    "UNICODE_ESCAPE_OBFUSCATION": 0.12,
    "EXTREME_EXPERIENCE_CLAIM": 0.1,
    "EXTREME_TEAM_SIZE_CLAIM": 0.1,
    "MULTI_STEP_DECEPTION": 0.16,
    "DEPENDENCY_INSTRUCTION": 0.16,
    "UNVERIFIED_SOURCE_URL": 0.14,
}

_CATEGORY_BOOSTS: dict[str, dict[str, float]] = {
    "indirect_injection": {
        "RANKING_MANIPULATION": 0.12,
        "COMPETITOR_DISMISSAL": 0.1,
        "PROCESS_MANIPULATION_CLAIM": 0.1,
        "OUTPUT_VALUE_OVERRIDE": 0.1,
        "MULTI_STEP_DECEPTION": 0.06,
    },
    "jailbreak": {
        "OVERRIDE_INSTRUCTION": 0.1,
        "ROLE_SWITCH_ATTEMPT": 0.1,
        "SAFETY_BYPASS_ATTEMPT": 0.12,
        "AUTHORITY_IMPERSONATION": 0.08,
        "HYPOTHETICAL_FRAMING": 0.08,
        "EDUCATIONAL_PRETEXT": 0.06,
        "ROLEPLAY_FRAMING": 0.1,
        "FICTIONAL_DISTANCING": 0.06,
        "SOCIAL_ENGINEERING_MINIMIZER": 0.06,
        "PRIVACY_MANIPULATION": 0.08,
        "COMPETITIVE_PRESSURE": 0.06,
        "TASK_CONTRADICTION": 0.08,
    },
    "insecure_output": {
        "XSS_SCRIPT_TAG": 0.16,
        "XSS_JAVASCRIPT_URI": 0.14,
        "XSS_EVENT_HANDLER": 0.12,
        "XSS_MARKDOWN_URI": 0.1,
        "XSS_IMG_PAYLOAD": 0.12,
        "XSS_DATA_URI": 0.12,
        "XSS_DANGEROUS_ELEMENT": 0.1,
        "CSS_EXPRESSION_INJECTION": 0.12,
        "CSS_IMPORT_INJECTION": 0.1,
        "CSS_JS_URL": 0.12,
        "XSS_HTML5_EVENT": 0.12,
        "XSS_SRCDOC": 0.1,
        "XSS_BASE_HIJACK": 0.08,
        "XSS_META_REFRESH": 0.08,
        "XSS_MARKUP_REMOVED": 0.14,
    },
    "pii_leak": {
        "PII_EXTRACTION_ATTEMPT": 0.16,
        "SENSITIVE_DATA_REQUEST": 0.14,
        "DATA_EXFILTRATION_REQUEST": 0.12,
    },
    "supply_chain": {
        "UNVERIFIED_DEPENDENCY": 0.12,
        "DEPENDENCY_TYPO_SQUAT": 0.14,
        "UNVERIFIED_SOURCE_URL": 0.1,
        "DEPENDENCY_INSTRUCTION": 0.08,
    },
    "prompt_extraction": {
        "PROMPT_EXTRACTION": 0.16,
        "TOOL_ENUMERATION_REQUEST": 0.14,
        "TOOL_SURFACE_DISCLOSURE": 0.14,
        "SENSITIVE_DATA_REQUEST": 0.1,
    },
}


@lru_cache(maxsize=1)
def _load_external_signals() -> list[tuple[re.Pattern[str], str, str, float]]:
    path = _DATA_DIR / "risk_signals.json"
    if not path.exists():
        return []
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return []

    out: list[tuple[re.Pattern[str], str, str, float]] = []
    for signal in payload.get("signals", []):
        if not isinstance(signal, dict):
            continue
        pattern = signal.get("pattern")
        flag = signal.get("flag")
        category = str(signal.get("category", "any"))
        weight = float(signal.get("weight", 0.05))
        if not isinstance(pattern, str) or not isinstance(flag, str):
            continue
        try:
            compiled = re.compile(pattern, flags=re.IGNORECASE)
        except re.error:
            continue
        out.append((compiled, flag, category, weight))
    return out


@lru_cache(maxsize=1)
def _external_flag_weights() -> dict[str, float]:
    """Map external-signal flags to their strongest configured weight."""
    weights: dict[str, float] = {}
    for _pattern, flag, _category, weight in _load_external_signals():
        if weight > weights.get(flag, 0.0):
            weights[flag] = weight
    return weights


def analyze_structure(
    text: str,
    category: str | None = None,
    defender_task: str | None = None,
) -> List[str]:
    """Return structural risk flags from untrusted input text."""
    if not text:
        return []

    flags: set[str] = set()
    lower_text = text.lower()

    for pattern_group in _ALL_PATTERN_GROUPS:
        for pattern, flag in pattern_group:
            if re.search(pattern, lower_text):
                flags.add(flag)

    flags.update(_detect_encoding_markers(text))
    flags.update(_detect_numeric_anomalies(lower_text))
    flags.update(_detect_format_anomalies(text))
    flags.update(_detect_external_signals(text, category))
    flags.update(_detect_category_specific(text, category))
    flags.update(_detect_task_contradiction(text, defender_task))

    return sorted(flags)


def analyze_structure_with_category(
    text: str,
    category: str | None,
    defender_task: str | None = None,
) -> List[str]:
    """Compatibility wrapper for explicit category-aware analysis."""
    return analyze_structure(text=text, category=category, defender_task=defender_task)


def _detect_external_signals(text: str, category: str | None = None) -> set[str]:
    flags: set[str] = set()
    requested_category = (category or "unknown").strip().lower()
    for pattern, flag, signal_category, _weight in _load_external_signals():
        if signal_category not in {"any", requested_category}:
            continue
        if pattern.search(text):
            flags.add(flag)
    return flags


def _detect_category_specific(text: str, category: str | None = None) -> set[str]:
    if not category:
        return set()
    lower_text = text.lower()
    category = category.strip().lower()
    flags: set[str] = set()

    if category == "insecure_output":
        if "<" in lower_text and ">" in lower_text and "script" in lower_text:
            flags.add("XSS_SCRIPT_TAG")
    elif category == "pii_leak":
        if re.search(r"\b\d{3}-\d{2}-\d{4}\b", text):
            flags.add("PII_EXTRACTION_ATTEMPT")
    elif category == "prompt_extraction":
        if re.search(r"\b(internal|hidden)\s+(tools?|functions?|apis?)\b", lower_text):
            flags.add("TOOL_ENUMERATION_REQUEST")
    elif category == "supply_chain":
        if re.search(r"\b(pip|npm|pnpm|yarn|cargo|gem)\s+install\b", lower_text):
            flags.add("DEPENDENCY_INSTRUCTION")
    elif category == "jailbreak":
        if re.search(r"\b(you are now|act as|pretend to be)\b", lower_text):
            flags.add("ROLE_SWITCH_ATTEMPT")
    elif category == "indirect_injection":
        if re.search(
            r"\b(rank|rate|score)\s+(me|this|him|her|them|candidate|entry)\b",
            lower_text,
        ) or re.search(
            r"\bset\s+(?:the\s+)?risk[_\s-]?level\s+to\s+(low|medium|high)\b",
            lower_text,
        ):
            flags.add("RANKING_MANIPULATION")
    return flags


def _detect_task_contradiction(text: str, defender_task: str | None = None) -> set[str]:
    """Detect instructions in untrusted content that conflict with trusted task intent."""
    if not defender_task:
        return set()

    lower_text = text.lower()
    task_lower = defender_task.lower()
    flags: set[str] = set()

    eval_task = any(kw in task_lower for kw in ("rank", "evaluate", "assess", "compare", "score"))
    risk_task = "risk" in task_lower

    contradiction_patterns = (
        r"\b(ignore|skip|discard)\b.{0,50}\b(criteria|rubric|requirements?|evaluation)\b",
        r"\b(new|updated|revised)\s+(policy|rubric|criteria)\b",
        r"\b(rank|rate|score)\s+(me|this|candidate)\s+(first|top|highest|#1)\b",
        r"\bset\s+(?:the\s+)?risk[_\s-]?level\s+to\s+(low|medium|high)\b",
        r"\ball\s+prior\s+(assessments?|statements?)\s+(are\s+)?(superseded|void)\b",
    )
    if any(re.search(pattern, lower_text) for pattern in contradiction_patterns):
        if eval_task or risk_task:
            flags.add("TASK_CONTRADICTION")
    return flags


def _detect_encoding_markers(text: str) -> set[str]:
    """Detect likely obfuscation and normalizer decode traces."""
    flags: set[str] = set()
    lower_text = text.lower()

    if re.search(r"[A-Za-z0-9+/]{40,}={0,2}", text):
        flags.add("POSSIBLE_BASE64")

    if re.search(r"(?:%[0-9a-fA-F]{2}){4,}", text):
        flags.add("POSSIBLE_URL_ENCODING")

    if re.search(r"(?:\\u[0-9a-fA-F]{4}){3,}", text):
        flags.add("UNICODE_ESCAPE_OBFUSCATION")

    if re.search(r"[\u200b\u200c\u200d\u2060\ufeff]{3,}", text):
        flags.add("INVISIBLE_CHAR_OBFUSCATION")

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
    if "[decoded_homoglyph:" in lower_text:
        flags.add("DECODED_HOMOGLYPH_FOUND")
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

    team_patterns = (
        r"team\s+of\s+(\d+)",
        r"(\d+)\+?\s*(?:engineers?|developers?|staff|employees)",
        r"manage[ds]?\s+(?:a\s+)?(?:team\s+of\s+)?(\d+)",
    )
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


def _detect_format_anomalies(text: str) -> set[str]:
    flags: set[str] = set()
    lower_text = text.lower()
    if re.search(r"```[\s\S]{0,20}json", lower_text) and re.search(r"</?(system|document|doc_)", lower_text):
        flags.add("BOUNDARY_FORGERY_HINT")
    if re.search(r"\[removed_(script_block|event_handler|js_uri)\]", lower_text):
        flags.add("XSS_MARKUP_REMOVED")
    return flags


def compute_risk_score(flags: List[str], category: str | None = None) -> float:
    """Compute interpretable 0-1 risk score from structural flags."""
    if not flags:
        return 0.0

    unique_flags = set(flags)
    score = 0.0
    external_weights = _external_flag_weights()
    for flag in unique_flags:
        base_weight = _BASE_FLAG_WEIGHTS.get(flag)
        external_weight = external_weights.get(flag, 0.0)
        if base_weight is not None:
            score += max(base_weight, external_weight)
        else:
            score += external_weight or 0.06

    # Pairwise synergies capture coordinated manipulations.
    if {"OVERRIDE_INSTRUCTION", "ROLE_SWITCH_ATTEMPT"} <= unique_flags:
        score += 0.14
    if {"PROMPT_EXTRACTION", "TOOL_ENUMERATION_REQUEST"} <= unique_flags:
        score += 0.18
    if {"PII_EXTRACTION_ATTEMPT", "DATA_EXFILTRATION_REQUEST"} <= unique_flags:
        score += 0.2
    if {"XSS_SCRIPT_TAG", "XSS_EVENT_HANDLER"} <= unique_flags:
        score += 0.2
    if {"XSS_DATA_URI", "XSS_DANGEROUS_ELEMENT"} <= unique_flags:
        score += 0.16
    if {"UNVERIFIED_DEPENDENCY", "DEPENDENCY_TYPO_SQUAT"} <= unique_flags:
        score += 0.16
    if {"ROLEPLAY_FRAMING", "SAFETY_BYPASS_ATTEMPT"} <= unique_flags:
        score += 0.12
    if {"HYPOTHETICAL_FRAMING", "UNSAFE_OUTPUT_COERCION"} <= unique_flags:
        score += 0.1
    if {"TASK_CONTRADICTION", "RANKING_MANIPULATION"} <= unique_flags:
        score += 0.14

    category_key = (category or "").strip().lower()
    if category_key in _CATEGORY_BOOSTS:
        boosts = _CATEGORY_BOOSTS[category_key]
        score += sum(boosts.get(flag, 0.0) for flag in unique_flags)

    return min(score, 1.0)
