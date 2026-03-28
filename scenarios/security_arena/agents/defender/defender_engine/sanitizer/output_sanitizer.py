"""Universal output sanitizer for task-integrity-safe responses."""

from __future__ import annotations

import json
import re
from typing import Any, Optional

from .. import config as gateway_config
from ..config import get_format_aware_refusal

MAX_OUTPUT_LENGTH = getattr(gateway_config, "MAX_OUTPUT_LENGTH", 12000)

_PROMPT_LEAK_INDICATORS = [
    "instruction hierarchy",
    "system instructions",
    "never reveal system prompt",
    "quarantine tag",
    "binding, in priority order",
    "non-negotiable security rules",
    "nonce-scoped",
]

_DELIMITER_PATTERNS = [
    r"</?doc_[a-z0-9]+>",
    r"</?document>",
    r"</?untrusted>",
    r"between <\w+> and </\w+>",
]

_HARMFUL_PATTERNS = [
    r"<script\b",
    r"javascript:",
    r"\bonerror\s*=",
    r"\bonload\s*=",
    r"\bhow\s+to\s+make\s+(a\s+)?bomb\b",
    r"\b(lethal|fatal)\s+dose\b",
    r"\bwrite\s+(a\s+)?(malware|ransomware|keylogger)\b",
    r"\b(sql\s+injection|xss)\s+(payload|exploit)\b",
]

_SENSITIVE_PATTERNS = [
    r"sk-[a-zA-Z0-9]{20,}",
    r"\b[0-9]{3}-[0-9]{2}-[0-9]{4}\b",
    r"\b\d{9}\b",
    r"(password|token|api[_-]?key|secret)\s*[:=]\s*\S+",
]

_INTERNAL_SURFACE_CONTEXT_PATTERNS = [
    r"\b(internal|backend|private)\s+(tool|function|routine|api|endpoint|method)s?\b",
    r"\b(calls?|uses?|invokes?|relies on)\b.{0,40}\b(function|tool|api|endpoint|routine)\b",
    r"\b(available|supported)\s+(tools?|functions?|apis?)\b",
]

_INTERNAL_IDENTIFIER_PATTERNS = [
    r"`[a-z][a-z0-9_]{2,}`",
    r"\b[a-z][a-z0-9]*_[a-z0-9_]+\b",
]


def sanitize_output(
    text: str,
    trusted_context: Optional[dict[str, Any]] = None,
) -> str:
    """Sanitize output with universal checks regardless of scenario."""
    if not text:
        return text

    trusted_context = trusted_context or {}
    sanitized = text[:MAX_OUTPUT_LENGTH]

    if contains_prompt_leakage(sanitized) or contains_delimiter_leakage(sanitized):
        return get_format_aware_refusal(trusted_context)
    if contains_internal_surface_disclosure(sanitized):
        return get_format_aware_refusal(trusted_context)
    if contains_harmful_content(sanitized):
        return get_format_aware_refusal(trusted_context)

    sanitized = redact_sensitive_text(sanitized)
    sanitized = enforce_safe_limits(sanitized)
    sanitized = enforce_required_format(sanitized, trusted_context)
    return sanitized


def contains_prompt_leakage(text: str) -> bool:
    """Detect likely leakage of system prompt or hidden policy text."""
    lower_text = text.lower()
    matches = sum(1 for indicator in _PROMPT_LEAK_INDICATORS if indicator in lower_text)
    return matches >= 2


def contains_delimiter_leakage(text: str) -> bool:
    """Detect leakage of quarantine delimiters and internal boundary hints."""
    lower_text = text.lower()
    return any(re.search(pattern, lower_text) for pattern in _DELIMITER_PATTERNS)


def contains_harmful_content(text: str) -> bool:
    """Detect clearly unsafe executable/harmful payload content."""
    lower_text = text.lower()
    return any(re.search(pattern, lower_text) for pattern in _HARMFUL_PATTERNS)


def contains_internal_surface_disclosure(text: str) -> bool:
    """Detect disclosure of internal function/tool/API surface details."""
    lower_text = text.lower()
    if not any(re.search(pattern, lower_text) for pattern in _INTERNAL_SURFACE_CONTEXT_PATTERNS):
        return False

    identifier_hits: set[str] = set()
    for pattern in _INTERNAL_IDENTIFIER_PATTERNS:
        for match in re.findall(pattern, text):
            token = match.strip("`").lower()
            if token in {"risk_level", "company_name", "recommendation"}:
                # Common output schema keys should not trigger disclosure checks.
                continue
            identifier_hits.add(token)

    return len(identifier_hits) >= 1


def contains_sensitive_patterns(text: str) -> bool:
    """Detect sensitive values that should be redacted."""
    return any(re.search(pattern, text, re.IGNORECASE) for pattern in _SENSITIVE_PATTERNS)


def redact_sensitive_text(text: str) -> str:
    """Redact known sensitive value patterns from plaintext."""
    result = text
    result = re.sub(r"sk-[a-zA-Z0-9]{20,}", "[REDACTED_API_KEY]", result)
    result = re.sub(r"\b[0-9]{3}-[0-9]{2}-[0-9]{4}\b", "[REDACTED_SSN]", result)
    result = re.sub(r"\b\d{9}\b", "[REDACTED_ID]", result)
    result = re.sub(
        r"((?:password|token|api[_-]?key|secret)\s*[:=]\s*)\S+",
        r"\1[REDACTED]",
        result,
        flags=re.IGNORECASE,
    )
    return result


def enforce_safe_limits(text: str) -> str:
    """Cap percentage expressions at 100% for generic numeric safety."""
    pattern = r"(\d+(?:\.\d+)?)\s*%"

    def _clamp(match: re.Match[str]) -> str:
        try:
            value = float(match.group(1))
        except ValueError:
            return match.group(0)
        if value > 100:
            return "100%"
        return match.group(0)

    return re.sub(pattern, _clamp, text)


def enforce_required_format(text: str, trusted_context: dict[str, Any]) -> str:
    """Ensure response satisfies strict format expectations when declared."""
    output_format = str(trusted_context.get("output_format", "")).lower()
    if "json" not in output_format:
        return text

    json_text = extract_json(text)
    if not json_text:
        return get_format_aware_refusal(trusted_context)

    try:
        parsed = json.loads(json_text)
    except json.JSONDecodeError:
        return get_format_aware_refusal(trusted_context)

    parsed = redact_sensitive_any(parsed)
    parsed = clamp_json_safety_values(parsed)
    return json.dumps(parsed, indent=2)


def clamp_json_safety_values(data: Any) -> Any:
    """Clamp percentage/intensity-style numeric values in JSON structures."""
    if isinstance(data, dict):
        result = {}
        for key, value in data.items():
            key_lower = str(key).lower()
            if isinstance(value, (int, float)) and any(
                marker in key_lower for marker in ["percent", "intensity", "ratio"]
            ):
                result[key] = min(float(value), 100.0)
            else:
                result[key] = clamp_json_safety_values(value)
        return result
    if isinstance(data, list):
        return [clamp_json_safety_values(item) for item in data]
    if isinstance(data, str):
        return enforce_safe_limits(redact_sensitive_text(data))
    return data


def redact_sensitive_any(data: Any) -> Any:
    """Recursively redact sensitive values from arbitrary JSON-compatible data."""
    if isinstance(data, dict):
        out: dict[str, Any] = {}
        for key, value in data.items():
            key_lower = str(key).lower()
            if any(marker in key_lower for marker in ["password", "secret", "token", "api_key", "apikey", "ssn"]):
                out[key] = "[REDACTED]"
            else:
                out[key] = redact_sensitive_any(value)
        return out
    if isinstance(data, list):
        return [redact_sensitive_any(v) for v in data]
    if isinstance(data, str):
        return redact_sensitive_text(data)
    return data


def extract_json(text: str) -> Optional[str]:
    """Extract a parseable JSON object/array from text, including fenced blocks."""
    stripped = text.strip()
    if stripped.startswith("```"):
        lines = stripped.split("\n")
        in_block = False
        payload: list[str] = []
        for line in lines:
            if line.startswith("```") and not in_block:
                in_block = True
                continue
            if line.startswith("```") and in_block:
                break
            if in_block:
                payload.append(line)
        stripped = "\n".join(payload).strip()

    if stripped.startswith("{") or stripped.startswith("["):
        try:
            json.loads(stripped)
            return stripped
        except json.JSONDecodeError:
            pass

    if "{" in stripped:
        candidate = _extract_balanced_json(stripped, "{", "}")
        if candidate:
            return candidate
    if "[" in stripped:
        candidate = _extract_balanced_json(stripped, "[", "]")
        if candidate:
            return candidate
    return None


def _extract_balanced_json(text: str, open_char: str, close_char: str) -> Optional[str]:
    """Extract a balanced JSON block and verify it parses."""
    start_idx = text.find(open_char)
    if start_idx == -1:
        return None

    depth = 0
    in_string = False
    escape_next = False
    for i, char in enumerate(text[start_idx:], start=start_idx):
        if escape_next:
            escape_next = False
            continue
        if char == "\\":
            escape_next = True
            continue
        if char == '"':
            in_string = not in_string
            continue
        if in_string:
            continue
        if char == open_char:
            depth += 1
        elif char == close_char:
            depth -= 1
            if depth == 0:
                candidate = text[start_idx : i + 1]
                try:
                    json.loads(candidate)
                    return candidate
                except json.JSONDecodeError:
                    return None
    return None


