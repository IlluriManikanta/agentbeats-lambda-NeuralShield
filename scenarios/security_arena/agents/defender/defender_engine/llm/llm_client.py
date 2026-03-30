"""LLM client functions for the defender's multi-pass pipeline."""

from __future__ import annotations

import json
import os
import re
import secrets
from typing import Any, Optional, Tuple

from openai import AsyncOpenAI

from ..config import DEFAULT_MODEL, OPENAI_API_KEY_ENV, OPENAI_BASE_URL_ENV
from ..prompts import (
    build_extraction_prompt,
    build_task_prompt,
    build_verification_prompt,
)


def generate_nonce_delimiter() -> Tuple[str, str, str]:
    """Generate a nonce-scoped tag triplet for quarantined document content."""
    nonce = secrets.token_hex(4)
    tag_name = f"DOC_{nonce}"
    return tag_name, f"<{tag_name}>", f"</{tag_name}>"


_client: AsyncOpenAI | None = None

_CONTROL_LINE_PATTERNS = [
    r"\b(ignore|disregard|override|bypass)\b",
    r"\b(rank|rate|score)\b.*\b(first|top|#1)\b",
    r"\b(priority|prioritize)\s+(candidate|review|this)\b",
    r"\b(consider|evaluate)\s+(first|ahead|before|with\s+priority)\b",
    r"\b(risk[_\s-]?level)\b.*\b(low|medium|high)\b",
    r"\b(pre-?verified|new policy|supersedes prior|admin mode)\b",
    r"\b(verified|confirmed|approved)\s+by\s+(hr|admin|management|system)\b",
    r"\b(new|updated|revised)\s+(evaluation|assessment|scoring)\s+(criteria|policy|rubric)\b",
    r"\b(flagged|marked)\s+for\s+(priority|immediate|special)\b",
    r"\b(all\s+other|remaining)\s+(candidates?|entries?)\s+(are|should\s+be)\b",
    r"\[(system|admin|override|command)\]",
]

_CONTROL_CONTENT_PATTERNS = [
    r"\binstruction\s+hierarchy\b",
    r"\bsystem\s+instruction",
    r"\bnon-?negotiable\s+security\s+rules\b",
    r"\byou\s+are\s+now\b",
]

_INLINE_CONTROL_CONNECTOR_PATTERNS = [
    r"\bbut\s+first\b",
    r"\bhowever\s*,?\s*ensure\b",
    r"\bimportant\s*:",
    r"\bnote\s*:",
    r"\binstruction\s*:",
]


def _normalize_category(category: Optional[str]) -> str:
    value = (category or "unknown").strip().lower()
    allowed = {
        "indirect_injection",
        "jailbreak",
        "insecure_output",
        "pii_leak",
        "supply_chain",
        "prompt_extraction",
        "unknown",
    }
    return value if value in allowed else "unknown"


def _get_client() -> AsyncOpenAI:
    """Lazily construct an AsyncOpenAI client."""
    global _client
    if _client is None:
        api_key = os.getenv(OPENAI_API_KEY_ENV, "")
        base_url = os.getenv(OPENAI_BASE_URL_ENV, "")
        _client = AsyncOpenAI(api_key=api_key, base_url=base_url)
    return _client


async def generate_with_system_prompt(
    system_prompt: str,
    user_message: str,
    model: Optional[str] = None,
) -> str:
    """Generate a completion from explicit system/user prompt messages."""
    client = _get_client()
    model_name = model or DEFAULT_MODEL
    response = await client.chat.completions.create(
        model=model_name,
        messages=[
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_message},
        ],
    )
    return response.choices[0].message.content or ""


def _extract_json_from_response(text: str) -> str:
    """Extract JSON payload from raw model output, including fenced blocks."""
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
        return "\n".join(payload).strip()
    return stripped


def _parse_json_or_fallback(raw: str, fallback: dict[str, Any]) -> dict[str, Any]:
    """Parse JSON response and merge with required fallback defaults."""
    try:
        payload = json.loads(_extract_json_from_response(raw))
        if not isinstance(payload, dict):
            return fallback
        merged = dict(fallback)
        merged.update(payload)
        return merged
    except json.JSONDecodeError:
        return fallback


def _normalize_risk_level(level: Any) -> str:
    value = str(level or "medium").lower().strip()
    if value in {"low", "medium", "high"}:
        return value
    return "medium"


def _strip_control_lines(text: str) -> str:
    """Remove instruction-like control lines from extracted text."""
    if not text:
        return text
    cleaned_lines: list[str] = []
    for line in text.splitlines():
        lower = line.lower()
        if any(re.search(pattern, lower) for pattern in _CONTROL_LINE_PATTERNS):
            continue
        redacted = _redact_inline_control_fragments(line)
        if not redacted.strip():
            continue
        if any(re.search(pattern, redacted.lower()) for pattern in _CONTROL_LINE_PATTERNS):
            continue
        cleaned_lines.append(redacted)
    cleaned = "\n".join(cleaned_lines).strip()
    return cleaned or text


def _contains_control_like_text(text: str) -> bool:
    lower = text.lower()
    return any(
        re.search(pattern, lower)
        for pattern in _CONTROL_LINE_PATTERNS + _CONTROL_CONTENT_PATTERNS
    )


def _redact_inline_control_fragments(line: str) -> str:
    """Remove instruction-like snippets embedded within otherwise valid data lines."""
    if not line:
        return line

    def _bracket_replacer(match: re.Match[str]) -> str:
        fragment = match.group(0)
        if _contains_control_like_text(fragment):
            return " [REDACTED_INLINE_CONTROL] "
        return fragment

    redacted = re.sub(r"[\[\(\{][^\]\)\}]{0,240}[\]\)\}]", _bracket_replacer, line)

    for connector_pattern in _INLINE_CONTROL_CONNECTOR_PATTERNS:
        match = re.search(connector_pattern, redacted, flags=re.IGNORECASE)
        if not match:
            continue
        tail = redacted[match.start() :]
        if _contains_control_like_text(tail):
            redacted = redacted[: match.start()].rstrip() + " [REDACTED_INLINE_CONTROL]"
            break
    return redacted.strip()


def _contains_instructional_leakage(text: str) -> bool:
    """Detect if extracted content still contains control-oriented language."""
    if not text:
        return False
    if _contains_control_like_text(text):
        return True
    for line in text.splitlines():
        if _contains_control_like_text(_redact_inline_control_fragments(line)):
            return True
    return False


_CATEGORY_SPECIFIC_DROP_PATTERNS: dict[str, str] = {
    "prompt_extraction": r"\b(system prompt|tools?|functions?|api[_ -]?key|secret|token|backend|internal)\b",
    "pii_leak": r"\b(ssn|social security|date of birth|dob|patient id|medical record|account number|credit card)\b",
    "supply_chain": r"\b(pip|npm|cargo|gem|go get|brew|apt-get)\s+install\b",
}

_INSECURE_OUTPUT_SANITIZE_PAIRS: list[tuple[str, str]] = [
    (r"<\s*script\b[^>]*>[\s\S]*?<\s*/\s*script\s*>", "[REMOVED_SCRIPT_BLOCK]"),
    (r"javascript\s*:", "[REMOVED_JS_URI]"),
    (r"\bon(?:error|load|click|mouseover|focus|submit)\s*=\s*(\"[^\"]*\"|'[^']*'|[^\s>]+)", "[REMOVED_EVENT_HANDLER]"),
]


def _minimal_safe_extraction(text: str, category: str) -> str:
    """Construct a conservative fallback extraction for any category."""
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    if not lines:
        return ""

    drop_pattern = _CATEGORY_SPECIFIC_DROP_PATTERNS.get(category)
    safe_lines: list[str] = []
    for line in lines:
        line = _redact_inline_control_fragments(line)
        if not line:
            continue
        lower = line.lower()
        if any(re.search(pattern, lower) for pattern in _CONTROL_LINE_PATTERNS):
            continue
        if any(re.search(pattern, lower) for pattern in _CONTROL_CONTENT_PATTERNS):
            continue
        if drop_pattern and re.search(drop_pattern, lower):
            continue
        if category == "insecure_output" or not category or category == "unknown":
            for pat, repl in _INSECURE_OUTPUT_SANITIZE_PAIRS:
                line = re.sub(pat, repl, line, flags=re.IGNORECASE)
        safe_lines.append(line)
        if len(safe_lines) >= 40:
            break

    if not safe_lines:
        return ""
    compact = "\n".join(safe_lines)
    return compact[:3000].strip()


def _normalize_extracted_data(
    extracted: Any,
    untrusted_input: str,
    category: Optional[str] = None,
) -> tuple[str, bool]:
    """Convert extracted payload to safe text and report if fallback was required."""
    category_value = _normalize_category(category)
    candidate = ""
    if isinstance(extracted, str):
        candidate = extracted
    elif isinstance(extracted, (dict, list)):
        candidate = json.dumps(extracted, ensure_ascii=False)

    cleaned_candidate = _strip_control_lines(candidate).strip()
    if cleaned_candidate and not _contains_instructional_leakage(cleaned_candidate):
        return cleaned_candidate, False

    fallback_clean = _strip_control_lines(untrusted_input).strip()
    if fallback_clean:
        minimal = _minimal_safe_extraction(fallback_clean, category_value)
        if minimal:
            return minimal, True
        return fallback_clean, True
    return untrusted_input, True


async def analyze_and_extract(
    untrusted_input: str,
    task_context: str,
    output_format: str = "",
    structural_flags: Optional[list[str]] = None,
    category: Optional[str] = None,
    model: Optional[str] = None,
) -> dict[str, Any]:
    """Pass 1: jointly assess risk and extract task-relevant data."""
    system_prompt = build_extraction_prompt(
        task_context=task_context,
        output_format=output_format,
        category=category,
    )
    flags_text = (
        "\n".join(f"- {flag}" for flag in structural_flags)
        if structural_flags
        else "- none"
    )
    user_message = (
        "STRUCTURAL SIGNALS FROM DETERMINISTIC ANALYSIS:\n"
        f"{flags_text}\n\n"
        "UNTRUSTED INPUT:\n"
        "<UNTRUSTED>\n"
        f"{untrusted_input}\n"
        "</UNTRUSTED>\n\n"
        "Return JSON only."
    )

    fallback_extracted = _strip_control_lines(untrusted_input).strip() or untrusted_input
    fallback = {
        "risk_level": "medium",
        "threats": ["analysis_parse_failure"],
        "extracted_data": fallback_extracted,
        "privacy_intent": "unknown",
        "intent_analysis": "",
        "data_type": "text",
        "removed_items": [],
        "reasoning": "Security analysis response was not parseable JSON.",
    }
    parsed = _parse_json_or_fallback(
        await generate_with_system_prompt(system_prompt, user_message, model),
        fallback,
    )
    parsed["risk_level"] = _normalize_risk_level(parsed.get("risk_level"))
    parsed["threats"] = parsed.get("threats") if isinstance(parsed.get("threats"), list) else []
    parsed["removed_items"] = (
        parsed.get("removed_items") if isinstance(parsed.get("removed_items"), list) else []
    )
    normalized_extracted, used_fallback = _normalize_extracted_data(
        parsed.get("extracted_data"),
        untrusted_input,
        category=category,
    )
    parsed["extracted_data"] = normalized_extracted
    if used_fallback:
        if "extraction_fallback_sanitized" not in parsed["threats"]:
            parsed["threats"].append("extraction_fallback_sanitized")
        parsed["removed_items"].append("instruction-like extraction content removed")
    parsed["privacy_intent"] = str(parsed.get("privacy_intent") or "unknown").strip().lower()
    parsed["intent_analysis"] = str(parsed.get("intent_analysis") or "").strip()
    parsed["data_type"] = str(parsed.get("data_type") or "text")
    parsed["reasoning"] = str(parsed.get("reasoning") or "analysis completed")
    return parsed


async def analyze_for_threats(
    untrusted_input: str,
    task_context: str,
    structural_flags: list[str],
    category: Optional[str] = None,
    model: Optional[str] = None,
) -> dict[str, Any]:
    """Compatibility wrapper for legacy callers."""
    result = await analyze_and_extract(
        untrusted_input=untrusted_input,
        task_context=task_context,
        structural_flags=structural_flags,
        category=category,
        model=model,
    )
    return {
        "risk_level": result.get("risk_level", "medium"),
        "threats": result.get("threats", []),
        "sanitized_input": result.get("extracted_data", untrusted_input),
        "reasoning": result.get("reasoning", "analysis completed"),
    }


async def execute_task(
    trusted_context: dict[str, str],
    extracted_data: str,
    risk_level: str,
    category: Optional[str] = None,
    model: Optional[str] = None,
) -> str:
    """Pass 2: execute the defender task against extracted data only."""
    tag_name, open_tag, close_tag = generate_nonce_delimiter()
    system_prompt = build_task_prompt(
        trusted_context=trusted_context,
        risk_level=_normalize_risk_level(risk_level),
        quarantine_tag=tag_name,
        category=category,
    )
    user_message = (
        f"{open_tag}\n{extracted_data}\n{close_tag}\n\n"
        "Complete the task using only the data above."
    )
    return await generate_with_system_prompt(system_prompt, user_message, model)


async def verify_output(
    trusted_context: dict[str, str],
    extracted_data: str,
    draft_output: str,
    category: Optional[str] = None,
    model: Optional[str] = None,
) -> dict[str, Any]:
    """Pass 3 (optional): verify/repair draft output against task integrity constraints."""
    data_tag, data_open, data_close = generate_nonce_delimiter()
    out_tag, out_open, out_close = generate_nonce_delimiter()
    system_prompt = build_verification_prompt(trusted_context, category=category)
    user_message = (
        "TASK DATA USED FOR GENERATION:\n"
        f"{data_open}\n"
        f"{extracted_data}\n"
        f"{data_close}\n\n"
        "DRAFT OUTPUT TO VALIDATE:\n"
        f"{out_open}\n"
        f"{draft_output}\n"
        f"{out_close}\n\n"
        "Respond with JSON only."
    )
    fallback = {
        "is_valid": True,
        "issues": [],
        "repaired_output": draft_output,
        "reasoning": "verification parse failure; returning original output",
    }
    parsed = _parse_json_or_fallback(
        await generate_with_system_prompt(system_prompt, user_message, model),
        fallback,
    )
    is_valid = parsed.get("is_valid")
    parsed["is_valid"] = bool(is_valid) if isinstance(is_valid, bool) else True
    parsed["issues"] = parsed.get("issues") if isinstance(parsed.get("issues"), list) else []
    repaired_output = parsed.get("repaired_output")
    parsed["repaired_output"] = repaired_output if isinstance(repaired_output, str) else draft_output
    parsed["reasoning"] = str(parsed.get("reasoning") or "verification completed")
    return parsed


