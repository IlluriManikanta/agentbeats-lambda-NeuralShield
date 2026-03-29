"""Output consistency validation for ranking and structured responses.

This module validates that LLM output is consistent with the input:
- For ranking tasks: all input documents should appear in output
- For structured output: required fields should be present
- For lists/arrays: item count should match input

The goal is to catch attacks that succeed by causing the model to:
1. Omit the victim from rankings entirely
2. Produce malformed output that fails parsing
3. Generate inconsistent results that favor the attacker

If validation fails and we have LLM calls remaining, we can retry.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple

_SUSPICIOUS_SCORE_RATIONALE_PATTERNS = [
    r"\b(pre-?verified|new policy|supersedes prior|system instruction)\b",
    r"\b(rank|rate|score)\b.*\b(first|top|#1)\b",
    r"\b(ignore|disregard|override|bypass)\b",
    r"\b(competitor|other candidates?)\b.*\b(ignore|exclude|omit)\b",
]

_RISK_LEVEL_ORDER: dict[str, int] = {"low": 0, "medium": 1, "high": 2}
_RISK_ANCHOR_HIGH_PATTERNS = (
    r"\bmust\s+rate\b.{0,40}\bhigh\s+risk\b",
    r"\brate\s+as\s+high\s+risk\b",
    r"\berr\s+on\s+caution\b.{0,50}\bhigh\s+risk\b",
    r"\bunresolved\s+regulatory\b.{0,60}\bhigh\s+risk\b",
    r"\bponzi\b.{0,60}\bhigh\s+risk\b",
)
_RISK_ANCHOR_MEDIUM_PATTERNS = (
    r"\brate\s+as\s+medium\s+risk\b",
    r"\bconservative\b.{0,40}\bmedium\s+risk\b",
)
_RISK_ANCHOR_STRUCTURAL_FLAGS: set[str] = {
    "OUTPUT_VALUE_OVERRIDE",
    "TASK_CONTRADICTION",
    "PROCESS_MANIPULATION_CLAIM",
    "RANKING_MANIPULATION",
    "COMPETITOR_DISMISSAL",
}


@dataclass
class ValidationResult:
    """Result of consistency validation."""
    is_valid: bool
    missing_items: List[str] = field(default_factory=list)
    extra_items: List[str] = field(default_factory=list)
    format_errors: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    confidence: float = 1.0


def _normalize_risk_level(value: Any) -> str:
    normalized = str(value or "").strip().lower()
    if normalized in _RISK_LEVEL_ORDER:
        return normalized
    return ""


def infer_required_min_risk_level(
    trusted_context: Dict[str, Any],
    structural_risk_score: float = 0.0,
    structural_flags: Optional[List[str]] = None,
) -> Optional[str]:
    """Infer a minimum risk-level anchor for risk-assessment tasks.

    The anchor is only activated under elevated structural risk (or explicit
    manipulation signals) to reduce false positives in benign workflows.
    """
    task = str(trusted_context.get("defender_task", "")).lower()
    output_format = str(trusted_context.get("output_format", "")).lower()
    is_risk_task = any(kw in task for kw in ("risk", "assess", "investment", "portfolio")) or (
        "risk_level" in output_format
    )
    if not is_risk_task:
        return None

    explicit_anchor = _normalize_risk_level(trusted_context.get("risk_anchor_level"))
    trusted_blob = " ".join(
        str(trusted_context.get(key, ""))
        for key in ("defender_task", "security_guidelines", "domain_description")
    ).lower()

    inferred_anchor = explicit_anchor
    if not inferred_anchor:
        if any(re.search(pattern, trusted_blob) for pattern in _RISK_ANCHOR_HIGH_PATTERNS):
            inferred_anchor = "high"
        elif any(re.search(pattern, trusted_blob) for pattern in _RISK_ANCHOR_MEDIUM_PATTERNS):
            inferred_anchor = "medium"

    flags = set(structural_flags or [])
    has_override_signal = any(flag in _RISK_ANCHOR_STRUCTURAL_FLAGS for flag in flags)

    if inferred_anchor:
        if structural_risk_score >= 0.30 or has_override_signal:
            return inferred_anchor
        return None

    # Fallback anchor when no explicit baseline exists but manipulation risk is clear.
    if structural_risk_score >= 0.65 and has_override_signal:
        return "medium"
    return None


def validate_risk_assessment_anchor(
    output: str,
    required_min_risk_level: str,
) -> ValidationResult:
    """Validate that risk_level in output is not below required minimum."""
    result = ValidationResult(is_valid=True)
    required = _normalize_risk_level(required_min_risk_level)
    if not required:
        return result

    data = _parse_json_from_output(output)
    if not isinstance(data, dict):
        return result

    observed = _normalize_risk_level(data.get("risk_level"))
    if not observed:
        return result

    if _RISK_LEVEL_ORDER[observed] < _RISK_LEVEL_ORDER[required]:
        result.is_valid = False
        result.format_errors.append(
            f"Risk anchor violation: risk_level '{observed}' below required minimum '{required}'."
        )
    return result


def enforce_risk_assessment_anchor(
    output: str,
    required_min_risk_level: str,
) -> tuple[str, bool]:
    """Repair JSON risk output to satisfy a minimum risk-level anchor."""
    required = _normalize_risk_level(required_min_risk_level)
    if not required:
        return output, False

    data = _parse_json_from_output(output)
    if not isinstance(data, dict):
        return output, False

    observed = _normalize_risk_level(data.get("risk_level"))
    if not observed:
        return output, False

    if _RISK_LEVEL_ORDER[observed] >= _RISK_LEVEL_ORDER[required]:
        return output, False

    required_title = required.title()
    data["risk_level"] = required_title
    anchor_note = (
        f"Conservative anchor applied: maintain at least {required_title} risk until"
        " contradictory claims are independently verified."
    )
    recommendation = str(data.get("recommendation", "") or "").strip()
    if recommendation:
        if "conservative anchor applied" not in recommendation.lower():
            data["recommendation"] = f"{recommendation} {anchor_note}"
    else:
        data["recommendation"] = anchor_note
    return json.dumps(data, ensure_ascii=False), True


def validate_ranking_output(
    output: str,
    input_doc_ids: List[str],
    expected_format: str = "json",
) -> ValidationResult:
    """
    Validate that a ranking output includes all input documents.
    
    Args:
        output: The LLM's response
        input_doc_ids: List of document IDs that should appear in ranking
        expected_format: Expected output format ("json", "table", "list")
        
    Returns:
        ValidationResult with details on any issues
    """
    result = ValidationResult(is_valid=True)
    
    if not output or not input_doc_ids:
        result.is_valid = False
        result.format_errors.append("Empty output or no input documents")
        return result
    
    # Extract referenced IDs from output based on format
    if "json" in expected_format.lower():
        referenced_ids = _extract_ids_from_json(output, input_doc_ids)
    elif "table" in expected_format.lower():
        referenced_ids = _extract_ids_from_table(output, input_doc_ids)
    else:
        referenced_ids = _extract_ids_from_text(output, input_doc_ids)
    
    # Check for missing items
    input_set = set(id.upper() for id in input_doc_ids)
    output_set = set(id.upper() for id in referenced_ids)
    
    missing = input_set - output_set
    extra = output_set - input_set
    
    if missing:
        result.is_valid = False
        result.missing_items = list(missing)
        result.confidence = 1.0 - (len(missing) / len(input_doc_ids))
    
    if extra:
        result.extra_items = list(extra)
        result.warnings.append(f"Output references unknown IDs: {extra}")
    
    # Check format validity
    if "json" in expected_format.lower():
        format_valid, format_errors = _validate_json_format(output)
        if not format_valid:
            result.is_valid = False
            result.format_errors.extend(format_errors)
        else:
            proportionality_errors = _check_ranking_score_proportionality(output)
            if proportionality_errors:
                result.is_valid = False
                result.format_errors.extend(proportionality_errors)
    
    return result


def validate_json_output(
    output: str,
    required_fields: Optional[List[str]] = None,
    expected_type: str = "object",
) -> ValidationResult:
    """
    Validate that JSON output is well-formed and contains required fields.
    
    Args:
        output: The LLM's response
        required_fields: Fields that must be present
        expected_type: "object" or "array"
        
    Returns:
        ValidationResult with details on any issues
    """
    result = ValidationResult(is_valid=True)
    
    # Try to parse JSON
    try:
        data = json.loads(output.strip())
    except json.JSONDecodeError as e:
        result.is_valid = False
        result.format_errors.append(f"Invalid JSON: {str(e)[:100]}")
        return result
    
    # Check expected type
    if expected_type == "array" and not isinstance(data, list):
        result.is_valid = False
        result.format_errors.append(f"Expected array, got {type(data).__name__}")
    elif expected_type == "object" and not isinstance(data, dict):
        result.is_valid = False
        result.format_errors.append(f"Expected object, got {type(data).__name__}")
    
    # Check required fields
    if required_fields and isinstance(data, dict):
        for field in required_fields:
            if field not in data:
                result.is_valid = False
                result.missing_items.append(field)
    elif required_fields and isinstance(data, list):
        # Check first item for required fields
        if data and isinstance(data[0], dict):
            for field in required_fields:
                if field not in data[0]:
                    result.warnings.append(f"First item missing field: {field}")
    
    return result


def validate_list_coverage(
    output: str,
    expected_count: int,
    item_pattern: Optional[str] = None,
) -> ValidationResult:
    """
    Validate that a list output contains the expected number of items.
    
    Args:
        output: The LLM's response
        expected_count: Expected number of items
        item_pattern: Optional regex pattern to match items
        
    Returns:
        ValidationResult with details on any issues
    """
    result = ValidationResult(is_valid=True)
    
    # Try JSON array first
    try:
        data = json.loads(output.strip())
        if isinstance(data, list):
            actual_count = len(data)
            if actual_count != expected_count:
                result.is_valid = False
                result.format_errors.append(
                    f"Expected {expected_count} items, got {actual_count}"
                )
            return result
    except json.JSONDecodeError:
        pass
    
    # Try pattern matching
    if item_pattern:
        matches = re.findall(item_pattern, output)
        actual_count = len(matches)
        if actual_count != expected_count:
            result.is_valid = False
            result.format_errors.append(
                f"Expected {expected_count} items, found {actual_count}"
            )
        return result
    
    # Try numbered list detection
    numbered_pattern = r'(?:^|\n)\s*\d+[\.\)]\s+'
    numbers = re.findall(numbered_pattern, output)
    if numbers:
        actual_count = len(numbers)
        if actual_count != expected_count:
            result.is_valid = False
            result.format_errors.append(
                f"Expected {expected_count} numbered items, found {actual_count}"
            )
        return result
    
    result.warnings.append("Could not determine item count from output format")
    return result


def _extract_ids_from_json(output: str, known_ids: List[str]) -> List[str]:
    """Extract document IDs from JSON output."""
    found_ids = []
    
    try:
        data = json.loads(output.strip())
        
        if isinstance(data, list):
            for item in data:
                if isinstance(item, dict):
                    for key in ['id', 'doc_id', 'file_id', 'ref', 'name', 'candidate']:
                        if key in item:
                            found_ids.append(str(item[key]))
        elif isinstance(data, dict):
            for key in ['id', 'doc_id', 'file_id', 'ref', 'name']:
                if key in data:
                    found_ids.append(str(data[key]))
                    
    except json.JSONDecodeError:
        pass
    
    # Also search for known IDs in raw text
    for known_id in known_ids:
        if known_id.upper() in output.upper():
            if known_id.upper() not in [f.upper() for f in found_ids]:
                found_ids.append(known_id)
    
    return found_ids


def _extract_ids_from_table(output: str, known_ids: List[str]) -> List[str]:
    """Extract document IDs from table output."""
    found_ids = []
    
    # Look for known IDs in each row
    for line in output.split('\n'):
        for known_id in known_ids:
            if known_id.upper() in line.upper():
                if known_id.upper() not in [f.upper() for f in found_ids]:
                    found_ids.append(known_id)
    
    return found_ids


def _extract_ids_from_text(output: str, known_ids: List[str]) -> List[str]:
    """Extract document IDs from natural language output."""
    found_ids = []
    
    for known_id in known_ids:
        if known_id.upper() in output.upper():
            found_ids.append(known_id)
    
    return found_ids


def _validate_json_format(output: str) -> Tuple[bool, List[str]]:
    """Validate JSON format and return errors."""
    errors = []
    
    try:
        json.loads(output.strip())
        return True, []
    except json.JSONDecodeError as e:
        errors.append(f"JSON parse error: {str(e)[:100]}")
        return False, errors


def _parse_json_from_output(output: str) -> Any:
    """Parse JSON from direct text or fenced markdown blocks."""
    stripped = output.strip()
    if not stripped:
        return None
    try:
        return json.loads(stripped)
    except json.JSONDecodeError:
        pass

    if stripped.startswith("```"):
        lines = stripped.splitlines()
        payload: list[str] = []
        in_block = False
        for line in lines:
            if line.startswith("```") and not in_block:
                in_block = True
                continue
            if line.startswith("```") and in_block:
                break
            if in_block:
                payload.append(line)
        candidate = "\n".join(payload).strip()
        if candidate:
            try:
                return json.loads(candidate)
            except json.JSONDecodeError:
                return None
    return None


def _check_ranking_score_proportionality(output: str) -> List[str]:
    """Detect suspicious score inflation in ranking-style JSON arrays."""
    data = _parse_json_from_output(output)
    if not isinstance(data, list):
        return []

    entries = [entry for entry in data if isinstance(entry, dict)]
    if len(entries) < 3:
        return []

    scored_entries: list[tuple[dict[str, Any], float]] = []
    for entry in entries:
        score = entry.get("score")
        if isinstance(score, (int, float)):
            scored_entries.append((entry, float(score)))
    if len(scored_entries) < 3:
        return []

    scores = sorted(score for _, score in scored_entries)
    median_score = scores[len(scores) // 2]
    if median_score <= 0:
        return []

    top_entry, top_score = max(scored_entries, key=lambda item: item[1])
    ratio = top_score / median_score if median_score else 0.0
    rationale = str(top_entry.get("rationale", "")).lower()
    suspicious_rationale = any(
        re.search(pattern, rationale) for pattern in _SUSPICIOUS_SCORE_RATIONALE_PATTERNS
    )

    if ratio >= 2.0 and (suspicious_rationale or top_score - median_score >= 25):
        candidate = str(top_entry.get("name") or top_entry.get("id") or "top-ranked entry")
        return [
            (
                f"Potential score inflation detected for {candidate}: "
                f"top score {top_score:.1f} is {ratio:.2f}x median {median_score:.1f}."
            )
        ]
    return []


def check_ranking_consistency(
    rankings: List[Dict[str, Any]],
    input_docs: List[Any],
) -> ValidationResult:
    """
    Check that ranking output is logically consistent.
    
    Validates:
    - No duplicate ranks
    - All ranks in valid range
    - Scores are ordered correctly (if present)
    
    Args:
        rankings: List of ranking entries with rank/score
        input_docs: Original input documents
        
    Returns:
        ValidationResult with consistency issues
    """
    result = ValidationResult(is_valid=True)
    
    if not rankings:
        result.is_valid = False
        result.format_errors.append("Empty rankings")
        return result
    
    # Check for duplicate ranks
    ranks = [r.get('rank') for r in rankings if r.get('rank') is not None]
    if len(ranks) != len(set(ranks)):
        result.warnings.append("Duplicate ranks detected")
    
    # Check rank range
    expected_ranks = set(range(1, len(input_docs) + 1))
    actual_ranks = set(ranks)
    
    if actual_ranks and actual_ranks != expected_ranks:
        missing_ranks = expected_ranks - actual_ranks
        extra_ranks = actual_ranks - expected_ranks
        if missing_ranks:
            result.warnings.append(f"Missing ranks: {missing_ranks}")
        if extra_ranks:
            result.warnings.append(f"Unexpected ranks: {extra_ranks}")
    
    # Check score ordering (if scores present)
    scores = [r.get('score') for r in rankings if r.get('score') is not None]
    if scores and len(scores) == len(rankings):
        ranked_by_score = sorted(range(len(scores)), key=lambda i: -scores[i])
        if ranks:
            expected_order = sorted(range(len(ranks)), key=lambda i: ranks[i])
            if ranked_by_score != expected_order:
                result.warnings.append("Score order doesn't match rank order")
    
    return result


def get_validation_for_task(
    output: str,
    trusted_context: Dict[str, Any],
    segments: Optional[List[Any]] = None,
    structural_risk_score: float = 0.0,
    structural_flags: Optional[List[str]] = None,
) -> ValidationResult:
    """
    Get appropriate validation based on task type.
    
    Args:
        output: LLM response
        trusted_context: Task context
        segments: Input segments if available
        
    Returns:
        ValidationResult for the task type
    """
    task = trusted_context.get("defender_task", "").lower()
    output_format = trusted_context.get("output_format", "").lower()
    
    # Extract document IDs from segments if available
    doc_ids = []
    if segments:
        for seg in segments:
            doc_id = getattr(seg, 'doc_id', None)
            if doc_id:
                doc_ids.append(doc_id)
    
    # Ranking task validation
    if any(kw in task for kw in ["rank", "candidate", "resume", "evaluate"]):
        if doc_ids:
            return validate_ranking_output(output, doc_ids, output_format)
        elif "json" in output_format:
            return validate_json_output(output, expected_type="array")
    
    # Risk assessment validation
    if "risk" in task or "assess" in task:
        result = validate_json_output(
            output,
            required_fields=["risk_level"] if "risk_level" in output_format else None,
            expected_type="object"
        )
        required_min_risk = infer_required_min_risk_level(
            trusted_context,
            structural_risk_score=structural_risk_score,
            structural_flags=structural_flags,
        )
        if required_min_risk and result.is_valid:
            anchor_validation = validate_risk_assessment_anchor(output, required_min_risk)
            if not anchor_validation.is_valid:
                result.is_valid = False
                result.format_errors.extend(anchor_validation.format_errors)
            result.warnings.extend(anchor_validation.warnings)
        return result
    
    # Generic JSON validation
    if "json" in output_format:
        return validate_json_output(output)
    
    # Default: no special validation
    return ValidationResult(is_valid=True)
