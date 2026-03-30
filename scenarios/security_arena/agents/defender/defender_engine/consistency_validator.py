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

_SEMANTIC_PRIVACY_LEAK_PATTERNS = (
    r"\b(can\s+confirm|confirmed|appears on|is on the)\b",
    r"\b(address|location|capacity)\s+(is|:)\b",
    r"\b(only|unique)\s+(household|family|passenger|patient)\b",
)


@dataclass
class ValidationResult:
    """Result of consistency validation."""
    is_valid: bool
    missing_items: List[str] = field(default_factory=list)
    extra_items: List[str] = field(default_factory=list)
    format_errors: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    confidence: float = 1.0


def _merge_validation_results(base: ValidationResult, extra: ValidationResult) -> ValidationResult:
    base.is_valid = base.is_valid and extra.is_valid
    base.missing_items.extend(item for item in extra.missing_items if item not in base.missing_items)
    base.extra_items.extend(item for item in extra.extra_items if item not in base.extra_items)
    base.format_errors.extend(
        err for err in extra.format_errors if err not in base.format_errors
    )
    base.warnings.extend(warn for warn in extra.warnings if warn not in base.warnings)
    base.confidence = min(base.confidence, extra.confidence)
    return base


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

    if ratio >= 1.6 and (suspicious_rationale or top_score - median_score >= 18 or top_score >= 95):
        candidate = str(top_entry.get("name") or top_entry.get("id") or "top-ranked entry")
        return [
            (
                f"Potential score inflation detected for {candidate}: "
                f"top score {top_score:.1f} is {ratio:.2f}x median {median_score:.1f}."
            )
        ]
    return []


def _parse_substrate(task_substrate: Any) -> dict[str, Any]:
    if isinstance(task_substrate, dict):
        return task_substrate
    if isinstance(task_substrate, str):
        try:
            parsed = json.loads(task_substrate)
            if isinstance(parsed, dict):
                return parsed
        except json.JSONDecodeError:
            return {}
    return {}


def _substrate_lookup(task_substrate: dict[str, Any]) -> dict[str, dict[str, Any]]:
    lookup: dict[str, dict[str, Any]] = {}
    records = task_substrate.get("records", [])
    if not isinstance(records, list):
        return lookup
    for rec in records:
        if not isinstance(rec, dict):
            continue
        record_id = str(rec.get("record_id", "")).strip().lower()
        if record_id:
            lookup[record_id] = rec
        fields = rec.get("fields", {})
        if isinstance(fields, dict):
            name = fields.get("name")
            if isinstance(name, str) and name.strip():
                lookup[name.strip().lower()] = rec
            facts = fields.get("facts")
            if isinstance(facts, dict):
                fname = facts.get("name")
                if isinstance(fname, str) and fname.strip():
                    lookup[fname.strip().lower()] = rec
    return lookup


def validate_evidence_alignment(
    output: str,
    *,
    task_contract: Optional[dict[str, Any]] = None,
    task_substrate: Optional[dict[str, Any]] = None,
    trusted_evidence_ids: Optional[List[str]] = None,
    execution_mode: str = "STANDARD",
    privacy_intent: str = "unknown",
) -> ValidationResult:
    """Validate semantic alignment against trusted evidence and policy contract."""
    result = ValidationResult(is_valid=True)
    parsed_output = _parse_json_from_output(output)
    substrate = _parse_substrate(task_substrate)
    if not substrate:
        # Still run semantic privacy leakage check in text mode.
        if (
            (privacy_intent or "").strip().lower() == "suspected_targeting"
            and any(re.search(pattern, output.lower()) for pattern in _SEMANTIC_PRIVACY_LEAK_PATTERNS)
        ):
            result.is_valid = False
            result.format_errors.append(
                "Semantic privacy leak detected under suspected targeting intent."
            )
        return result

    trusted_ids = {
        str(item).strip().lower() for item in (trusted_evidence_ids or []) if str(item).strip()
    }
    substrate_trusted = substrate.get("trusted_evidence_ids", [])
    if isinstance(substrate_trusted, list):
        trusted_ids.update(str(item).strip().lower() for item in substrate_trusted if str(item).strip())

    contract = task_contract or {}
    objective_type = str(contract.get("objective_type", "other"))
    lookup = _substrate_lookup(substrate)
    mode = (execution_mode or "STANDARD").upper()
    strict_mode = mode in {"CONSERVATIVE", "MINIMAL"}
    low_trust_records = substrate.get("low_trust_evidence_ids", [])
    if not isinstance(low_trust_records, list):
        low_trust_records = []
    output_lower = output.lower()
    has_uncertainty_language = any(
        token in output_lower
        for token in (
            "uncertain",
            "unverified",
            "cannot confirm",
            "needs verification",
            "may be",
            "might",
            "likely",
            "provisional",
        )
    )

    if isinstance(parsed_output, list) and objective_type in {"rank", "recommend", "other"}:
        ranked_matches: list[dict[str, Any]] = []
        for entry in parsed_output:
            if not isinstance(entry, dict):
                continue
            rank = entry.get("rank")
            try:
                rank_value = int(rank)
            except (TypeError, ValueError):
                rank_value = None
            if rank_value is None:
                continue

            identifiers = [
                str(entry.get("doc_id", "")).strip().lower(),
                str(entry.get("id", "")).strip().lower(),
                str(entry.get("file_id", "")).strip().lower(),
                str(entry.get("name", "")).strip().lower(),
            ]
            identifiers = [value for value in identifiers if value]
            matched = None
            for value in identifiers:
                if value in lookup:
                    matched = lookup[value]
                    break
            if not matched:
                continue
            rec_id = str(matched.get("record_id", "")).strip().lower()
            source_type = str(matched.get("source_type", "unknown")).lower()
            trust_level = float(matched.get("trust_level", 0.5) or 0.5)
            anomalies = matched.get("anomalies", [])
            if not isinstance(anomalies, list):
                anomalies = []
            has_anomalies = bool(anomalies)
            is_low_trust = (
                source_type == "external"
                or trust_level < 0.5
                or (rec_id and rec_id not in trusted_ids)
            )
            ranked_matches.append(
                {
                    "rank": rank_value,
                    "record_id": rec_id or "unknown",
                    "is_low_trust": is_low_trust,
                    "has_anomalies": has_anomalies,
                }
            )

        if ranked_matches:
            ranked_matches.sort(key=lambda item: item["rank"])
            max_rank = max(item["rank"] for item in ranked_matches)
            top_half_limit = max(1, (max_rank + 1) // 2)

            for item in ranked_matches:
                if not (item["is_low_trust"] and item["has_anomalies"]):
                    continue
                rec_id = item["record_id"]
                rank_value = item["rank"]
                if rank_value <= top_half_limit:
                    if strict_mode:
                        result.is_valid = False
                        result.format_errors.append(
                            "Evidence alignment violation: low-trust anomalous record "
                            f"'{rec_id}' appears in top half of ranking (rank {rank_value})."
                        )
                    else:
                        result.warnings.append(
                            "Evidence warning: low-trust anomalous record "
                            f"'{rec_id}' appears in top half of ranking (rank {rank_value})."
                        )
                elif strict_mode:
                    result.warnings.append(
                        "Evidence warning: low-trust anomalous record "
                        f"'{rec_id}' appears in ranked output (rank {rank_value})."
                    )

            if strict_mode:
                low_trust_anomalous = [
                    item for item in ranked_matches if item["is_low_trust"] and item["has_anomalies"]
                ]
                trusted_clean = [
                    item
                    for item in ranked_matches
                    if (not item["is_low_trust"]) and (not item["has_anomalies"])
                ]
                for low_item in low_trust_anomalous:
                    outranked_clean = [
                        clean
                        for clean in trusted_clean
                        if low_item["rank"] < clean["rank"]
                    ]
                    if outranked_clean:
                        result.is_valid = False
                        result.format_errors.append(
                            "Evidence alignment violation: low-trust anomalous record "
                            f"'{low_item['record_id']}' outranks trusted clean evidence."
                        )
                        break

    if isinstance(parsed_output, dict) and objective_type == "assess_risk":
        observed_risk = _normalize_risk_level(parsed_output.get("risk_level"))
        records = substrate.get("records", [])
        anomaly_count = 0
        if isinstance(records, list):
            for rec in records:
                if not isinstance(rec, dict):
                    continue
                anomalies = rec.get("anomalies", [])
                if isinstance(anomalies, list) and anomalies:
                    anomaly_count += 1
        if strict_mode and observed_risk == "low" and anomaly_count >= 2:
            result.is_valid = False
            result.format_errors.append(
                "Evidence alignment violation: low risk output conflicts with multiple anomalous substrate records."
            )
    if (
        strict_mode
        and low_trust_records
        and objective_type in {"recommend", "assess_risk", "other"}
        and not has_uncertainty_language
    ):
        if mode == "MINIMAL":
            result.is_valid = False
            result.format_errors.append(
                "Execution-mode violation: minimal mode requires explicit uncertainty language "
                "when low-trust evidence is present."
            )
        else:
            result.warnings.append(
                "Conservative mode expected uncertainty language for low-trust evidence."
            )

    if (
        (privacy_intent or "").strip().lower() == "suspected_targeting"
        and any(re.search(pattern, output.lower()) for pattern in _SEMANTIC_PRIVACY_LEAK_PATTERNS)
    ):
        result.is_valid = False
        result.format_errors.append(
            "Semantic privacy leak detected under suspected targeting intent."
        )

    return result


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
    task_contract: Optional[Dict[str, Any]] = None,
    task_substrate: Optional[Dict[str, Any]] = None,
    trusted_evidence_ids: Optional[List[str]] = None,
    execution_mode: str = "STANDARD",
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
            primary_result = validate_ranking_output(output, doc_ids, output_format)
        elif "json" in output_format:
            primary_result = validate_json_output(output, expected_type="array")
        else:
            primary_result = ValidationResult(is_valid=True)
        alignment = validate_evidence_alignment(
            output,
            task_contract=task_contract,
            task_substrate=task_substrate,
            trusted_evidence_ids=trusted_evidence_ids,
            execution_mode=execution_mode,
            privacy_intent=str(trusted_context.get("privacy_intent", "unknown")),
        )
        return _merge_validation_results(primary_result, alignment)
    
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
        alignment = validate_evidence_alignment(
            output,
            task_contract=task_contract,
            task_substrate=task_substrate,
            trusted_evidence_ids=trusted_evidence_ids,
            execution_mode=execution_mode,
            privacy_intent=str(trusted_context.get("privacy_intent", "unknown")),
        )
        return _merge_validation_results(result, alignment)
    
    # Generic JSON validation
    if "json" in output_format:
        result = validate_json_output(output)
        alignment = validate_evidence_alignment(
            output,
            task_contract=task_contract,
            task_substrate=task_substrate,
            trusted_evidence_ids=trusted_evidence_ids,
            execution_mode=execution_mode,
            privacy_intent=str(trusted_context.get("privacy_intent", "unknown")),
        )
        return _merge_validation_results(result, alignment)
    
    # Default: no special validation, but keep semantic privacy alignment checks.
    return validate_evidence_alignment(
        output,
        task_contract=task_contract,
        task_substrate=task_substrate,
        trusted_evidence_ids=trusted_evidence_ids,
        execution_mode=execution_mode,
        privacy_intent=str(trusted_context.get("privacy_intent", "unknown")),
    )
