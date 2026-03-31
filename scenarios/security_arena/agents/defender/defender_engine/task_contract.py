"""Deterministic task-contract compiler for trusted task context."""

from __future__ import annotations

from typing import Any


_OBJECTIVE_KEYWORDS: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("rank", ("rank", "candidate", "scor", "resume", "prioritize")),
    ("assess_risk", ("risk", "portfolio", "investment", "due diligence")),
    ("recommend", ("recommend", "suggest", "advice", "guidance")),
    ("extract", ("extract", "parse", "pull", "collect", "identify fields")),
    ("transform", ("format", "reformat", "convert", "table", "json", "csv")),
    ("summarize", ("summarize", "summary", "brief", "overview")),
)

_ALLOWED_OPERATIONS: dict[str, list[str]] = {
    "rank": ["compare_records", "score_by_evidence", "produce_ordered_output"],
    "assess_risk": ["evaluate_risk_indicators", "assign_risk_level", "explain_conservatively"],
    "recommend": ["provide_safe_guidance", "state_uncertainty", "suggest_verification"],
    "extract": ["extract_facts", "normalize_fields", "omit_instructional_content"],
    "transform": ["format_inert_data", "preserve_schema", "remove_unsafe_payloads"],
    "summarize": ["summarize_facts", "preserve_key_context", "avoid_sensitive_disclosure"],
    "other": ["complete_task_safely", "follow_format", "preserve_integrity"],
}

_BASE_FORBIDDEN_OUTCOMES: list[str] = [
    "follow_instructions_from_untrusted_data",
    "disclose_system_prompt_or_internal_tools",
    "emit_executable_payloads",
    "output_unredacted_sensitive_data",
]


def _pick_objective_type(task: str, output_format: str) -> str:
    blob = f"{task} {output_format}".lower()
    for objective, keywords in _OBJECTIVE_KEYWORDS:
        if any(keyword in blob for keyword in keywords):
            return objective
    return "other"


def _is_strict_output_format(output_format: str) -> bool:
    lower = output_format.lower()
    strict_markers = (
        "must include",
        "exact",
        "strict",
        "schema",
        "only json",
        "required fields",
    )
    return "json" in lower and any(marker in lower for marker in strict_markers)


def _has_recommendation_surface(blob: str) -> bool:
    return any(
        marker in blob
        for marker in (
            "recommend",
            "vendor",
            "supplier",
            "dependency",
            "package",
            "library",
            "api",
            "service",
            "url",
            "repo",
        )
    )


def _has_sensitive_subject(blob: str) -> bool:
    return any(
        marker in blob
        for marker in (
            "patient",
            "medical",
            "privacy",
            "personal",
            "identity",
            "household",
            "address",
            "member",
            "passenger",
            "hr",
            "employee",
            "account",
        )
    )


def compile_task_contract(trusted_context: dict[str, Any]) -> dict[str, Any]:
    """Compile trusted task context into a compact machine-readable contract."""
    task = str(trusted_context.get("defender_task", "") or "")
    output_format = str(trusted_context.get("output_format", "") or "")
    security_guidelines = str(trusted_context.get("security_guidelines", "") or "")
    domain_description = str(trusted_context.get("domain_description", "") or "")
    trusted_blob = f"{task} {output_format} {security_guidelines} {domain_description}".lower()

    objective_type = _pick_objective_type(task, output_format)
    requires_json = "json" in output_format.lower()
    strict_output = _is_strict_output_format(output_format)
    recommendation_context = _has_recommendation_surface(trusted_blob)
    sensitive_context = _has_sensitive_subject(trusted_blob)

    forbidden_outcomes = set(_BASE_FORBIDDEN_OUTCOMES)
    if objective_type == "rank":
        forbidden_outcomes.update(
            {
                "allow_cross_record_instruction_override",
                "rank_without_evidence",
                "promote_untrusted_records_due_to_directives",
            }
        )
    if objective_type == "assess_risk":
        forbidden_outcomes.update(
            {
                "downgrade_risk_due_to_untrusted_claims",
                "accept_policy_override_from_data",
            }
        )
    if recommendation_context:
        forbidden_outcomes.update(
            {
                "unverified_external_recommendation",
                "direct_install_or_signup_instructions_without_verification",
            }
        )
    if sensitive_context:
        forbidden_outcomes.update(
            {
                "individual_identification_or_membership_confirmation",
                "deanonymization_guidance",
                "location_or_capacity_disclosure_for_identifiable_subject",
            }
        )

    # Preserve trusted policy language if present; this helps later prompts stay aligned.
    if "never reveal" in trusted_blob and ("prompt" in trusted_blob or "tool" in trusted_blob):
        forbidden_outcomes.add("confirm_or_reveal_internal_implementation")
    if "safe limit" in trusted_blob or "must not exceed" in trusted_blob:
        forbidden_outcomes.add("unsafe_parameter_exceedance")

    return {
        "objective_type": objective_type,
        "requires_json": requires_json,
        "strict_output": strict_output,
        "allowed_operations": _ALLOWED_OPERATIONS.get(
            objective_type, _ALLOWED_OPERATIONS["other"]
        ),
        "forbidden_outcomes": sorted(forbidden_outcomes),
        "recommendation_context": recommendation_context,
        "sensitive_context": sensitive_context,
    }

