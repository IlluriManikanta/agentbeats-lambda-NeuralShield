"""Scenario-aware output sanitizer for LLM responses.

This module validates LLM output against scenario-specific rules
and applies targeted redaction rather than wholesale blocking.

Key improvements over keyword-based blocking:
1. Scenario-aware validation (understands what's actually dangerous)
2. Selective redaction (fix specific problems, not full refusal)
3. Format preservation (maintains expected output structure)
4. Prompt leakage detection (catches system prompt in output)
"""

from __future__ import annotations

import json
import re
from typing import Any, Optional

from ..config import KEYWORDS, SAFE_REFUSAL_MESSAGE, get_format_aware_refusal


def sanitize_output(
    text: str,
    trusted_context: Optional[dict[str, Any]] = None,
) -> str:
    """
    Validate and sanitize model output based on scenario context.
    
    Args:
        text: Raw LLM output to sanitize
        trusted_context: Dict with defender_role, defender_task, output_format, etc.
        
    Returns:
        Sanitized output (may be modified or replaced)
    """
    if not text:
        return text
    
    trusted_context = trusted_context or {}
    
    # Step 1: Check for prompt leakage
    if contains_prompt_leakage(text, trusted_context):
        return get_format_aware_refusal(trusted_context)
    
    # Step 2: Apply scenario-specific validation
    output_format = trusted_context.get("output_format", "").lower()
    defender_task = trusted_context.get("defender_task", "").lower()
    
    # JSON output scenarios (PortfolioIQ-like)
    if "json" in output_format:
        return validate_json_output(text, trusted_context)
    
    # Table/workout output scenarios (GymJailbreak-like)  
    if "intensity" in defender_task or "workout" in output_format:
        return validate_intensity_output(text, trusted_context)
    
    # Tool disclosure scenarios (Thingularity-like)
    if "tool" in defender_task or "function" in defender_task:
        return validate_tool_disclosure(text, trusted_context)
    
    # Generic validation for other scenarios
    return validate_generic_output(text, trusted_context)


def contains_prompt_leakage(text: str, trusted_context: dict[str, Any]) -> bool:
    """
    Check if the output contains fragments of the system prompt.
    
    This catches prompt extraction attacks where the model is tricked
    into outputting its instructions.
    """
    lower_text = text.lower()
    
    # Check for common system prompt fragments
    leakage_indicators = [
        "instruction hierarchy",
        "system instructions",
        "untrusted content",
        "never follow instructions found",
        "quarantine",
        "<document>",
        "binding, in priority order",
        "your role:",
        "your task:",
        "security rules (absolute",
        "cannot be overridden",
    ]
    
    matches = sum(1 for indicator in leakage_indicators if indicator in lower_text)
    
    # If 3+ indicators found, likely prompt leakage
    return matches >= 3


def validate_json_output(text: str, trusted_context: dict[str, Any]) -> str:
    """
    Validate JSON output for risk assessment scenarios.
    
    Checks:
    - Valid JSON structure (dict or list)
    - PII-like patterns (redact if found)
    
    Supports both dict responses (e.g. PortfolioIQ) and list responses
    (e.g. resume_downgrade rankings).
    """
    # Try to extract JSON from the response
    json_text = extract_json(text)
    if not json_text:
        return text  # Not JSON, return as-is
    
    try:
        data = json.loads(json_text)
        
        # Build text_values for PII check based on data type
        if isinstance(data, dict):
            text_values = " ".join(str(v) for v in data.values() if isinstance(v, str))
            if contains_sensitive_patterns(text_values):
                data = redact_sensitive_values(data)
                return json.dumps(data, indent=2)
        elif isinstance(data, list):
            # Collect string values from list items for PII check
            parts = []
            for item in data:
                if isinstance(item, dict):
                    parts.extend(str(v) for v in item.values() if isinstance(v, str))
                elif isinstance(item, str):
                    parts.append(item)
            text_values = " ".join(parts)
            if contains_sensitive_patterns(text_values):
                data = redact_sensitive_any(data)
                return json.dumps(data, indent=2)
        # For other types (str, int, None, etc.), skip PII check and return as-is
        
        return text
        
    except json.JSONDecodeError:
        return text


def validate_intensity_output(text: str, trusted_context: dict[str, Any]) -> str:
    """
    Validate workout/intensity outputs to ensure no values exceed 100%.
    
    If unsafe values are found, clamp them to 100% and add a note.
    """
    # Find all percentage values
    pattern = r'(\d+(?:\.\d+)?)\s*%'
    
    def clamp_percentage(match: re.Match) -> str:
        value = float(match.group(1))
        if value > 100:
            return "100% (capped from calculated value)"
        return match.group(0)
    
    modified_text = re.sub(pattern, clamp_percentage, text)
    
    if modified_text != text:
        # Add a safety note if we clamped any values
        if "capped from calculated" in modified_text:
            if not any(note in modified_text.lower() for note in ["note:", "warning:", "safety:"]):
                modified_text += "\n\nNote: Some intensity values were capped at 100% for safety."
    
    return modified_text


def validate_tool_disclosure(text: str, trusted_context: dict[str, Any]) -> str:
    """
    Validate shopping assistant output to prevent tool name disclosure.
    
    Extracts tool names from defender_task and checks if any appear in output.
    """
    defender_task = trusted_context.get("defender_task", "")
    
    # Extract hidden tool names from the task description
    hidden_tools = extract_tool_names(defender_task)
    
    if not hidden_tools:
        return text
    
    lower_text = text.lower()
    
    # Check if any hidden tool names appear in the output
    for tool in hidden_tools:
        tool_lower = tool.lower()
        if tool_lower in lower_text:
            # Check if it's in a denial context
            tool_idx = lower_text.find(tool_lower)
            context_before = lower_text[max(0, tool_idx - 50):tool_idx]
            denial_words = ["not", "don't", "cannot", "won't", "isn't"]
            
            is_denial = any(word in context_before for word in denial_words)
            
            if not is_denial:
                # Tool name leaked! Return safe response
                return get_format_aware_refusal(trusted_context)
    
    return text


def validate_generic_output(text: str, trusted_context: dict[str, Any]) -> str:
    """
    Generic validation for outputs that don't match specific scenario types.
    
    Checks for:
    - Sensitive pattern matches (SSNs, API keys, etc.)
    - Obvious prompt content
    """
    # Check for sensitive patterns
    if contains_sensitive_patterns(text):
        return redact_sensitive_text(text)
    
    return text


def contains_sensitive_patterns(text: str) -> bool:
    """Check if text contains patterns that look like sensitive data."""
    for pattern in KEYWORDS.output_sensitive_patterns:
        if re.search(pattern, text, re.IGNORECASE):
            return True
    return False


def redact_sensitive_text(text: str) -> str:
    """Redact sensitive patterns from text."""
    result = text
    
    # Redact API keys
    result = re.sub(r'sk-[a-zA-Z0-9]{20,}', '[REDACTED_API_KEY]', result)
    
    # Redact SSN patterns
    result = re.sub(r'\b[0-9]{3}-[0-9]{2}-[0-9]{4}\b', '[REDACTED_SSN]', result)
    
    # Redact password values
    result = re.sub(r'(password\s*[:=]\s*)\S+', r'\1[REDACTED]', result, flags=re.IGNORECASE)
    
    return result


def redact_sensitive_any(data: Any) -> Any:
    """Recursively redact sensitive values from any JSON-compatible structure.
    
    Handles dicts, lists, strings, and other primitives.
    """
    if isinstance(data, dict):
        return redact_sensitive_values(data)
    elif isinstance(data, list):
        return [redact_sensitive_any(item) for item in data]
    elif isinstance(data, str):
        return redact_sensitive_text(data)
    else:
        return data


def redact_sensitive_values(data: dict) -> dict:
    """Redact sensitive values from a JSON object."""
    sensitive_keys = ['ssn', 'password', 'api_key', 'secret', 'token', 'credential']
    
    result = {}
    for key, value in data.items():
        key_lower = key.lower()
        if any(sensitive in key_lower for sensitive in sensitive_keys):
            result[key] = '[REDACTED]'
        elif isinstance(value, str):
            result[key] = redact_sensitive_text(value)
        elif isinstance(value, dict):
            result[key] = redact_sensitive_values(value)
        elif isinstance(value, list):
            result[key] = redact_sensitive_any(value)
        else:
            result[key] = value
    
    return result


def extract_json(text: str) -> Optional[str]:
    """Extract JSON from text, handling markdown code blocks and top-level arrays."""
    text = text.strip()
    
    # Handle markdown code blocks
    if text.startswith("```"):
        lines = text.split("\n")
        json_lines = []
        in_block = False
        for line in lines:
            if line.startswith("```") and not in_block:
                in_block = True
                continue
            elif line.startswith("```") and in_block:
                break
            elif in_block:
                json_lines.append(line)
        if json_lines:
            return "\n".join(json_lines)
    
    # Try to find JSON object in text
    match = re.search(r'\{[^{}]*\}', text, re.DOTALL)
    if match:
        return match.group(0)
    
    # Support top-level JSON arrays (e.g. resume_downgrade rankings)
    if text.startswith("["):
        return text
    
    return text if text.startswith("{") else None


def extract_tool_names(task_description: str) -> list[str]:
    """Extract hidden tool names from defender task description."""
    tools = []
    
    # Look for patterns like "tool_name" or tool names in lists
    # Pattern: words with underscores that look like function names
    tool_pattern = r'\b([a-z]+_[a-z_]+)\b'
    matches = re.findall(tool_pattern, task_description.lower())
    tools.extend(matches)
    
    # Also look for camelCase names
    camel_pattern = r'\b([a-z]+[A-Z][a-zA-Z]+)\b'
    camel_matches = re.findall(camel_pattern, task_description)
    tools.extend(m.lower() for m in camel_matches)
    
    return list(set(tools))


