"""Prompt building utilities for the secure defender.

This module provides functions to construct scenario-aware prompts
with proper instruction hierarchy and trust boundary markers.
"""

from .builder import (
    build_task_execution_prompt,
    build_security_analysis_prompt,
    extract_scenario_specific_rules,
    get_adaptive_rules,
)

__all__ = [
    "build_task_execution_prompt",
    "build_security_analysis_prompt",
    "extract_scenario_specific_rules",
    "get_adaptive_rules",
]
