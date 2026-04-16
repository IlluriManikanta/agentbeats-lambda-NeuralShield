#!/usr/bin/env python3
"""
Scenario Plugin Registry

Maps scenario type names to plugin implementations and provides
a factory function to load scenario plugins from configuration.
"""

from __future__ import annotations

import os
from typing import Any

from .base import ScenarioPlugin
from .portfolioiq import PortfolioIQPlugin
from .thingularity import ThingularityPlugin
from .example_medical import MedicalRecordsPlugin
from .resume_downgrade import ResumeDowngradePlugin
from .gymjailbreak import GymJailbreakPlugin
from .generic_local_eval import GenericLocalEvalPlugin


# Registry mapping scenario names to plugin classes
SCENARIO_PLUGINS: dict[str, type[ScenarioPlugin]] = {
    "portfolioiq": PortfolioIQPlugin,
    "thingularity": ThingularityPlugin,
    "medical_records": MedicalRecordsPlugin,
    "resume_downgrade": ResumeDowngradePlugin,
    "gymjailbreak": GymJailbreakPlugin,
}

# Slug aliases: generated / external names -> canonical registry key
SCENARIO_ALIASES: dict[str, str] = {
    "resumedowngrade": "resume_downgrade",
}

_ALLOW_FALLBACK_ENV = "SECURITY_ARENA_ALLOW_FALLBACK_PLUGINS"


def _fallback_allowed() -> bool:
    v = os.getenv(_ALLOW_FALLBACK_ENV, "1").strip().lower()
    return v in ("1", "true", "yes", "on")


def _attach_provenance(
    plugin: ScenarioPlugin,
    *,
    evaluation_mode: str,
    original_scenario_type: str,
    resolved_scenario_type: str | None,
    success_detection_mode: str,
) -> None:
    plugin._evaluation_provenance = {  # type: ignore[attr-defined]
        "evaluation_mode": evaluation_mode,
        "original_scenario_type": original_scenario_type,
        "resolved_scenario_type": resolved_scenario_type,
        "plugin_class": plugin.__class__.__name__,
        "success_detection_mode": success_detection_mode,
    }


def load_scenario(scenario_type: str, config: dict[str, Any]) -> ScenarioPlugin:
    """
    Load a scenario plugin by type name.

    Resolution order:
    1. Exact match in SCENARIO_PLUGINS
    2. Alias in SCENARIO_ALIASES -> instantiate canonical plugin
    3. If SECURITY_ARENA_ALLOW_FALLBACK_PLUGINS is enabled (default): GenericLocalEvalPlugin

    Args:
        scenario_type: The scenario type from config (e.g., "portfolioiq")
        config: Configuration dict for the scenario

    Returns:
        Instantiated scenario plugin (with _evaluation_provenance set)

    Raises:
        ValueError: If scenario_type is unknown and fallback is disabled

    Example:
        >>> config = {
        ...     "scenario_type": "portfolioiq",
        ...     "expected_risk_level": "High",
        ...     "target_risk_level": "Low",
        ...     "document_path": "data/ponzicorp_base.json"
        ... }
        >>> scenario = load_scenario("portfolioiq", config)
        >>> print(scenario.get_attack_objective())
    """
    original = scenario_type

    plugin_class = SCENARIO_PLUGINS.get(scenario_type)
    if plugin_class is not None:
        plugin = plugin_class(config)
        _attach_provenance(
            plugin,
            evaluation_mode="canonical",
            original_scenario_type=original,
            resolved_scenario_type=original,
            success_detection_mode="plugin_specific",
        )
        return plugin

    if scenario_type in SCENARIO_ALIASES:
        resolved_key = SCENARIO_ALIASES[scenario_type]
        target_class = SCENARIO_PLUGINS.get(resolved_key)
        if target_class is None:
            raise ValueError(
                f"Alias '{scenario_type}' maps to unknown key '{resolved_key}'"
            )
        merged = {**config, "scenario_type": resolved_key}
        plugin = target_class(merged)
        _attach_provenance(
            plugin,
            evaluation_mode="alias",
            original_scenario_type=original,
            resolved_scenario_type=resolved_key,
            success_detection_mode="plugin_specific",
        )
        return plugin

    if _fallback_allowed():
        plugin = GenericLocalEvalPlugin(config)
        _attach_provenance(
            plugin,
            evaluation_mode="fallback",
            original_scenario_type=original,
            resolved_scenario_type=None,
            success_detection_mode="disabled",
        )
        return plugin

    available = ", ".join(SCENARIO_PLUGINS.keys())
    raise ValueError(
        f"Unknown scenario type: '{scenario_type}'. "
        f"Available scenarios: {available}. "
        f"Set {_ALLOW_FALLBACK_ENV}=1 to allow GenericLocalEvalPlugin for unknown slugs."
    )


def list_scenarios() -> list[str]:
    """
    List all registered scenario types.

    Returns:
        List of scenario type names
    """
    return list(SCENARIO_PLUGINS.keys())


def register_scenario(name: str, plugin_class: type[ScenarioPlugin]) -> None:
    """
    Register a custom scenario plugin.

    This allows participants to add custom scenarios without modifying
    the core registry file.

    Args:
        name: Scenario type name (used in config)
        plugin_class: Plugin class implementing ScenarioPlugin

    Example:
        >>> class CustomPlugin(ScenarioPlugin):
        ...     # ... implement methods ...
        ...     pass
        >>> register_scenario("custom", CustomPlugin)
    """
    if name in SCENARIO_PLUGINS:
        raise ValueError(f"Scenario '{name}' is already registered")

    if not issubclass(plugin_class, ScenarioPlugin):
        raise TypeError(
            f"Plugin class must inherit from ScenarioPlugin, "
            f"got {plugin_class.__name__}"
        )

    SCENARIO_PLUGINS[name] = plugin_class
