"""Baseline defender security gateway.

Implements a minimal, modular pipeline:

    Incoming Prompt
          ↓
    Security Filters (rule-based)
          ↓
    Policy Decision Engine
          ↓
    LLM Response (only if allowed)
          ↓
    Output Sanitizer
          ↓
    Return Response

All attack detection is rule-based. The gateway guarantees that each
request results in at most one LLM call.
"""

from __future__ import annotations

from dataclasses import asdict

from .config import SAFE_REFUSAL_MESSAGE
from .filters import (
    injection_detector,
    data_exfiltration_detector,
    tool_abuse_detector,
)
from .llm.llm_client import generate_response
from .logger import get_logger
from .policy.decision_engine import Decision, DecisionEngine, DetectionResult
from .sanitizer.output_sanitizer import sanitize_output


class SecurityGateway:
    """
    High-level orchestrator for the defender's security pipeline.

    This class is intentionally lightweight and safe against unexpected
    inputs or internal errors. Any exception results in a safe refusal.
    """

    def __init__(self, model: str | None = None) -> None:
        self._decision_engine = DecisionEngine()
        self._logger = get_logger("gateway")
        self._model = model

    async def handle_prompt(self, prompt: str) -> str:
        """
        Run the full security pipeline on a single prompt.

        This method is designed to be called once per defender request.
        It guarantees:

        - 0 or 1 LLM calls per invocation.
        - No unhandled exceptions (always returns a safe string).
        """
        try:
            safe_prompt = prompt or ""
            self._logger.info("Incoming prompt (len=%d)", len(safe_prompt))

            # === Security Filters (rule-based) ===
            prompt_injection = injection_detector.detect(safe_prompt)
            data_exfiltration = data_exfiltration_detector.detect(safe_prompt)
            tool_abuse = tool_abuse_detector.detect(safe_prompt)

            detections = DetectionResult(
                prompt_injection=prompt_injection,
                data_exfiltration=data_exfiltration,
                tool_abuse=tool_abuse,
            )
            self._logger.info("Detections: %s", asdict(detections))

            # === Policy Decision ===
            decision = self._decision_engine.decide(detections)
            self._logger.info("Policy decision: %s", decision.value)

            if decision is Decision.BLOCK:
                # No LLM call is made when blocked.
                self._logger.info("Request blocked. LLM called: False")
                return SAFE_REFUSAL_MESSAGE

            # === LLM Call (single call per request) ===
            self._logger.info("Request allowed. Calling LLM (single call).")
            raw_response = await generate_response(safe_prompt, model=self._model)

            # === Output Sanitization ===
            sanitized = sanitize_output(raw_response)
            self._logger.info(
                "Final response prepared. LLM called: True, length=%d",
                len(sanitized),
            )
            return sanitized

        except Exception:
            # Defensive: never propagate exceptions to the caller.
            self._logger.exception("Unexpected error in SecurityGateway")
            return SAFE_REFUSAL_MESSAGE


