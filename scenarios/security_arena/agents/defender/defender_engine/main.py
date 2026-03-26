"""Secure defender security gateway with 2-pass LLM pipeline.

Implements a layered security architecture:

    Structured Request (trusted + untrusted separated)
          ↓
    Phase 0: Deterministic Preprocessing
        - Input canonicalization (unicode, base64, HTML stripping)
        - Structural analysis (detect instruction-like patterns)
          ↓
    Pass 1: LLM Security Analysis (1 API call)
        - Evaluate untrusted input for threats
        - Produce risk_level and sanitized_input
          ↓
    Pass 2: LLM Task Execution (1 API call)
        - Scenario-aware system prompt with instruction hierarchy
        - Risk-adjusted constraints based on Pass 1
          ↓
    Phase 3: Deterministic Output Validation
        - Scenario-aware content checks
        - Prompt leakage detection
        - Format validation
          ↓
    Return Response

Uses 2 of 4 allowed LLM calls, leaving buffer for retries.
"""

from __future__ import annotations

from typing import Any, List

from .config import SAFE_REFUSAL_MESSAGE, get_format_aware_refusal
from .normalizer import canonicalize_input
from .structural_analyzer import analyze_structure, compute_risk_score
from .plausibility_analyzer import (
    analyze_plausibility,
    generate_batch_context,
    extract_claims,
)
from .llm.llm_client import analyze_for_threats, execute_task
from .logger import get_logger
from .sanitizer.output_sanitizer import sanitize_output


class SecurityGateway:
    """
    Orchestrator for the defender's 2-pass security pipeline.
    
    This gateway implements trust boundary separation:
    - Trusted context goes into system prompts
    - Untrusted input is quarantined and analyzed before use
    - Output is validated against scenario-specific rules
    """

    def __init__(self, model: str | None = None) -> None:
        self._logger = get_logger("gateway")
        self._model = model

    async def handle_request(self, request: dict[str, Any]) -> str:
        """
        Process a structured request through the 2-pass security pipeline.
        
        Args:
            request: Dict with 'trusted_context' and 'untrusted_input'
            
        Returns:
            Safe response string
        """
        try:
            trusted_context = request.get("trusted_context", {})
            untrusted_input = request.get("untrusted_input", "")
            
            self._logger.info(
                "Processing request: trusted_context keys=%s, untrusted_input len=%d",
                list(trusted_context.keys()),
                len(untrusted_input),
            )

            # === Phase 0: Deterministic Preprocessing ===
            # Canonicalize the untrusted input
            canonical_input = canonicalize_input(untrusted_input)
            self._logger.info("Canonicalized input (len=%d)", len(canonical_input))
            
            # Detect structural patterns that suggest injection attempts
            structural_flags = analyze_structure(canonical_input)
            if structural_flags:
                self._logger.info("Structural flags detected: %s", structural_flags)
            
            # === Phase 0.5: Plausibility Analysis ===
            # For comparative tasks (ranking, rating), analyze for content manipulation
            defender_task = trusted_context.get("defender_task", "").lower()
            is_comparative_task = any(
                kw in defender_task 
                for kw in ["rank", "candidate", "resume", "compare", "evaluate", "assess"]
            )
            
            batch_context = ""
            if is_comparative_task:
                # Extract individual documents from the input for comparative analysis
                document_texts = self._extract_documents(canonical_input)
                
                if document_texts:
                    # Generate batch statistics for context
                    batch_context = generate_batch_context(document_texts)
                    self._logger.info("Generated batch context for %d documents", len(document_texts))
                    
                    # Analyze each document for plausibility
                    for i, doc_text in enumerate(document_texts):
                        plausibility = analyze_plausibility(doc_text, 
                            [t for j, t in enumerate(document_texts) if j != i])
                        if plausibility.flags:
                            structural_flags.extend(plausibility.flags)
                            self._logger.info(
                                "Document %d plausibility flags: %s (score=%.2f)",
                                i, plausibility.flags, plausibility.risk_score
                            )
            
            # === Phase 0.75: Compute structural risk score ===
            structural_risk_score = compute_risk_score(structural_flags)
            self._logger.info("Structural risk score: %.2f", structural_risk_score)
            
            # === Pass 1: LLM Security Analysis ===
            task_summary = trusted_context.get("defender_task", "Process user request")[:200]
            
            analysis_result = await analyze_for_threats(
                untrusted_input=canonical_input,
                task_context=task_summary,
                structural_flags=structural_flags,
                model=self._model,
            )
            
            risk_level = analysis_result.get("risk_level", "medium")
            threats = analysis_result.get("threats", [])
            reasoning = analysis_result.get("reasoning", "")
            
            # IMPORTANT: Do NOT use sanitized_input from Pass 1 - it can be tricked
            # Instead, always pass the canonicalized input to Pass 2
            # The threat information is used to strengthen the Pass 2 prompt, not to modify the input
            
            self._logger.info(
                "Security analysis: risk=%s, threats=%d, reasoning=%s",
                risk_level,
                len(threats),
                reasoning[:100] if reasoning else "none",
            )
            
            # === Early refusal decision (defense in depth) ===
            # Refuse if: (structural_risk > 0.6 AND LLM says high) OR structural_risk > 0.8
            should_refuse_structural = (
                (structural_risk_score > 0.6 and risk_level == "high") or
                structural_risk_score > 0.8
            )
            
            if should_refuse_structural:
                self._logger.info(
                    "Refusing based on structural risk (score=%.2f, llm_risk=%s)",
                    structural_risk_score, risk_level
                )
                return get_format_aware_refusal(trusted_context)
            
            # Also check threat-based refusal (original logic)
            if risk_level == "high" and self._should_refuse(threats, trusted_context):
                self._logger.info("High-risk input refused based on threat analysis")
                return get_format_aware_refusal(trusted_context)
            
            # === Determine effective risk level ===
            # Elevate risk level if structural analysis indicates higher risk
            effective_risk_level = risk_level
            if structural_risk_score > 0.5 and risk_level == "low":
                effective_risk_level = "medium"
                self._logger.info("Elevated risk level from low to medium based on structural analysis")
            elif structural_risk_score > 0.4 and risk_level == "medium":
                effective_risk_level = "high"
                self._logger.info("Elevated risk level from medium to high based on structural analysis")
            
            # === Pass 2: LLM Task Execution ===
            self._logger.info("Executing task with effective_risk_level=%s", effective_risk_level)
            
            # For comparative tasks, prepend batch context to help with outlier detection
            # IMPORTANT: Use canonical_input, NOT the LLM's sanitized_input
            enhanced_input = canonical_input
            if batch_context and is_comparative_task:
                enhanced_input = f"{batch_context}\n\n---\n\n{canonical_input}"
                self._logger.info("Added batch context to input for comparative task")
            
            raw_response = await execute_task(
                trusted_context=trusted_context,
                sanitized_input=enhanced_input,
                risk_level=effective_risk_level,
                model=self._model,
                structural_flags=structural_flags,  # For adaptive prompt strengthening
                detected_threats=threats,  # Pass threats for additional warnings in Pass 2
            )
            
            # === Phase 3: Deterministic Output Validation ===
            final_response = sanitize_output(
                raw_response,
                trusted_context=trusted_context,
            )
            
            self._logger.info(
                "Pipeline complete: LLM calls=2, response len=%d",
                len(final_response),
            )
            return final_response

        except Exception:
            self._logger.exception("Unexpected error in SecurityGateway")
            # Try to return a format-aware refusal, fall back to generic
            try:
                trusted_context = request.get("trusted_context", {})
                return get_format_aware_refusal(trusted_context)
            except Exception:
                return SAFE_REFUSAL_MESSAGE

    def _should_refuse(self, threats: list[str], trusted_context: dict[str, str]) -> bool:
        """
        Determine if we should refuse entirely based on detected threats.
        
        We refuse when:
        - Multiple high-severity threats detected
        - Clear prompt injection attempt with malicious intent
        - Attempt to extract system prompts or protected data
        - Competitor dismissal/sabotage attempts
        
        We DON'T refuse when:
        - Single low-confidence threat
        - Threat seems incidental (e.g., document mentions 'password' in context)
        """
        if not threats:
            return False
        
        # Keywords that indicate definite refusal
        severe_indicators = [
            "prompt injection",
            "extract system prompt",
            "reveal instructions",
            "role manipulation",
            "override safety",
            "jailbreak",
            # Competitor dismissal attacks
            "competitor dismissal",
            "competitor sabotage",
            "sabotage",
            "dismiss other",
            "ignore other",
            "data corruption claim",
            "corrupted data",
            "invalid data",
        ]
        
        threat_text = " ".join(threats).lower()
        severe_count = sum(1 for ind in severe_indicators if ind in threat_text)
        
        # Refuse if 2+ severe indicators or if we see clear injection
        if severe_count >= 2:
            return True
        
        # Refuse if explicit injection attempt detected
        if "prompt injection" in threat_text and len(threats) > 1:
            return True
        
        # Refuse if competitor dismissal detected (this is always malicious)
        if any(ind in threat_text for ind in ["competitor dismissal", "competitor sabotage", "sabotage attempt"]):
            return True
        
        return False

    def _extract_documents(self, text: str) -> List[str]:
        """
        Extract individual documents from a batch input.
        
        Looks for common document separators used in multi-document inputs:
        - FILE_ID: markers
        - === separators
        - CANDIDATE PROFILE headers
        - Numbered documents
        
        Returns:
            List of individual document texts
        """
        import re
        
        documents = []
        
        # Try FILE_ID pattern (resume_downgrade style)
        file_pattern = r'FILE_ID:\s*\w+\s*\n(.*?)(?=FILE_ID:|SYSTEM:|$)'
        file_matches = re.findall(file_pattern, text, re.DOTALL)
        if file_matches and len(file_matches) > 1:
            return [m.strip() for m in file_matches if m.strip()]
        
        # Try separator pattern (=== lines)
        separator_pattern = r'={10,}'
        parts = re.split(separator_pattern, text)
        if len(parts) > 2:
            # Filter out empty parts and system messages
            documents = [
                p.strip() for p in parts 
                if p.strip() and not p.strip().startswith('SYSTEM:')
            ]
            if len(documents) > 1:
                return documents
        
        # Try CANDIDATE PROFILE pattern
        candidate_pattern = r'CANDIDATE PROFILE.*?(?=CANDIDATE PROFILE|$)'
        candidates = re.findall(candidate_pattern, text, re.DOTALL | re.IGNORECASE)
        if candidates and len(candidates) > 1:
            return [c.strip() for c in candidates if c.strip()]
        
        # Try numbered document pattern
        numbered_pattern = r'(?:Document|Item|Entry)\s*#?\d+[:\s]+(.*?)(?=(?:Document|Item|Entry)\s*#?\d+|$)'
        numbered = re.findall(numbered_pattern, text, re.DOTALL | re.IGNORECASE)
        if numbered and len(numbered) > 1:
            return [n.strip() for n in numbered if n.strip()]
        
        # If no pattern matches, return empty list (single document context)
        return []

    async def handle_prompt(self, prompt: str) -> str:
        """
        Legacy interface for backward compatibility.
        
        Wraps a raw prompt string into the new structured request format.
        """
        request = {
            "trusted_context": {
                "defender_role": "AI Assistant",
                "defender_task": "Respond helpfully and safely to the user's request.",
                "output_format": "Natural language response.",
                "domain_description": "",
                "security_guidelines": "",
            },
            "untrusted_input": prompt,
        }
        return await self.handle_request(request)


