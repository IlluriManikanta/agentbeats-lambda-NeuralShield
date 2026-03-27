"""Secure defender security gateway with 2-pass LLM pipeline.

Implements a layered security architecture:

    Structured Request (trusted + untrusted separated)
          ↓
    Phase 0: Deterministic Preprocessing
        - Input canonicalization (unicode, base64, HTML stripping)
        - Source trust segmentation (internal vs external documents)
        - Structural analysis (detect instruction-like patterns)
          ↓
    Pass 1: LLM Security Analysis (1 API call)
        - Evaluate untrusted input for threats
        - Produce risk_level and sanitized_input
          ↓
    Graceful Degradation Decision
        - If external doc is high-risk but internal docs are clean,
          complete task with internal docs only
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
from .segmenter import (
    segment_input,
    build_input_without_external,
    compute_segment_risk_summary,
    get_external_segments,
    get_internal_segments,
    Segment,
)
from .intent_classifier import (
    classify_intent,
    classify_segments,
    get_intent_risk_adjustment,
    IntentType,
)
from .consistency_validator import (
    get_validation_for_task,
    ValidationResult,
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
            
            # === Phase 0.25: Source Trust Segmentation ===
            # Parse multi-document inputs and assign trust levels
            segments = segment_input(canonical_input)
            self._logger.info(
                "Segmented input: %d segments (external=%d, internal=%d)",
                len(segments),
                len(get_external_segments(segments)),
                len(get_internal_segments(segments)),
            )
            
            # Detect structural patterns that suggest injection attempts
            structural_flags = analyze_structure(canonical_input)
            if structural_flags:
                self._logger.info("Structural flags detected: %s", structural_flags)
            
            # Analyze each segment separately for per-segment risk
            segment_flags: dict[str, List[str]] = {}
            for seg in segments:
                seg_key = seg.doc_id or f"seg_{seg.start_idx}"
                seg_struct_flags = analyze_structure(seg.content)
                segment_flags[seg_key] = seg_struct_flags
                if seg_struct_flags:
                    self._logger.info(
                        "Segment %s (%s) flags: %s",
                        seg_key, seg.source_type, seg_struct_flags
                    )
            
            # === Phase 0.35: Intent Classification ===
            # Detect instructions/meta-claims embedded in data segments
            segment_intents = classify_segments(segments, defender_task)
            intent_risk_boost = 0.0
            
            for seg_key, intent_result in segment_intents.items():
                if intent_result.primary_intent != IntentType.DATA:
                    # Add intent flags to segment flags
                    segment_flags[seg_key] = segment_flags.get(seg_key, []) + intent_result.flags
                    structural_flags.extend(intent_result.flags)
                    
                    # Compute risk adjustment
                    seg_risk_adj = get_intent_risk_adjustment(intent_result)
                    intent_risk_boost = max(intent_risk_boost, seg_risk_adj)
                    
                    self._logger.info(
                        "Segment %s intent: %s (conf=%.2f, flags=%s, risk_adj=%.2f)",
                        seg_key,
                        intent_result.primary_intent.value,
                        intent_result.confidence,
                        intent_result.flags[:3],  # Log first 3 flags
                        seg_risk_adj,
                    )
            
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
            base_structural_risk = compute_risk_score(structural_flags)
            # Add intent-based risk boost (capped at 1.0)
            structural_risk_score = min(1.0, base_structural_risk + intent_risk_boost)
            self._logger.info(
                "Structural risk score: %.2f (base=%.2f, intent_boost=%.2f)",
                structural_risk_score, base_structural_risk, intent_risk_boost
            )
            
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
            
            # === Graceful Degradation Decision ===
            # For multi-document tasks: if external doc is risky but internal docs are clean,
            # complete the task using only internal documents instead of refusing entirely
            use_graceful_degradation = False
            excluded_doc_warning = ""
            
            if len(segments) > 1 and is_comparative_task:
                risk_summary = compute_segment_risk_summary(segments, segment_flags)
                
                self._logger.info(
                    "Segment risk summary: external_high_risk=%s, internal_clean=%s, risky_docs=%s",
                    risk_summary["external_high_risk"],
                    risk_summary["internal_clean"],
                    risk_summary["risky_doc_ids"],
                )
                
                if risk_summary["external_high_risk"] and risk_summary["internal_clean"]:
                    # External doc is suspicious but internal docs are clean
                    # We can complete the task with internal docs only
                    use_graceful_degradation = True
                    risky_ids = risk_summary["risky_doc_ids"]
                    
                    if risky_ids:
                        excluded_doc_warning = (
                            f"Note: Document(s) {', '.join(risky_ids)} excluded from evaluation "
                            "due to format/integrity concerns."
                        )
                    else:
                        excluded_doc_warning = (
                            "Note: One or more externally-uploaded documents were excluded from "
                            "evaluation due to format/integrity concerns."
                        )
                    
                    self._logger.info(
                        "Using graceful degradation: excluding external docs %s",
                        risky_ids or "[unidentified]"
                    )
            
            # === Pass 2: LLM Task Execution ===
            self._logger.info("Executing task with effective_risk_level=%s", effective_risk_level)
            
            # For comparative tasks, prepend batch context to help with outlier detection
            # IMPORTANT: Use canonical_input, NOT the LLM's sanitized_input
            enhanced_input = canonical_input
            
            # Apply graceful degradation: rebuild input without risky external segments
            if use_graceful_degradation:
                enhanced_input = build_input_without_external(segments, canonical_input)
                self._logger.info(
                    "Rebuilt input without external segments (new len=%d, was %d)",
                    len(enhanced_input), len(canonical_input)
                )
            
            if batch_context and is_comparative_task:
                enhanced_input = f"{batch_context}\n\n---\n\n{enhanced_input}"
                self._logger.info("Added batch context to input for comparative task")
            
            raw_response = await execute_task(
                trusted_context=trusted_context,
                sanitized_input=enhanced_input,
                risk_level=effective_risk_level,
                model=self._model,
                structural_flags=structural_flags,  # For adaptive prompt strengthening
                detected_threats=threats,  # Pass threats for additional warnings in Pass 2
            )
            
            # === Phase 2.5: Output Consistency Validation ===
            # Validate that ranking outputs include all input documents
            validation_result = get_validation_for_task(
                raw_response,
                trusted_context,
                segments=segments if len(segments) > 1 else None,
            )
            
            if not validation_result.is_valid:
                self._logger.warning(
                    "Output validation failed: missing=%s, errors=%s",
                    validation_result.missing_items,
                    validation_result.format_errors,
                )
                
                # If we have LLM calls remaining (used 2 of 4), we could retry
                # For now, we log the issue but don't retry to stay within budget
                # Future enhancement: use 3rd call for retry with explicit coverage request
            
            if validation_result.warnings:
                self._logger.info(
                    "Output validation warnings: %s",
                    validation_result.warnings,
                )
            
            # === Phase 3: Deterministic Output Validation ===
            final_response = sanitize_output(
                raw_response,
                trusted_context=trusted_context,
            )
            
            # Append excluded document warning if graceful degradation was used
            if use_graceful_degradation and excluded_doc_warning:
                output_format = trusted_context.get("output_format", "").lower()
                if "json" in output_format:
                    # For JSON output, we don't append text - the response should be valid JSON
                    # The warning is only logged, not included in output
                    self._logger.info("Graceful degradation warning (not appended to JSON): %s", excluded_doc_warning)
                else:
                    # For non-JSON output, append the warning
                    final_response = f"{final_response}\n\n{excluded_doc_warning}"
            
            self._logger.info(
                "Pipeline complete: LLM calls=2, response len=%d, graceful_degradation=%s",
                len(final_response),
                use_graceful_degradation,
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


