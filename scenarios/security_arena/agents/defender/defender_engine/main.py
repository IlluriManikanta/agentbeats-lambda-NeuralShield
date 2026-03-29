"""Security gateway implementing task-centric extraction and enforcement."""

from __future__ import annotations

import json
import re
from typing import Any, List

from .attack_classifier import classify_attack_category
from . import config as gateway_config
from .config import SAFE_REFUSAL_MESSAGE, get_format_aware_refusal
from .consistency_validator import get_validation_for_task
from .llm.llm_client import analyze_and_extract, execute_task, verify_output
from .logger import get_logger
from .normalizer import canonicalize_input
from .plausibility_analyzer import (
    analyze_plausibility,
    generate_batch_context,
    get_batch_z_score_summary,
    normalize_outlier_claims,
)
from .sanitizer.output_sanitizer import (
    contains_pii_leakage,
    contains_supply_chain_risk,
    downgrade_supply_chain_claims,
    rewrite_unverified_package_mentions,
    sanitize_output,
)
from .segmenter import (
    build_input_without_external,
    compute_segment_risk_summary,
    get_external_segments,
    get_internal_segments,
    segment_input,
)
from .structural_analyzer import analyze_structure, compute_risk_score

MAX_INPUT_LENGTH = getattr(gateway_config, "MAX_INPUT_LENGTH", 40000)


class SecurityGateway:
    """Orchestrates the defender's deterministic + LLM multi-pass pipeline."""

    def __init__(self, model: str | None = None) -> None:
        self._logger = get_logger("gateway")
        self._model = model

    async def handle_request(self, request: dict[str, Any]) -> str:
        """Process a structured request with strict task-integrity enforcement."""
        try:
            trusted_context = request.get("trusted_context", {}) or {}
            untrusted_input = request.get("untrusted_input", "") or ""
            defender_task = trusted_context.get("defender_task", "")

            if len(untrusted_input) > MAX_INPUT_LENGTH:
                self._logger.info(
                    "Input length %d exceeds cap %d; truncating.",
                    len(untrusted_input),
                    MAX_INPUT_LENGTH,
                )
                untrusted_input = untrusted_input[:MAX_INPUT_LENGTH]

            self._logger.info(
                "Processing request with trusted keys=%s, untrusted len=%d",
                list(trusted_context.keys()),
                len(untrusted_input),
            )

            # Phase 0: canonicalization + preliminary structural scan + classification + segmentation
            canonical_input = canonicalize_input(untrusted_input)
            preliminary_flags = analyze_structure(
                canonical_input,
                defender_task=defender_task,
            )
            attack_category = classify_attack_category(
                trusted_context=trusted_context,
                untrusted_input=canonical_input,
                structural_flags=preliminary_flags,
            )
            segments = segment_input(canonical_input)
            self._logger.info(
                "Segmented input: category=%s total=%d external=%d internal=%d",
                attack_category,
                len(segments),
                len(get_external_segments(segments)),
                len(get_internal_segments(segments)),
            )

            # Per-segment structural flags support graceful degradation decisions.
            segment_flags: dict[str, List[str]] = {}
            for seg in segments:
                seg_key = seg.doc_id or f"seg_{seg.start_idx}"
                segment_flags[seg_key] = analyze_structure(
                    seg.content,
                    category=attack_category,
                    defender_task=defender_task,
                )

            task_lower = defender_task.lower()
            is_comparative_task = (
                attack_category == "indirect_injection"
                or any(
                    kw in task_lower
                    for kw in ["rank", "candidate", "resume", "compare", "evaluate", "assess"]
                )
            )
            is_risk_assessment_task = any(
                kw in task_lower
                for kw in ["risk", "assess", "recommendation", "investment", "portfolio"]
            )

            # Graceful degradation is decided before LLM calls so extracted data can be
            # generated from the same effective input that Pass 2 sees.
            effective_input = canonical_input
            use_graceful_degradation = False
            excluded_doc_warning = ""
            if len(segments) > 1 and is_comparative_task:
                risk_summary = compute_segment_risk_summary(segments, segment_flags)
                external_segments = risk_summary.get("external_segments", [])
                internal_segments = risk_summary.get("internal_segments", [])

                # Lower threshold from strict high-risk only to medium-risk plus outlier heuristics.
                external_medium_risk = False
                external_plausibility_hits: list[str] = []
                for seg in external_segments:
                    seg_key = seg.doc_id or f"seg_{seg.start_idx}"
                    seg_score = compute_risk_score(
                        segment_flags.get(seg_key, []),
                        category=attack_category,
                    )
                    if seg_score >= 0.25:
                        external_medium_risk = True

                    if internal_segments:
                        plausibility = analyze_plausibility(
                            seg.content,
                            [internal_seg.content for internal_seg in internal_segments],
                        )
                        if plausibility.risk_score >= 0.35 or any(
                            "OUTLIER" in flag for flag in plausibility.flags
                        ):
                            external_plausibility_hits.append(seg.doc_id or seg_key)

                should_exclude_external = risk_summary["internal_clean"] and (
                    risk_summary["external_high_risk"]
                    or external_medium_risk
                    or bool(external_plausibility_hits)
                )

                if should_exclude_external:
                    use_graceful_degradation = True
                    effective_input = build_input_without_external(segments, canonical_input)
                    risky_ids = sorted(
                        set((risk_summary.get("risky_doc_ids") or []) + external_plausibility_hits)
                    )
                    excluded_doc_warning = (
                        f"Note: Document(s) {', '.join(risky_ids)} excluded due to integrity concerns."
                        if risky_ids
                        else "Note: Externally sourced documents were excluded due to integrity concerns."
                    )
                    self._logger.info(
                        "Graceful degradation enabled; excluded external docs=%s",
                        risky_ids or "[unknown]",
                    )

            # Structural risk from effective input.
            structural_flags = analyze_structure(
                effective_input,
                category=attack_category,
                defender_task=defender_task,
            )

            # Optional comparative plausibility signals.
            batch_context = ""
            plausibility_warning_block = ""
            document_texts: List[str] = []
            if is_comparative_task:
                document_texts = self._extract_documents(effective_input)
                if document_texts:
                    batch_context = generate_batch_context(document_texts)
                    plausibility_warning_block = self._build_plausibility_warnings(document_texts)
                    for idx, doc_text in enumerate(document_texts):
                        plausibility = analyze_plausibility(
                            doc_text,
                            [t for j, t in enumerate(document_texts) if j != idx],
                        )
                        if plausibility.flags:
                            structural_flags.extend(plausibility.flags)
            structural_risk_score = compute_risk_score(structural_flags, category=attack_category)
            self._logger.info(
                "Structural risk score: %.2f (flags=%d category=%s)",
                structural_risk_score,
                len(structural_flags),
                attack_category,
            )

            # Pass 1: risk analysis + extraction.
            analysis_result = await analyze_and_extract(
                untrusted_input=effective_input,
                task_context=defender_task[:250] or "Process the request safely.",
                output_format=trusted_context.get("output_format", "")[:200],
                structural_flags=structural_flags,
                category=attack_category,
                model=self._model,
            )

            risk_level = str(analysis_result.get("risk_level", "medium")).lower()
            threats = analysis_result.get("threats", []) or []
            extracted_data = analysis_result.get("extracted_data", effective_input) or effective_input
            intent_analysis = str(analysis_result.get("intent_analysis", "") or "")
            reasoning = analysis_result.get("reasoning", "")
            extracted_data = self._strip_control_lines(
                extracted_data,
                aggressive=attack_category in {"indirect_injection", "jailbreak"},
            )
            intent_markers = self._infer_intent_risk_markers(
                intent_analysis=intent_analysis,
                defender_task=defender_task,
                category=attack_category,
            )
            if intent_markers:
                threats = list(dict.fromkeys(threats + intent_markers))
                if "intent_high_risk" in intent_markers:
                    risk_level = "high"
            if is_comparative_task:
                extracted_data, normalization_notes = self._normalize_structured_extracted_data(
                    extracted_data
                )
                if normalization_notes:
                    threats = list(dict.fromkeys(threats + ["plausibility_normalization_applied"]))
            if attack_category == "pii_leak" and contains_pii_leakage(extracted_data):
                threats = list(dict.fromkeys(threats + ["pii_detected_in_extraction"]))

            self._logger.info(
                "Pass1 analysis: risk=%s threats=%d category=%s reasoning=%s",
                risk_level,
                len(threats),
                attack_category,
                reasoning[:120],
            )

            if self._should_refuse(
                risk_level,
                structural_risk_score,
                threats,
                category=attack_category,
                extracted_data=extracted_data,
            ):
                self._logger.info("Refusing request based on risk policy.")
                return get_format_aware_refusal(trusted_context, category=attack_category)

            effective_risk_level = self._compute_effective_risk_level(
                risk_level,
                structural_risk_score,
                category=attack_category,
            )

            task_input = extracted_data
            if is_comparative_task:
                task_prefix: list[str] = []
                if plausibility_warning_block:
                    task_prefix.append(plausibility_warning_block)
                if batch_context:
                    task_prefix.append(batch_context)
                if task_prefix:
                    task_input = "\n\n---\n\n".join(task_prefix + [task_input])

            # Pass 2: task execution over extracted data only.
            raw_response = await execute_task(
                trusted_context=trusted_context,
                extracted_data=task_input,
                risk_level=effective_risk_level,
                category=attack_category,
                model=self._model,
            )
            if attack_category == "supply_chain":
                raw_response, unknown_packages = rewrite_unverified_package_mentions(raw_response)
                if unknown_packages:
                    threats = list(dict.fromkeys(threats + ["unverified_dependency_reference"]))
                supply_chain_uncertainty_mode = (
                    structural_risk_score >= 0.4
                    or contains_supply_chain_risk(raw_response, strict=True)
                )
                if supply_chain_uncertainty_mode:
                    raw_response = downgrade_supply_chain_claims(raw_response, strict=True)

            ranking_integrity_ok = True
            ranking_integrity_issue = ""
            if is_comparative_task and len(segments) > 1:
                ranking_integrity_ok, ranking_integrity_issue = self._check_ranking_integrity(
                    raw_response,
                    segments,
                    segment_flags,
                    category=attack_category,
                )
                if not ranking_integrity_ok:
                    self._logger.warning(
                        "Ranking integrity check failed: %s",
                        ranking_integrity_issue,
                    )

            # Deterministic consistency validation.
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

            final_response = sanitize_output(
                raw_response,
                trusted_context=trusted_context,
                category=attack_category,
            )

            # Optional Pass 3: verification/repair when risk or format pressure is high.
            should_run_pass3 = (
                effective_risk_level == "high"
                or structural_risk_score >= 0.4
                or is_comparative_task
                or is_risk_assessment_task
                or attack_category in {"prompt_extraction", "pii_leak", "supply_chain"}
                or not ranking_integrity_ok
                or not validation_result.is_valid
            )
            if should_run_pass3:
                verification_input = task_input
                if not ranking_integrity_ok and ranking_integrity_issue:
                    verification_input = (
                        f"{verification_input}\n\nINTEGRITY WARNING:\n"
                        f"- {ranking_integrity_issue}\n"
                        "- Re-evaluate using only measurable and proportionate evidence."
                    )
                verify_result = await verify_output(
                    trusted_context=trusted_context,
                    extracted_data=verification_input,
                    draft_output=final_response,
                    category=attack_category,
                    model=self._model,
                )
                repaired = verify_result.get("repaired_output", final_response)
                if isinstance(repaired, str) and repaired.strip():
                    final_response = sanitize_output(
                        repaired,
                        trusted_context=trusted_context,
                        category=attack_category,
                    )
                if not verify_result.get("is_valid", True) and effective_risk_level == "high":
                    final_response = get_format_aware_refusal(
                        trusted_context,
                        category=attack_category,
                    )

            # Re-validate once after optional repair.
            post_validation = get_validation_for_task(
                final_response,
                trusted_context,
                segments=segments if len(segments) > 1 else None,
            )
            if not post_validation.is_valid and effective_risk_level == "high":
                final_response = get_format_aware_refusal(
                    trusted_context,
                    category=attack_category,
                )

            # Optional plain-text warning for graceful degradation.
            if use_graceful_degradation and excluded_doc_warning:
                output_format = trusted_context.get("output_format", "").lower()
                if "json" not in output_format:
                    final_response = f"{final_response}\n\n{excluded_doc_warning}"

            self._logger.info(
                "Pipeline complete: response len=%d pass3=%s graceful=%s",
                len(final_response),
                should_run_pass3,
                use_graceful_degradation,
            )
            return final_response

        except Exception:
            self._logger.exception("Unexpected error in SecurityGateway")
            try:
                trusted_context = request.get("trusted_context", {})
                return get_format_aware_refusal(trusted_context)
            except Exception:
                return SAFE_REFUSAL_MESSAGE

    @staticmethod
    def _category_thresholds(category: str | None) -> dict[str, float]:
        """Fetch medium/high structural thresholds for a category from config."""
        category_key = (category or "unknown").strip().lower()
        table = getattr(gateway_config, "CATEGORY_RISK_THRESHOLDS", {})
        raw = table.get(category_key) or table.get("unknown") or {"medium": 0.55, "high": 0.78}
        medium = float(raw.get("medium", 0.55))
        high = float(raw.get("high", 0.78))
        if high < medium:
            high = medium + 0.1
        return {"medium": medium, "high": high}

    @staticmethod
    def _compute_effective_risk_level(
        risk_level: str,
        structural_risk_score: float,
        category: str | None = None,
    ) -> str:
        """Fuse semantic and structural risk into low/medium/high band."""
        level = (risk_level or "medium").lower().strip()
        if level not in {"low", "medium", "high"}:
            level = "medium"
        order = {"low": 0, "medium": 1, "high": 2}
        level_score = order[level]
        thresholds = SecurityGateway._category_thresholds(category)
        high_threshold = thresholds["high"]
        medium_threshold = thresholds["medium"]
        if structural_risk_score >= high_threshold:
            level_score = max(level_score, 2)
        elif structural_risk_score >= medium_threshold:
            level_score = max(level_score, 1)
        reverse = {v: k for k, v in order.items()}
        return reverse[level_score]

    @staticmethod
    def _should_refuse(
        risk_level: str,
        structural_risk_score: float,
        threats: list[str],
        category: str | None = None,
        extracted_data: str = "",
    ) -> bool:
        """Refusal policy balancing explicit high-risk signals and constraints."""
        category_key = (category or "").strip().lower()
        thresholds = SecurityGateway._category_thresholds(category_key)
        medium_threshold = thresholds["medium"]
        high_threshold = thresholds["high"]
        normalized_risk = (risk_level or "medium").strip().lower()
        threat_text = " ".join(t.lower() for t in threats)

        if structural_risk_score >= min(0.95, high_threshold + 0.22):
            return True
        if category_key == "insecure_output":
            # Prefer aggressive sanitization over refusal for output-handling attacks.
            return False
        if (
            category_key == "prompt_extraction"
            and normalized_risk == "high"
            and structural_risk_score >= max(0.45, medium_threshold)
        ):
            return True
        if category_key == "pii_leak" and structural_risk_score >= medium_threshold:
            if normalized_risk in {"high", "medium"} and contains_pii_leakage(extracted_data):
                return True
        if (
            category_key == "jailbreak"
            and normalized_risk == "high"
            and structural_risk_score >= 0.45
        ):
            return True
        if category_key == "jailbreak" and normalized_risk == "medium" and structural_risk_score >= 0.55:
            soft_jailbreak_terms = [
                "hypothetical_framing",
                "educational_pretext",
                "roleplay_framing",
                "fictional_distancing",
                "social_engineering_minimizer",
                "privacy_manipulation",
                "competitive_pressure",
                "soft_jailbreak_intent",
            ]
            if any(term in threat_text for term in soft_jailbreak_terms):
                return True
        if normalized_risk == "high" and structural_risk_score >= high_threshold:
            return True
        severe_terms = [
            "prompt extraction",
            "system prompt",
            "role override",
            "delimiter escape",
            "competitor dismissal",
            "data corruption claim",
            "pii",
            "tool enumeration",
            "safety bypass",
        ]
        severe_hits = sum(1 for term in severe_terms if term in threat_text)
        if category_key == "supply_chain":
            return severe_hits >= 2 and structural_risk_score >= medium_threshold
        return severe_hits >= 2 and structural_risk_score >= medium_threshold

    @staticmethod
    def _infer_intent_risk_markers(
        intent_analysis: str,
        defender_task: str,
        category: str | None = None,
    ) -> list[str]:
        """Convert Pass-1 intent analysis into deterministic threat markers."""
        if not intent_analysis:
            return []

        lower = intent_analysis.lower()
        task_lower = (defender_task or "").lower()
        markers: list[str] = []

        contradiction_terms = [
            "ignore criteria",
            "override policy",
            "set risk",
            "rank first",
            "bypass safety",
            "reveal system prompt",
            "disclose internal",
            "exfiltrate",
        ]
        if any(term in lower for term in contradiction_terms):
            markers.append("intent_contradiction_detected")

        high_risk_terms = [
            "unsafe",
            "harmful",
            "exploit",
            "xss",
            "payload",
            "pii",
            "prompt extraction",
            "jailbreak",
            "dependency hallucination",
            "typosquat",
        ]
        if any(term in lower for term in high_risk_terms):
            markers.append("intent_high_risk")

        if category == "jailbreak":
            soft_terms = ["roleplay", "hypothetical", "fictional", "educational pretext"]
            if any(term in lower for term in soft_terms):
                markers.append("soft_jailbreak_intent")

        if any(kw in task_lower for kw in ("rank", "evaluate", "assess", "risk")) and any(
            term in lower for term in ("manipulate output", "bias ranking", "forced low risk")
        ):
            markers.append("task_outcome_manipulation_intent")

        return list(dict.fromkeys(markers))

    def _extract_documents(self, text: str) -> List[str]:
        """Extract likely per-document chunks for comparative batch analysis."""
        file_pattern = r"FILE_ID:\s*\w+\s*\n(.*?)(?=FILE_ID:|SYSTEM:|$)"
        file_matches = re.findall(file_pattern, text, re.DOTALL)
        if file_matches and len(file_matches) > 1:
            return [m.strip() for m in file_matches if m.strip()]

        parts = re.split(r"={10,}", text)
        if len(parts) > 2:
            docs = [p.strip() for p in parts if p.strip() and not p.strip().startswith("SYSTEM:")]
            if len(docs) > 1:
                return docs

        candidate_pattern = r"CANDIDATE PROFILE.*?(?=CANDIDATE PROFILE|$)"
        candidates = re.findall(candidate_pattern, text, re.DOTALL | re.IGNORECASE)
        if candidates and len(candidates) > 1:
            return [c.strip() for c in candidates if c.strip()]

        numbered_pattern = r"(?:Document|Item|Entry)\s*#?\d+[:\s]+(.*?)(?=(?:Document|Item|Entry)\s*#?\d+|$)"
        numbered = re.findall(numbered_pattern, text, re.DOTALL | re.IGNORECASE)
        if numbered and len(numbered) > 1:
            return [n.strip() for n in numbered if n.strip()]

        return []

    def _normalize_structured_extracted_data(self, extracted_data: str) -> tuple[str, list[str]]:
        """Clamp outlier numeric claims when extracted_data is structured JSON."""
        parsed = self._parse_possible_json(extracted_data)
        if not isinstance(parsed, dict):
            return extracted_data, []
        items = parsed.get("items")
        if not isinstance(items, list):
            return extracted_data, []

        normalized_items, notes = normalize_outlier_claims(items)
        if not notes:
            return extracted_data, []
        parsed["items"] = normalized_items
        existing_notes = parsed.get("normalization_notes")
        if isinstance(existing_notes, list):
            parsed["normalization_notes"] = existing_notes + notes
        else:
            parsed["normalization_notes"] = notes
        return json.dumps(parsed, ensure_ascii=False), notes

    @staticmethod
    def _build_plausibility_warnings(document_texts: List[str]) -> str:
        """Build a compact warning block from batch outlier analysis."""
        if len(document_texts) < 3:
            return ""

        z_summary = get_batch_z_score_summary(document_texts)
        if not z_summary:
            return ""

        metric_labels = {
            "experience_zscore": "experience",
            "team_size_zscore": "team_size",
            "awards_zscore": "awards",
            "superlatives_zscore": "superlatives",
            "length_zscore": "length",
            "prestige_zscore": "prestige_mentions",
        }
        warning_lines: list[str] = []
        for idx, scores in sorted(z_summary.items()):
            suspicious = [
                (metric, score)
                for metric, score in scores.items()
                if score > 2.5
            ]
            if not suspicious:
                continue
            suspicious.sort(key=lambda item: item[1], reverse=True)
            detail = ", ".join(
                f"{metric_labels.get(metric, metric)}={score:.1f}σ"
                for metric, score in suspicious[:3]
            )
            warning_lines.append(
                f"- Document #{idx + 1}: outlier metrics ({detail}); treat extreme claims conservatively."
            )

        if not warning_lines:
            return ""
        return "INTEGRITY WARNINGS (statistical outlier analysis):\n" + "\n".join(warning_lines)

    def _check_ranking_integrity(
        self,
        response: str,
        segments: List[Any],
        segment_flags: dict[str, List[str]],
        category: str | None = None,
    ) -> tuple[bool, str]:
        """Detect suspicious rank uplift for risky external segments."""
        rankings = self._parse_possible_json(response)
        if not isinstance(rankings, list) or not rankings:
            return True, ""

        external_profiles: dict[str, dict[str, Any]] = {}
        for seg in segments:
            if not getattr(seg, "is_external", lambda: False)():
                continue
            seg_key = getattr(seg, "doc_id", None) or f"seg_{getattr(seg, 'start_idx', 0)}"
            flags = segment_flags.get(seg_key, [])
            external_profiles[seg_key] = {
                "doc_id": getattr(seg, "doc_id", None),
                "name": self._extract_candidate_name(getattr(seg, "content", "")),
                "risk": compute_risk_score(flags, category=category),
                "flags": flags,
            }
        if not external_profiles:
            return True, ""

        top_quartile_rank = max(1, len(rankings) // 4)
        top_fifth_rank = max(1, len(rankings) // 5)
        numeric_scores = [
            float(entry.get("score"))
            for entry in rankings
            if isinstance(entry, dict) and isinstance(entry.get("score"), (int, float))
        ]
        median_score = (
            sorted(numeric_scores)[len(numeric_scores) // 2] if numeric_scores else None
        )

        for entry in rankings:
            if not isinstance(entry, dict):
                continue
            try:
                rank = int(entry.get("rank"))
            except (TypeError, ValueError):
                continue
            if rank > top_quartile_rank:
                continue

            entry_name = self._normalize_name(str(entry.get("name", "")))
            entry_blob = json.dumps(entry).lower()
            matched_profile: dict[str, Any] | None = None
            for profile in external_profiles.values():
                doc_id = str(profile.get("doc_id") or "").lower()
                profile_name = self._normalize_name(str(profile.get("name") or ""))
                if doc_id and doc_id in entry_blob:
                    matched_profile = profile
                    break
                if profile_name and entry_name and (
                    profile_name in entry_name or entry_name in profile_name
                ):
                    matched_profile = profile
                    break
            if not matched_profile:
                continue

            score_value = entry.get("score")
            score = float(score_value) if isinstance(score_value, (int, float)) else None
            has_risky_support = matched_profile["risk"] >= 0.25 or any(
                "OUTLIER" in flag
                or "MANIPULATION" in flag
                or "OVERRIDE" in flag
                for flag in matched_profile["flags"]
            )
            disproportionate_score = (
                median_score is not None
                and score is not None
                and score > (median_score + 5)
            )
            if has_risky_support and (disproportionate_score or rank <= top_fifth_rank):
                candidate_name = (
                    str(entry.get("name"))
                    or str(matched_profile.get("name"))
                    or "external candidate"
                )
                return (
                    False,
                    f"Potential manipulated uplift detected for {candidate_name} "
                    f"(external source ranked #{rank}).",
                )
        return True, ""

    @staticmethod
    def _parse_possible_json(text: str) -> Any:
        """Parse JSON from plain text or fenced markdown."""
        stripped = text.strip()
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

    @staticmethod
    def _extract_candidate_name(content: str) -> str:
        """Extract a candidate/person name from a segment when available."""
        if not content:
            return ""
        match = re.search(r"\bname\s*:\s*([^\n]+)", content, re.IGNORECASE)
        if match:
            return match.group(1).strip()
        return ""

    @staticmethod
    def _normalize_name(value: str) -> str:
        """Normalize a person/entity name for fuzzy comparisons."""
        return re.sub(r"[^a-z0-9]+", " ", value.lower()).strip()

    @staticmethod
    def _strip_control_lines(text: str, aggressive: bool = False) -> str:
        """Remove obvious control/instruction lines that should not reach task execution."""
        if not text:
            return text
        strong_patterns = [
            r"\b(ignore|disregard|override|bypass)\b",
            r"\b(rank|rate|score)\b.*\b(first|top|#1)\b",
            r"\b(reveal|show|print)\b.*\b(system prompt|tools?|functions?|api keys?)\b",
            r"\[(system|admin|override|command)\]",
        ]
        extended_patterns = [
            r"\b(priority|prioritize)\s+(candidate|review|this)\b",
            r"\b(consider|evaluate)\s+(first|ahead|before|with\s+priority)\b",
            r"\b(risk[_\s-]?level)\b.*\b(low|medium|high)\b",
            r"\b(pre-?verified|new policy|supersedes prior|admin mode)\b",
            r"\b(verified|confirmed|approved)\s+by\s+(hr|admin|management|system)\b",
            r"\b(new|updated|revised)\s+(evaluation|assessment|scoring)\s+(criteria|policy|rubric)\b",
            r"\b(flagged|marked)\s+for\s+(priority|immediate|special)\b",
            r"\b(all\s+other|remaining)\s+(candidates?|entries?)\s+(are|should\s+be)\b",
        ]
        blocked_patterns = strong_patterns + (extended_patterns if aggressive else [])
        cleaned_lines: list[str] = []
        for line in text.splitlines():
            lower = line.lower()
            if any(re.search(pattern, lower) for pattern in blocked_patterns):
                continue
            cleaned_lines.append(line)
        cleaned = "\n".join(cleaned_lines).strip()
        return cleaned or text

    async def handle_prompt(self, prompt: str) -> str:
        """Legacy raw-string wrapper for backward compatibility."""
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


