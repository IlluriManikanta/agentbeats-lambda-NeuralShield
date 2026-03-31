"""Deterministic evidence-audit heuristics for contradiction detection.

This module focuses on semantic evidence manipulation in mixed-trust inputs.
It does not attempt full NLI; instead it applies targeted, low-cost checks:
- claim extraction from risk-relevant sentences
- topic overlap + polarity inversion contradiction detection
- position-aware suspicion for late-appended reversals
"""

from __future__ import annotations

from dataclasses import dataclass, field
import re
from typing import Any, Iterable


_TOPIC_KEYWORDS: dict[str, tuple[str, ...]] = {
    "regulatory": (
        "regulatory",
        "regulator",
        "compliance",
        "investigation",
        "sanction",
        "penalty",
        "violation",
    ),
    "fraud": ("fraud", "ponzi", "scam", "misrepresentation", "deceptive"),
    "audit": ("audit", "audited", "assurance", "attestation", "verified"),
    "financial_health": (
        "debt",
        "liquidity",
        "insolvent",
        "loss",
        "profit",
        "withdrawal",
        "cashflow",
        "revenue",
    ),
    "risk_rating": ("risk", "high risk", "low risk", "safe", "unsafe", "warning"),
    "security": ("breach", "security", "vulnerability", "compromised", "incident"),
}

_NEGATIVE_TERMS: tuple[str, ...] = (
    "allegation",
    "allegations",
    "investigation",
    "inquiry",
    "violation",
    "penalty",
    "sanction",
    "warning",
    "high risk",
    "concern",
    "concerns",
    "delay",
    "dispute",
    "fraud",
    "ponzi",
    "loss",
    "default",
    "breach",
    "unresolved",
)

_POSITIVE_TERMS: tuple[str, ...] = (
    "resolved",
    "cleared",
    "dismissed",
    "approved",
    "compliant",
    "verified",
    "audited",
    "certified",
    "stabilized",
    "low risk",
    "no findings",
    "passed",
    "secure",
    "strong",
    "profitable",
)

_CLAIM_SIGNAL_PATTERN = re.compile(
    r"\b("
    r"risk|regulatory|audit|investigation|compliance|penalty|violation|fraud|ponzi|"
    r"debt|withdrawal|liquidity|profit|loss|security|breach|sanction|warning|resolved|"
    r"cleared|verified|approved|certified"
    r")\b",
    re.IGNORECASE,
)

_TEMPORAL_PATTERN = re.compile(
    r"\b("
    r"q[1-4]\s*20\d{2}|20\d{2}|jan(?:uary)?|feb(?:ruary)?|mar(?:ch)?|apr(?:il)?|"
    r"may|jun(?:e)?|jul(?:y)?|aug(?:ust)?|sep(?:t(?:ember)?)?|oct(?:ober)?|"
    r"nov(?:ember)?|dec(?:ember)?"
    r")\b",
    re.IGNORECASE,
)

_NUMERIC_PATTERN = re.compile(r"\b\d+(?:[.,]\d+)?%?\b")


@dataclass
class Claim:
    text: str
    position: float
    start_idx: int
    end_idx: int
    topics: set[str] = field(default_factory=set)
    polarity: str = "neutral"


@dataclass
class Contradiction:
    topics: list[str]
    earlier_claim: str
    later_claim: str
    earlier_position: float
    later_position: float
    suspicious_late_reversal: bool = False


@dataclass
class EvidenceAuditResult:
    flags: list[str] = field(default_factory=list)
    contradictions: list[Contradiction] = field(default_factory=list)
    contradiction_density: float = 0.0
    summary: str = ""


def _iter_sentences(text: str) -> Iterable[tuple[str, int, int]]:
    if not text:
        return []
    chunks = []
    pattern = re.compile(r"[^.!?\n]+(?:[.!?]|$)")
    for match in pattern.finditer(text):
        sentence = match.group(0).strip()
        if sentence:
            chunks.append((sentence, match.start(), match.end()))
    return chunks


def _extract_topics(lower_text: str) -> set[str]:
    topics: set[str] = set()
    for topic, keywords in _TOPIC_KEYWORDS.items():
        if any(keyword in lower_text for keyword in keywords):
            topics.add(topic)
    return topics


def _infer_polarity(lower_text: str) -> str:
    positive_hits = sum(1 for token in _POSITIVE_TERMS if token in lower_text)
    negative_hits = sum(1 for token in _NEGATIVE_TERMS if token in lower_text)
    if positive_hits > negative_hits:
        return "positive"
    if negative_hits > positive_hits:
        return "negative"
    return "neutral"


def _extract_claims(text: str) -> list[Claim]:
    if not text:
        return []
    total_len = max(1, len(text))
    claims: list[Claim] = []
    for sentence, start, end in _iter_sentences(text):
        lower = sentence.lower()
        if len(lower) < 24:
            continue
        has_signal = bool(_CLAIM_SIGNAL_PATTERN.search(lower))
        has_temporal = bool(_TEMPORAL_PATTERN.search(lower))
        has_numeric = len(_NUMERIC_PATTERN.findall(lower)) >= 1
        topics = _extract_topics(lower)
        if not (has_signal or has_temporal or (has_numeric and topics)):
            continue
        polarity = _infer_polarity(lower)
        if polarity == "neutral" and not topics:
            continue
        claims.append(
            Claim(
                text=sentence,
                position=min(1.0, max(0.0, end / total_len)),
                start_idx=start,
                end_idx=end,
                topics=topics,
                polarity=polarity,
            )
        )
    return claims


def _is_suspicious_reversal(earlier: Claim, later: Claim) -> bool:
    if earlier.position > 0.7 or later.position < 0.7:
        return False
    if earlier.polarity != "negative" or later.polarity != "positive":
        return False
    lower_later = later.text.lower()
    return any(
        token in lower_later
        for token in ("resolved", "cleared", "verified", "approved", "no findings", "compliant")
    )


def _build_summary(contradictions: list[Contradiction], max_items: int = 4) -> str:
    if not contradictions:
        return ""
    lines = []
    for idx, item in enumerate(contradictions[:max_items], start=1):
        topic_text = ", ".join(item.topics) if item.topics else "general"
        marker = " [late-reversal]" if item.suspicious_late_reversal else ""
        lines.append(
            f"{idx}. topic={topic_text}{marker}; "
            f"early=\"{item.earlier_claim[:140]}\"; "
            f"later=\"{item.later_claim[:140]}\""
        )
    return "\n".join(lines)


def audit_evidence_consistency(
    source_text: str,
    *,
    extracted_data: str = "",
    segments: list[Any] | None = None,
) -> EvidenceAuditResult:
    """Detect contradiction-heavy evidence patterns used for semantic manipulation."""
    # Prefer extracted data (already normalized) and fall back to source text.
    candidate_text = extracted_data or source_text
    claims = _extract_claims(candidate_text)
    if len(claims) < 2 and source_text and source_text != candidate_text:
        claims = _extract_claims(source_text)
    if len(claims) < 2:
        return EvidenceAuditResult()

    contradictions: list[Contradiction] = []
    for idx, first in enumerate(claims):
        if not first.topics:
            continue
        for second in claims[idx + 1 :]:
            if not second.topics:
                continue
            overlap = sorted(first.topics & second.topics)
            if not overlap:
                continue
            if first.polarity == second.polarity:
                continue
            if "neutral" in {first.polarity, second.polarity}:
                continue
            earlier, later = (first, second) if first.position <= second.position else (second, first)
            contradictions.append(
                Contradiction(
                    topics=overlap,
                    earlier_claim=earlier.text,
                    later_claim=later.text,
                    earlier_position=earlier.position,
                    later_position=later.position,
                    suspicious_late_reversal=_is_suspicious_reversal(earlier, later),
                )
            )

    if not contradictions:
        return EvidenceAuditResult()

    suspicious_late = [item for item in contradictions if item.suspicious_late_reversal]
    density = len(contradictions) / max(1, len(claims))
    flags: list[str] = ["EVIDENCE_CONTRADICTION"]
    if suspicious_late:
        flags.append("POSITION_SUSPICIOUS_CLAIM")
    if len(suspicious_late) >= 2:
        flags.append("EVIDENCE_FABRICATION_PATTERN")
    if density >= 0.25 and len(contradictions) >= 2:
        flags.append("EVIDENCE_CONTRADICTION_DENSITY_HIGH")

    summary = _build_summary(contradictions)
    return EvidenceAuditResult(
        flags=flags,
        contradictions=contradictions,
        contradiction_density=round(density, 4),
        summary=summary,
    )

