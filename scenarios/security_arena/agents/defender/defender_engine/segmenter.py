"""Source trust segmentation for multi-document inputs.

This module parses inputs containing multiple documents (e.g., RAG-style 
retrieval results) and assigns trust levels based on source indicators.

Trust Boundaries:
- Internal documents (from system/database): HIGH trust (1.0)
- External uploads (user-provided): LOW trust (0.2)
- Unknown/ambiguous sources: MEDIUM trust (0.5)

The trust level informs downstream processing:
- High-risk content in low-trust segments can be excluded
- Internal segments are assumed to be legitimate data
- External segments require extra scrutiny
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import List, Literal, Optional


SourceType = Literal["internal", "external", "unknown"]


@dataclass
class Segment:
    """A parsed segment from multi-document input."""
    
    content: str
    source_type: SourceType
    doc_id: Optional[str] = None
    trust_level: float = 0.5
    start_idx: int = 0
    end_idx: int = 0
    metadata: dict = field(default_factory=dict)
    
    def is_external(self) -> bool:
        """Check if this segment is from an external/untrusted source."""
        return self.source_type == "external"
    
    def is_internal(self) -> bool:
        """Check if this segment is from an internal/trusted source."""
        return self.source_type == "internal"


@dataclass
class ChannelSpan:
    """Annotated field/channel span discovered inside untrusted content."""

    key: str
    value: str
    channel_type: str
    risk_score: float
    start_idx: int = 0
    end_idx: int = 0
    flags: list[str] = field(default_factory=list)


# Patterns for detecting document boundaries
FILE_ID_PATTERN = re.compile(
    r'FILE_ID:\s*(REF_\d+|[A-Z0-9_]+)',
    re.IGNORECASE
)

# Patterns indicating external/user-uploaded content
EXTERNAL_MARKERS = [
    r'\(Source:\s*External\s*Upload\)',
    r'\(External\s*Upload\)',
    r'\[External\s*Source\]',
    r'\[User\s*Upload\]',
    r'\(User\s*Provided\)',
    r'\(Uploaded\s*by\s*User\)',
    r'\[Unverified\s*Source\]',
    r'\(Third[\s-]*Party\)',
    r'\[Third[\s-]*Party\]',
    r'\(User[\s-]*Submitted\)',
    r'\[User[\s-]*Submitted\]',
    r'\(External\s*Document\)',
    r'\[External\s*Document\]',
    r'\(Uploaded\s*Document\)',
    r'\[Uploaded\]',
    r'\(Unverified\)',
    r'\(Web\s*Source\)',
    r'\[Web\s*Source\]',
    r'\(Customer[\s-]*Provided\)',
    r'\[Customer[\s-]*Provided\]',
    r'\(Applicant[\s-]*Provided\)',
    r'\[Applicant[\s-]*Provided\]',
    r'\(Uploaded\s*by\s*Candidate\)',
    r'\(Submitted\s*Externally\)',
    r'\(Third[\s-]*Party\s*Data\)',
    r'\(External\s*Submission\)',
    r'\(User[\s-]*Provided\)',
    r'\(Applicant[\s-]*Submitted\)',
    r'\(Candidate\s*Upload\)',
    r'\[External\]',
    r'\[Unverified\]',
]
EXTERNAL_PATTERN = re.compile(
    '|'.join(EXTERNAL_MARKERS),
    re.IGNORECASE
)

# Document separator patterns
SEPARATOR_PATTERNS = [
    r'^={10,}$',  # ========== (10+ equals)
    r'^-{10,}$',  # ---------- (10+ dashes)
    r'^\*{10,}$',  # ********** (10+ asterisks)
]
SEPARATOR_PATTERN = re.compile(
    '|'.join(SEPARATOR_PATTERNS),
    re.MULTILINE
)

_INTRA_SEGMENT_SEPARATOR_PATTERN = re.compile(
    r"\n\s*(?:={8,}|-{8,}|\*{8,}|(?:system|command)\s*:)\s*",
    re.IGNORECASE,
)

_CHANNEL_KEY_VALUE_PATTERN = re.compile(
    r"(?m)^([A-Za-z][A-Za-z0-9 _/\-]{1,40})\s*:\s*(.+)$"
)

_MARKDOWN_IMAGE_PATTERN = re.compile(r"!\[([^\]]{0,160})\]\(([^)]+)\)")

_CHANNEL_TYPE_KEYWORDS: dict[str, tuple[str, ...]] = {
    "metadata": ("metadata", "header", "tag", "label", "comment", "annotation"),
    "filename": ("filename", "file name", "path", "attachment", "subject"),
    "alt_text": ("alt", "caption", "ocr", "transcript", "subtitle"),
    "identity": ("name", "email", "phone", "account", "patient", "user", "passenger"),
    "telemetry": ("log", "event", "trace", "metric", "sensor", "signal"),
}

_CHANNEL_RISK_RULES: list[tuple[str, float, str]] = [
    (r"\b(ignore|disregard|override|bypass)\b", 0.18, "channel_override_phrase"),
    (r"\b(rank|rate|score)\b.{0,30}\b(first|top|#1|highest)\b", 0.18, "channel_ranking_directive"),
    (r"\brisk[_\s-]?level\b.{0,20}\b(low|medium|high)\b", 0.18, "channel_risk_override"),
    (r"\b(reveal|show|print)\b.{0,40}\b(system prompt|internal|tool)\b", 0.2, "channel_exfiltration_phrase"),
]


def segment_input(text: str) -> List[Segment]:
    """
    Parse input into trust-tagged segments.
    
    Identifies document boundaries using:
    - FILE_ID markers (e.g., FILE_ID: REF_4920)
    - Visual separators (===, ---, etc.)
    - External upload indicators
    
    Args:
        text: The raw input text potentially containing multiple documents
        
    Returns:
        List of Segment objects with trust levels assigned
    """
    if not text:
        return []
    
    segments: List[Segment] = []
    
    # Strategy 1: Parse FILE_ID-based documents (resume_downgrade pattern)
    file_id_segments = _parse_file_id_segments(text)
    if file_id_segments:
        return file_id_segments
    
    # Strategy 2: Parse separator-based documents
    separator_segments = _parse_separator_segments(text)
    if separator_segments:
        return separator_segments
    
    # Strategy 3: Single document - determine trust from content
    trust_level, source_type = _determine_trust(text)
    adjusted_trust, position_ratio, position_flags = _apply_position_trust_decay(
        content=text,
        base_trust=trust_level,
        start_idx=0,
        end_idx=len(text),
        total_len=len(text),
    )
    source_type = _adjust_source_type_by_trust(source_type, adjusted_trust)
    return [Segment(
        content=text,
        source_type=source_type,
        trust_level=adjusted_trust,
        start_idx=0,
        end_idx=len(text),
        metadata={
            "position_ratio": round(position_ratio, 4),
            "position_trust": round(adjusted_trust, 4),
            "position_flags": position_flags,
        },
    )]


def _infer_channel_type(key: str) -> str:
    lower = key.lower().strip()
    for channel_type, keywords in _CHANNEL_TYPE_KEYWORDS.items():
        if any(keyword in lower for keyword in keywords):
            return channel_type
    return "generic_field"


def _channel_risk(value: str) -> tuple[float, list[str]]:
    lower = value.lower()
    score = 0.0
    flags: list[str] = []
    for pattern, weight, flag in _CHANNEL_RISK_RULES:
        if re.search(pattern, lower):
            score += weight
            flags.append(flag)
    return min(score, 1.0), flags


def extract_channel_spans(text: str) -> List[ChannelSpan]:
    """Extract field-level channels (metadata/filename/alt/log/etc.) with risk tags."""
    if not text:
        return []

    spans: List[ChannelSpan] = []
    for match in _CHANNEL_KEY_VALUE_PATTERN.finditer(text):
        key = match.group(1).strip()
        value = match.group(2).strip()
        if not value:
            continue
        channel_type = _infer_channel_type(key)
        risk_score, flags = _channel_risk(value)
        spans.append(
            ChannelSpan(
                key=key,
                value=value[:240],
                channel_type=channel_type,
                risk_score=risk_score,
                start_idx=match.start(),
                end_idx=match.end(),
                flags=flags,
            )
        )

    for match in _MARKDOWN_IMAGE_PATTERN.finditer(text):
        alt_text = match.group(1).strip()
        url = match.group(2).strip()
        combined = f"{alt_text} {url}".strip()
        risk_score, flags = _channel_risk(combined)
        spans.append(
            ChannelSpan(
                key="markdown_image",
                value=combined[:240],
                channel_type="alt_text",
                risk_score=min(1.0, risk_score + (0.12 if "javascript:" in url.lower() else 0.0)),
                start_idx=match.start(),
                end_idx=match.end(),
                flags=flags,
            )
        )

    return spans


def compute_channel_anomaly_score(spans: List[ChannelSpan]) -> float:
    """Aggregate micro-channel anomaly score used by policy and suspicion fusion."""
    if not spans:
        return 0.0
    high = sum(1 for span in spans if span.risk_score >= 0.25)
    medium = sum(1 for span in spans if 0.12 <= span.risk_score < 0.25)
    score = min(1.0, high * 0.22 + medium * 0.08)
    return score


def _parse_file_id_segments(text: str) -> List[Segment]:
    """Parse segments delimited by FILE_ID markers."""
    segments: List[Segment] = []
    
    # Find all FILE_ID occurrences
    file_id_matches = list(FILE_ID_PATTERN.finditer(text))
    if not file_id_matches:
        return []
    
    # Also find separators to determine segment boundaries
    separator_positions = [m.start() for m in SEPARATOR_PATTERN.finditer(text)]
    
    for i, match in enumerate(file_id_matches):
        doc_id = match.group(1).upper()
        start_idx = match.start()
        
        # Find end of this segment (next FILE_ID, next separator, or end of text)
        if i + 1 < len(file_id_matches):
            # Next FILE_ID exists
            next_file_start = file_id_matches[i + 1].start()
            # Find separator before next FILE_ID
            end_idx = next_file_start
            for sep_pos in separator_positions:
                if start_idx < sep_pos < next_file_start:
                    end_idx = sep_pos
                    break
        else:
            # Last FILE_ID - go to end or next separator
            end_idx = len(text)
            for sep_pos in separator_positions:
                if sep_pos > start_idx:
                    # Check if there's meaningful content after separator
                    remaining = text[sep_pos:].strip()
                    if remaining and not remaining.startswith('SYSTEM:'):
                        end_idx = sep_pos
                        break
        
        content = text[start_idx:end_idx].strip()
        
        # Determine trust level based on external markers and doc_id patterns
        trust_level, source_type = _determine_trust(content, doc_id)
        adjusted_trust, position_ratio, position_flags = _apply_position_trust_decay(
            content=content,
            base_trust=trust_level,
            start_idx=start_idx,
            end_idx=end_idx,
            total_len=len(text),
        )
        source_type = _adjust_source_type_by_trust(source_type, adjusted_trust)
        
        segments.append(Segment(
            content=content,
            source_type=source_type,
            doc_id=doc_id,
            trust_level=adjusted_trust,
            start_idx=start_idx,
            end_idx=end_idx,
            metadata={
                "doc_id": doc_id,
                "position_ratio": round(position_ratio, 4),
                "position_trust": round(adjusted_trust, 4),
                "position_flags": position_flags,
            },
        ))
    
    return segments


def _parse_separator_segments(text: str) -> List[Segment]:
    """Parse segments delimited by visual separators (===, ---, etc.)."""
    # Split by separator pattern
    parts = SEPARATOR_PATTERN.split(text)
    
    # Need at least 2 meaningful segments
    meaningful_parts = [p.strip() for p in parts if p.strip()]
    if len(meaningful_parts) < 2:
        return []
    
    segments: List[Segment] = []
    current_pos = 0
    
    for part in meaningful_parts:
        part_stripped = part.strip()
        if not part_stripped:
            continue
        
        # Find actual position in original text
        start_idx = text.find(part_stripped, current_pos)
        if start_idx == -1:
            start_idx = current_pos
        end_idx = start_idx + len(part_stripped)
        current_pos = end_idx
        
        # Skip system/command segments
        if part_stripped.startswith('SYSTEM:') or part_stripped.startswith('COMMAND:'):
            continue
        
        trust_level, source_type = _determine_trust(part_stripped)
        adjusted_trust, position_ratio, position_flags = _apply_position_trust_decay(
            content=part_stripped,
            base_trust=trust_level,
            start_idx=start_idx,
            end_idx=end_idx,
            total_len=len(text),
        )
        source_type = _adjust_source_type_by_trust(source_type, adjusted_trust)
        
        segments.append(Segment(
            content=part_stripped,
            source_type=source_type,
            trust_level=adjusted_trust,
            start_idx=start_idx,
            end_idx=end_idx,
            metadata={
                "position_ratio": round(position_ratio, 4),
                "position_trust": round(adjusted_trust, 4),
                "position_flags": position_flags,
            },
        ))
    
    return segments


_CONTENT_RISK_PATTERNS: list[tuple[str, float]] = [
    (r"\b(ignore|disregard|forget)\s+(all\s+)?(previous|above|prior)\s+(instructions?|rules?|prompts?)", 0.30),
    (r"\b(new|updated|actual)\s+instructions?\s*:", 0.22),
    (r"\byou\s+are\s+now\b", 0.22),
    (r"\b(act|pretend)\s+as\b", 0.18),
    (r"\b(reveal|print|show)\s+(your|the)\s+(system\s+prompt|instructions?)\b", 0.30),
    (r"\b(developer mode|admin mode|maintenance mode|god mode)\b", 0.22),
    (r"\b(bypass|disable|remove)\b.{0,40}\b(safety|guardrail|policy|restriction)\b", 0.25),
    (r"\[(system|admin|override|command)\]", 0.22),
    (r"<\s*system\s*>", 0.22),
    (r"</?\s*doc_[a-z0-9]+\s*>", 0.28),
    (r"\b(rank|rate|score)\s+(me|this|him|her|them|candidate)\s*(#?\s*1|first|highest|top)\b", 0.25),
    (r"\b(ignore|skip|exclude|omit)\s+(the\s+)?(other|rest|remaining|candidate)\b", 0.25),
    (r"\b(pre-?verified|verified\s+by\s+(hr|admin|system)|new\s+policy)\b", 0.20),
    (r"\brisk[_\s-]?level\b.{0,20}\b(should\s+be|must\s+be|set\s+to)\s*(low|medium|high)\b", 0.25),
    (r"\b(all\s+prior|previous)\s+(risk|assessment|statement)s?\s+(are\s+)?(superseded|void)\b", 0.22),
    (r"\binstruction\s+hierarchy\b", 0.28),
    (r"\bnon-?negotiable\s+security\s+rules\b", 0.28),
]

_CONTENT_RISK_THRESHOLD = 0.25


def _compute_content_risk(content: str) -> float:
    """Score content for manipulation/injection signals independent of format markers."""
    if not content:
        return 0.0
    lower = content.lower()
    score = 0.0
    seen: set[str] = set()
    for pattern, weight in _CONTENT_RISK_PATTERNS:
        if pattern in seen:
            continue
        if re.search(pattern, lower):
            score += weight
            seen.add(pattern)
    return min(score, 1.0)


def _determine_trust(content: str, doc_id: Optional[str] = None) -> tuple[float, SourceType]:
    """
    Determine trust level and source type from format markers AND content risk.

    Layer 1 -- format-based signals (explicit markers, doc_id patterns).
    Layer 2 -- content-based risk scoring: any segment whose content carries
    manipulation/injection signals above threshold is downgraded to external
    regardless of format markers.
    """
    content_lower = content.lower()

    if EXTERNAL_PATTERN.search(content):
        return 0.2, "external"

    if doc_id:
        if doc_id in ("REF_9999", "REF_99999"):
            return 0.2, "external"

        match = re.search(r'REF_(\d+)', doc_id)
        if match:
            ref_num = int(match.group(1))
            if ref_num >= 9000:
                return 0.2, "external"

    external_content_markers = [
        "external upload",
        "user provided",
        "uploaded by user",
        "user-submitted",
        "external source",
        "third-party",
        "third party",
        "unverified source",
        "web source",
        "customer provided",
        "customer-provided",
        "applicant provided",
        "applicant-provided",
        "external document",
        "uploaded document",
        "uploaded by candidate",
        "submitted externally",
        "third-party data",
        "external submission",
        "user-provided",
        "applicant-submitted",
        "candidate upload",
    ]
    if any(marker in content_lower for marker in external_content_markers):
        return 0.2, "external"

    content_risk = _compute_content_risk(content)
    if content_risk >= _CONTENT_RISK_THRESHOLD:
        return 0.2, "external"

    if doc_id:
        match = re.search(r'REF_(\d+)', doc_id)
        if match:
            return 1.0, "internal"

    internal_markers = [
        "system:",
        "instruction:",
        "file_id:",
        "candidate profile\n",
    ]
    if any(marker in content_lower for marker in internal_markers):
        if not EXTERNAL_PATTERN.search(content):
            return 1.0, "internal"

    return 0.5, "unknown"


def _apply_position_trust_decay(
    *,
    content: str,
    base_trust: float,
    start_idx: int,
    end_idx: int,
    total_len: int,
) -> tuple[float, float, list[str]]:
    """Apply conservative trust decay for late-position or structurally-shifted content."""
    if total_len <= 0:
        return max(0.1, min(1.0, base_trust)), 0.5, []
    midpoint = (start_idx + end_idx) / 2
    position_ratio = min(1.0, max(0.0, midpoint / total_len))
    adjusted = max(0.1, min(1.0, base_trust))
    flags: list[str] = []

    if position_ratio > 0.60:
        adjusted *= 0.60
        flags.append("position_tail_decay")
    if position_ratio > 0.85:
        adjusted *= 0.85
        flags.append("position_deep_tail")
    if _INTRA_SEGMENT_SEPARATOR_PATTERN.search(content):
        adjusted *= 0.75
        flags.append("intra_segment_separator_shift")

    return max(0.1, min(1.0, adjusted)), position_ratio, flags


def _adjust_source_type_by_trust(source_type: SourceType, trust_level: float) -> SourceType:
    """Downgrade source type if position-adjusted trust is significantly reduced."""
    if source_type == "internal" and trust_level < 0.5:
        return "unknown"
    if source_type == "unknown" and trust_level < 0.35:
        return "external"
    return source_type


def get_external_segments(segments: List[Segment]) -> List[Segment]:
    """Filter to only external/untrusted segments."""
    return [s for s in segments if s.is_external()]


def get_internal_segments(segments: List[Segment]) -> List[Segment]:
    """Filter to only internal/trusted segments."""
    return [s for s in segments if s.is_internal()]


def build_input_without_external(
    segments: List[Segment],
    original_text: str,
) -> str:
    """
    Rebuild input excluding external/untrusted segments.
    
    Used for graceful degradation: complete the task with only
    trusted internal documents when external docs are suspicious.
    
    Args:
        segments: Parsed segments with trust levels
        original_text: Original input text
        
    Returns:
        Reconstructed input with external segments removed
    """
    if not segments:
        return original_text
    
    # If no external segments, return original
    external = get_external_segments(segments)
    if not external:
        return original_text
    
    # Build list of ranges to exclude
    exclude_ranges = [(s.start_idx, s.end_idx) for s in external]
    
    # Sort by start position
    exclude_ranges.sort(key=lambda x: x[0])
    
    # Merge overlapping ranges
    merged = []
    for start, end in exclude_ranges:
        if merged and start <= merged[-1][1]:
            merged[-1] = (merged[-1][0], max(merged[-1][1], end))
        else:
            merged.append((start, end))
    
    # Build result by including non-excluded parts
    result_parts = []
    current_pos = 0
    
    for start, end in merged:
        if current_pos < start:
            result_parts.append(original_text[current_pos:start])
        current_pos = end
    
    if current_pos < len(original_text):
        result_parts.append(original_text[current_pos:])
    
    # Clean up result
    result = ''.join(result_parts)
    
    # Remove empty separator sequences
    result = re.sub(r'={10,}\s*={10,}', '=' * 50, result)
    result = re.sub(r'\n{3,}', '\n\n', result)
    
    return result.strip()


def compute_segment_risk_summary(
    segments: List[Segment],
    segment_flags: dict[str, List[str]],
    category: Optional[str] = None,
) -> dict[str, any]:
    """
    Compute risk summary across all segments.
    
    Args:
        segments: Parsed segments
        segment_flags: Dict mapping doc_id to list of structural flags
        category: Attack category for category-aware risk scoring
        
    Returns:
        Summary dict with:
        - external_high_risk: bool
        - internal_clean: bool  
        - external_segments: List[Segment]
        - risky_doc_ids: List[str]
    """
    from .structural_analyzer import compute_risk_score
    
    external_segments = get_external_segments(segments)
    internal_segments = get_internal_segments(segments)
    
    external_high_risk = False
    risky_doc_ids = []
    
    for seg in external_segments:
        doc_key = seg.doc_id or f"seg_{seg.start_idx}"
        flags = segment_flags.get(doc_key, [])
        risk_score = compute_risk_score(flags, category=category)
        if risk_score >= 0.35:
            external_high_risk = True
            if seg.doc_id:
                risky_doc_ids.append(seg.doc_id)
    
    internal_clean = True
    for seg in internal_segments:
        doc_key = seg.doc_id or f"seg_{seg.start_idx}"
        flags = segment_flags.get(doc_key, [])
        risk_score = compute_risk_score(flags, category=category)
        if risk_score > 0.3:
            internal_clean = False
            break
    
    return {
        "external_high_risk": external_high_risk,
        "internal_clean": internal_clean,
        "external_segments": external_segments,
        "internal_segments": internal_segments,
        "risky_doc_ids": risky_doc_ids,
        "total_segments": len(segments),
        "external_count": len(external_segments),
        "internal_count": len(internal_segments),
    }
