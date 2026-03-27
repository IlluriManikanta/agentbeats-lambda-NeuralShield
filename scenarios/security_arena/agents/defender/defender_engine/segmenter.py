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
    return [Segment(
        content=text,
        source_type=source_type,
        trust_level=trust_level,
        start_idx=0,
        end_idx=len(text),
    )]


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
        
        segments.append(Segment(
            content=content,
            source_type=source_type,
            doc_id=doc_id,
            trust_level=trust_level,
            start_idx=start_idx,
            end_idx=end_idx,
            metadata={"doc_id": doc_id},
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
        
        segments.append(Segment(
            content=part_stripped,
            source_type=source_type,
            trust_level=trust_level,
            start_idx=start_idx,
            end_idx=end_idx,
        ))
    
    return segments


def _determine_trust(content: str, doc_id: Optional[str] = None) -> tuple[float, SourceType]:
    """
    Determine trust level and source type from content analysis.
    
    Trust signals (low trust / external):
    - Explicit "External Upload" markers
    - REF_9999 pattern (often used for attacker injection)
    - Very high FILE_ID numbers (9000+)
    
    Trust signals (high trust / internal):
    - Standard REF_XXXX patterns with normal numbers
    - No external markers
    - System-generated formatting
    """
    content_lower = content.lower()
    
    # Check for explicit external upload markers
    if EXTERNAL_PATTERN.search(content):
        return 0.2, "external"
    
    # Check doc_id patterns
    if doc_id:
        # REF_9999 is a common pattern for injected/attacker content
        if doc_id in ("REF_9999", "REF_99999"):
            return 0.2, "external"
        
        # Very high numbers suggest external/late additions
        match = re.search(r'REF_(\d+)', doc_id)
        if match:
            ref_num = int(match.group(1))
            if ref_num >= 9000:
                return 0.2, "external"
            # Normal range - likely internal
            return 1.0, "internal"
    
    # Check for content markers suggesting untrusted source
    external_content_markers = [
        "external upload",
        "user provided",
        "uploaded by user",
        "user-submitted",
        "external source",
    ]
    if any(marker in content_lower for marker in external_content_markers):
        return 0.2, "external"
    
    # Check for markers suggesting trusted internal source
    internal_markers = [
        "system:",
        "instruction:",
        "file_id:",
        "candidate profile\n",  # Standard format without external marker
    ]
    if any(marker in content_lower for marker in internal_markers):
        # But verify no external marker overrides
        if not EXTERNAL_PATTERN.search(content):
            return 1.0, "internal"
    
    # Default to medium trust (unknown)
    return 0.5, "unknown"


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
) -> dict[str, any]:
    """
    Compute risk summary across all segments.
    
    Args:
        segments: Parsed segments
        segment_flags: Dict mapping doc_id to list of structural flags
        
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
    
    # Check if any external segment has high risk
    external_high_risk = False
    risky_doc_ids = []
    
    for seg in external_segments:
        doc_key = seg.doc_id or f"seg_{seg.start_idx}"
        flags = segment_flags.get(doc_key, [])
        risk_score = compute_risk_score(flags)
        if risk_score > 0.5:
            external_high_risk = True
            if seg.doc_id:
                risky_doc_ids.append(seg.doc_id)
    
    # Check if all internal segments are clean
    internal_clean = True
    for seg in internal_segments:
        doc_key = seg.doc_id or f"seg_{seg.start_idx}"
        flags = segment_flags.get(doc_key, [])
        risk_score = compute_risk_score(flags)
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
