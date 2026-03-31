"""Plausibility analysis for detecting content manipulation attacks.

This module provides statistical analysis of untrusted input to detect
data poisoning attacks where content is fabricated to influence outcomes
without using obvious injection syntax.

Key capabilities:
1. Extract quantitative claims (years of experience, team sizes, etc.)
2. Detect statistical outliers within batch contexts using Z-scores
3. Flag implausible credentials or achievements
4. Provide comparative context for evaluation tasks

Z-Score Detection:
- Uses standard deviation to detect outliers
- Flag at 2 sigma for moderate suspicion
- Flag at 3 sigma for high suspicion (likely manipulation)
"""

from __future__ import annotations

import math
import re
from copy import deepcopy
from dataclasses import dataclass, field
from typing import Any, List, Optional, Tuple, Dict


@dataclass
class ExtractedClaims:
    """Quantitative claims extracted from a document."""
    years_experience: List[int] = field(default_factory=list)
    team_sizes: List[int] = field(default_factory=list)
    percentages: List[float] = field(default_factory=list)
    award_count: int = 0
    degree_level: int = 0  # 0=none, 1=BS, 2=MS, 3=PhD
    prestigious_institutions: List[str] = field(default_factory=list)
    superlative_count: int = 0
    document_length: int = 0


@dataclass
class PlausibilityFlags:
    """Flags indicating potential content manipulation."""
    flags: List[str] = field(default_factory=list)
    risk_score: float = 0.0
    summary: str = ""


def extract_claims(text: str) -> ExtractedClaims:
    """
    Extract quantitative and qualitative claims from text.
    
    Looks for:
    - Years of experience (e.g., "10+ years", "25 years")
    - Team sizes (e.g., "team of 40", "200+ engineers")
    - Percentages and statistics
    - Awards and recognitions
    - Degree levels
    - Prestigious institution mentions
    - Superlative language
    """
    claims = ExtractedClaims()
    claims.document_length = len(text)
    lower_text = text.lower()
    
    # Extract years of experience
    experience_patterns = [
        r'(\d+)\+?\s*years?\s*(?:of\s+)?(?:experience|expertise)',
        r'(\d+)\+?\s*years?\s+(?:in|as|of)',
        r'over\s+(\d+)\s*years?',
        r'(\d+)\+?\s*year\s+(?:track\s+record|career|history)',
    ]
    for pattern in experience_patterns:
        for match in re.finditer(pattern, lower_text):
            try:
                years = int(match.group(1))
                claims.years_experience.append(years)
            except (ValueError, IndexError):
                pass
    
    # Extract team sizes
    team_patterns = [
        r'team\s+of\s+(\d+)',
        r'(\d+)\+?\s*(?:engineers?|developers?|staff|employees|people)',
        r'lead(?:ing)?\s+(\d+)\+?\s*(?:person|member|engineer)',
        r'manage[ds]?\s+(?:a\s+)?(?:team\s+of\s+)?(\d+)',
        r'(\d+)\s*(?:\+|-)?\s*person\s+team',
    ]
    for pattern in team_patterns:
        for match in re.finditer(pattern, lower_text):
            try:
                size = int(match.group(1))
                if size > 5:  # Filter out small numbers that might be something else
                    claims.team_sizes.append(size)
            except (ValueError, IndexError):
                pass
    
    # Extract percentages
    pct_pattern = r'(\d+(?:\.\d+)?)\s*%'
    for match in re.finditer(pct_pattern, text):
        try:
            pct = float(match.group(1))
            claims.percentages.append(pct)
        except ValueError:
            pass
    
    # Count awards and recognitions
    award_patterns = [
        r'\baward',
        r'\bwinner\b',
        r'\bhonor',
        r'\brecognition',
        r'\bprize\b',
        r'\bof the year\b',
        r'\bbest\s+\w+\s+award',
        r'\bgartner',
        r'\bforbes',
    ]
    for pattern in award_patterns:
        claims.award_count += len(re.findall(pattern, lower_text))
    
    # Detect degree level
    if re.search(r'\bph\.?d\.?\b', lower_text):
        claims.degree_level = max(claims.degree_level, 3)
    if re.search(r'\bm\.?s\.?\b|\bmaster', lower_text):
        claims.degree_level = max(claims.degree_level, 2)
    if re.search(r'\bb\.?s\.?\b|\bbachelor', lower_text):
        claims.degree_level = max(claims.degree_level, 1)
    
    # Detect prestigious institutions
    prestigious = [
        'stanford', 'mit', 'harvard', 'berkeley', 'princeton', 'yale',
        'google', 'amazon', 'microsoft', 'apple', 'meta', 'facebook',
        'fortune 500', 'fortune500', 'f500',
        'acm', 'ieee', 'aws', 'gcp',
    ]
    for inst in prestigious:
        if inst in lower_text:
            claims.prestigious_institutions.append(inst)
    
    # Count superlatives
    superlatives = [
        r'\bbest\b', r'\bleading\b', r'\btop\b', r'\bworld-?class\b',
        r'\bexceptional\b', r'\boutstanding\b', r'\bvisionary\b',
        r'\bglobal\b', r'\brenowned\b', r'\bpioneer',
        r'\binnovati', r'\btransform',
    ]
    for pattern in superlatives:
        claims.superlative_count += len(re.findall(pattern, lower_text))
    
    return claims


def analyze_plausibility(
    text: str,
    context_texts: Optional[List[str]] = None,
) -> PlausibilityFlags:
    """
    Analyze text for plausibility and flag potential manipulation.
    
    Args:
        text: The text to analyze
        context_texts: Optional list of other texts for comparative analysis
        
    Returns:
        PlausibilityFlags with detected issues
    """
    flags = PlausibilityFlags()
    claims = extract_claims(text)
    
    # Absolute thresholds for implausible claims
    max_years = max(claims.years_experience) if claims.years_experience else 0
    max_team = max(claims.team_sizes) if claims.team_sizes else 0
    
    # Flag extreme experience claims
    if max_years > 20:
        flags.flags.append('EXPERIENCE_OUTLIER')
        flags.risk_score += 0.2
    if max_years > 30:
        flags.flags.append('EXTREME_NUMBERS')
        flags.risk_score += 0.3
    
    # Flag extreme team sizes
    if max_team > 100:
        flags.flags.append('STATISTICAL_OUTLIER')
        flags.risk_score += 0.2
    if max_team > 200:
        flags.flags.append('EXTREME_NUMBERS')
        flags.risk_score += 0.3
    
    # Flag excessive awards
    if claims.award_count > 3:
        flags.flags.append('AWARD_DENSITY_HIGH')
        flags.risk_score += 0.15
    if claims.award_count > 5:
        flags.flags.append('IMPLAUSIBLE_CLAIMS')
        flags.risk_score += 0.25
    
    # Flag excessive prestige name-dropping
    if len(claims.prestigious_institutions) > 3:
        flags.flags.append('PRESTIGE_NAME_DROPPING')
        flags.risk_score += 0.2
    
    # Flag excessive superlatives
    if claims.superlative_count > 5:
        flags.flags.append('EXCESSIVE_SUPERLATIVES')
        flags.risk_score += 0.15
    if claims.superlative_count > 10:
        flags.flags.append('CREDENTIAL_INFLATION')
        flags.risk_score += 0.25
    
    # Comparative analysis if context provided
    if context_texts:
        context_claims = [extract_claims(t) for t in context_texts]
        comparative_flags = _compare_to_batch(claims, context_claims)
        flags.flags.extend(comparative_flags)
        flags.risk_score += len(comparative_flags) * 0.15
    
    # Cap risk score at 1.0
    flags.risk_score = min(flags.risk_score, 1.0)
    
    # Generate summary
    if flags.flags:
        flags.summary = f"Detected {len(flags.flags)} plausibility concerns: {', '.join(flags.flags[:3])}"
    else:
        flags.summary = "No significant plausibility concerns detected"
    
    return flags


def compute_z_score(value: float, values: List[float]) -> float:
    """
    Compute the Z-score of a value relative to a distribution.
    
    Z-score = (value - mean) / std_dev
    
    Args:
        value: The value to compute Z-score for
        values: The distribution to compare against
        
    Returns:
        Z-score (positive if above mean, negative if below)
        Returns 0 if standard deviation is 0 (all values same)
    """
    if not values:
        return 0.0
    
    n = len(values)
    mean = sum(values) / n
    
    if n < 2:
        return 0.0
    
    variance = sum((x - mean) ** 2 for x in values) / (n - 1)
    std_dev = math.sqrt(variance) if variance > 0 else 0
    
    if std_dev == 0:
        return 0.0
    
    return (value - mean) / std_dev


def compute_outlier_scores(claims: ExtractedClaims, batch_claims: List[ExtractedClaims]) -> Dict[str, float]:
    """
    Compute Z-scores for all metrics comparing one document to the batch.
    
    Args:
        claims: The document's extracted claims
        batch_claims: Claims from comparison documents
        
    Returns:
        Dict mapping metric name to Z-score
    """
    scores = {}
    
    if not batch_claims:
        return scores
    
    # Gather all values including the target for distribution
    all_with_target = batch_claims + [claims]
    
    # Experience Z-score (use max experience if multiple)
    all_exp_values = [max(bc.years_experience) if bc.years_experience else 0 for bc in all_with_target]
    target_exp = max(claims.years_experience) if claims.years_experience else 0
    if any(v > 0 for v in all_exp_values):
        scores['experience_zscore'] = compute_z_score(target_exp, all_exp_values[:-1])
    
    # Team size Z-score (use max team size)
    all_team_values = [max(bc.team_sizes) if bc.team_sizes else 0 for bc in all_with_target]
    target_team = max(claims.team_sizes) if claims.team_sizes else 0
    if any(v > 0 for v in all_team_values):
        scores['team_size_zscore'] = compute_z_score(target_team, all_team_values[:-1])
    
    # Award count Z-score
    all_award_values = [bc.award_count for bc in all_with_target]
    if any(v > 0 for v in all_award_values):
        scores['awards_zscore'] = compute_z_score(claims.award_count, all_award_values[:-1])
    
    # Superlative count Z-score
    all_super_values = [bc.superlative_count for bc in all_with_target]
    if any(v > 0 for v in all_super_values):
        scores['superlatives_zscore'] = compute_z_score(claims.superlative_count, all_super_values[:-1])
    
    # Document length Z-score
    all_len_values = [bc.document_length for bc in all_with_target]
    if any(v > 0 for v in all_len_values):
        scores['length_zscore'] = compute_z_score(claims.document_length, all_len_values[:-1])
    
    # Prestige institution count Z-score
    all_prestige_values = [len(bc.prestigious_institutions) for bc in all_with_target]
    if any(v > 0 for v in all_prestige_values):
        scores['prestige_zscore'] = compute_z_score(
            len(claims.prestigious_institutions), 
            all_prestige_values[:-1]
        )
    
    return scores


def _compare_to_batch(claims: ExtractedClaims, batch_claims: List[ExtractedClaims]) -> List[str]:
    """
    Compare claims against a batch using Z-score based outlier detection.
    
    Uses standard deviation to detect statistical outliers:
    - Z-score > 2: Moderate outlier (flagged)
    - Z-score > 3: Extreme outlier (high suspicion)
    """
    flags = []
    
    if not batch_claims:
        return flags
    
    # Compute Z-scores for all metrics
    z_scores = compute_outlier_scores(claims, batch_claims)
    
    # Flag based on Z-score thresholds
    high_z_threshold = 3.0  # 3 sigma - extreme outlier
    moderate_z_threshold = 2.0  # 2 sigma - moderate outlier
    
    # Experience outlier
    exp_z = z_scores.get('experience_zscore', 0)
    if exp_z > high_z_threshold:
        flags.append('EXPERIENCE_EXTREME_OUTLIER')
        flags.append('Z_SCORE_ANOMALY')
    elif exp_z > moderate_z_threshold:
        flags.append('EXPERIENCE_OUTLIER')
    
    # Team size outlier
    team_z = z_scores.get('team_size_zscore', 0)
    if team_z > high_z_threshold:
        flags.append('TEAM_SIZE_EXTREME_OUTLIER')
        flags.append('Z_SCORE_ANOMALY')
    elif team_z > moderate_z_threshold:
        flags.append('STATISTICAL_OUTLIER')
    
    # Award count outlier
    award_z = z_scores.get('awards_zscore', 0)
    if award_z > high_z_threshold:
        flags.append('AWARD_EXTREME_OUTLIER')
        flags.append('Z_SCORE_ANOMALY')
    elif award_z > moderate_z_threshold:
        flags.append('AWARD_DENSITY_HIGH')
    
    # Superlative count outlier
    super_z = z_scores.get('superlatives_zscore', 0)
    if super_z > high_z_threshold:
        flags.append('SUPERLATIVE_EXTREME_OUTLIER')
    elif super_z > moderate_z_threshold:
        flags.append('EXCESSIVE_SUPERLATIVES')
    
    # Document length outlier
    len_z = z_scores.get('length_zscore', 0)
    if len_z > high_z_threshold:
        flags.append('LENGTH_EXTREME_OUTLIER')
    elif len_z > moderate_z_threshold:
        flags.append('DOCUMENT_LENGTH_OUTLIER')
    
    # Prestige name-dropping outlier
    prestige_z = z_scores.get('prestige_zscore', 0)
    if prestige_z > high_z_threshold:
        flags.append('PRESTIGE_EXTREME_OUTLIER')
    elif prestige_z > moderate_z_threshold:
        flags.append('PRESTIGE_NAME_DROPPING')
    
    # Composite check: if multiple moderate outliers, it's suspicious
    moderate_outlier_count = sum(1 for z in z_scores.values() if z > moderate_z_threshold)
    if moderate_outlier_count >= 3:
        flags.append('MULTI_METRIC_OUTLIER')
    
    return list(set(flags))  # Remove duplicates


def generate_batch_context(texts: List[str]) -> str:
    """
    Generate a statistical summary of a batch of documents.
    
    This provides context for comparative evaluation tasks.
    
    Args:
        texts: List of document texts to analyze
        
    Returns:
        Human-readable summary of batch statistics
    """
    if not texts:
        return "No batch context available."
    
    all_claims = [extract_claims(t) for t in texts]
    
    # Aggregate statistics
    all_experience = []
    all_teams = []
    all_awards = []
    all_lengths = []
    degree_counts = {0: 0, 1: 0, 2: 0, 3: 0}
    
    for c in all_claims:
        all_experience.extend(c.years_experience)
        all_teams.extend(c.team_sizes)
        all_awards.append(c.award_count)
        all_lengths.append(c.document_length)
        degree_counts[c.degree_level] += 1
    
    summary_parts = []
    
    if all_experience:
        avg_exp = sum(all_experience) / len(all_experience)
        max_exp = max(all_experience)
        summary_parts.append(f"Experience: avg {avg_exp:.1f} years, max {max_exp} years")
    
    if all_teams:
        avg_team = sum(all_teams) / len(all_teams)
        max_team = max(all_teams)
        summary_parts.append(f"Team sizes: avg {avg_team:.0f}, max {max_team}")
    
    if all_awards:
        avg_awards = sum(all_awards) / len(all_awards)
        max_awards = max(all_awards)
        summary_parts.append(f"Awards mentioned: avg {avg_awards:.1f}, max {max_awards}")
    
    phd_count = degree_counts[3]
    ms_count = degree_counts[2]
    summary_parts.append(f"Education: {phd_count} PhD, {ms_count} MS among {len(texts)} documents")
    
    if all_lengths:
        avg_len = sum(all_lengths) / len(all_lengths)
        max_len = max(all_lengths)
        summary_parts.append(f"Document length: avg {avg_len:.0f} chars, max {max_len} chars")
    
    return "BATCH STATISTICS:\n" + "\n".join(f"- {p}" for p in summary_parts)


def detect_outlier_document(
    target_text: str,
    batch_texts: List[str],
) -> Tuple[bool, List[str], str]:
    """
    Determine if a target document is a statistical outlier compared to batch.
    
    Uses Z-score analysis to detect documents that are statistically anomalous.
    
    Args:
        target_text: The document to check
        batch_texts: Other documents for comparison
        
    Returns:
        Tuple of (is_outlier, flags, explanation)
    """
    target_claims = extract_claims(target_text)
    batch_claims = [extract_claims(t) for t in batch_texts]
    
    # Z-score based comparison
    z_scores = compute_outlier_scores(target_claims, batch_claims)
    flags = _compare_to_batch(target_claims, batch_claims)
    
    # Also run absolute plausibility check
    abs_flags = analyze_plausibility(target_text)
    all_flags = list(set(flags + abs_flags.flags))
    
    # Determine if outlier based on Z-scores and flag count
    has_extreme_z = any(z > 3.0 for z in z_scores.values())
    has_multiple_moderate_z = sum(1 for z in z_scores.values() if z > 2.0) >= 2
    
    is_outlier = (
        has_extreme_z or 
        has_multiple_moderate_z or 
        len(all_flags) >= 3 or 
        abs_flags.risk_score > 0.5
    )
    
    if is_outlier:
        # Build explanation with Z-score details
        z_details = []
        for metric, z in sorted(z_scores.items(), key=lambda x: -x[1]):
            if z > 2.0:
                z_details.append(f"{metric}={z:.1f}σ")
        
        z_summary = ", ".join(z_details[:3]) if z_details else "N/A"
        explanation = (
            f"Document shows {len(all_flags)} anomaly indicators. "
            f"Z-scores: {z_summary}. "
            f"Risk score: {abs_flags.risk_score:.2f}. "
            f"Flags: {', '.join(all_flags[:5])}"
        )
    else:
        explanation = "Document appears within normal range for this batch."
    
    return is_outlier, all_flags, explanation


def get_batch_z_score_summary(texts: List[str]) -> Dict[int, Dict[str, float]]:
    """
    Compute Z-scores for all documents in a batch relative to each other.
    
    Useful for identifying which document(s) in a set are potential outliers.
    
    Args:
        texts: List of document texts
        
    Returns:
        Dict mapping document index to its Z-scores dict
    """
    if len(texts) < 3:
        return {}
    
    all_claims = [extract_claims(t) for t in texts]
    result = {}
    
    for i, claims in enumerate(all_claims):
        # Compare this document to all others
        other_claims = all_claims[:i] + all_claims[i+1:]
        result[i] = compute_outlier_scores(claims, other_claims)
    
    return result


def normalize_outlier_claims(
    records: List[Dict[str, Any]],
    numeric_fields: Optional[List[str]] = None,
) -> Tuple[List[Dict[str, Any]], List[str]]:
    """Clamp extreme numeric fields to robust batch bounds (median + 1.5*IQR).

    This is used to reduce decision bias from adversarially inflated claims while
    preserving normal variation in legitimate records.
    """
    if not records:
        return records, []

    fields = numeric_fields or [
        "years_experience",
        "team_leadership_size",
        "award_count",
        "superlative_count",
    ]
    normalized = deepcopy(records)
    notes: list[str] = []

    def _extract_numeric(record: Dict[str, Any], field: str) -> Optional[float]:
        value = record.get(field)
        facts = record.get("facts")
        if isinstance(facts, dict) and field in facts:
            value = facts.get(field)
        if isinstance(value, (int, float)):
            return float(value)
        return None

    def _set_numeric(record: Dict[str, Any], field: str, value: float) -> None:
        if isinstance(record.get("facts"), dict) and field in record["facts"]:
            record["facts"][field] = int(value) if value.is_integer() else value
        elif field in record:
            record[field] = int(value) if value.is_integer() else value

    def _quantile(sorted_values: List[float], q: float) -> float:
        if not sorted_values:
            return 0.0
        if len(sorted_values) == 1:
            return sorted_values[0]
        position = (len(sorted_values) - 1) * q
        low = int(math.floor(position))
        high = int(math.ceil(position))
        if low == high:
            return sorted_values[low]
        weight = position - low
        return sorted_values[low] * (1 - weight) + sorted_values[high] * weight

    for field in fields:
        values = sorted(
            v for v in (_extract_numeric(record, field) for record in normalized) if v is not None
        )
        if len(values) < 3:
            continue
        q1 = _quantile(values, 0.25)
        median = _quantile(values, 0.50)
        q3 = _quantile(values, 0.75)
        iqr = max(0.0, q3 - q1)
        upper_bound = median + (1.5 * iqr)

        for idx, record in enumerate(normalized):
            raw_value = _extract_numeric(record, field)
            if raw_value is None or raw_value <= upper_bound:
                continue
            _set_numeric(record, field, upper_bound)
            record_name = str(record.get("name") or record.get("doc_id") or f"record_{idx + 1}")
            notes.append(
                f"{record_name}: clamped {field} from {raw_value:.2f} to {upper_bound:.2f}"
            )

    return normalized, notes
