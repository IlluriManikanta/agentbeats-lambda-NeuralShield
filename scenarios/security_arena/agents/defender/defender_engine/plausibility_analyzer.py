"""Plausibility analysis for detecting content manipulation attacks.

This module provides statistical analysis of untrusted input to detect
data poisoning attacks where content is fabricated to influence outcomes
without using obvious injection syntax.

Key capabilities:
1. Extract quantitative claims (years of experience, team sizes, etc.)
2. Detect statistical outliers within batch contexts
3. Flag implausible credentials or achievements
4. Provide comparative context for evaluation tasks
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import List, Optional, Tuple


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


def _compare_to_batch(claims: ExtractedClaims, batch_claims: List[ExtractedClaims]) -> List[str]:
    """Compare claims against a batch to detect outliers."""
    flags = []
    
    if not batch_claims:
        return flags
    
    # Calculate batch statistics for experience
    all_experience = []
    for bc in batch_claims:
        all_experience.extend(bc.years_experience)
    
    if all_experience and claims.years_experience:
        avg_exp = sum(all_experience) / len(all_experience)
        max_claim_exp = max(claims.years_experience)
        if max_claim_exp > avg_exp * 2:
            flags.append('EXPERIENCE_OUTLIER')
        if max_claim_exp > avg_exp * 3:
            flags.append('STATISTICAL_OUTLIER')
    
    # Calculate batch statistics for team sizes
    all_teams = []
    for bc in batch_claims:
        all_teams.extend(bc.team_sizes)
    
    if all_teams and claims.team_sizes:
        avg_team = sum(all_teams) / len(all_teams)
        max_claim_team = max(claims.team_sizes)
        if max_claim_team > avg_team * 3:
            flags.append('STATISTICAL_OUTLIER')
    
    # Compare document length
    avg_length = sum(bc.document_length for bc in batch_claims) / len(batch_claims)
    if claims.document_length > avg_length * 2:
        flags.append('DOCUMENT_LENGTH_OUTLIER')
    
    # Compare award density
    avg_awards = sum(bc.award_count for bc in batch_claims) / len(batch_claims)
    if claims.award_count > avg_awards * 3 and claims.award_count > 2:
        flags.append('AWARD_DENSITY_HIGH')
    
    return flags


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
    
    Args:
        target_text: The document to check
        batch_texts: Other documents for comparison
        
    Returns:
        Tuple of (is_outlier, flags, explanation)
    """
    target_claims = extract_claims(target_text)
    batch_claims = [extract_claims(t) for t in batch_texts]
    
    flags = _compare_to_batch(target_claims, batch_claims)
    
    # Also run absolute plausibility check
    abs_flags = analyze_plausibility(target_text)
    all_flags = list(set(flags + abs_flags.flags))
    
    is_outlier = len(all_flags) >= 2 or abs_flags.risk_score > 0.5
    
    if is_outlier:
        explanation = (
            f"Document shows {len(all_flags)} anomaly indicators. "
            f"Risk score: {abs_flags.risk_score:.2f}. "
            f"Flags: {', '.join(all_flags[:5])}"
        )
    else:
        explanation = "Document appears within normal range for this batch."
    
    return is_outlier, all_flags, explanation
