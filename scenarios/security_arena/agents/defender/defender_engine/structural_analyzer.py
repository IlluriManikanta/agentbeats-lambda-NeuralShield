"""Structural analysis for detecting injection patterns.

This module performs deterministic pattern matching on untrusted input
to identify structural indicators of prompt injection attempts.

Unlike keyword matching, structural analysis looks for:
- Instruction-like syntax patterns
- Role/authority impersonation markers
- Format manipulation attempts
- Encoded/obfuscated content markers

The output is a list of flags that inform the LLM security analysis pass.
"""

from __future__ import annotations

import re
from typing import List


def analyze_structure(text: str) -> List[str]:
    """
    Analyze text for structural patterns that suggest injection attempts.
    
    Returns a list of flag strings describing detected patterns.
    """
    if not text:
        return []
    
    flags: List[str] = []
    lower_text = text.lower()
    
    # === Instruction-like patterns ===
    flags.extend(detect_instruction_markers(text, lower_text))
    
    # === Authority/role impersonation ===
    flags.extend(detect_authority_claims(lower_text))
    
    # === System/admin command syntax ===
    flags.extend(detect_command_syntax(text, lower_text))
    
    # === Encoding indicators ===
    flags.extend(detect_encoding_markers(text))
    
    # === Output manipulation ===
    flags.extend(detect_output_manipulation(lower_text))
    
    # === Content manipulation indicators (quantitative anomaly detection) ===
    flags.extend(detect_content_manipulation(text, lower_text))
    
    # === Competitor dismissal attacks ===
    flags.extend(detect_competitor_dismissal(text, lower_text))
    
    return flags


def detect_instruction_markers(text: str, lower_text: str) -> List[str]:
    """Detect patterns that look like instructions to the model."""
    flags = []
    
    # Imperative patterns that override previous context
    override_patterns = [
        (r'\b(ignore|disregard|forget)\s+(all\s+)?(previous|above|prior)\s+(instructions?|context|rules?|prompts?)', 
         'OVERRIDE_INSTRUCTION'),
        (r'\b(new|updated|actual)\s+instructions?\s*:', 'NEW_INSTRUCTION_BLOCK'),
        (r'\b(instead|actually|really)\s*,?\s*(you\s+(should|must|need|are))', 'REDIRECTION_ATTEMPT'),
        (r'from\s+now\s+on\s*,?\s*you', 'BEHAVIORAL_OVERRIDE'),
    ]
    
    for pattern, flag in override_patterns:
        if re.search(pattern, lower_text):
            flags.append(flag)
    
    # Role switching attempts
    role_patterns = [
        (r'\byou\s+are\s+(now|actually|really)\s+', 'ROLE_SWITCH_ATTEMPT'),
        (r'\b(act|behave|respond)\s+as\s+(if\s+you\s+(are|were)|a|an)\s+', 'ROLE_IMPERSONATION'),
        (r'\bpretend\s+(to\s+be|you\s+are)', 'ROLEPLAY_REQUEST'),
        (r'\benable\s+(developer|debug|admin|sudo)\s+mode', 'PRIVILEGE_ESCALATION'),
    ]
    
    for pattern, flag in role_patterns:
        if re.search(pattern, lower_text):
            flags.append(flag)
    
    return flags


def detect_authority_claims(lower_text: str) -> List[str]:
    """Detect claims of special authority or access."""
    flags = []
    
    authority_patterns = [
        (r'\bi\s+am\s+(the|a|an)\s+(developer|admin|administrator|owner|creator)', 'DEVELOPER_CLAIM'),
        (r'\bi\s+(work|am)\s+(for|from|at)\s+(support|it|engineering|security)', 'SUPPORT_CLAIM'),
        (r'\b(my|the)\s+(manager|boss|supervisor)\s+(said|told|authorized)', 'AUTHORITY_REFERENCE'),
        (r'\bi\s+(have|got)\s+(special|admin|elevated)\s+access', 'ACCESS_CLAIM'),
        (r'\bauthorized\s+to\s+(access|view|retrieve|see)', 'AUTHORIZATION_CLAIM'),
        (r'\b(executive|emergency|priority)\s+override', 'OVERRIDE_CLAIM'),
    ]
    
    for pattern, flag in authority_patterns:
        if re.search(pattern, lower_text):
            flags.append(flag)
    
    return flags


def detect_command_syntax(text: str, lower_text: str) -> List[str]:
    """Detect syntax that looks like system commands or structured injections."""
    flags = []
    
    # Bracketed commands (often used in injection attempts)
    bracket_patterns = [
        (r'\[SYSTEM\]', 'SYSTEM_BRACKET'),
        (r'\[ADMIN\]', 'ADMIN_BRACKET'),
        (r'\[IMPORTANT\]', 'IMPORTANT_BRACKET'),
        (r'\[DEBUG\]', 'DEBUG_BRACKET'),
        (r'\[OVERRIDE\]', 'OVERRIDE_BRACKET'),
        (r'\[INSTRUCTION\]', 'INSTRUCTION_BRACKET'),
        (r'<\s*system\s*>', 'SYSTEM_TAG'),
        (r'<\s*/?\s*(?:instructions?|prompt|context)\s*>', 'INSTRUCTION_TAG'),
    ]
    
    for pattern, flag in bracket_patterns:
        if re.search(pattern, text, re.IGNORECASE):
            flags.append(flag)
    
    # Command-like syntax
    if re.search(r'^(?:sudo|admin|system|execute|run)\s*:', lower_text, re.MULTILINE):
        flags.append('COMMAND_PREFIX')
    
    # Markdown/code block that might contain hidden instructions
    if re.search(r'```(?:system|hidden|private|secret)', lower_text):
        flags.append('SUSPICIOUS_CODE_BLOCK')
    
    return flags


def detect_encoding_markers(text: str) -> List[str]:
    """Detect indicators that content may be encoded or obfuscated."""
    flags = []
    
    # Long base64-like strings
    if re.search(r'[A-Za-z0-9+/]{40,}={0,2}', text):
        flags.append('POSSIBLE_BASE64')
    
    # Hex-encoded content
    if re.search(r'(?:0x)?[0-9a-fA-F]{20,}', text):
        flags.append('POSSIBLE_HEX_ENCODING')
    
    # Excessive special characters (possible encoding)
    special_ratio = sum(1 for c in text if not c.isalnum() and not c.isspace()) / max(len(text), 1)
    if special_ratio > 0.3:
        flags.append('HIGH_SPECIAL_CHAR_RATIO')
    
    # Unicode anomalies (mixing scripts that shouldn't normally mix)
    has_cyrillic = bool(re.search(r'[\u0400-\u04FF]', text))
    has_latin = bool(re.search(r'[a-zA-Z]', text))
    if has_cyrillic and has_latin:
        flags.append('MIXED_SCRIPTS')
    
    # Detected decoded content (from normalizer)
    if '[DECODED_BASE64:' in text:
        flags.append('DECODED_BASE64_FOUND')
    
    if '[REMOVED_SUSPICIOUS_COMMENT]' in text:
        flags.append('SUSPICIOUS_COMMENT_REMOVED')
    
    return flags


def detect_output_manipulation(lower_text: str) -> List[str]:
    """Detect attempts to manipulate the output format or content."""
    flags = []
    
    manipulation_patterns = [
        (r'\b(output|respond|answer|reply)\s+(only|just|exactly)\s+(with|as|in)', 'OUTPUT_CONTROL'),
        (r'\bformat\s+(your\s+)?(response|output|answer)\s+as', 'FORMAT_OVERRIDE'),
        (r'\b(always|must|should)\s+(say|output|respond|answer)\s+', 'RESPONSE_FORCING'),
        (r'\bdo\s+not\s+(include|mention|reveal|say)\s+', 'NEGATIVE_INSTRUCTION'),
        (r'\b(print|echo|display|show)\s+(your|the)\s+(prompt|instructions|system)', 'PROMPT_EXTRACTION'),
        (r'\brepeat\s+(everything|all|the\s+text)\s+(above|before)', 'CONTEXT_EXTRACTION'),
    ]
    
    for pattern, flag in manipulation_patterns:
        if re.search(pattern, lower_text):
            flags.append(flag)
    
    return flags


def detect_competitor_dismissal(text: str, lower_text: str) -> List[str]:
    """
    Detect attempts to dismiss, discredit, or sabotage other candidates/entries.
    
    This catches attacks where an injected document tries to make the model
    ignore or downgrade other legitimate entries. Common patterns:
    - "ALERT: record X is corrupted"
    - "ignore/skip entry X"
    - "data for X is invalid"
    - "[END OF DATA]" followed by dismissal instructions
    """
    flags = []
    
    # === Alert/Warning/Notice patterns that precede dismissal instructions ===
    alert_patterns = [
        (r'\balert\s*:', 'ALERT_MARKER'),
        (r'\bwarning\s*:', 'WARNING_MARKER'),
        (r'\bnotice\s*:', 'NOTICE_MARKER'),
        (r'\bcaution\s*:', 'CAUTION_MARKER'),
        (r'\bimportant\s*note\s*:', 'IMPORTANT_NOTE_MARKER'),
        (r'\bnote\s*:\s*(?:the\s+)?(?:record|data|entry|file|document)', 'NOTE_DATA_MARKER'),
    ]
    
    for pattern, flag in alert_patterns:
        if re.search(pattern, lower_text):
            flags.append(flag)
    
    # === Direct dismissal instructions targeting other entries ===
    dismissal_patterns = [
        # "ignore X" / "skip X" / "disregard X"
        (r'\b(ignore|skip|disregard|exclude|omit)\s+(?:the\s+)?(?:record|entry|file|data|candidate|document)\s+(?:for\s+)?[\w\s]+', 'COMPETITOR_DISMISSAL'),
        # "X is corrupted/invalid/outdated"
        (r'(?:record|entry|file|data|document)\s+(?:for\s+)?[\w\s]+\s+is\s+(?:corrupted|invalid|outdated|incomplete|unreliable|legacy|broken|damaged)', 'DATA_CORRUPTION_CLAIM'),
        # "corrupted data for X"
        (r'(?:corrupted|invalid|outdated|incomplete|unreliable|legacy|broken)\s+(?:data|record|entry|file)\s+(?:for\s+)?[\w\s]+', 'DATA_CORRUPTION_CLAIM'),
        # "do not consider/include X"
        (r'\bdo\s+not\s+(?:consider|include|count|rank|evaluate)\s+(?:the\s+)?(?:record|entry|candidate|document)', 'COMPETITOR_DISMISSAL'),
        # "X should be excluded/removed"
        (r'(?:record|entry|candidate|document)\s+(?:for\s+)?[\w\s]+\s+should\s+be\s+(?:excluded|removed|ignored|skipped)', 'COMPETITOR_DISMISSAL'),
    ]
    
    for pattern, flag in dismissal_patterns:
        if re.search(pattern, lower_text):
            flags.append(flag)
    
    # === End-of-data markers followed by instructions ===
    # This catches patterns like "[END OF CANDIDATE DATA]" followed by "ALERT: ignore X"
    end_markers = [
        r'\[end\s+of\s+(?:candidate\s+)?data\]',
        r'\[end\s+of\s+(?:document|file|entry|record)s?\]',
        r'={5,}\s*$',  # Separator at end of text
        r'-{5,}\s*$',  # Dashes separator at end
        r'end\s+of\s+(?:file|document|data|entry)',
    ]
    
    for marker_pattern in end_markers:
        # Check if there's an end marker followed by content (which would be suspicious)
        match = re.search(marker_pattern + r'\s*\n\s*\S', lower_text)
        if match:
            # Check if the content after is instruction-like
            after_marker = lower_text[match.end():]
            if any(re.search(p, after_marker) for p in [
                r'\balert\b', r'\bignore\b', r'\bskip\b', r'\bnote\b', 
                r'\bcorrupted\b', r'\binvalid\b', r'\bdisregard\b'
            ]):
                flags.append('TRAILING_INSTRUCTION_AFTER_END_MARKER')
                break
    
    # === Attempts to claim other candidates have issues ===
    # Look for patterns where specific names are targeted
    sabotage_patterns = [
        # "Alice's credentials are unverified"
        (r"[\w]+'s\s+(?:credentials?|qualifications?|experience|data|record)\s+(?:are|is)\s+(?:unverified|fake|fabricated|suspicious)", 'COMPETITOR_SABOTAGE'),
        # "credentials for Alice are invalid"
        (r'(?:credentials?|qualifications?|data|record)\s+for\s+[\w\s]+\s+(?:are|is)\s+(?:unverified|invalid|fake|suspicious)', 'COMPETITOR_SABOTAGE'),
        # "Alice has been flagged"
        (r'[\w]+\s+(?:has\s+been|was)\s+(?:flagged|marked|identified)\s+(?:as|for)', 'COMPETITOR_SABOTAGE'),
    ]
    
    for pattern, flag in sabotage_patterns:
        if re.search(pattern, lower_text):
            flags.append(flag)
    
    return list(set(flags))  # Deduplicate


def detect_content_manipulation(text: str, lower_text: str) -> List[str]:
    """
    Detect quantitative anomalies that may indicate content manipulation.
    
    This catches data poisoning attacks where content is fabricated to
    influence evaluation outcomes without using obvious injection syntax.
    
    Looks for:
    - Extreme numerical claims (years of experience, team sizes)
    - Excessive superlatives and prestige indicators
    - Unusual credential density
    """
    flags = []
    
    # === Extreme numerical claims ===
    
    # Years of experience > 20 is suspicious, > 25 is very suspicious
    experience_matches = re.findall(r'(\d+)\+?\s*years?\s*(?:of\s+)?(?:experience|expertise)', lower_text)
    for match in experience_matches:
        try:
            years = int(match)
            if years > 25:
                flags.append('EXTREME_NUMBERS')
            elif years > 20:
                flags.append('EXPERIENCE_OUTLIER')
        except ValueError:
            pass
    
    # Team sizes > 100 is unusual, > 200 is suspicious
    team_patterns = [
        r'team\s+of\s+(\d+)',
        r'(\d+)\+?\s*(?:engineers?|developers?|staff|employees)',
        r'lead(?:ing)?\s+(\d+)\+?\s*(?:person|member|engineer)',
        r'manage[ds]?\s+(?:a\s+)?(?:team\s+of\s+)?(\d+)',
    ]
    for pattern in team_patterns:
        for match in re.finditer(pattern, lower_text):
            try:
                size = int(match.group(1))
                if size > 200:
                    flags.append('EXTREME_NUMBERS')
                elif size > 100:
                    flags.append('STATISTICAL_OUTLIER')
            except (ValueError, IndexError):
                pass
    
    # === Excessive superlatives ===
    superlatives = [
        r'\bbest\b', r'\bleading\b', r'\btop\b', r'\bworld-?class\b',
        r'\bexceptional\b', r'\boutstanding\b', r'\bvisionary\b',
        r'\bglobal\b', r'\brenowned\b', r'\bpioneer',
        r'\bgroundbreaking\b', r'\btrailblaz', r'\blegendary\b',
    ]
    superlative_count = sum(len(re.findall(p, lower_text)) for p in superlatives)
    
    if superlative_count > 10:
        flags.append('CREDENTIAL_INFLATION')
        flags.append('EXCESSIVE_SUPERLATIVES')
    elif superlative_count > 5:
        flags.append('EXCESSIVE_SUPERLATIVES')
    
    # === Prestige name-dropping ===
    prestigious_institutions = [
        r'\bstanford\b', r'\bmit\b', r'\bharvard\b', r'\bberkeley\b',
        r'\bprinceton\b', r'\byale\b', r'\boxford\b', r'\bcambridge\b',
    ]
    prestigious_companies = [
        r'\bgoogle\b', r'\bamazon\b', r'\bmicrosoft\b', r'\bapple\b',
        r'\bmeta\b', r'\bfacebook\b', r'\bnetflix\b', r'\buber\b',
    ]
    prestigious_awards = [
        r'\bgartner\b', r'\bforbes\b', r'\bfortune\s*500\b',
        r'\bcto\s+of\s+the\s+year\b', r'\bengineer\s+of\s+the\s+year\b',
        r'\bglobal\s+\w+\s+award\b', r'\bbest\s+\w+\s+award\b',
    ]
    
    prestige_count = 0
    for pattern in prestigious_institutions + prestigious_companies + prestigious_awards:
        prestige_count += len(re.findall(pattern, lower_text))
    
    if prestige_count > 5:
        flags.append('PRESTIGE_NAME_DROPPING')
        flags.append('IMPLAUSIBLE_CLAIMS')
    elif prestige_count > 3:
        flags.append('PRESTIGE_NAME_DROPPING')
    
    # === Award density ===
    award_patterns = [
        r'\baward', r'\bwinner\b', r'\bhonor', r'\brecognition',
        r'\bprize\b', r'\bof the year\b', r'\bbest\s+\w+\s+award',
    ]
    award_count = sum(len(re.findall(p, lower_text)) for p in award_patterns)
    
    if award_count > 5:
        flags.append('AWARD_DENSITY_HIGH')
        flags.append('IMPLAUSIBLE_CLAIMS')
    elif award_count > 3:
        flags.append('AWARD_DENSITY_HIGH')
    
    # === Multiple PhDs or excessive credentials ===
    phd_count = len(re.findall(r'\bph\.?d\.?\b', lower_text))
    if phd_count > 1:
        flags.append('CREDENTIAL_INFLATION')
    
    # === Very long document (may indicate padding for impressiveness) ===
    if len(text) > 3000:
        flags.append('DOCUMENT_LENGTH_OUTLIER')
    
    # Deduplicate flags
    return list(set(flags))


def compute_risk_score(flags: List[str]) -> float:
    """
    Compute a risk score (0.0 to 1.0) based on detected flags.
    
    This can be used for graduated responses when combined with LLM analysis.
    """
    if not flags:
        return 0.0
    
    # Weight different flag categories
    high_risk_flags = {
        'OVERRIDE_INSTRUCTION', 'ROLE_SWITCH_ATTEMPT', 'PRIVILEGE_ESCALATION',
        'SYSTEM_BRACKET', 'ADMIN_BRACKET', 'PROMPT_EXTRACTION', 'CONTEXT_EXTRACTION',
        'DECODED_BASE64_FOUND', 'SUSPICIOUS_COMMENT_REMOVED',
        # Content manipulation high-risk flags
        'EXTREME_NUMBERS', 'IMPLAUSIBLE_CLAIMS', 'CREDENTIAL_INFLATION',
        # Competitor dismissal high-risk flags
        'COMPETITOR_DISMISSAL', 'COMPETITOR_SABOTAGE', 'DATA_CORRUPTION_CLAIM',
        'TRAILING_INSTRUCTION_AFTER_END_MARKER',
    }
    
    medium_risk_flags = {
        'NEW_INSTRUCTION_BLOCK', 'REDIRECTION_ATTEMPT', 'ROLE_IMPERSONATION',
        'DEVELOPER_CLAIM', 'SUPPORT_CLAIM', 'AUTHORIZATION_CLAIM',
        'OUTPUT_CONTROL', 'FORMAT_OVERRIDE', 'RESPONSE_FORCING',
        # Content manipulation medium-risk flags
        'STATISTICAL_OUTLIER', 'EXPERIENCE_OUTLIER', 'EXCESSIVE_SUPERLATIVES',
        'PRESTIGE_NAME_DROPPING', 'AWARD_DENSITY_HIGH', 'DOCUMENT_LENGTH_OUTLIER',
        # Competitor dismissal medium-risk flags (markers that might be legitimate)
        'ALERT_MARKER', 'WARNING_MARKER', 'NOTICE_MARKER', 'CAUTION_MARKER',
        'IMPORTANT_NOTE_MARKER', 'NOTE_DATA_MARKER',
    }
    
    high_count = sum(1 for f in flags if f in high_risk_flags)
    medium_count = sum(1 for f in flags if f in medium_risk_flags)
    low_count = len(flags) - high_count - medium_count
    
    # Score calculation (max 1.0)
    score = (high_count * 0.3) + (medium_count * 0.15) + (low_count * 0.05)
    
    return min(score, 1.0)
