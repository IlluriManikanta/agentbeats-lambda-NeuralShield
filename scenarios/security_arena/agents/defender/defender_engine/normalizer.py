"""Input canonicalization for the secure defender.

This module expands obfuscated attacker content into a canonical representation
that deterministic analyzers and prompts can reason about consistently.
"""

from __future__ import annotations

import base64
import codecs
import html
import re
import unicodedata
from typing import Sequence, Tuple
from urllib.parse import unquote

_SUSPICIOUS_KEYWORDS: tuple[str, ...] = (
    "ignore",
    "system",
    "prompt",
    "instruction",
    "reveal",
    "bypass",
    "admin",
    "override",
    "secret",
    "token",
    "api key",
    "rank",
    "risk_level",
    "set risk",
    "javascript:",
    "<script",
)

_ZERO_WIDTH_CHARS: tuple[str, ...] = (
    "\u200b",  # zero-width space
    "\u200c",  # zero-width non-joiner
    "\u200d",  # zero-width joiner
    "\u2060",  # word joiner
    "\ufeff",  # BOM / zero-width no-break space
)

_HOMOGLYPH_MAP = {
    # Cyrillic lookalikes
    "а": "a",
    "е": "e",
    "о": "o",
    "р": "p",
    "с": "c",
    "у": "y",
    "х": "x",
    "і": "i",
    "ј": "j",
    "ӏ": "l",
    "ѕ": "s",
    "ԁ": "d",
    # Greek lookalikes
    "Α": "A",
    "Β": "B",
    "Ε": "E",
    "Ζ": "Z",
    "Η": "H",
    "Ι": "I",
    "Κ": "K",
    "Μ": "M",
    "Ν": "N",
    "Ο": "O",
    "Ρ": "P",
    "Τ": "T",
    "Υ": "Y",
    "Χ": "X",
    "α": "a",
    "β": "b",
    "γ": "y",
    "δ": "d",
    "ε": "e",
    "ι": "i",
    "κ": "k",
    "ο": "o",
    "ρ": "p",
    "τ": "t",
    "υ": "u",
    "χ": "x",
}


def canonicalize_input(text: str) -> str:
    """Apply all canonicalization steps to produce a normalized version."""
    if not text:
        return text

    result = text

    # Step 1: Unicode normalization (NFKC)
    result = normalize_unicode(result)

    # Step 2: Strip HTML/XML comments
    result = strip_html_comments(result)

    # Step 3: Unescape HTML entities
    result = unescape_html(result)

    # Step 4: Decode URL-encoded segments
    result = decode_url_encoding(result)

    # Step 5: Decode detected base64 segments
    result = decode_base64_segments(result)

    # Step 6: Decode ROT13-encoded segments
    result = decode_rot13_segments(result)

    # Step 7: Detect and mark leetspeak obfuscation
    result = decode_leetspeak_segments(result)

    # Step 8: Detect and mark reversed text obfuscation
    result = decode_reversed_segments(result)

    # Step 9: Detect zero-width steganography before markup sanitization.
    result = detect_zero_width_steganography(result)

    # Step 10: Neutralize executable markup and URL schemes.
    result = neutralize_active_markup(result)

    # Step 11: Normalize known homoglyph confusables.
    result = normalize_homoglyphs(result)

    # Step 12: Surface hidden instructions inside fenced code/JSON blobs.
    result = extract_code_fence_instructions(result)

    # Step 13: Normalize whitespace (do this last to clean up)
    result = normalize_whitespace(result)

    return result


def normalize_unicode(text: str) -> str:
    """Apply Unicode NFKC normalization."""
    return unicodedata.normalize("NFKC", text)


def strip_html_comments(text: str) -> str:
    """Remove HTML/XML comments that might hide instructions."""
    # Match HTML comments, including multi-line
    pattern = r"<!--[\s\S]*?-->"

    # Replace comments with a marker so we know they were there
    def replace_comment(match: re.Match) -> str:
        content = match.group(0)
        # Keep a marker if the comment contained instruction-like content
        if _contains_any_keyword(content.lower(), _SUSPICIOUS_KEYWORDS):
            return "[REMOVED_SUSPICIOUS_COMMENT]"
        return ""

    return re.sub(pattern, replace_comment, text)


def unescape_html(text: str) -> str:
    """Unescape HTML entities that might hide characters."""
    return html.unescape(text)


def decode_base64_segments(text: str) -> str:
    """Detect and decode base64-encoded segments inline."""
    # Pattern to match potential base64 strings (at least 20 chars, valid chars, ends with 0-2 =)
    base64_pattern = r"(?<![A-Za-z0-9+/=])[A-Za-z0-9+/]{20,}={0,2}(?![A-Za-z0-9+/=])"

    def try_decode(match: re.Match) -> str:
        encoded = match.group(0)
        try:
            # Attempt to decode
            decoded_bytes = base64.b64decode(encoded, validate=True)
            # Try to interpret as UTF-8 text
            decoded_text = decoded_bytes.decode("utf-8")
            # Check if result looks like text (has mostly printable chars)
            if is_printable_text(decoded_text):
                # Mark as decoded so we know it was transformed
                return f"[DECODED_BASE64: {decoded_text}]"
        except Exception:
            pass
        # Return original if decoding fails
        return encoded

    return re.sub(base64_pattern, try_decode, text)


def is_printable_text(text: str) -> bool:
    """Check if a string contains mostly printable characters."""
    if not text:
        return False
    printable_count = sum(1 for c in text if c.isprintable() or c.isspace())
    return printable_count / len(text) > 0.8


def decode_url_encoding(text: str) -> str:
    """Decode URL-encoded sequences (%xx) that might hide instructions."""
    # Only attempt decode if we see URL-encoded patterns
    if "%" not in text:
        return text

    # Pattern: sequences of %XX that might form words
    url_pattern = r"(?:%[0-9A-Fa-f]{2})+"

    def try_decode_url(match: re.Match) -> str:
        encoded = match.group(0)
        try:
            decoded = unquote(encoded)
            if decoded != encoded and is_printable_text(decoded):
                if _contains_any_keyword(decoded.lower(), _SUSPICIOUS_KEYWORDS):
                    return f"[DECODED_URL: {decoded}]"
                return decoded
        except Exception:
            pass
        return encoded

    return re.sub(url_pattern, try_decode_url, text)


def decode_rot13_segments(text: str) -> str:
    """Detect and decode ROT13-encoded segments."""
    # Look for word-like sequences that might be ROT13
    word_pattern = r"\b[a-zA-Z]{4,}\b"
    words = re.findall(word_pattern, text)

    if not words:
        return text

    # Try ROT13 decoding on the whole text
    try:
        decoded_full = codecs.decode(text, "rot_13")
        if _contains_any_keyword(decoded_full.lower(), _SUSPICIOUS_KEYWORDS):
            return f"{text}\n[DECODED_ROT13: {decoded_full}]"
    except Exception:
        pass

    # Also try decoding individual suspicious-looking words
    result = text
    for word in words:
        try:
            decoded_word = codecs.decode(word, "rot_13")
            if decoded_word.lower() in _SUSPICIOUS_KEYWORDS:
                result = result.replace(word, f"{word}[ROT13:{decoded_word}]", 1)
        except Exception:
            pass

    return result


def decode_leetspeak_segments(text: str) -> str:
    """Detect and decode leetspeak obfuscation."""
    detected, decoded = detect_leetspeak(text)
    if detected and decoded != text:
        return f"{text}\n[DECODED_LEET: {decoded}]"
    return text.strip()


def decode_reversed_segments(text: str) -> str:
    """Detect reversed text that might hide instructions."""
    # Look for sequences of reversed words (lowercase letters that don't form common English words)
    # Check if reversing the entire text or significant segments reveals suspicious content

    detected, decoded = detect_reversed_text(text)
    if detected and decoded != text:
        return f"{text}\n[DECODED_REVERSED: {decoded}]"

    # Also check individual lines that might be reversed
    lines = text.split("\n")
    modified_lines = []
    any_reversed = False

    for line in lines:
        if len(line) > 10:
            line_detected, line_decoded = detect_reversed_text(line)
            if line_detected and line_decoded != line:
                modified_lines.append(f"{line}\n[DECODED_REVERSED_LINE: {line_decoded}]")
                any_reversed = True
            else:
                modified_lines.append(line)
        else:
            modified_lines.append(line)

    if any_reversed:
        return "\n".join(modified_lines)

    return text


def neutralize_active_markup(text: str) -> str:
    """Neutralize common executable markup payloads while preserving signal markers."""
    if not text:
        return text

    sanitized = text
    sanitized = re.sub(
        r"<\s*script\b[^>]*>[\s\S]*?<\s*/\s*script\s*>",
        "[REMOVED_SCRIPT_BLOCK]",
        sanitized,
        flags=re.IGNORECASE,
    )
    sanitized = re.sub(
        r"<\s*style\b[^>]*>[\s\S]*?<\s*/\s*style\s*>",
        "[REMOVED_STYLE_BLOCK]",
        sanitized,
        flags=re.IGNORECASE,
    )
    sanitized = re.sub(
        r"\bon(?:error|load|click|mouseover|focus|submit)\s*=\s*(\"[^\"]*\"|'[^']*'|[^\s>]+)",
        " [REMOVED_EVENT_HANDLER] ",
        sanitized,
        flags=re.IGNORECASE,
    )
    sanitized = re.sub(
        r"javascript\s*:",
        "[REMOVED_JS_URI]",
        sanitized,
        flags=re.IGNORECASE,
    )
    sanitized = re.sub(
        r"\[[^\]]{1,120}\]\(\s*javascript:[^)]+\)",
        "[REMOVED_JS_MARKDOWN_LINK]",
        sanitized,
        flags=re.IGNORECASE,
    )
    sanitized = re.sub(
        r"<\s*iframe\b[^>]*>",
        "[REMOVED_IFRAME_TAG]",
        sanitized,
        flags=re.IGNORECASE,
    )
    return sanitized


def normalize_homoglyphs(text: str) -> str:
    """Map common Greek/Cyrillic confusables to ASCII lookalikes."""
    if not text:
        return text
    translated = "".join(_HOMOGLYPH_MAP.get(char, char) for char in text)
    if translated == text:
        return text
    lower = translated.lower()
    if _contains_any_keyword(lower, _SUSPICIOUS_KEYWORDS):
        return f"{translated}\n[DECODED_HOMOGLYPH: suspicious confusables normalized]"
    return translated


def extract_code_fence_instructions(text: str) -> str:
    """Surface suspicious control text hidden in fenced code blocks or JSON blobs."""
    if not text:
        return text

    snippets: list[str] = []
    for match in re.finditer(r"```(?:[\w.+-]+)?\n([\s\S]*?)```", text):
        block = match.group(1).strip()
        if len(block) < 8:
            continue
        lower = block.lower()
        if _contains_any_keyword(lower, _SUSPICIOUS_KEYWORDS):
            snippets.append(_truncate_for_marker(block))

    for match in re.finditer(r"\"(?:ignore|override|reveal|system|prompt)[^\"]{0,120}\"", text, re.I):
        snippets.append(_truncate_for_marker(match.group(0)))

    if not snippets:
        return text
    unique = list(dict.fromkeys(snippets))[:3]
    marker = "\n".join(f"[DECODED_CODE_BLOCK: {snippet}]" for snippet in unique)
    return f"{text}\n{marker}"


def detect_zero_width_steganography(text: str) -> str:
    """Detect hidden payload text carried by zero-width characters."""
    if not text:
        return text
    zw_count = sum(text.count(char) for char in _ZERO_WIDTH_CHARS)
    if zw_count < 3:
        return text
    decoded = text
    for char in _ZERO_WIDTH_CHARS:
        decoded = decoded.replace(char, "")
    if decoded == text:
        return text

    decoded_lower = decoded.lower()
    if _contains_any_keyword(decoded_lower, _SUSPICIOUS_KEYWORDS):
        snippet = _truncate_for_marker(decoded)
        return f"{decoded}\n[DECODED_ZERO_WIDTH: {snippet}]"
    return decoded


def _contains_any_keyword(text: str, keywords: Sequence[str]) -> bool:
    return any(keyword in text for keyword in keywords)


def _truncate_for_marker(text: str, limit: int = 200) -> str:
    compact = re.sub(r"\s+", " ", text).strip()
    if len(compact) <= limit:
        return compact
    return f"{compact[:limit]}..."


def normalize_whitespace(text: str) -> str:
    """Normalize whitespace to catch hidden characters."""
    # Remove zero-width characters
    for char in _ZERO_WIDTH_CHARS:
        text = text.replace(char, "")

    # Collapse multiple spaces/tabs to single space (but preserve newlines)
    text = re.sub(r"[ \t]+", " ", text)

    # Collapse multiple newlines to max 2
    text = re.sub(r"\n{3,}", "\n\n", text)

    return text


def detect_leetspeak(text: str) -> Tuple[bool, str]:
    """Detect and optionally decode leetspeak-style obfuscation."""
    # Common leetspeak substitutions
    leet_map = {
        "0": "o",
        "1": "i",
        "3": "e",
        "4": "a",
        "5": "s",
        "7": "t",
        "8": "b",
        "9": "g",
        "@": "a",
        "$": "s",
        "|": "i",
        "!": "i",
        "(": "c",
        ")": "o",
    }

    # Only process if we see numeric/special characters mixed with letters
    if not re.search(r"[\d@$|!()]", text) or not re.search(r"[a-zA-Z]", text):
        return False, text

    decoded = []
    for char in text:
        if char in leet_map:
            decoded.append(leet_map[char])
        else:
            decoded.append(char)

    decoded_text = "".join(decoded)

    # Check if decoding produced recognizable suspicious words
    suspicious_words = set(_SUSPICIOUS_KEYWORDS) | {
        "password",
        "jailbreak",
        "disable",
        "forget",
        "disregard",
        "pretend",
        "roleplay",
        "developer",
        "debug",
    }
    if any(word in decoded_text.lower() for word in suspicious_words):
        return True, decoded_text

    return False, text


def detect_reversed_text(text: str) -> Tuple[bool, str]:
    """Detect text that might be reversed to hide instructions."""
    reversed_text = text[::-1]

    suspicious_words = set(_SUSPICIOUS_KEYWORDS) | {
        "password",
        "jailbreak",
        "disable",
        "forget",
        "disregard",
        "pretend",
        "roleplay",
        "developer",
        "debug",
    }
    if any(word in reversed_text.lower() for word in suspicious_words):
        return True, reversed_text

    return False, text
