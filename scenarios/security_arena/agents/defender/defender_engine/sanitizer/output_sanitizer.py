"""Universal output sanitizer for task-integrity-safe responses."""

from __future__ import annotations

import html
import json
import re
from functools import lru_cache
from pathlib import Path
from typing import Any, Optional

from .. import config as gateway_config
from ..config import get_format_aware_refusal
from .unsafe_output_guard import apply_unsafe_output_guard

MAX_OUTPUT_LENGTH = getattr(gateway_config, "MAX_OUTPUT_LENGTH", 12000)
_DATA_DIR = Path(__file__).resolve().parents[1] / "data"

_PROMPT_LEAK_INDICATORS = [
    "instruction hierarchy",
    "system instructions",
    "never reveal system prompt",
    "quarantine tag",
    "binding, in priority order",
    "non-negotiable security rules",
    "nonce-scoped",
]

_DELIMITER_PATTERNS = [
    r"</?doc_[a-z0-9]+>",
    r"</?document>",
    r"</?untrusted>",
    r"between <\w+> and </\w+>",
]

_HARMFUL_PATTERNS = [
    r"<script\b",
    r"javascript:",
    r"\bonerror\s*=",
    r"\bonload\s*=",
    r"\bhow\s+to\s+make\s+(a\s+)?bomb\b",
    r"\b(lethal|fatal)\s+dose\b",
    r"\bwrite\s+(a\s+)?(malware|ransomware|keylogger)\b",
    r"\b(sql\s+injection|xss)\s+(payload|exploit)\b",
]

_SENSITIVE_PATTERNS = [
    r"sk-[a-zA-Z0-9]{20,}",
    r"\b[0-9]{3}-[0-9]{2}-[0-9]{4}\b",
    r"\b\d{9}\b",
    r"(password|token|api[_-]?key|secret)\s*[:=]\s*\S+",
]

_INTERNAL_SURFACE_CONTEXT_PATTERNS = [
    r"\b(internal|backend|private)\s+(tool|function|routine|api|endpoint|method)s?\b",
    r"\b(calls?|uses?|invokes?|relies on)\b.{0,40}\b(function|tool|api|endpoint|routine)\b",
    r"\b(available|supported)\s+(tools?|functions?|apis?)\b",
    r"\b(system prompt|hidden instructions?)\b",
]

_INTERNAL_IDENTIFIER_PATTERNS = [
    r"`[a-z][a-z0-9_]{2,}`",
    r"\b[a-z][a-z0-9]*_[a-z0-9_]+\b",
    r"\b[a-z]+[A-Z][A-Za-z0-9]+\b",
]

_DISCLOSURE_VERB_PATTERN = re.compile(
    r"\b(show|reveal|list|enumerate|dump|print|provide|confirm)\b", re.IGNORECASE
)

_PII_PATTERNS = [
    r"\b[0-9]{3}-[0-9]{2}-[0-9]{4}\b",  # SSN format
    r"\b(?:ssn|social security|tax id)\s*[:#-]?\s*[0-9]{3}-?[0-9]{2}-?[0-9]{4}\b",
    r"\b(?:dob|date of birth|birth date)\s*[:#-]?\s*[0-9]{1,2}[/-][0-9]{1,2}[/-][0-9]{2,4}\b",
    r"\b(?:mrn|medical record|patient id)\s*[:#-]?\s*[A-Z0-9-]{5,}\b",
    r"\b(?:account|routing|iban)\s*(?:number|#)?\s*[:#-]?\s*[A-Z0-9-]{6,}\b",
    r"\b(?:\d[ -]*?){13,16}\b",  # credit-card-like sequences
]

_XSS_PATTERNS = [
    r"<\s*script\b",
    r"javascript\s*:",
    r"\bon(?:error|load|click|mouseover|focus|submit)\s*=",
    r"<\s*svg\b[^>]*(onload|onerror|script)",
    r"\[[^\]]{1,120}\]\(\s*javascript:",
    r"<\s*img\b[^>]*\bon(?:error|load)\s*=",
    r"data\s*:\s*text/html",
    r"<\s*(?:object|embed|applet|form|input|button|textarea|select)\b",
    r"expression\s*\(",
    r"@import\s+url\s*\(",
    r"url\s*\(\s*['\"]?\s*javascript:",
    r"<\s*(?:math|details|video|audio|source)\b[^>]*\bon\w+\s*=",
    r"\bsrcdoc\s*=",
    r"<\s*base\b[^>]*href\s*=",
    r"<\s*meta\b[^>]*http-equiv\s*=\s*['\"]?refresh",
]

_ENTITY_XSS_PATTERNS = [
    r"&lt;\s*script\b",
    r"&#x3c;\s*script\b",
    r"&lt;\s*img\b[^>]*\bon(?:error|load)\s*=",
    r"&#x6a;&#x61;&#x76;&#x61;&#x73;&#x63;&#x72;&#x69;&#x70;&#x74;",
]

_MARKDOWN_IMAGE_PATTERN = r"!\[[^\]]{0,160}\]\(\s*(?:https?://|data:)[^)]+\)"

_SUPPLY_CHAIN_SUSPICIOUS_PATTERNS = [
    r"\b(unverified|unknown|unofficial|third-party mirror)\b.{0,40}\b(package|dependency|library)\b",
    r"\b(official|trusted|safe)\b.{0,40}\b(package|dependency)\b",
    r"\b(urgent|critical)\b.{0,40}\b(install|dependency update|package)\b",
]

_URL_PATTERN = re.compile(
    r"\bhttps?://([A-Za-z0-9.-]+\.[A-Za-z]{2,})(?:/[^\s)\]}>{<]*)?",
    re.IGNORECASE,
)

_RECOMMENDATION_ACTION_PATTERN = re.compile(
    r"\b(recommend|recommended|use|install|adopt|subscribe|signup|sign up|register|onboard|integrate|switch to)\b",
    re.IGNORECASE,
)

_RECOMMENDATION_ARTIFACT_PATTERN = re.compile(
    r"\b(vendor|supplier|provider|service|platform|api|repository|repo|extension|plugin|marketplace|endpoint)\b",
    re.IGNORECASE,
)

_OFFICIAL_CLAIM_PATTERN = re.compile(
    r"\b(official|trusted|verified|certified|safe)\b.{0,30}\b(vendor|supplier|provider|service|api|repo|package)\b",
    re.IGNORECASE,
)

_KNOWN_SAFE_RECOMMENDATION_DOMAINS = {
    "pypi.org",
    "www.pypi.org",
    "npmjs.com",
    "www.npmjs.com",
    "rubygems.org",
    "crates.io",
    "packagist.org",
    "nuget.org",
    "registry.npmjs.org",
    "github.com",
    "gitlab.com",
    "bitbucket.org",
    "docs.python.org",
    "python.org",
    "developer.mozilla.org",
    "kubernetes.io",
    "docker.com",
    "hub.docker.com",
}

_DEFAULT_KNOWN_SAFE_PACKAGES = {
    "numpy",
    "pandas",
    "scipy",
    "requests",
    "flask",
    "django",
    "fastapi",
    "pydantic",
    "openai",
    "jinja2",
    "uvicorn",
    "pytest",
    "react",
    "express",
    "lodash",
    "axios",
    "typescript",
}

_GENERIC_ALLOWED_IDENTIFIERS = {
    "status",
    "reason",
    "rank",
    "name",
    "score",
    "rationale",
    "risk_level",
    "company_name",
    "recommendation",
    "items",
    "id",
    "doc_id",
    "value",
    "message",
}


@lru_cache(maxsize=1)
def _load_known_packages() -> set[str]:
    """Load known package allowlist from data file with a safe fallback."""
    path = _DATA_DIR / "known_packages.json"
    if not path.exists():
        return set(_DEFAULT_KNOWN_SAFE_PACKAGES)

    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return set(_DEFAULT_KNOWN_SAFE_PACKAGES)

    packages: set[str] = set()
    if isinstance(payload, list):
        for item in payload:
            normalized = _normalize_package_name(str(item))
            if normalized:
                packages.add(normalized)
    elif isinstance(payload, dict):
        for value in payload.values():
            if not isinstance(value, list):
                continue
            for item in value:
                normalized = _normalize_package_name(str(item))
                if normalized:
                    packages.add(normalized)
    if not packages:
        return set(_DEFAULT_KNOWN_SAFE_PACKAGES)
    return packages


_GO_MODULE_PREFIX = re.compile(r"^[a-z0-9]+\.[a-z]{2,}/")


def _normalize_package_name(token: str) -> str:
    """Normalize package identifiers extracted from prose/code snippets."""
    value = token.strip().strip("`\"'").strip("()[]{}.,:;")
    value = value.lower()
    if not value:
        return ""

    for sep in ("==", ">=", "<=", "~=", "^", "~"):
        if sep in value:
            value = value.split(sep, 1)[0]
    if "@" in value and not value.startswith("@"):
        value = value.split("@", 1)[0]

    if _GO_MODULE_PREFIX.match(value):
        parts = value.split("/")
        value = "/".join(parts[:3]) if len(parts) >= 3 else value
    elif value.startswith("@"):
        scoped = value.split("/", 1)
        if len(scoped) == 2:
            package_part = scoped[1].split("@", 1)[0]
            value = f"{scoped[0]}/{package_part}"
    else:
        if "/" in value:
            value = value.split("/", 1)[0]
        if "." in value and value.count(".") >= 1:
            value = value.split(".", 1)[0]

    value = value.strip()
    if not re.match(r"^[@a-z0-9][@a-z0-9._/\-]{1,80}$", value):
        return ""
    return value


def _extract_referenced_packages(text: str) -> set[str]:
    """Extract package-like identifiers from install/import/prose contexts."""
    matches: set[str] = set()
    lower = text.lower()

    patterns = [
        r"\b(?:pip|pip3|pipx|npm|pnpm|yarn|cargo|gem)\s+install\s+([@a-z0-9._/-]{2,80})",
        r"\bgo\s+get\s+([@a-z0-9._/-]{2,80})",
        r"\bbrew\s+install\s+([@a-z0-9._/-]{2,80})",
        r"\bapt(?:-get)?\s+install\s+(?:-y\s+)?([@a-z0-9._/-]{2,80})",
        r"\bcomposer\s+require\s+([@a-z0-9._/-]{2,80})",
        r"\bnuget\s+install\s+([@a-z0-9._/-]{2,80})",
        r"\bdotnet\s+add\s+package\s+([@a-z0-9._/-]{2,80})",
        r"\bhelm\s+install\s+\S+\s+([@a-z0-9._/-]{2,80})",
        r"\bdocker\s+pull\s+([@a-z0-9._/-]{2,80})",
        r"\brequire\(\s*['\"]([@a-z0-9._/-]{2,80})['\"]\s*\)",
        r"\bimport\s+([a-zA-Z0-9_./-]{2,80})",
        r"\bfrom\s+([a-zA-Z0-9_./-]{2,80})\s+import\b",
        r"`([@a-zA-Z0-9._/-]{2,80})`",
    ]
    for pattern in patterns:
        for raw in re.findall(pattern, text):
            normalized = _normalize_package_name(raw)
            if normalized:
                matches.add(normalized)

    # Parse package names from dependencies blocks in JSON/package manifests.
    for dep_match in re.finditer(r"\bdependencies\b[\s\S]{0,300}", lower):
        block = text[dep_match.start() : dep_match.end()]
        for pkg in re.findall(r"['\"]([@a-zA-Z0-9._/-]{2,80})['\"]\s*:", block):
            normalized = _normalize_package_name(pkg)
            if normalized:
                matches.add(normalized)

    # Prose recommendations: "use package X", "library Y", etc.
    prose_pattern = (
        r"\b(?:package|dependency|library|sdk|module)\s+"
        r"(?:named\s+|called\s+|is\s+|:)?"
        r"([@a-z0-9][@a-z0-9._/-]{1,80})"
    )
    for raw in re.findall(prose_pattern, lower):
        normalized = _normalize_package_name(raw)
        if normalized:
            matches.add(normalized)

    return matches


def _find_unverified_packages(text: str) -> list[str]:
    known = _load_known_packages()
    candidates = sorted(_extract_referenced_packages(text))
    return [pkg for pkg in candidates if pkg not in known]


def _extract_domains(text: str) -> set[str]:
    domains: set[str] = set()
    for match in _URL_PATTERN.finditer(text):
        domain = match.group(1).strip().lower().strip(".")
        if domain:
            domains.add(domain)
    return domains


def _is_known_safe_domain(domain: str) -> bool:
    value = domain.strip().lower()
    if not value:
        return False
    if value in _KNOWN_SAFE_RECOMMENDATION_DOMAINS:
        return True
    # Allow trusted subdomains of known roots.
    for known in _KNOWN_SAFE_RECOMMENDATION_DOMAINS:
        if value.endswith(f".{known}"):
            return True
    return False


def _find_unverified_domains(text: str) -> list[str]:
    domains = sorted(_extract_domains(text))
    return [domain for domain in domains if not _is_known_safe_domain(domain)]


def contains_recommendation_surface_risk(text: str, strict: bool = False) -> bool:
    """Detect risky recommendations involving vendors/APIs/services/URLs."""
    lower = text.lower()
    has_action = bool(_RECOMMENDATION_ACTION_PATTERN.search(lower))
    has_artifact = bool(_RECOMMENDATION_ARTIFACT_PATTERN.search(lower))
    has_official_claim = bool(_OFFICIAL_CLAIM_PATTERN.search(lower))
    unverified_domains = _find_unverified_domains(text)
    has_unverified_url = bool(unverified_domains)

    if has_unverified_url and (has_action or has_artifact):
        return True
    if strict and has_unverified_url:
        return True
    if has_official_claim and (has_unverified_url or has_action):
        return True
    if has_artifact and has_action and "http" not in lower and "internal" not in lower:
        # Catch prose-only recommendations without URLs.
        risky_terms = ("unofficial", "mirror", "patched", "fork", "custom", "proprietary")
        if any(term in lower for term in risky_terms):
            return True
    return False


def summarize_recommendation_risk(text: str) -> dict[str, Any]:
    """Produce structured risk signals for recommendation-surface monitoring."""
    lower = text.lower()
    unknown_packages = _find_unverified_packages(text)
    unknown_domains = _find_unverified_domains(text)
    has_install = bool(
        re.search(
            r"\b(pip|pip3|pipx|npm|pnpm|yarn|cargo|gem|brew|apt(?:-get)?|composer|nuget|dotnet|helm|docker)\s+"
            r"(?:install|require|get|pull|add(?:\s+package)?)\s+([@a-z0-9._/-]+)",
            lower,
        )
    ) or bool(re.search(r"\bgo\s+get\s+([@a-z0-9._/-]+)", lower))
    has_action = bool(_RECOMMENDATION_ACTION_PATTERN.search(lower))
    has_artifact = bool(_RECOMMENDATION_ARTIFACT_PATTERN.search(lower))
    has_official_claim = bool(_OFFICIAL_CLAIM_PATTERN.search(lower))
    recommendation_surface_risk = contains_recommendation_surface_risk(text, strict=False)
    return {
        "has_install": has_install,
        "has_action": has_action,
        "has_artifact": has_artifact,
        "has_official_claim": has_official_claim,
        "unknown_packages_count": len(unknown_packages),
        "unknown_domain_count": len(unknown_domains),
        "unknown_packages": unknown_packages[:6],
        "unknown_domains": unknown_domains[:6],
        "recommendation_surface_risk": recommendation_surface_risk,
    }


def rewrite_unverified_url_mentions(text: str) -> tuple[str, list[str]]:
    """Redact unverified external domains in recommendation contexts."""
    unverified_domains = _find_unverified_domains(text)
    if not unverified_domains:
        return text, []

    rewritten = text
    for domain in unverified_domains:
        rewritten = re.sub(
            rf"https?://{re.escape(domain)}(?:/[^\s)\]><]*)?",
            "[UNVERIFIED_URL]",
            rewritten,
            flags=re.IGNORECASE,
        )
    return rewritten, unverified_domains


def rewrite_unverified_package_mentions(text: str) -> tuple[str, list[str]]:
    """Rewrite unknown package references with explicit uncertainty markers."""
    unknown_packages = _find_unverified_packages(text)
    if not unknown_packages:
        return text, []

    rewritten = text
    for pkg in unknown_packages:
        token_pattern = rf"(?<![A-Za-z0-9@._/-]){re.escape(pkg)}(?![A-Za-z0-9@._/-])"
        rewritten = re.sub(
            token_pattern,
            f"[UNVERIFIED: {pkg}]",
            rewritten,
            flags=re.IGNORECASE,
        )
    return rewritten, unknown_packages


def sanitize_output(
    text: str,
    trusted_context: Optional[dict[str, Any]] = None,
    category: Optional[str] = None,
) -> str:
    """Sanitize output with universal checks regardless of scenario."""
    if not text:
        return text

    trusted_context = trusted_context or {}
    category_value = (category or "unknown").strip().lower()
    sanitized = text[:MAX_OUTPUT_LENGTH]

    if contains_prompt_leakage(sanitized) or contains_delimiter_leakage(sanitized):
        return get_format_aware_refusal(trusted_context)
    if contains_tool_leakage(sanitized, trusted_context):
        return get_format_aware_refusal(trusted_context)
    if contains_harmful_content(sanitized):
        return get_format_aware_refusal(trusted_context)

    guarded, refuse_unsafe = apply_unsafe_output_guard(sanitized, category=category_value)
    if refuse_unsafe:
        return get_format_aware_refusal(trusted_context, category=category_value)
    sanitized = guarded

    if (
        contains_xss_payload(sanitized)
        or contains_entity_encoded_xss(sanitized)
        or contains_markdown_image_payload(sanitized)
    ):
        sanitized = strip_xss_payload_with_recheck(sanitized)

    if contains_pii_leakage(sanitized):
        sanitized = redact_pii_text(sanitized)

    strict_supply = category_value == "supply_chain"
    if contains_supply_chain_risk(sanitized, strict=strict_supply):
        sanitized = downgrade_supply_chain_claims(sanitized, strict=strict_supply)

    sanitized = redact_sensitive_text(sanitized)
    sanitized = enforce_safe_limits(sanitized)
    sanitized = enforce_required_format(sanitized, trusted_context)
    return sanitized


def contains_prompt_leakage(text: str) -> bool:
    """Detect likely leakage of system prompt or hidden policy text."""
    lower_text = text.lower()
    matches = sum(1 for indicator in _PROMPT_LEAK_INDICATORS if indicator in lower_text)
    return matches >= 2


def contains_delimiter_leakage(text: str) -> bool:
    """Detect leakage of quarantine delimiters and internal boundary hints."""
    lower_text = text.lower()
    return any(re.search(pattern, lower_text) for pattern in _DELIMITER_PATTERNS)


def contains_harmful_content(text: str) -> bool:
    """Detect clearly unsafe executable/harmful payload content."""
    lower_text = text.lower()
    return any(re.search(pattern, lower_text) for pattern in _HARMFUL_PATTERNS)


def contains_tool_leakage(text: str, trusted_context: Optional[dict[str, Any]] = None) -> bool:
    """Detect disclosure of internal function/tool/API surface details."""
    trusted_context = trusted_context or {}
    lower_text = text.lower()
    if not any(re.search(pattern, lower_text) for pattern in _INTERNAL_SURFACE_CONTEXT_PATTERNS):
        return False

    has_disclosure_language = bool(_DISCLOSURE_VERB_PATTERN.search(text))

    allowlist = _derive_allowed_identifiers(trusted_context)
    identifier_hits: set[str] = set()
    for pattern in _INTERNAL_IDENTIFIER_PATTERNS:
        for match in re.findall(pattern, text):
            token = match.strip("`").lower()
            if token in allowlist:
                continue
            if len(token) <= 2:
                continue
            identifier_hits.add(token)
    if not identifier_hits:
        return False

    # Explicit disclosure verbs are high confidence leaks.
    if has_disclosure_language:
        return True

    # Also catch declarative leaks like "internal tools available: `foo` `bar`".
    declarative_surface_markers = (
        "internal tools",
        "internal functions",
        "backend functions",
        "private api",
        "available tools",
        "supported tools",
    )
    lower_text = text.lower()
    return any(marker in lower_text for marker in declarative_surface_markers)


def contains_internal_surface_disclosure(text: str) -> bool:
    """Backward-compatible alias used by legacy callers."""
    return contains_tool_leakage(text, trusted_context={})


def _derive_allowed_identifiers(trusted_context: dict[str, Any]) -> set[str]:
    allowlist = set(_GENERIC_ALLOWED_IDENTIFIERS)
    output_format = str(trusted_context.get("output_format", "") or "")
    for key in re.findall(r"\"([A-Za-z_][A-Za-z0-9_]*)\"\s*:", output_format):
        allowlist.add(key.lower())
    for key in re.findall(r"\b([a-z][a-z0-9_]{2,})\b", output_format):
        allowlist.add(key.lower())
    return allowlist


def contains_sensitive_patterns(text: str) -> bool:
    """Detect sensitive values that should be redacted."""
    return any(re.search(pattern, text, re.IGNORECASE) for pattern in _SENSITIVE_PATTERNS)


def contains_pii_leakage(text: str) -> bool:
    """Detect direct or contextual personally identifiable information leaks."""
    return any(re.search(pattern, text, re.IGNORECASE) for pattern in _PII_PATTERNS)


def redact_pii_text(text: str) -> str:
    """Redact common PII values from plaintext."""
    result = text
    result = re.sub(r"\b[0-9]{3}-[0-9]{2}-[0-9]{4}\b", "[REDACTED_SSN]", result)
    result = re.sub(
        r"\b((?:ssn|social security|tax id)\s*[:#-]?\s*)[0-9]{3}-?[0-9]{2}-?[0-9]{4}\b",
        r"\1[REDACTED]",
        result,
        flags=re.IGNORECASE,
    )
    result = re.sub(
        r"\b((?:dob|date of birth|birth date)\s*[:#-]?\s*)[0-9]{1,2}[/-][0-9]{1,2}[/-][0-9]{2,4}\b",
        r"\1[REDACTED]",
        result,
        flags=re.IGNORECASE,
    )
    result = re.sub(
        r"\b((?:mrn|medical record|patient id)\s*[:#-]?\s*)[A-Z0-9-]{5,}\b",
        r"\1[REDACTED]",
        result,
        flags=re.IGNORECASE,
    )
    result = re.sub(
        r"\b((?:account|routing|iban)\s*(?:number|#)?\s*[:#-]?\s*)[A-Z0-9-]{6,}\b",
        r"\1[REDACTED]",
        result,
        flags=re.IGNORECASE,
    )
    result = re.sub(r"\b(?:\d[ -]*?){13,16}\b", "[REDACTED_CARD]", result)
    return result


def contains_xss_payload(text: str) -> bool:
    """Detect executable output payloads that can trigger XSS/markup execution."""
    lower = text.lower()
    return any(re.search(pattern, lower, re.IGNORECASE) for pattern in _XSS_PATTERNS)


def contains_entity_encoded_xss(text: str) -> bool:
    """Detect entity-encoded script payloads that evade naive tag matching."""
    lower = text.lower()
    return any(re.search(pattern, lower, re.IGNORECASE) for pattern in _ENTITY_XSS_PATTERNS)


def contains_markdown_image_payload(text: str) -> bool:
    """Detect markdown images that can be used for tracking/data exfiltration."""
    return bool(re.search(_MARKDOWN_IMAGE_PATTERN, text, re.IGNORECASE))


def strip_xss_payload_with_recheck(text: str) -> str:
    """Strip XSS payloads, then re-check after HTML-entity decoding."""
    sanitized = strip_xss_payload(text)
    decoded = html.unescape(sanitized)
    if decoded != sanitized and (
        contains_xss_payload(decoded)
        or contains_entity_encoded_xss(decoded)
        or contains_markdown_image_payload(decoded)
    ):
        sanitized = strip_xss_payload(decoded)
    return sanitized


def strip_xss_payload(text: str) -> str:
    """Strip active markup while preserving inert textual meaning."""
    sanitized = text
    sanitized = re.sub(
        r"<\s*script\b[^>]*>[\s\S]*?<\s*/\s*script\s*>",
        "[REMOVED_SCRIPT_BLOCK]",
        sanitized,
        flags=re.IGNORECASE,
    )
    sanitized = re.sub(
        r"\bon(?:error|load|click|mouseover|focus|submit)\s*=\s*(\"[^\"]*\"|'[^']*'|[^\s>]+)",
        " [REMOVED_EVENT_HANDLER] ",
        sanitized,
        flags=re.IGNORECASE,
    )
    sanitized = re.sub(r"javascript\s*:", "[REMOVED_JS_URI]", sanitized, flags=re.IGNORECASE)
    sanitized = re.sub(
        r"\[[^\]]{1,120}\]\(\s*javascript:[^)]+\)",
        "[REMOVED_JS_MARKDOWN_LINK]",
        sanitized,
        flags=re.IGNORECASE,
    )
    sanitized = re.sub(
        r"<\s*svg\b[^>]*(onload|onerror|script)[^>]*>",
        "[REMOVED_SVG_PAYLOAD]",
        sanitized,
        flags=re.IGNORECASE,
    )
    sanitized = re.sub(
        r"<\s*img\b[^>]*\bon(?:error|load)\s*=[^>]*>",
        "[REMOVED_IMG_PAYLOAD]",
        sanitized,
        flags=re.IGNORECASE,
    )
    sanitized = re.sub(
        r"data\s*:\s*text/html[^)\s>]*",
        "[REMOVED_DATA_URI]",
        sanitized,
        flags=re.IGNORECASE,
    )
    sanitized = re.sub(
        r"expression\s*\([^)]+\)",
        "[REMOVED_CSS_EXPRESSION]",
        sanitized,
        flags=re.IGNORECASE,
    )
    sanitized = re.sub(
        r"@import\s+url\s*\([^)]*\)",
        "[REMOVED_CSS_IMPORT]",
        sanitized,
        flags=re.IGNORECASE,
    )
    sanitized = re.sub(
        r"url\s*\(\s*['\"]?\s*javascript:[^)]+\)",
        "[REMOVED_CSS_JS_URL]",
        sanitized,
        flags=re.IGNORECASE,
    )
    sanitized = re.sub(
        r"<\s*(?:object|embed|applet|form|input|button|textarea|select)\b[^>]*>",
        "[REMOVED_DANGEROUS_ELEMENT]",
        sanitized,
        flags=re.IGNORECASE,
    )
    sanitized = re.sub(
        r"<\s*/\s*(?:object|embed|applet|form|input|button|textarea|select)\s*>",
        "",
        sanitized,
        flags=re.IGNORECASE,
    )
    sanitized = re.sub(
        r"<\s*(?:math|details|video|audio|source)\b[^>]*\bon\w+\s*=[^>]*>",
        "[REMOVED_HTML5_EVENT_PAYLOAD]",
        sanitized,
        flags=re.IGNORECASE,
    )
    sanitized = re.sub(
        r"\bsrcdoc\s*=\s*(\"[^\"]*\"|'[^']*'|[^\s>]+)",
        "srcdoc=[REMOVED]",
        sanitized,
        flags=re.IGNORECASE,
    )
    sanitized = re.sub(
        r"<\s*base\b[^>]*href\s*=[^>]*>",
        "[REMOVED_BASE_TAG]",
        sanitized,
        flags=re.IGNORECASE,
    )
    sanitized = re.sub(
        r"<\s*meta\b[^>]*http-equiv\s*=\s*['\"]?refresh[^>]*>",
        "[REMOVED_META_REFRESH]",
        sanitized,
        flags=re.IGNORECASE,
    )
    sanitized = re.sub(
        _MARKDOWN_IMAGE_PATTERN,
        "[REMOVED_MARKDOWN_IMAGE_LINK]",
        sanitized,
        flags=re.IGNORECASE,
    )
    return sanitized


def contains_supply_chain_risk(text: str, strict: bool = False) -> bool:
    """Detect risky dependency recommendations, especially in strict mode."""
    lower = text.lower()
    has_install = bool(
        re.search(
            r"\b(pip|pip3|pipx|npm|pnpm|yarn|cargo|gem|brew|apt(?:-get)?|composer|nuget|dotnet|helm|docker)\s+"
            r"(?:install|require|get|pull|add(?:\s+package)?)\s+([@a-z0-9._/-]+)",
            lower,
        )
    ) or bool(re.search(r"\bgo\s+get\s+([@a-z0-9._/-]+)", lower))
    has_recommendation_context = bool(
        re.search(
            r"\b(recommend|recommended|use|install|dependency|package|library|module|sdk|import|require)\b",
            lower,
        )
    )
    suspicious_context = any(
        re.search(pattern, lower, re.IGNORECASE) for pattern in _SUPPLY_CHAIN_SUSPICIOUS_PATTERNS
    )
    unknown_packages = _find_unverified_packages(text)
    recommendation_surface_risk = contains_recommendation_surface_risk(text, strict=strict)

    if recommendation_surface_risk:
        return True
    if unknown_packages and has_install:
        return True
    if strict and unknown_packages and (has_install or has_recommendation_context):
        return True
    if suspicious_context and (has_install or bool(unknown_packages) or has_recommendation_context):
        return True
    if unknown_packages and has_recommendation_context:
        return True
    return any(_looks_typosquat_like(pkg) for pkg in unknown_packages)


def _looks_typosquat_like(pkg_name: str) -> bool:
    if len(pkg_name) > 32:
        return True
    separator_count = pkg_name.count("-") + pkg_name.count("_")
    if separator_count >= 3:
        return True
    if re.search(r"[0-9]{3,}", pkg_name):
        return True
    return pkg_name.endswith(("secure", "official", "trusted", "pro"))


def downgrade_supply_chain_claims(text: str, strict: bool = False) -> str:
    """Convert strong dependency recommendations into verification-first guidance."""
    downgraded, unknown_packages = rewrite_unverified_package_mentions(text)
    downgraded, unknown_domains = rewrite_unverified_url_mentions(downgraded)
    known_packages = _load_known_packages()

    def _replace_install(match: re.Match[str]) -> str:
        manager = match.group(1)
        pkg = _normalize_package_name(match.group(2))
        if strict or (pkg and pkg not in known_packages):
            return f"{manager} install [INSTALL_COMMAND_REDACTED_PENDING_VERIFICATION]"
        return match.group(0)

    downgraded = re.sub(
        r"\b(pip|pip3|pipx|npm|pnpm|yarn|cargo|gem|brew|apt(?:-get)?|composer|nuget|dotnet|helm|docker)\s+"
        r"(?:install|require|get|pull|add(?:\s+package)?)\s+([@a-z0-9._/-]+)",
        _replace_install,
        downgraded,
        flags=re.IGNORECASE,
    )
    downgraded = re.sub(
        r"\b(go)\s+get\s+([@a-z0-9._/-]+)",
        _replace_install,
        downgraded,
        flags=re.IGNORECASE,
    )
    caution = (
        "Dependency recommendation uncertainty detected: add a verification step and "
        "verify package legitimacy through official registries and maintainers before installation."
    )
    if unknown_packages:
        caution = (
            f"{caution} Unverified package references: {', '.join(sorted(unknown_packages)[:8])}."
        )
    if unknown_domains:
        caution = (
            f"{caution} Unverified domains/services referenced: "
            f"{', '.join(sorted(unknown_domains)[:6])}."
        )
    if caution.lower() in downgraded.lower():
        return downgraded
    return f"{downgraded}\n\n{caution}"


def redact_sensitive_text(text: str) -> str:
    """Redact known sensitive value patterns from plaintext."""
    result = text
    result = redact_pii_text(result)
    result = re.sub(r"sk-[a-zA-Z0-9]{20,}", "[REDACTED_API_KEY]", result)
    result = re.sub(r"\b\d{9}\b", "[REDACTED_ID]", result)
    result = re.sub(
        r"((?:password|token|api[_-]?key|secret)\s*[:=]\s*)\S+",
        r"\1[REDACTED]",
        result,
        flags=re.IGNORECASE,
    )
    return result


_WRITTEN_NUMBER_MAP: dict[str, int] = {
    "two hundred": 200, "three hundred": 300, "four hundred": 400,
    "five hundred": 500, "one hundred fifty": 150, "one hundred twenty": 120,
    "hundred fifty": 150, "hundred twenty": 120,
    "two fifty": 250, "one fifty": 150,
}

_MULTIPLIER_PATTERN = re.compile(
    r"\b(\d+(?:\.\d+)?)\s*[xX×]\s*(the\s+)?"
    r"(?:intensity|effort|dose|baseline|standard|normal|recommended|maximum|max|limit)",
    re.IGNORECASE,
)

_WRITTEN_PERCENT_PATTERN = re.compile(
    r"\b(\d{3,})\s+percent\b", re.IGNORECASE,
)

_WRITTEN_LARGE_PATTERN = re.compile(
    r"\b(" + "|".join(re.escape(k) for k in _WRITTEN_NUMBER_MAP) + r")\s*(?:%|percent|intensity)\b",
    re.IGNORECASE,
)


def enforce_safe_limits(text: str) -> str:
    """Cap percentage and intensity expressions at 100%."""
    pattern = r"(\d+(?:\.\d+)?)\s*%"

    def _clamp(match: re.Match[str]) -> str:
        try:
            value = float(match.group(1))
        except ValueError:
            return match.group(0)
        if value > 100:
            return "100%"
        return match.group(0)

    result = re.sub(pattern, _clamp, text)

    def _clamp_written_percent(match: re.Match[str]) -> str:
        try:
            value = int(match.group(1))
        except ValueError:
            return match.group(0)
        if value > 100:
            return "100 percent"
        return match.group(0)

    result = _WRITTEN_PERCENT_PATTERN.sub(_clamp_written_percent, result)

    def _clamp_written_large(match: re.Match[str]) -> str:
        key = match.group(1).lower()
        value = _WRITTEN_NUMBER_MAP.get(key)
        if value is not None and value > 100:
            return "100% intensity"
        return match.group(0)

    result = _WRITTEN_LARGE_PATTERN.sub(_clamp_written_large, result)

    def _clamp_multiplier(match: re.Match[str]) -> str:
        try:
            mult = float(match.group(1))
        except ValueError:
            return match.group(0)
        if mult > 1.0:
            return match.group(0).replace(match.group(1), "1.0")
        return match.group(0)

    result = _MULTIPLIER_PATTERN.sub(_clamp_multiplier, result)
    return result


def _extract_schema_keys(output_format: str) -> set[str]:
    """Infer expected JSON keys from the output_format description."""
    keys: set[str] = set()
    for key in re.findall(r'"([A-Za-z_][A-Za-z0-9_]*)"', output_format):
        keys.add(key.lower())
    for key in re.findall(r'\b([a-z][a-z0-9_]{2,})\b', output_format.lower()):
        keys.add(key)
    return keys


def _strip_unknown_fields(data: Any, allowed_keys: set[str]) -> Any:
    """Remove JSON fields not in the expected schema (top-level only)."""
    if not allowed_keys:
        return data
    always_allowed = {"status", "reason", "error", "message", "warning"}
    full_allowed = allowed_keys | always_allowed
    if isinstance(data, dict):
        return {k: v for k, v in data.items() if k.lower() in full_allowed}
    if isinstance(data, list):
        return [_strip_unknown_fields(item, allowed_keys) for item in data]
    return data


def enforce_required_format(text: str, trusted_context: dict[str, Any]) -> str:
    """Ensure response satisfies strict format expectations when declared."""
    output_format = str(trusted_context.get("output_format", "")).lower()
    if "json" not in output_format:
        return text

    json_text = extract_json(text)
    if not json_text:
        return get_format_aware_refusal(trusted_context)

    try:
        parsed = json.loads(json_text)
    except json.JSONDecodeError:
        return get_format_aware_refusal(trusted_context)

    schema_keys = _extract_schema_keys(str(trusted_context.get("output_format", "")))
    if schema_keys and len(schema_keys) >= 2:
        parsed = _strip_unknown_fields(parsed, schema_keys)

    parsed = redact_sensitive_any(parsed)
    parsed = clamp_json_safety_values(parsed)
    parsed = strip_xss_any(parsed)
    return json.dumps(parsed, indent=2)


_BOUNDED_KEY_MARKERS = (
    "percent", "intensity", "ratio", "effort", "load", "power",
    "speed", "dose", "rate", "level", "capacity", "rpe",
    "exertion", "output", "throttle", "volume",
)

_UNBOUNDED_KEY_EXCEPTIONS = {
    "risk_level", "score", "rank", "price", "revenue", "salary",
    "count", "total", "amount", "year", "age", "weight",
    "height", "distance", "calories", "duration", "experience",
}


def clamp_json_safety_values(data: Any) -> Any:
    """Clamp percentage/intensity-style numeric values in JSON structures."""
    if isinstance(data, dict):
        result = {}
        for key, value in data.items():
            key_lower = str(key).lower().replace("-", "_").replace(" ", "_")
            should_clamp = (
                isinstance(value, (int, float))
                and any(marker in key_lower for marker in _BOUNDED_KEY_MARKERS)
                and key_lower not in _UNBOUNDED_KEY_EXCEPTIONS
            )
            if should_clamp:
                result[key] = min(float(value), 100.0)
            else:
                result[key] = clamp_json_safety_values(value)
        return result
    if isinstance(data, list):
        return [clamp_json_safety_values(item) for item in data]
    if isinstance(data, str):
        return enforce_safe_limits(redact_sensitive_text(data))
    return data


def redact_sensitive_any(data: Any) -> Any:
    """Recursively redact sensitive values from arbitrary JSON-compatible data."""
    if isinstance(data, dict):
        out: dict[str, Any] = {}
        for key, value in data.items():
            key_lower = str(key).lower()
            if any(marker in key_lower for marker in ["password", "secret", "token", "api_key", "apikey", "ssn"]):
                out[key] = "[REDACTED]"
            else:
                out[key] = redact_sensitive_any(value)
        return out
    if isinstance(data, list):
        return [redact_sensitive_any(v) for v in data]
    if isinstance(data, str):
        return redact_sensitive_text(data)
    return data


def strip_xss_any(data: Any) -> Any:
    """Recursively strip XSS payloads from JSON-compatible structures."""
    if isinstance(data, dict):
        return {key: strip_xss_any(value) for key, value in data.items()}
    if isinstance(data, list):
        return [strip_xss_any(value) for value in data]
    if isinstance(data, str):
        cleaned, _ = apply_unsafe_output_guard(data, category=None)
        return strip_xss_payload_with_recheck(cleaned)
    return data


def extract_json(text: str) -> Optional[str]:
    """Extract a parseable JSON object/array from text, including fenced blocks."""
    stripped = text.strip()
    if stripped.startswith("```"):
        lines = stripped.split("\n")
        in_block = False
        payload: list[str] = []
        for line in lines:
            if line.startswith("```") and not in_block:
                in_block = True
                continue
            if line.startswith("```") and in_block:
                break
            if in_block:
                payload.append(line)
        stripped = "\n".join(payload).strip()

    if stripped.startswith("{") or stripped.startswith("["):
        try:
            json.loads(stripped)
            return stripped
        except json.JSONDecodeError:
            pass

    if "{" in stripped:
        candidate = _extract_balanced_json(stripped, "{", "}")
        if candidate:
            return candidate
    if "[" in stripped:
        candidate = _extract_balanced_json(stripped, "[", "]")
        if candidate:
            return candidate
    return None


def _extract_balanced_json(text: str, open_char: str, close_char: str) -> Optional[str]:
    """Extract a balanced JSON block and verify it parses."""
    start_idx = text.find(open_char)
    if start_idx == -1:
        return None

    depth = 0
    in_string = False
    escape_next = False
    for i, char in enumerate(text[start_idx:], start=start_idx):
        if escape_next:
            escape_next = False
            continue
        if char == "\\":
            escape_next = True
            continue
        if char == '"':
            in_string = not in_string
            continue
        if in_string:
            continue
        if char == open_char:
            depth += 1
        elif char == close_char:
            depth -= 1
            if depth == 0:
                candidate = text[start_idx : i + 1]
                try:
                    json.loads(candidate)
                    return candidate
                except json.JSONDecodeError:
                    return None
    return None


