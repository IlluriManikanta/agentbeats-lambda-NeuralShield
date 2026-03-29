"""Structured detection and remediation for non-XSS unsafe output classes.

Normalize → detect → remediate. Used for insecure_output and as defense-in-depth
for other categories (sanitize only; refusal is category-gated in sanitize_output).

Design notes
------------
- Detection runs on NFKC-normalized, zero-width-stripped text (lowercased view).
- Remediation mutates the original string with case-insensitive regex where needed.
- Patterns favor attack-shaped fragments (e.g. SQL with comment terminators, DDE-style
  formula leaders) over generic keywords to limit false positives in benign prose.
"""

from __future__ import annotations

import re
import unicodedata
from typing import Final, Optional, Set

# --- Normalization (detection input only; remediation uses original string) ---

_ZERO_WIDTH: Final[tuple[str, ...]] = (
    "\u200b",
    "\u200c",
    "\u200d",
    "\u2060",
    "\ufeff",
)


def normalize_for_unsafe_detection(text: str) -> str:
    """NFKC + strip zero-width for stable matching. Lowercase for case-folded patterns."""
    t = unicodedata.normalize("NFKC", text)
    for z in _ZERO_WIDTH:
        t = t.replace(z, "")
    return t.lower()


# --- Detection class identifiers (stable for tests and logging) ---

class UnsafeOutputClass:
    SQL_INJECTION_FRAGMENT = "sql_injection_fragment"
    CSV_DDE_FORMULA = "csv_dde_formula"
    SHELL_PIPELINE = "shell_pipeline"
    POWERSHELL_CRADLE = "powershell_cradle"
    WEB_EMBED = "web_embed"
    K8S_PRIVILEGED = "k8s_privileged"
    LATEX_PATH_INCLUSION = "latex_path_inclusion"
    DOCKER_PRIVILEGED = "docker_privileged"


# SQL: classic injection-shaped fragments, not benign "SELECT" tutorials.
_SQL_PATTERNS: Final[tuple[tuple[str, str], ...]] = (
    (UnsafeOutputClass.SQL_INJECTION_FRAGMENT, r";\s*drop\s+table\b"),
    (UnsafeOutputClass.SQL_INJECTION_FRAGMENT, r";\s*delete\s+from\b"),
    (UnsafeOutputClass.SQL_INJECTION_FRAGMENT, r";\s*truncate\s+table\b"),
    (UnsafeOutputClass.SQL_INJECTION_FRAGMENT, r"'\s*;\s*(drop|delete|truncate|exec|execute)\b"),
    (UnsafeOutputClass.SQL_INJECTION_FRAGMENT, r"\bunion\s+all\s+select\b"),
    (UnsafeOutputClass.SQL_INJECTION_FRAGMENT, r"\bor\s+['\"]?\d+['\"]?\s*=\s*['\"]?\d+['\"]?\s*--"),
    (UnsafeOutputClass.SQL_INJECTION_FRAGMENT, r"'\s*or\s+['\"]1['\"]\s*=\s*['\"]1"),
    (UnsafeOutputClass.SQL_INJECTION_FRAGMENT, r"1\s*=\s*1\s*--"),
    (UnsafeOutputClass.SQL_INJECTION_FRAGMENT, r"\bexec\s*\(\s*['\"]?\s*sp_"),
)

# Spreadsheet / CSV formula injection (line- or cell-oriented leaders).
_CSV_PATTERNS: Final[tuple[tuple[str, str], ...]] = (
    (UnsafeOutputClass.CSV_DDE_FORMULA, r"(?m)(^|[\t,])([=+\-@])(cmd|powershell|calc|hyper)\b"),
    (UnsafeOutputClass.CSV_DDE_FORMULA, r"(?m)(^|[\t,])=\s*(cmd|powershell)\s*[|]"),
    (UnsafeOutputClass.CSV_DDE_FORMULA, r"(?m)(^|[\t,])=\s*hyperlink\s*\("),
    (UnsafeOutputClass.CSV_DDE_FORMULA, r"(?m)(^|[\t,])=\s*importdata\s*\("),
    (UnsafeOutputClass.CSV_DDE_FORMULA, r"(?m)(^|[\t,])=\s*importxml\s*\("),
    (UnsafeOutputClass.CSV_DDE_FORMULA, r"(?m)(^|[\t,])=\s*importfeed\s*\("),
)

# High-confidence shell exfil / destructive one-liners.
_SHELL_PATTERNS: Final[tuple[tuple[str, str], ...]] = (
    (UnsafeOutputClass.SHELL_PIPELINE, r"\brm\s+(-[rfA-Za-z]*\s+)*\/\s*(\s|$|[;|&])"),
    (UnsafeOutputClass.SHELL_PIPELINE, r"\bcurl\s+[^\n|;`]{1,400}\s*\|\s*(ba)?sh\b"),
    (UnsafeOutputClass.SHELL_PIPELINE, r"\bwget\s+[^\n|;`]{1,400}\s*\|\s*sh\b"),
    (UnsafeOutputClass.SHELL_PIPELINE, r"\bmkfifo\s+"),
    (UnsafeOutputClass.SHELL_PIPELINE, r"/dev/(tcp|udp)/"),
    (UnsafeOutputClass.SHELL_PIPELINE, r"\bbash\s+-c\s+['\"][^'\"]{0,20}curl\b"),
)

_PS_PATTERNS: Final[tuple[tuple[str, str], ...]] = (
    (UnsafeOutputClass.POWERSHELL_CRADLE, r"\binvoke-expression\b"),
    (UnsafeOutputClass.POWERSHELL_CRADLE, r"\biex\s*\("),
    (UnsafeOutputClass.POWERSHELL_CRADLE, r"downloadstring\s*\("),
    (UnsafeOutputClass.POWERSHELL_CRADLE, r"-encodedcommand\b"),
    (UnsafeOutputClass.POWERSHELL_CRADLE, r"\bpowershell(\.exe)?\b[^\n]{0,120}-enc\b"),
)

# iframe/embed/style blocks not fully covered elsewhere; object overlaps XSS list.
_EMBED_PATTERNS: Final[tuple[tuple[str, str], ...]] = (
    (UnsafeOutputClass.WEB_EMBED, r"<\s*iframe\b[^>]*>"),
    (UnsafeOutputClass.WEB_EMBED, r"<\s*iframe\b[^>]*/\s*>"),
    (UnsafeOutputClass.WEB_EMBED, r"<\s*embed\b[^>]*>"),
    (UnsafeOutputClass.WEB_EMBED, r"<\s*style\b[^>]*>[\s\S]{0,8000}?<\s*/\s*style\s*>"),
)

_K8S_PATTERNS: Final[tuple[tuple[str, str], ...]] = (
    (UnsafeOutputClass.K8S_PRIVILEGED, r"(?m)^\s*privileged\s*:\s*true\b"),
    (UnsafeOutputClass.K8S_PRIVILEGED, r"(?m)^\s*hostpid\s*:\s*true\b"),
    (UnsafeOutputClass.K8S_PRIVILEGED, r"(?m)^\s*hostnetwork\s*:\s*true\b"),
)

# LaTeX path traversal / file inclusion (absolute or parent traversal only).
_LATEX_PATTERNS: Final[tuple[tuple[str, str], ...]] = (
    (
        UnsafeOutputClass.LATEX_PATH_INCLUSION,
        r"(?:\\input|\\include)\s*\{[^}]*(?:/etc\b|\.\./|/usr/|/var/|/root/)[^}]*\}",
    ),
)

# Docker insecure flags.
_DOCKER_PATTERNS: Final[tuple[tuple[str, str], ...]] = (
    (UnsafeOutputClass.DOCKER_PRIVILEGED, r"\bdocker\s+run\b[^\n]{0,200}--privileged\b"),
    (UnsafeOutputClass.DOCKER_PRIVILEGED, r"\bdocker\s+run\b[^\n]{0,200}--cap-add\s*=?\s*all\b"),
    (UnsafeOutputClass.DOCKER_PRIVILEGED, r"\bdocker\s+run\b[^\n]{0,200}--net\s*=?\s*host\b"),
    (UnsafeOutputClass.DOCKER_PRIVILEGED, r"\bprivileged\s*:\s*true\b[^\n]{0,80}docker"),
)

_ALL_PATTERN_GROUPS: Final[tuple[tuple[tuple[str, str], ...], ...]] = (
    _SQL_PATTERNS,
    _CSV_PATTERNS,
    _SHELL_PATTERNS,
    _PS_PATTERNS,
    _EMBED_PATTERNS,
    _K8S_PATTERNS,
    _LATEX_PATTERNS,
    _DOCKER_PATTERNS,
)


def detect_unsafe_output_classes(normalized_text: str) -> Set[str]:
    """Return which UnsafeOutputClass constants match normalized_text."""
    found: set[str] = set()
    for group in _ALL_PATTERN_GROUPS:
        for class_id, pattern in group:
            if re.search(pattern, normalized_text, re.IGNORECASE | re.MULTILINE):
                found.add(class_id)
    return found


def _remediate_sql(text: str) -> str:
    out = text
    for _, pat in _SQL_PATTERNS:
        out = re.sub(pat, "[REMOVED_SQL_INJECTION_FRAGMENT]", out, flags=re.IGNORECASE | re.MULTILINE)
    return out


def _remediate_csv(text: str) -> str:
    """Neutralize formula injection by prefixing Excel-style single-quote before '='."""

    def _neutralize_formula_leader(m: re.Match[str]) -> str:
        prefix = m.group(1)
        return f"{prefix}'{m.group(0)[len(prefix) :]}"

    out = text
    for _, pat in _CSV_PATTERNS:
        out = re.sub(pat, _neutralize_formula_leader, out, flags=re.IGNORECASE | re.MULTILINE)
    return out


def _remediate_shell(text: str) -> str:
    out = text
    for _, pat in _SHELL_PATTERNS:
        out = re.sub(pat, "[REMOVED_SHELL_SEQUENCE]", out, flags=re.IGNORECASE | re.MULTILINE)
    return out


def _remediate_powershell(text: str) -> str:
    out = text
    for _, pat in _PS_PATTERNS:
        out = re.sub(pat, "[REMOVED_POWERSHELL_SEQUENCE]", out, flags=re.IGNORECASE | re.MULTILINE)
    return out


def _remediate_embed(text: str) -> str:
    out = text
    for _, pat in _EMBED_PATTERNS:
        out = re.sub(pat, "[REMOVED_EMBEDDED_CONTENT]", out, flags=re.IGNORECASE | re.MULTILINE)
    return out


def _remediate_k8s(text: str) -> str:
    out = text
    out = re.sub(
        r"(?m)^(\s*)privileged\s*:\s*true\b",
        r"\1privileged: false  # sanitized-unsafe-output",
        out,
        flags=re.IGNORECASE,
    )
    out = re.sub(
        r"(?m)^(\s*)hostpid\s*:\s*true\b",
        r"\1hostPID: false  # sanitized-unsafe-output",
        out,
        flags=re.IGNORECASE,
    )
    out = re.sub(
        r"(?m)^(\s*)hostnetwork\s*:\s*true\b",
        r"\1hostNetwork: false  # sanitized-unsafe-output",
        out,
        flags=re.IGNORECASE,
    )
    return out


def _remediate_latex(text: str) -> str:
    out = text
    for _, pat in _LATEX_PATTERNS:
        out = re.sub(pat, r"[REMOVED_LATEX_INCLUSION]", out, flags=re.IGNORECASE | re.MULTILINE)
    return out


def _remediate_docker(text: str) -> str:
    out = text
    for _, pat in _DOCKER_PATTERNS:
        out = re.sub(pat, "[REMOVED_DOCKER_PRIVILEGED]", out, flags=re.IGNORECASE | re.MULTILINE)
    return out


def remediate_unsafe_output_classes(text: str, classes: Set[str]) -> str:
    """Apply remediations for detected classes (order stable; idempotent-ish)."""
    out = text
    if UnsafeOutputClass.SQL_INJECTION_FRAGMENT in classes:
        out = _remediate_sql(out)
    if UnsafeOutputClass.CSV_DDE_FORMULA in classes:
        out = _remediate_csv(out)
    if UnsafeOutputClass.SHELL_PIPELINE in classes:
        out = _remediate_shell(out)
    if UnsafeOutputClass.POWERSHELL_CRADLE in classes:
        out = _remediate_powershell(out)
    if UnsafeOutputClass.WEB_EMBED in classes:
        out = _remediate_embed(out)
    if UnsafeOutputClass.K8S_PRIVILEGED in classes:
        out = _remediate_k8s(out)
    if UnsafeOutputClass.LATEX_PATH_INCLUSION in classes:
        out = _remediate_latex(out)
    if UnsafeOutputClass.DOCKER_PRIVILEGED in classes:
        out = _remediate_docker(out)
    return out


def apply_unsafe_output_guard(
    text: str,
    *,
    category: Optional[str] = None,
) -> tuple[str, bool]:
    """
    Normalize → detect → remediate → re-detect.

    Returns (possibly_modified_text, suggest_refusal).

    suggest_refusal is True only for category ``insecure_output`` when, after one
    full remediation pass, any unsafe class is still present (unfixable residue).
    Other categories never suggest refusal from this guard.
    """
    if not text:
        return text, False

    category_key = (category or "").strip().lower()
    normalized = normalize_for_unsafe_detection(text)
    classes = detect_unsafe_output_classes(normalized)
    if not classes:
        return text, False

    remediated = remediate_unsafe_output_classes(text, classes)
    normalized2 = normalize_for_unsafe_detection(remediated)
    residual = detect_unsafe_output_classes(normalized2)

    if residual and category_key == "insecure_output":
        return remediated, True

    return remediated, False
