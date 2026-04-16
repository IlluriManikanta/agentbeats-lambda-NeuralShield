"""
HTML parsing for individual AgentBeats scenario pages.

Scenario pages use div.section blocks with .section-title and .description;
this module also falls back to h1–h6 heading walks for other layouts.
"""

from __future__ import annotations

import re
from typing import Any
from urllib.parse import urlparse

from bs4 import BeautifulSoup, NavigableString, Tag

from utils import clean_text

# Keyword → display tag (case-insensitive match on haystack).
_KEYWORD_TAG_PATTERNS: tuple[tuple[str, str], ...] = (
    ("jailbreak", "Keyword: jailbreak"),
    ("injection", "Keyword: injection"),
    ("pii", "Keyword: PII"),
    ("supply chain", "Keyword: supply chain"),
    ("xss", "Keyword: XSS"),
)


def _scenario_slug(url: str) -> str:
    path = urlparse(url).path.strip("/").split("/")
    return path[0] if path else ""


def _normalize_section_title(title: str) -> str:
    """Lowercase label with emoji/punctuation trimmed for matching."""
    t = clean_text(title).lower()
    # Strip leading non-alphanumeric (emoji, bullets).
    t = re.sub(r"^[^\w]+", "", t, flags=re.UNICODE)
    return t.strip()


def _section_body_from_div(section: Tag) -> str:
    """
    Collect prose (.description) plus diagram/code sources (<pre>, e.g. mermaid).
    """
    chunks: list[str] = []
    desc = section.select_one(".description")
    if desc:
        chunks.append(desc.get_text("\n", strip=True))
    for pre in section.find_all("pre"):
        chunks.append(pre.get_text("\n", strip=True))
    return clean_text("\n".join(chunks))


def _parse_div_sections(soup: BeautifulSoup) -> dict[str, str]:
    """Map logical keys to body text using AgentBeats' div.section layout."""
    out: dict[str, str] = {
        "description": "",
        "attack_vector": "",
        "goal": "",
        "context": "",
        "constraints": "",
        "attack_flow_diagram": "",
    }
    for block in soup.select("div.content div.section, .content div.section"):
        title_el = block.select_one(".section-title")
        if not title_el:
            continue
        label = _normalize_section_title(title_el.get_text())
        body = _section_body_from_div(block)
        if not body:
            continue

        if "description" in label:
            out["description"] = body
        elif "intended flow" in label:
            out["context"] = body
        elif "attack vector" in label:
            out["attack_vector"] = body
        elif "success condition" in label:
            out["goal"] = body
        elif "goal" in label.split() or label.startswith("goal"):
            out["goal"] = body
        elif "context" in label.split() or label.startswith("context"):
            out["context"] = body
        elif "constraint" in label or "limitation" in label:
            out["constraints"] = body
        elif "attack flow" in label or "flow diagram" in label:
            out["attack_flow_diagram"] = body
    return out


def _iter_section_blocks(soup: BeautifulSoup) -> list[dict[str, str]]:
    """Every div.section in DOM order with original heading + full body (incl. mermaid)."""
    blocks: list[dict[str, str]] = []
    for block in soup.select("div.content div.section, .content div.section"):
        title_el = block.select_one(".section-title")
        if not title_el:
            continue
        heading = clean_text(title_el.get_text())
        body = _section_body_from_div(block)
        blocks.append({"heading": heading, "body": body})
    return blocks


def _extract_subtitle(soup: BeautifulSoup) -> str:
    """Parenthetical subtype next to the colored badge (e.g. Hallucinated Package/...)."""
    h1 = soup.find("h1")
    if not h1:
        return ""
    for sib in h1.next_siblings:
        if not isinstance(sib, Tag):
            continue
        if sib.name != "div":
            continue
        for span in sib.find_all("span"):
            t = clean_text(span.get_text())
            if len(t) >= 2 and t.startswith("(") and t.endswith(")"):
                return clean_text(t[1:-1])
        break
    return ""


def _extract_taxonomy(soup: BeautifulSoup) -> dict[str, str]:
    """
    Full grey callout: header line, Concept, Focus, and raw blob for training.
    """
    item = soup.select_one("div.content .taxonomy-item, .content .taxonomy-item")
    empty = {
        "header_line": "",
        "subtype": "",
        "concept": "",
        "focus": "",
        "raw": "",
    }
    if not item:
        return empty

    raw = clean_text(item.get_text("\n", strip=True))
    tag_el = item.select_one(".attack-tag")
    strong_el = item.select_one(".taxonomy-header strong")
    header_line = clean_text(
        " ".join(
            x
            for x in (
                tag_el.get_text() if tag_el else "",
                strong_el.get_text() if strong_el else "",
            )
            if x
        )
    )
    subtype = clean_text(strong_el.get_text()) if strong_el else ""

    concept = ""
    focus = ""
    for p in item.select(".taxonomy-content p"):
        line = clean_text(p.get_text())
        low = line.lower()
        if low.startswith("concept:"):
            concept = clean_text(line.split(":", 1)[1])
        elif low.startswith("focus:"):
            focus = clean_text(line.split(":", 1)[1])

    return {
        "header_line": header_line,
        "subtype": subtype,
        "concept": concept,
        "focus": focus,
        "raw": raw,
    }


def _heading_level(tag: Tag) -> int:
    name = tag.name.lower()
    if len(name) == 2 and name.startswith("h") and name[1].isdigit():
        return int(name[1])
    return 0


def _parse_heading_sections(soup: BeautifulSoup) -> dict[str, str]:
    """
    Fallback: walk h1–h6 in document order and slice content between headings.
    """
    out: dict[str, str] = {
        "description": "",
        "attack_vector": "",
        "goal": "",
        "context": "",
        "constraints": "",
        "attack_flow_diagram": "",
    }
    root = soup.body or soup
    headings: list[tuple[int, str, Tag]] = []
    for tag in root.find_all(re.compile(r"^h[1-6]$", re.I)):
        if not isinstance(tag, Tag):
            continue
        lvl = _heading_level(tag)
        if not lvl:
            continue
        label = _normalize_section_title(tag.get_text())
        headings.append((lvl, label, tag))

    def slice_after(heading_tag: Tag, level: int) -> str:
        chunks: list[str] = []
        for sib in heading_tag.next_siblings:
            if isinstance(sib, Tag):
                if sib.name and sib.name.lower().startswith("h"):
                    hl = _heading_level(sib)
                    if hl and hl <= level:
                        break
                chunks.append(sib.get_text("\n", strip=True))
            elif isinstance(sib, NavigableString):
                chunks.append(str(sib))
        return clean_text("\n".join(chunks))

    for level, label, el in headings:
        text = slice_after(el, level)
        if not text:
            continue
        if "description" in label:
            out["description"] = text
        elif "intended flow" in label:
            out["context"] = text
        elif "attack vector" in label:
            out["attack_vector"] = text
        elif "success condition" in label:
            out["goal"] = text
        elif label.startswith("goal") or label.split()[0:1] == ["goal"]:
            out["goal"] = text
        elif label.startswith("context"):
            out["context"] = text
        elif "constraint" in label or "limitation" in label:
            out["constraints"] = text
        elif "attack flow" in label or "flow diagram" in label:
            out["attack_flow_diagram"] = text
    return out


def _extract_name(soup: BeautifulSoup, url: str) -> str:
    title_tag = soup.find("title")
    if title_tag:
        raw = clean_text(title_tag.get_text())
        for suffix in (" - Scenario Browser", " – Scenario Browser"):
            if raw.endswith(suffix):
                raw = raw[: -len(suffix)].strip()
        if raw:
            return raw
    h1 = soup.find("h1")
    if h1:
        t = clean_text(h1.get_text())
        if t:
            return t
    slug = _scenario_slug(url)
    return slug.replace("_", " ").title() if slug else "unknown"


def _extract_category_tags(soup: BeautifulSoup) -> list[str]:
    """Pull taxonomy labels from badges and taxonomy headers."""
    tags: list[str] = []
    seen: set[str] = set()

    def add(tag: str) -> None:
        t = clean_text(tag)
        if not t:
            return
        key = t.lower()
        if key in seen:
            return
        seen.add(key)
        tags.append(t)

    for el in soup.select(".attack-tag"):
        add(el.get_text())

    for strong in soup.select(".taxonomy-header strong"):
        add(strong.get_text())

    return tags


def _build_comprehensive_raw_text(
    soup: BeautifulSoup,
    name: str,
    subtitle: str,
    taxonomy: dict[str, str],
    section_blocks: list[dict[str, str]],
) -> str:
    """
    Reassemble visible copy in reading order: nav, title, subtype, taxonomy callout,
    then every section heading + body (including mermaid source as text).
    """
    parts: list[str] = []
    bl = soup.select_one("a.back-link")
    if bl:
        parts.append(clean_text(bl.get_text()))
    parts.append(name)
    if subtitle:
        parts.append(f"({subtitle})")
    if taxonomy.get("raw"):
        parts.append(taxonomy["raw"])
    for blk in section_blocks:
        h = blk.get("heading", "")
        b = blk.get("body", "")
        block_txt = f"{h}\n{b}".strip() if b else h
        if block_txt:
            parts.append(block_txt)
    return clean_text("\n\n".join(p for p in parts if p))


def _merge_keyword_tags(tags: list[str], haystack: str) -> list[str]:
    """Append Keyword: … tags when substrings appear (case-insensitive)."""
    lower = haystack.lower()
    seen = {t.lower() for t in tags}
    for needle, label in _KEYWORD_TAG_PATTERNS:
        if needle not in lower:
            continue
        if label.lower() in seen:
            continue
        seen.add(label.lower())
        tags.append(label)
    return tags


def parse_scenario_page(html: str, url: str) -> dict[str, Any]:
    """
    Parse one scenario HTML document into the dataset row schema.

    Steps:
    1. Build soup and strip script/style for fallback full-text extraction.
    2. Extract subtitle, taxonomy callout, every section block, and mapped sections.
    3. Build raw_text in reading order so nav, badges, Concept/Focus, and mermaid all appear.
    4. Merge taxonomy tags and keyword-derived tags.
    5. Attach metadata (url + content length).
    """
    # Step 1 — soup for DOM structure (sections, taxonomy, subtitles).
    soup = BeautifulSoup(html, "html.parser")

    # Clone without executable nodes — used if the page has no div.section layout.
    soup_copy = BeautifulSoup(html, "html.parser")
    for bad in soup_copy(["script", "style", "noscript"]):
        bad.decompose()
    main = soup_copy.find("main") or soup_copy.find("div", class_="content")
    body = soup_copy.body
    raw_root = main or body or soup_copy
    raw_fallback = clean_text(raw_root.get_text("\n", strip=True))

    # Step 2 — structured fields (standard AgentBeats layout uses div.section).
    sections_map = _parse_div_sections(soup)
    if not any(sections_map.values()):
        sections_map = _parse_heading_sections(soup)

    section_blocks = _iter_section_blocks(soup)
    subtitle = _extract_subtitle(soup)
    taxonomy = _extract_taxonomy(soup)

    description = sections_map["description"]
    if not description:
        # Do not use Concept as Description; only fall back to first taxonomy paragraph
        # when there is no 📖 Description section (rare).
        p0 = soup.select_one(".taxonomy-content p")
        if p0:
            line = clean_text(p0.get_text("\n", strip=True))
            low = line.lower()
            if not low.startswith("concept:") and not low.startswith("focus:"):
                description = line

    name = _extract_name(soup, url)
    tags = _extract_category_tags(soup)

    # Step 3 — raw_text: deterministic join of every visible block when we have sections.
    if section_blocks:
        raw_text = _build_comprehensive_raw_text(
            soup, name, subtitle, taxonomy, section_blocks
        )
    else:
        raw_text = raw_fallback

    blocks_flat = " ".join(f'{b["heading"]} {b["body"]}' for b in section_blocks)
    haystack = " ".join(
        [
            name,
            subtitle,
            taxonomy.get("raw", ""),
            taxonomy.get("concept", ""),
            taxonomy.get("focus", ""),
            description,
            sections_map["attack_vector"],
            sections_map["goal"],
            sections_map["context"],
            sections_map["constraints"],
            sections_map.get("attack_flow_diagram", ""),
            blocks_flat,
            raw_text,
        ]
    )
    # Step 4 — keyword tags for mining.
    tags = _merge_keyword_tags(tags, haystack)

    row = {
        "name": name,
        "subtitle": subtitle,
        "url": url,
        "taxonomy": taxonomy,
        "description": description,
        "tags": tags,
        "sections": {
            "attack_vector": sections_map["attack_vector"],
            "goal": sections_map["goal"],
            "context": sections_map["context"],
            "constraints": sections_map["constraints"],
            "attack_flow_diagram": sections_map.get("attack_flow_diagram", ""),
        },
        "section_blocks": section_blocks,
        "raw_text": raw_text,
        "metadata": {
            "url": url,
            "content_length": len(raw_text),
        },
    }
    return row
