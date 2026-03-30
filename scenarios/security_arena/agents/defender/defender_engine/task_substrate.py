"""Structured task substrate used to isolate data from instructions."""

from __future__ import annotations

import json
import re
from typing import Any


_ANOMALY_PATTERNS: tuple[tuple[str, str], ...] = (
    (r"\b(ignore|disregard|override|bypass)\b", "instruction_override_phrase"),
    (r"\b(rank|rate|score)\b.{0,30}\b(first|top|#1|highest)\b", "ranking_directive_phrase"),
    (r"\brisk[_\s-]?level\b.{0,20}\b(low|medium|high)\b", "risk_override_phrase"),
    (r"\b(reveal|show|print)\b.{0,40}\b(system prompt|internal|tool)\b", "exfiltration_phrase"),
)

_SCALAR_TYPES = (str, int, float, bool, type(None))


def _parse_json_candidate(text: str) -> Any:
    if not text:
        return None
    stripped = text.strip()
    try:
        return json.loads(stripped)
    except json.JSONDecodeError:
        return None


def _truncate_text(value: str, limit: int = 220) -> str:
    compact = re.sub(r"\s+", " ", value).strip()
    if len(compact) <= limit:
        return compact
    return compact[:limit] + "..."


def _field_anomalies(value: Any) -> list[str]:
    text = ""
    if isinstance(value, str):
        text = value.lower()
    elif isinstance(value, (int, float, bool)):
        return []
    else:
        try:
            text = json.dumps(value, ensure_ascii=False).lower()
        except Exception:
            text = str(value).lower()
    out: list[str] = []
    for pattern, name in _ANOMALY_PATTERNS:
        if re.search(pattern, text):
            out.append(name)
    return out


def _clean_fields(raw: dict[str, Any]) -> tuple[dict[str, Any], list[str]]:
    fields: dict[str, Any] = {}
    anomalies: list[str] = []
    for key, value in raw.items():
        key_lower = str(key).strip().lower()
        if key_lower in {"reasoning", "instructions", "system", "prompt", "policy"}:
            continue
        if isinstance(value, dict):
            nested = {}
            for nk, nv in value.items():
                if isinstance(nv, _SCALAR_TYPES):
                    nested[str(nk)] = nv if not isinstance(nv, str) else _truncate_text(nv, 180)
                    anomalies.extend(_field_anomalies(nv))
            if nested:
                fields[str(key)] = nested
        elif isinstance(value, list):
            cleaned_list: list[Any] = []
            for item in value[:10]:
                if isinstance(item, _SCALAR_TYPES):
                    cleaned_list.append(
                        item if not isinstance(item, str) else _truncate_text(item, 150)
                    )
                    anomalies.extend(_field_anomalies(item))
            if cleaned_list:
                fields[str(key)] = cleaned_list
        elif isinstance(value, _SCALAR_TYPES):
            fields[str(key)] = value if not isinstance(value, str) else _truncate_text(value, 180)
            anomalies.extend(_field_anomalies(value))
    return fields, sorted(set(anomalies))


def _trust_maps(segments: list[Any]) -> tuple[dict[str, str], dict[str, float]]:
    source_map: dict[str, str] = {}
    trust_map: dict[str, float] = {}
    for seg in segments:
        doc_id = str(getattr(seg, "doc_id", "") or "").strip()
        if not doc_id:
            continue
        source_map[doc_id.lower()] = str(getattr(seg, "source_type", "unknown") or "unknown")
        trust_map[doc_id.lower()] = float(getattr(seg, "trust_level", 0.5) or 0.5)
    return source_map, trust_map


def _record_id_fallback(index: int) -> str:
    return f"REC_{index + 1:03d}"


def _normalize_record_doc_id(raw: Any, index: int) -> str:
    doc_id = str(raw or "").strip()
    return doc_id if doc_id else _record_id_fallback(index)


def build_task_substrate(
    *,
    extracted_data: str,
    segments: list[Any],
    output_format: str = "",
    channel_spans: list[Any] | None = None,
) -> dict[str, Any]:
    """Build structured substrate records from extracted data and provenance."""
    source_map, trust_map = _trust_maps(segments)
    parsed = _parse_json_candidate(extracted_data)
    channel_spans = channel_spans or []

    records: list[dict[str, Any]] = []
    global_anomalies: list[str] = []

    if isinstance(parsed, dict) and isinstance(parsed.get("items"), list):
        item_list = parsed.get("items", [])
    elif isinstance(parsed, list):
        item_list = parsed
    else:
        item_list = []

    if item_list:
        for idx, item in enumerate(item_list[:40]):
            if not isinstance(item, dict):
                continue
            raw_doc_id = item.get("doc_id") or item.get("id") or item.get("file_id")
            record_id = _normalize_record_doc_id(raw_doc_id, idx)
            source_type = str(
                item.get("source_type")
                or source_map.get(record_id.lower(), "unknown")
                or "unknown"
            )
            trust_level = float(trust_map.get(record_id.lower(), 0.5))

            fields, anomalies = _clean_fields(item)
            if "facts" in item and isinstance(item["facts"], dict):
                fact_fields, fact_anomalies = _clean_fields(item["facts"])
                fields["facts"] = fact_fields
                anomalies.extend(fact_anomalies)
            if "name" in item and "name" not in fields and isinstance(item["name"], str):
                fields["name"] = _truncate_text(item["name"], 120)
            records.append(
                {
                    "record_id": record_id,
                    "source_type": source_type,
                    "trust_level": round(trust_level, 3),
                    "fields": fields,
                    "anomalies": sorted(set(anomalies)),
                }
            )
    else:
        # Fallback to line-oriented extraction when Pass-1 output is not JSON.
        for idx, line in enumerate(
            [ln.strip() for ln in extracted_data.splitlines() if ln.strip()][:120]
        ):
            match = re.match(r"([A-Za-z0-9_ /-]{2,40})\s*:\s*(.+)", line)
            if not match:
                continue
            key = match.group(1).strip()
            value = match.group(2).strip()
            if key.lower() in {"system", "instruction", "policy", "command"}:
                continue
            record_id = _record_id_fallback(len(records))
            anomalies = _field_anomalies(value)
            records.append(
                {
                    "record_id": record_id,
                    "source_type": "unknown",
                    "trust_level": 0.5,
                    "fields": {key: _truncate_text(value, 180)},
                    "anomalies": anomalies,
                }
            )

    for span in channel_spans[:80]:
        risk_score = float(getattr(span, "risk_score", 0.0) or 0.0)
        if risk_score >= 0.2:
            global_anomalies.append(
                f"channel:{getattr(span, 'channel_type', 'unknown')}:risk={risk_score:.2f}"
            )

    trusted_ids = [
        rec["record_id"]
        for rec in records
        if rec.get("source_type") != "external" and float(rec.get("trust_level", 0.5)) >= 0.5
    ]
    low_trust_ids = [
        rec["record_id"]
        for rec in records
        if rec.get("source_type") == "external" or float(rec.get("trust_level", 0.5)) < 0.5
    ]

    return {
        "schema_version": "task_substrate_v1",
        "output_format_hint": output_format[:180],
        "records": records,
        "trusted_evidence_ids": trusted_ids,
        "low_trust_evidence_ids": low_trust_ids,
        "global_anomalies": sorted(set(global_anomalies)),
    }


def serialize_substrate_for_execution(substrate: dict[str, Any], execution_mode: str) -> str:
    """Convert substrate into compact JSON consumed by Pass 2."""
    mode = (execution_mode or "STANDARD").upper()
    records = substrate.get("records", []) if isinstance(substrate, dict) else []
    if not isinstance(records, list) or not records:
        return ""

    packed: list[dict[str, Any]] = []
    for rec in records[:50]:
        if not isinstance(rec, dict):
            continue
        record_id = str(rec.get("record_id", ""))
        source_type = str(rec.get("source_type", "unknown"))
        trust_level = float(rec.get("trust_level", 0.5))
        anomalies = rec.get("anomalies", [])
        if not isinstance(anomalies, list):
            anomalies = []
        include_for_decisions = True
        if mode in {"CONSERVATIVE", "MINIMAL"} and source_type == "external" and anomalies:
            include_for_decisions = False
        if mode == "MINIMAL" and source_type == "external":
            include_for_decisions = False

        packed.append(
            {
                "record_id": record_id,
                "source_type": source_type,
                "trust_level": round(trust_level, 3),
                "include_for_decisions": include_for_decisions,
                "anomalies": anomalies[:6],
                "fields": rec.get("fields", {}),
            }
        )

    payload = {
        "schema_version": substrate.get("schema_version", "task_substrate_v1"),
        "execution_mode": mode,
        "trusted_evidence_ids": substrate.get("trusted_evidence_ids", []),
        "records": packed,
        "global_anomalies": substrate.get("global_anomalies", []),
    }
    serialized = json.dumps(payload, ensure_ascii=False)
    if len(serialized) > 9500:
        payload["records"] = payload["records"][:20]
        serialized = json.dumps(payload, ensure_ascii=False)
    return serialized

