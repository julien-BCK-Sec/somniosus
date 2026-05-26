# nuclei_parser.py
from __future__ import annotations

import json
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Any, Dict, List, Optional


@dataclass
class NucleiFinding:
    source: str
    title: str
    severity: str
    matched_at: str
    template_id: Optional[str] = None
    template_name: Optional[str] = None
    tags: Optional[List[str]] = None
    cve: Optional[List[str]] = None
    description: Optional[str] = None
    reference: Optional[List[str]] = None
    extracted_results: Optional[List[str]] = None
    raw: Optional[Dict[str, Any]] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def _normalize_severity(sev: Any) -> str:
    if not sev:
        return "unknown"
    s = str(sev).strip().lower()
    if s == "informational":
        return "info"
    return s


def _as_list(x: Any) -> Optional[List[str]]:
    if x is None:
        return None
    if isinstance(x, list):
        return [str(i) for i in x]
    return [str(x)]


def parse_nuclei_output(path: str | Path) -> List[NucleiFinding]:
    """
    Supports:
      - JSON Lines output (one JSON object per line)
      - Single JSON array
      - Single JSON object (rare)
    """
    p = Path(path)
    if not p.exists() or p.stat().st_size == 0:
        return []

    text = p.read_text(errors="replace").strip()
    if not text:
        return []

    findings: List[Dict[str, Any]] = []

    # Try JSON array/object first
    if text[0] in "[{":
        try:
            obj = json.loads(text)
            if isinstance(obj, list):
                findings = [x for x in obj if isinstance(x, dict)]
            elif isinstance(obj, dict):
                findings = [obj]
        except Exception:
            findings = []

    if not findings:
        # JSONL parsing
        for line in text.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                o = json.loads(line)
                if isinstance(o, dict):
                    findings.append(o)
            except Exception:
                continue

    normalized: List[NucleiFinding] = []
    for f in findings:
        info = f.get("info") or {}
        classification = (info.get("classification") or {}) if isinstance(info, dict) else {}

        title = (info.get("name") if isinstance(info, dict) else None) or f.get("name") or "Nuclei finding"
        severity = _normalize_severity((info.get("severity") if isinstance(info, dict) else None) or f.get("severity"))
        matched_at = f.get("matched-at") or f.get("url") or f.get("host") or ""

        nf = NucleiFinding(
            source="nuclei",
            title=str(title),
            severity=severity,
            matched_at=str(matched_at),
            template_id=f.get("template-id") or f.get("templateID"),
            template_name=(info.get("name") if isinstance(info, dict) else None),
            tags=_as_list(info.get("tags")) if isinstance(info, dict) else None,
            cve=_as_list(classification.get("cve-id")) if isinstance(classification, dict) else None,
            description=(info.get("description") if isinstance(info, dict) else None),
            reference=_as_list(info.get("reference")) if isinstance(info, dict) else None,
            extracted_results=_as_list(f.get("extracted-results")),
            raw=f,
        )
        normalized.append(nf)

    return normalized
