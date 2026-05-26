"""
Parser template for Somniosus.
Use when adapter output needs structured parsing (e.g. JSONL, XML).
Place in core/ or adapters/ as appropriate. Keep parsing deterministic and defensive.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List


def parse_raw(text: str) -> List[Dict[str, Any]]:
    """
    Parse tool output defensively. Handle missing/malformed data.
    Returns list of structured dicts.
    """
    items: List[Dict[str, Any]] = []
    for line in text.strip().splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
            if isinstance(obj, dict):
                items.append(obj)
        except json.JSONDecodeError:
            continue
    return items


def parse_file(path: Path) -> List[Dict[str, Any]]:
    """
    Parse a file. Returns empty list if file missing or unreadable.
    """
    if not path.exists():
        return []
    try:
        return parse_raw(path.read_text(errors="replace"))
    except Exception:
        return []
