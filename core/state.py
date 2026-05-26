# core/state.py
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class ToolResult:
    tool: str
    ok: bool
    skipped: bool = False
    reason: str = ""
    count: Optional[int] = None
    data: Dict[str, Any] = field(default_factory=dict)
    raw_files: List[str] = field(default_factory=list)
    started_at: str = ""
    ended_at: str = ""

    def to_extras(self) -> Dict[str, Any]:
        if self.skipped:
            return {"skipped": True, "reason": self.reason}
        out: Dict[str, Any] = {"skipped": False}
        if self.count is not None:
            out["count"] = self.count
        for k, v in (self.data or {}).items():
            if k in ("skipped", "reason", "count"):
                continue
            out[k] = v
        return out


@dataclass
class State:
    target: str
    container: Dict[str, Any]
    tool_results: Dict[str, ToolResult] = field(default_factory=dict)

    # convenience mirrors used by plugins
    nmap: Optional[Dict[str, Any]] = None
    subfinder: Optional[Dict[str, Any]] = None
