from __future__ import annotations

from datetime import datetime

from core.helpers import tool_available
from core.io import write_json
from core.registry import Tool
from core.state import State, ToolResult
from core.paths import RunPaths
from adapters import nmap_scan


class NmapTool(Tool):
    name = "nmap"
    provides = {"nmap"}

    def available(self) -> bool:
        return tool_available("nmap")

    def run(self, state: State, paths: RunPaths, args) -> ToolResult:
        start = datetime.now().isoformat(timespec="seconds")
        if not self.available():
            return ToolResult(tool=self.name, ok=False, skipped=True, reason="nmap not available", started_at=start, ended_at=start)

        nmap_obj = nmap_scan.scan(state.target, paths.raw)
        state.nmap = nmap_obj
        state.container["findings"] = nmap_obj
        write_json(paths.base / "findings.json", nmap_obj)

        end = datetime.now().isoformat(timespec="seconds")
        count = len(nmap_obj.get("open_ports", [])) if isinstance(nmap_obj.get("open_ports"), list) else None
        return ToolResult(tool=self.name, ok=True, count=count, started_at=start, ended_at=end)
