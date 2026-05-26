from __future__ import annotations

from datetime import datetime

from core.helpers import tool_available
from core.io import write_json
from core.registry import Tool
from core.state import State, ToolResult
from core.paths import RunPaths
from adapters import dnssec_check


class DnssecTool(Tool):
    name = "dnssec"
    interactive_only = True
    requires = {"nmap"}   # keeps ordering predictable
    provides = {"dnssec"}

    def available(self) -> bool:
        return tool_available("dig")

    def run(self, state: State, paths: RunPaths, args) -> ToolResult:
        start = datetime.now().isoformat(timespec="seconds")

        if not self.available():
            return ToolResult(tool=self.name, ok=True, skipped=True, reason="dig not available", started_at=start, ended_at=start)

        out = dnssec_check.scan(state.target, paths.raw)
        write_json(paths.base / "dnssec.json", out)

        end = datetime.now().isoformat(timespec="seconds")
        return ToolResult(tool=self.name, ok=True, data=out, started_at=start, ended_at=end)
