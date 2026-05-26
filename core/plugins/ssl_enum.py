from __future__ import annotations

from datetime import datetime

from core.helpers import open_tcp_ports
from core.io import write_json
from core.registry import Tool
from core.state import State, ToolResult
from core.paths import RunPaths
from adapters import ssl_enum


class SslEnumTool(Tool):
    name = "ssl_enum"
    interactive_only = True
    requires = {"nmap"}
    provides = {"ssl_enum"}

    def should_run(self, state: State, args) -> bool:
        return bool(state.nmap) and (443 in open_tcp_ports(state.nmap))

    def run(self, state: State, paths: RunPaths, args) -> ToolResult:
        start = datetime.now().isoformat(timespec="seconds")

        if not self.should_run(state, args):
            return ToolResult(tool=self.name, ok=True, skipped=True, reason="443 not open", started_at=start, ended_at=start)

        out = ssl_enum.scan(state.target, paths.raw, port=443)
        write_json(paths.base / "ssl_enum.json", out)

        end = datetime.now().isoformat(timespec="seconds")
        return ToolResult(tool=self.name, ok=True, data=out, started_at=start, ended_at=end)
