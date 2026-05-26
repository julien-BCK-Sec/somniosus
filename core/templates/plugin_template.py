"""
Plugin template for Somniosus.
Copy to core/plugins/<tool>.py and replace:
  - TOOL / ToolPlugin -> <Tool>Tool (e.g. FeroxTool)
  - tool_scan -> <tool>_scan (e.g. ferox_scan)
  - TOOL_BINARY -> binary name (e.g. feroxbuster)
Plugin responsibility: orchestration, prerequisites, state integration.
Never call subprocess here — call the adapter only.
"""
from __future__ import annotations

from datetime import datetime

from core.helpers import tool_available
from core.io import write_json
from core.registry import Tool
from core.state import State, ToolResult
from core.paths import RunPaths
# REPLACE with your adapter: from adapters import ferox_scan
from adapters import subfinder_scan as _adapter  # placeholder — replace before use


class ToolPlugin(Tool):
    name = "TOOL"
    requires = set()  # e.g. {"nmap"} if needs port scan first
    provides = {"TOOL"}
    interactive_only = False  # True for noisy/intrusive tools

    def available(self) -> bool:
        return tool_available("TOOL_BINARY")

    def should_run(self, state: State, args) -> bool:
        # Gate by profile: safe vs thorough vs interactive
        if getattr(args, "profile", "safe") != "thorough":
            return False
        return True

    def run(self, state: State, paths: RunPaths, args) -> ToolResult:
        start = datetime.now().isoformat(timespec="seconds")

        if not self.available():
            return ToolResult(
                tool=self.name, ok=True, skipped=True,
                reason="TOOL_BINARY not available",
                started_at=start, ended_at=start,
            )
        if not self.should_run(state, args):
            return ToolResult(
                tool=self.name, ok=True, skipped=True,
                reason="skipped by profile or prerequisites",
                started_at=start, ended_at=start,
            )

        result = _adapter.scan(state.target, paths.raw)
        write_json(paths.base / "TOOL.json", result)

        end = datetime.now().isoformat(timespec="seconds")
        return ToolResult(
            tool=self.name,
            ok=result.get("returncode", 1) == 0,
            count=result.get("count"),
            data=result,
            started_at=start,
            ended_at=end,
        )
