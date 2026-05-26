"""
whois — Domain registration metadata lookup.

Category: passive / low-noise. Safe for `safe` profile.
Returns registrar, creation/expiry dates, nameservers.
Skips IP targets.
"""
from __future__ import annotations

from datetime import datetime

from core.helpers import looks_like_ip, tool_available
from core.io import write_json
from core.registry import Tool
from core.state import State, ToolResult
from core.paths import RunPaths
from adapters import whois_scan


class WhoisTool(Tool):
    name = "whois"
    provides = {"whois"}
    interactive_only = False

    def available(self) -> bool:
        return tool_available("whois")

    def should_run(self, state: State, args) -> bool:
        return not looks_like_ip(state.target)

    def run(self, state: State, paths: RunPaths, args) -> ToolResult:
        start = datetime.now().isoformat(timespec="seconds")

        if not self.available():
            return ToolResult(
                tool=self.name,
                ok=True,
                skipped=True,
                reason="whois not available",
                started_at=start,
                ended_at=start,
            )
        if not self.should_run(state, args):
            return ToolResult(
                tool=self.name,
                ok=True,
                skipped=True,
                reason="target looks like IP",
                started_at=start,
                ended_at=start,
            )

        result = whois_scan.scan(state.target, paths.raw)
        write_json(paths.base / "whois.json", result)

        count = len(result.get("nameservers", [])) or (1 if result.get("ok") else 0)
        end = datetime.now().isoformat(timespec="seconds")

        return ToolResult(
            tool=self.name,
            ok=result.get("ok", False),
            count=count,
            data=result,
            started_at=start,
            ended_at=end,
        )
