"""
crt.sh — passive subdomain discovery via certificate transparency logs.

Category: passive / low-noise (safe for `safe` profile).
No binary required; uses HTTP API.
"""
from __future__ import annotations

from datetime import datetime

from core.helpers import looks_like_ip
from core.io import write_json
from core.registry import Tool
from core.state import State, ToolResult
from core.paths import RunPaths
from adapters import crtsh_scan


class CrtshTool(Tool):
    name = "crtsh"
    provides = {"crtsh"}

    def available(self) -> bool:
        # HTTP-based; no binary required
        return True

    def should_run(self, state: State, args) -> bool:
        return not looks_like_ip(state.target)

    def run(self, state: State, paths: RunPaths, args) -> ToolResult:
        start = datetime.now().isoformat(timespec="seconds")

        if not self.should_run(state, args):
            return ToolResult(
                tool=self.name,
                ok=True,
                skipped=True,
                reason="target looks like IP",
                started_at=start,
                ended_at=start,
            )

        result = crtsh_scan.scan(state.target, paths.raw)
        write_json(paths.base / "crtsh.json", result)

        count = result.get("count", 0)
        end = datetime.now().isoformat(timespec="seconds")

        return ToolResult(
            tool=self.name,
            ok=result.get("ok", False),
            count=count,
            data=result,
            started_at=start,
            ended_at=end,
        )
