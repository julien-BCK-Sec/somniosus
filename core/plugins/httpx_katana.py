from __future__ import annotations

from datetime import datetime

from core.helpers import tool_available
from core.io import write_json
from core.registry import Tool
from core.state import State, ToolResult
from core.paths import RunPaths
from core import helpers
from adapters import httpx_scan


class HttpxKatanaTool(Tool):
    name = "httpx_katana"
    requires = {"katana"}
    provides = {"httpx_katana"}

    def available(self) -> bool:
        return tool_available("httpx")

    def should_run(self, state: State, args) -> bool:
        web = state.container.get("extras", {}).get("web", {})
        discovered = web.get("urls", {}).get("discovered", [])
        return bool(discovered)

    def run(self, state: State, paths: RunPaths, args) -> ToolResult:
        start = datetime.now().isoformat(timespec="seconds")

        if not self.available():
            return ToolResult(tool=self.name, ok=True, skipped=True, reason="httpx not available", started_at=start, ended_at=start)

        web = state.container.get("extras", {}).get("web", {})
        discovered = web.get("urls", {}).get("discovered", [])

        if not discovered:
            return ToolResult(tool=self.name, ok=True, skipped=True, reason="no katana urls", started_at=start, ended_at=start)

        obj = httpx_scan.scan(
            state.target,
            paths.raw,
            inputs=discovered,
            label="httpx_katana",
        )

        write_json(paths.base / "httpx_katana.json", obj)

        # Extract validated URLs
        records = obj.get("httpx", []) or []
        live_urls = [r.get("url") for r in records if isinstance(r, dict) and r.get("url")]

        if not getattr(args, "include_subdomains", False):
            live_urls = helpers.filter_urls_by_scope(live_urls, state.target)
        helpers.web_add_source(state, "httpx_katana", live_urls, kind="validated")

        end = datetime.now().isoformat(timespec="seconds")
        return ToolResult(tool=self.name, ok=True, count=obj.get("count"), data=obj, started_at=start, ended_at=end)
