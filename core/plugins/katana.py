from __future__ import annotations

from datetime import datetime

from core.helpers import tool_available
from core.io import write_json
from core.registry import Tool
from core.state import State, ToolResult
from core.paths import RunPaths
from core import helpers
from adapters import katana_scan


class KatanaTool(Tool):
    name = "katana"
    requires = {"httpx_main"}
    provides = {"katana"}

    def available(self) -> bool:
        return tool_available("katana")

    def should_run(self, state: State, args) -> bool:
        # Keep noise out of safe by default
        if getattr(args, "profile", "") != "thorough":
            return False

        web = helpers.ensure_web_bucket(state)
        return bool(web.get("live"))

    def run(self, state: State, paths: RunPaths, args) -> ToolResult:
        start = datetime.now().isoformat(timespec="seconds")

        if not self.available():
            return ToolResult(tool=self.name, ok=True, skipped=True, reason="katana not available", started_at=start, ended_at=start)

        web = helpers.ensure_web_bucket(state)
        roots = web.get("live", [])
        if not roots:
            return ToolResult(tool=self.name, ok=True, skipped=True, reason="no live web roots", started_at=start, ended_at=start)

        result = katana_scan.scan(
            roots,
            raw_dir=paths.raw,
        )

        # Persist full structured artifact
        write_json(paths.base / "katana.json", result)

        if not result.get("ok"):
            end_fail = datetime.now().isoformat(timespec="seconds")
            return ToolResult(tool=self.name, ok=False, error=result.get("error", "katana failed"), data=result, started_at=start, ended_at=end_fail)

        urls = (result.get("data") or {}).get("urls", []) or []
        if not getattr(args, "include_subdomains", False):
            urls = helpers.filter_urls_by_scope(urls, state.target)
        helpers.web_add_source(state, "katana", urls, kind="discovered")

        # Optional: keep a tool-specific shortcut extras key
        state.container.setdefault("extras", {})["katana"] = (result.get("data") or {})

        end = datetime.now().isoformat(timespec="seconds")
        return ToolResult(tool=self.name, ok=True, count=len(urls), data=result, started_at=start, ended_at=end)
