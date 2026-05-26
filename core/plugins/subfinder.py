from __future__ import annotations

from datetime import datetime

from core.helpers import tool_available, looks_like_ip
from core.io import write_json
from core.registry import Tool
from core.state import State, ToolResult
from core.paths import RunPaths
from adapters import subfinder_scan


class SubfinderTool(Tool):
    name = "subfinder"
    provides = {"subdomains"}

    def available(self) -> bool:
        return tool_available("subfinder")

    def should_run(self, state: State, args) -> bool:
        return not looks_like_ip(state.target)

    def run(self, state: State, paths: RunPaths, args) -> ToolResult:
        start = datetime.now().isoformat(timespec="seconds")

        if not self.available():
            return ToolResult(tool=self.name, ok=True, skipped=True, reason="subfinder not available", started_at=start, ended_at=start)
        if not self.should_run(state, args):
            return ToolResult(tool=self.name, ok=True, skipped=True, reason="target looks like IP", started_at=start, ended_at=start)

        sf = subfinder_scan.scan(state.target, paths.raw)
        subs = list(sf.get("subdomains", []) or [])

        # Merge crt.sh subdomains (passive CT source) if available
        crtsh = state.container.get("extras", {}).get("crtsh", {})
        if isinstance(crtsh, dict) and not crtsh.get("skipped"):
            crtsh_subs = crtsh.get("subdomains", []) or []
            if isinstance(crtsh_subs, list):
                seen = {s for s in subs}
                for s in crtsh_subs:
                    if s and s not in seen:
                        seen.add(s)
                        subs.append(str(s))

        sf["subdomains"] = subs
        sf["count"] = len(subs)
        state.subfinder = sf
        write_json(paths.base / "subfinder.json", sf)

        end = datetime.now().isoformat(timespec="seconds")
        return ToolResult(tool=self.name, ok=True, count=len(subs), data=sf, started_at=start, ended_at=end)
