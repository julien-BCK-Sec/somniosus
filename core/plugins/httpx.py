from __future__ import annotations

from datetime import datetime

from core import helpers
from core.helpers import has_web_ports, httpx_probe_urls, httpx_subdomain_probe_urls, projectdiscovery_httpx_available
from core.io import write_json
from core.registry import Tool
from core.state import State, ToolResult
from core.paths import RunPaths
from adapters import httpx_scan



class HttpxMainTool(Tool):
    name = "httpx_main"
    requires = {"nmap"}
    provides = {"httpx_main"}

    def available(self) -> bool:
        return projectdiscovery_httpx_available()

    def should_run(self, state: State, args) -> bool:
        return bool(state.nmap) and has_web_ports(state.nmap)

    def run(self, state: State, paths: RunPaths, args) -> ToolResult:
        start = datetime.now().isoformat(timespec="seconds")

        if not self.available():
            return ToolResult(
                tool=self.name,
                ok=True,
                skipped=True,
                reason="ProjectDiscovery httpx not available (wrong binary or not installed)",
                started_at=start,
                ended_at=start,
            )
        if not self.should_run(state, args):
            return ToolResult(tool=self.name, ok=True, skipped=True, reason="no web ports found", started_at=start, ended_at=start)

        probe_urls = httpx_probe_urls(state.target, state.nmap)
        obj = httpx_scan.scan(state.target, paths.raw, inputs=probe_urls, label="httpx")
        write_json(paths.base / "httpx.json", obj)

        if obj.get("ok") is False and obj.get("returncode") == -1:
            end = datetime.now().isoformat(timespec="seconds")
            return ToolResult(
                tool=self.name,
                ok=False,
                skipped=False,
                reason=(obj.get("stderr") or "httpx failed")[:500],
                data=obj,
                started_at=start,
                ended_at=end,
            )

        # Extract live URLs from httpx records
        records = obj.get("httpx", []) or []
        live_urls = [r.get("url") for r in records if isinstance(r, dict) and r.get("url")]

        if not getattr(args, "include_subdomains", False):
            live_urls = helpers.filter_urls_by_scope(live_urls, state.target)

        helpers.web_add_source(state, "httpx_main", live_urls, kind="live")


        end = datetime.now().isoformat(timespec="seconds")
        return ToolResult(tool=self.name, ok=True, count=obj.get("count"), data=obj, started_at=start, ended_at=end)


class HttpxSubdomainsTool(Tool):
    name = "httpx_subdomains"
    requires = {"subdomains"}
    provides = {"httpx_subdomains"}

    def available(self) -> bool:
        return projectdiscovery_httpx_available()

    def should_run(self, state: State, args) -> bool:
        if not state.subfinder:
            return False
        subs = state.subfinder.get("subdomains", [])
        return isinstance(subs, list) and len(subs) > 0

    def run(self, state: State, paths: RunPaths, args) -> ToolResult:
        start = datetime.now().isoformat(timespec="seconds")

        if not self.available():
            return ToolResult(
                tool=self.name,
                ok=True,
                skipped=True,
                reason="ProjectDiscovery httpx not available (wrong binary or not installed)",
                started_at=start,
                ended_at=start,
            )
        if not self.should_run(state, args):
            reason = "no subdomains"
            return ToolResult(tool=self.name, ok=True, skipped=True, reason=reason, started_at=start, ended_at=start)

        subs = [str(x) for x in state.subfinder.get("subdomains", []) if x is not None]
        subs = subs[: max(0, args.max_subdomains)]

        probe_urls = httpx_subdomain_probe_urls(subs, state.nmap)
        obj = httpx_scan.scan(state.target, paths.raw, inputs=probe_urls, label="httpx_subdomains")
        write_json(paths.base / "httpx_subdomains.json", obj)

        end = datetime.now().isoformat(timespec="seconds")
        return ToolResult(tool=self.name, ok=True, count=obj.get("count"), data=obj, started_at=start, ended_at=end)
