"""
dns_enum — DNS record enumeration (A, AAAA, MX, TXT, NS, CNAME, SOA) and AXFR attempt.

Category: passive / low-noise (safe for `safe` profile).
Runs when port 53 is open and target is a domain.
"""
from __future__ import annotations

from datetime import datetime

from core.helpers import has_dns_port, looks_like_ip, tool_available
from core.io import write_json
from core.registry import Tool
from core.state import State, ToolResult
from core.paths import RunPaths
from adapters import dns_enum_scan


class DnsEnumTool(Tool):
    name = "dns_enum"
    requires = {"nmap"}
    provides = {"dns_enum"}

    def available(self) -> bool:
        return tool_available("dig")

    def should_run(self, state: State, args) -> bool:
        if looks_like_ip(state.target):
            return False
        return has_dns_port(state.nmap or {})

    def run(self, state: State, paths: RunPaths, args) -> ToolResult:
        start = datetime.now().isoformat(timespec="seconds")

        if not self.available():
            return ToolResult(
                tool=self.name,
                ok=True,
                skipped=True,
                reason="dig not available",
                started_at=start,
                ended_at=start,
            )
        if not self.should_run(state, args):
            return ToolResult(
                tool=self.name,
                ok=True,
                skipped=True,
                reason="port 53 not open or target is IP",
                started_at=start,
                ended_at=start,
            )

        result = dns_enum_scan.scan(state.target, paths.raw)
        write_json(paths.base / "dns_enum.json", result)

        record_count = sum(len(v) for v in result.get("records", {}).values() if isinstance(v, list))
        end = datetime.now().isoformat(timespec="seconds")

        return ToolResult(
            tool=self.name,
            ok=result.get("ok", False),
            count=record_count,
            data=result,
            started_at=start,
            ended_at=end,
        )
