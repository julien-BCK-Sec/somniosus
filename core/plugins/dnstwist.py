"""
dnstwist — domain permutation / typosquatting detection.

Category: active, noisy (many DNS lookups). Interactive-only.
Generates domain variations and checks which are registered.
"""
from __future__ import annotations

from datetime import datetime

from core.helpers import is_full_mode, looks_like_ip, tool_available
from core.io import write_json
from core.registry import Tool
from core.state import State, ToolResult
from core.paths import RunPaths
from adapters import dnstwist_scan


def yes_no(prompt: str, default_no: bool = True) -> bool:
    suffix = " [y/N]: " if default_no else " [Y/n]: "
    ans = input(prompt + suffix).strip().lower()
    if ans == "":
        return not default_no
    return ans in ("y", "yes")


class DnstwistTool(Tool):
    name = "dnstwist"
    interactive_only = True
    provides = {"dnstwist"}

    def available(self) -> bool:
        return tool_available("dnstwist")

    def should_run(self, state: State, args) -> bool:
        return not looks_like_ip(state.target)

    def run(self, state: State, paths: RunPaths, args) -> ToolResult:
        start = datetime.now().isoformat(timespec="seconds")

        if not self.available():
            return ToolResult(
                tool=self.name,
                ok=True,
                skipped=True,
                reason="dnstwist not available",
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

        if not is_full_mode(args) and not yes_no("Run dnstwist? (many DNS lookups, can take several minutes). Proceed?"):
            return ToolResult(
                tool=self.name,
                ok=True,
                skipped=True,
                reason="user declined",
                started_at=start,
                ended_at=start,
            )

        whois = is_full_mode(args) or yes_no("Include WHOIS lookups for registered domains? (adds extra time)", default_no=True)

        result = dnstwist_scan.scan(state.target, paths.raw, whois=whois)
        write_json(paths.base / "dnstwist.json", result)

        count = result.get("registered_count", 0)
        end = datetime.now().isoformat(timespec="seconds")

        return ToolResult(
            tool=self.name,
            ok=result.get("ok", False),
            count=count,
            data=result,
            started_at=start,
            ended_at=end,
        )
