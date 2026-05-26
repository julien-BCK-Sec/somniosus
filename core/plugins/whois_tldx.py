"""
whois_tldx — WHOIS lookups on domains returned by tldx.

Category: active (WHOIS queries). Interactive-only.
Runs whois on each TLD variation from tldx (e.g. scanme.com, scanme.io).
Requires tldx to have run first.
"""
from __future__ import annotations

import json
from datetime import datetime
from typing import Any, Dict, List

from core.helpers import is_full_mode, looks_like_ip, tool_available
from core.io import write_json
from core.registry import Tool
from core.state import State, ToolResult
from core.paths import RunPaths
from adapters import whois_scan


def yes_no(prompt: str, default_no: bool = True) -> bool:
    suffix = " [y/N]: " if default_no else " [Y/n]: "
    ans = input(prompt + suffix).strip().lower()
    if ans == "":
        return not default_no
    return ans in ("y", "yes")


def _get_tldx_domains(state: State, paths: RunPaths) -> List[str]:
    """Extract registered domain list from tldx results (extras or file).
    Only domains tldx found as registered (available=false) are included.
    """
    def _registered(r: dict) -> bool:
        return isinstance(r, dict) and r.get("domain") and r.get("available") is False

    # From extras (if tldx ran this session)
    extras = state.container.get("extras", {})
    tldx_data = extras.get("tldx")
    if isinstance(tldx_data, dict):
        results = tldx_data.get("results", [])
        if isinstance(results, list):
            domains = [r.get("domain") for r in results if _registered(r)]
            if domains:
                return domains

    # From file (tldx.json in run dir; tldx outputs array or adapter may wrap)
    tldx_path = paths.base / "tldx.json"
    if tldx_path.exists():
        try:
            data = json.loads(tldx_path.read_text(encoding="utf-8"))
            results = data if isinstance(data, list) else (data.get("results", []) if isinstance(data, dict) else [])
            return [r.get("domain") for r in results if _registered(r)]
        except (json.JSONDecodeError, OSError):
            pass

    return []


class WhoisTldxTool(Tool):
    name = "whois_tldx"
    requires = {"tldx"}
    provides = {"whois_tldx"}
    interactive_only = True

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

        domains = _get_tldx_domains(state, paths)
        if not domains:
            return ToolResult(
                tool=self.name,
                ok=True,
                skipped=True,
                reason="no tldx results (run tldx first)",
                started_at=start,
                ended_at=start,
            )

        if not is_full_mode(args) and not yes_no(f"Run whois on {len(domains)} tldx domains? Proceed?"):
            return ToolResult(
                tool=self.name,
                ok=True,
                skipped=True,
                reason="user declined",
                started_at=start,
                ended_at=start,
            )

        result = whois_scan.scan_many(domains, paths.raw)
        write_json(paths.base / "whois_tldx.json", result)

        end = datetime.now().isoformat(timespec="seconds")

        return ToolResult(
            tool=self.name,
            ok=result.get("ok", False),
            count=result.get("count", 0),
            data=result,
            started_at=start,
            ended_at=end,
        )
