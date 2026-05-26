"""
tldx — TLD enumeration / domain availability research.

Category: active (RDAP lookups). Interactive-only.
Checks which TLD variations of a domain are registered vs available.
Complementary to dnstwist (typosquatting).
"""
from __future__ import annotations

from datetime import datetime

from core.helpers import is_full_mode, looks_like_ip, tool_available
from core.io import write_json
from core.registry import Tool
from core.state import State, ToolResult
from core.paths import RunPaths
from adapters import tldx_scan


def _parse_tlds(args):
    """Parse TLD list from args. Returns None for default, list for explicit, or 'preset:X' for preset."""
    preset = getattr(args, "tld_preset", None)
    tlds_str = getattr(args, "tlds", None)
    if preset:
        return ["__preset__", preset]  # adapter will use --tld-preset
    if tlds_str:
        return [t.strip() for t in tlds_str.split(",") if t.strip()]
    return None


def _tlds_hint(args) -> str:
    """Return a short hint about which TLDs will be checked."""
    preset = getattr(args, "tld_preset", None)
    tlds = getattr(args, "tlds", None)
    if preset:
        return f", preset: {preset}"
    if tlds:
        return f", TLDs: {tlds[:50]}{'...' if len(tlds) > 50 else ''}"
    return ", checks com/io/org/net/ai/dev/app/co"


def yes_no(prompt: str, default_no: bool = True) -> bool:
    suffix = " [y/N]: " if default_no else " [Y/n]: "
    ans = input(prompt + suffix).strip().lower()
    if ans == "":
        return not default_no
    return ans in ("y", "yes")


class TldxTool(Tool):
    name = "tldx"
    interactive_only = True
    provides = {"tldx"}

    def available(self) -> bool:
        return tool_available("tldx")

    def should_run(self, state: State, args) -> bool:
        return not looks_like_ip(state.target)

    def run(self, state: State, paths: RunPaths, args) -> ToolResult:
        start = datetime.now().isoformat(timespec="seconds")

        if not self.available():
            return ToolResult(
                tool=self.name,
                ok=True,
                skipped=True,
                reason="tldx not available",
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

        tlds_hint = _tlds_hint(args)
        if not is_full_mode(args) and not yes_no(f"Run tldx? (TLD enumeration via RDAP{tlds_hint}). Proceed?"):
            return ToolResult(
                tool=self.name,
                ok=True,
                skipped=True,
                reason="user declined",
                started_at=start,
                ended_at=start,
            )

        tlds = _parse_tlds(args)
        result = tldx_scan.scan(state.target, paths.raw, tlds=tlds)
        write_json(paths.base / "tldx.json", result)

        count = result.get("registered_count", 0) + result.get("available_count", 0)
        end = datetime.now().isoformat(timespec="seconds")

        return ToolResult(
            tool=self.name,
            ok=result.get("ok", False),
            count=count,
            data=result,
            started_at=start,
            ended_at=end,
        )
