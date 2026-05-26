from __future__ import annotations

from datetime import datetime
from pathlib import Path

from adapters import ffuf_scan
from core import helpers
from core.helpers import is_full_mode, tool_available
from core.io import write_json
from core.paths import RunPaths
from core.registry import Tool
from core.state import State, ToolResult


def yes_no(prompt: str, default_no: bool = True) -> bool:
    suffix = " [y/N]: " if default_no else " [Y/n]: "
    ans = input(prompt + suffix).strip().lower()
    if ans == "":
        return not default_no
    return ans in ("y", "yes")


def _default_wordlist() -> Path | None:
    candidates = [
        # Your manual install
        Path("/opt/SecLists/Discovery/Web-Content/raft-medium-directories.txt"),

        # Kali / Parrot typical locations
        Path("/usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt"),
        Path("/usr/share/seclists/Discovery/Web-Content/common.txt"),

        # Ubuntu minimal fallback
        Path("/usr/share/wordlists/dirb/common.txt"),
    ]

    for p in candidates:
        if p.exists() and p.is_file():
            return p

    return None



class FfufTool(Tool):
    name = "ffuf"
    interactive_only = True
    requires = {"httpx_main"}  # we want at least baseline web visibility
    provides = {"ffuf"}

    def available(self) -> bool:
        return tool_available("ffuf")

    def run(self, state: State, paths: RunPaths, args) -> ToolResult:
        start = datetime.now().isoformat(timespec="seconds")

        if not self.available():
            return ToolResult(tool=self.name, ok=True, skipped=True, reason="ffuf not available", started_at=start, ended_at=start)

        # Always interactive (noisy)
        if not is_full_mode(args) and not yes_no("Run ffuf? This is noisy (many requests). Proceed?"):
            return ToolResult(tool=self.name, ok=True, skipped=True, reason="user declined", started_at=start, ended_at=start)

        # Pick targets: prefer validated URLs from katana->httpx_katana, else live roots from httpx_main
        web = helpers.ensure_web_bucket(state)
        validated = web.get("urls", {}).get("validated", []) or []
        live = web.get("live", []) or []

        base_targets = validated or live
        if not base_targets:
            return ToolResult(tool=self.name, ok=True, skipped=True, reason="no web targets", started_at=start, ended_at=start)

        wl = _default_wordlist()
        if wl is None:
            return ToolResult(tool=self.name, ok=True, skipped=True, reason="no default wordlist found", started_at=start, ended_at=start)

        # Run ffuf per base URL; aggregate results
        aggregated = {
            "ok": True,
            "tool": "ffuf",
            "wordlist": str(wl),
            "targets": base_targets,
            "runs": [],
            "count": 0,
        }

        total = 0
        for base in base_targets:
            r = ffuf_scan.scan(
                base_url=base,
                wordlist=wl,
                raw_dir=paths.raw,
                threads=20,
            )
            aggregated["runs"].append(r)
            total += int((r.get("data") or {}).get("count") or 0)

        aggregated["count"] = total

        write_json(paths.base / "ffuf.json", aggregated)
        state.container.setdefault("extras", {})["ffuf"] = aggregated

        end = datetime.now().isoformat(timespec="seconds")
        return ToolResult(tool=self.name, ok=True, count=total, data=aggregated, started_at=start, ended_at=end)
