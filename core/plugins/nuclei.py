# core/plugins/nuclei.py
from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, List

from core import helpers
from core.helpers import is_full_mode, tool_available
from core.io import write_json
from core.registry import Tool
from core.state import State, ToolResult
from core.paths import RunPaths
from core.nuclei_parser import parse_nuclei_output
from adapters import nuclei_scan


def yes_no(prompt: str, default_no: bool = True) -> bool:
    suffix = " [y/N]: " if default_no else " [Y/n]: "
    ans = input(prompt + suffix).strip().lower()
    if ans == "":
        return not default_no
    return ans in ("y", "yes")


def merge_findings_list(findings_obj: dict, new_findings: List[Dict[str, Any]]) -> dict:
    if "findings" not in findings_obj or not isinstance(findings_obj.get("findings"), list):
        findings_obj["findings"] = []

    existing = findings_obj["findings"]
    seen = set()
    for f in existing:
        if not isinstance(f, dict):
            continue
        ev = f.get("evidence", {}) if isinstance(f.get("evidence"), dict) else {}
        seen.add((f.get("source"), f.get("title"), ev.get("matched_at") or f.get("matched_at") or ""))

    for nf in new_findings:
        if not isinstance(nf, dict):
            continue
        ev = nf.get("evidence", {}) if isinstance(nf.get("evidence"), dict) else {}
        key = (nf.get("source"), nf.get("title"), ev.get("matched_at") or nf.get("matched_at") or "")
        if key in seen:
            continue
        existing.append(nf)
        seen.add(key)

    return findings_obj


def nuclei_to_structured_findings(nuclei_jsonl_path: str) -> List[Dict[str, Any]]:
    parsed = parse_nuclei_output(nuclei_jsonl_path)
    out: List[Dict[str, Any]] = []
    for nf in parsed:
        out.append(
            {
                "source": "nuclei",
                "title": nf.title,
                "severity": nf.severity,
                "description": nf.description or "",
                "recommendation": (
                    "Validate the finding manually and adjust configuration or patch as appropriate. "
                    "Treat nuclei results as indicators; confirm impact and exposure."
                ),
                "matched_at": nf.matched_at,
                "evidence": {
                    "matched_at": nf.matched_at,
                    "template_id": nf.template_id,
                    "template_name": nf.template_name,
                    "tags": nf.tags,
                    "cve": nf.cve,
                    "reference": nf.reference,
                    "extracted_results": nf.extracted_results,
                    "raw": nf.raw,
                },
            }
        )
    return out


class NucleiTool(Tool):
    name = "nuclei"
    interactive_only = True
    requires = {"nmap"}  # keep as-is; we use web targets opportunistically
    provides = {"nuclei"}

    def available(self) -> bool:
        return tool_available("nuclei")

    def run(self, state: State, paths: RunPaths, args) -> ToolResult:
        start = datetime.now().isoformat(timespec="seconds")

        if not self.available():
            return ToolResult(
                tool=self.name,
                ok=True,
                skipped=True,
                reason="nuclei not available",
                started_at=start,
                ended_at=start,
            )

        if not is_full_mode(args) and not yes_no("Run nuclei? This can generate more traffic. Proceed?"):
            return ToolResult(
                tool=self.name,
                ok=True,
                skipped=True,
                reason="user declined",
                started_at=start,
                ended_at=start,
            )

        # Prefer validated URLs, then fall back to live roots.
        web = helpers.ensure_web_bucket(state)
        targets = (web.get("urls", {}).get("validated") or []) or (web.get("live") or [])

        # Strict adapter expects a list. If empty, skip cleanly.
        if not isinstance(targets, list) or len(targets) == 0:
            end = datetime.now().isoformat(timespec="seconds")
            return ToolResult(
                tool=self.name,
                ok=True,
                skipped=True,
                reason="no web targets available for nuclei",
                started_at=start,
                ended_at=end,
            )

        out = nuclei_scan.scan(
            inputs=targets,
            raw_dir=paths.raw,
            severity="low,medium,high,critical",
            concurrency=25,
            rate_limit=50,
            timeout=None,
        )
        write_json(paths.base / "nuclei.json", out)

        raw_file = out.get("raw_file") if isinstance(out, dict) else None
        if isinstance(raw_file, str) and raw_file:
            structured = nuclei_to_structured_findings(raw_file)
            if structured and isinstance(state.container.get("findings"), dict):
                state.container["findings"] = merge_findings_list(state.container["findings"], structured)
                write_json(paths.base / "findings.json", state.container["findings"])

        end = datetime.now().isoformat(timespec="seconds")
        return ToolResult(tool=self.name, ok=True, data=out, started_at=start, ended_at=end)
