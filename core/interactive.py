# core/interactive.py
from __future__ import annotations

import json
from dataclasses import asdict
from typing import Any, Dict, List, Tuple

from core import helpers
from core.io import write_json
from core.registry import execute_tools, write_tool_results
from core.reporting import export_report_md
from core.llm import analyze_with_llm
from core.hybrid.build_report_data import build_report_data
from core.hybrid.llm_input import build_llm_input
from core.hybrid.render_report_md import render_report_md
from core.hybrid.llm_appendix import render_llm_md
from core.hybrid.llm_guardrails import sanitize_llm_obj


# Menu options: (description, [tools], includes_vuln_scan)
SCAN_OPTIONS: List[Tuple[str, List[str], bool]] = [
    ("Baseline", ["nmap", "httpx_main", "crtsh", "subfinder", "dns_enum", "whois", "httpx_subdomains"], False),
    ("Baseline + Discovery", ["nmap", "httpx_main", "crtsh", "subfinder", "dns_enum", "whois", "httpx_subdomains", "dnssec", "ssl_enum", "dnstwist", "tldx", "whois_tldx", "whois"], False),
    ("Baseline + Discovery + Vuln Scan", ["nmap", "httpx_main", "crtsh", "subfinder", "dns_enum", "whois", "httpx_subdomains", "dnssec", "ssl_enum", "dnstwist", "tldx", "whois_tldx", "whois", "nuclei", "ffuf"], True),
    ("Full Attack Mode", ["nmap", "httpx_main", "crtsh", "subfinder", "dns_enum", "whois", "httpx_subdomains", "dnssec", "ssl_enum", "dnstwist", "tldx", "whois_tldx", "whois", "katana", "httpx_katana", "nuclei", "ffuf"], True),
]


def _yes_no(prompt: str, default_no: bool = True) -> bool:
    suffix = " [y/N]: " if default_no else " [Y/n]: "
    ans = input(prompt + suffix).strip().lower()
    if ans == "":
        return not default_no
    return ans in ("y", "yes")


def _subdomain_live_urls(paths) -> List[str]:
    """Extract live URLs from httpx_subdomains output (file or extras)."""
    urls: List[str] = []
    # Try file first
    p = paths.base / "httpx_subdomains.json"
    if p.exists():
        try:
            data = json.loads(p.read_text(encoding="utf-8"))
            records = data.get("httpx", []) if isinstance(data, dict) else []
            for r in records if isinstance(records, list) else []:
                if isinstance(r, dict) and r.get("url"):
                    urls.append(r["url"])
        except (json.JSONDecodeError, OSError):
            pass
    return urls


def run_interactive_loop(
    *,
    reg,
    state,
    paths,
    args,
) -> None:
    """
    Shows menu first. User picks a scan, it runs. After vuln scans, asks about subdomains.
    Typosquats/TLDs are discovery-only (never active-scanned).
    """
    if not args.interactive or args.quiet:
        return

    def refresh_ai_and_report(container: Dict[str, Any], run_ai: bool | None = None) -> None:
        tool_results_dict = {k: asdict(v) for k, v in state.tool_results.items()}
        tools_run = list(state.tool_results.keys())

        report_data = build_report_data(
            target=state.target,
            run_id=paths.base.name,
            profile=args.profile,
            findings=container.get("findings", {}),
            extras=container.get("extras", {}),
            tool_results=tool_results_dict,
            tools_run=tools_run,
            tools_skipped=[],
        )
        write_json(paths.base / "report_data.json", report_data.to_dict())
        (paths.base / "report.md").write_text(render_report_md(report_data), encoding="utf-8")

        llm_obj: Dict[str, Any] = {}
        do_ai = run_ai if run_ai is not None else (not args.no_ai)
        if do_ai:
            try:
                llm_input = build_llm_input(report_data)
                write_json(paths.base / "llm_input.json", llm_input)
                raw, llm_obj = analyze_with_llm(llm_input, args.url, args.model, args.temperature)
                (paths.base / "llm_raw.txt").write_text(raw, encoding="utf-8")
                write_json(paths.base / "llm_raw.json", llm_obj)
                llm_obj_s = sanitize_llm_obj(llm_obj)
                write_json(paths.base / "llm.json", llm_obj_s)
                (paths.base / "llm.md").write_text(render_llm_md(llm_obj_s), encoding="utf-8")
                container["llm"] = llm_obj_s
            except Exception as e:
                (paths.base / "llm_error.txt").write_text(str(e), encoding="utf-8")

        export_report_md(
            paths.base,
            container.get("findings", {}),
            container.get("extras", {}),
            container.get("llm", {}),
            tool_results=tool_results_dict,
            output_name="report_legacy.md",
        )
        print(f"Updated: {paths.base/'report.md'}")

    while True:
        print("\nWhat would you like to run?")
        for i, (desc, tools, _) in enumerate(SCAN_OPTIONS, 1):
            tools_str = ", ".join(tools)
            print(f"  {i}) {desc}")
            print(f"      → {tools_str}")
        print("  r) Re-run AI/report (if scan already done)")
        print("  q) Quit")

        choice = input("Choose: ").strip().lower()
        if choice == "q":
            break

        if choice == "r":
            if state.tool_results:
                run_ai = not args.no_ai and _yes_no("Run AI analysis?", default_no=False)
                refresh_ai_and_report(state.container, run_ai=run_ai)
            else:
                print("Run a scan first.")
            continue

        if choice.isdigit() and 1 <= int(choice) <= len(SCAN_OPTIONS):
            desc, tools, includes_vuln_scan = SCAN_OPTIONS[int(choice) - 1]

            # Ask before: subdomains (for vuln scans) and AI
            run_on_subdomains = includes_vuln_scan and _yes_no("Include subdomains in active scans (nuclei, ffuf)?")
            run_ai = not args.no_ai and _yes_no("Run AI analysis?", default_no=False)

            args.interactive_bundle = True
            execute_tools(reg, tools, state, paths, args)
            args.interactive_bundle = False
            write_tool_results(paths, state)
            refresh_ai_and_report(state.container, run_ai=run_ai)

            if run_on_subdomains:
                sub_urls = _subdomain_live_urls(paths)
                if sub_urls:
                    helpers.web_add_source(state, "httpx_subdomains", sub_urls, kind="live")
                    args.include_subdomains = True
                    execute_tools(reg, ["nuclei", "ffuf"], state, paths, args)
                    args.include_subdomains = False
                    write_tool_results(paths, state)
                    refresh_ai_and_report(state.container, run_ai=run_ai)
                    print("Subdomain scan complete.")
                else:
                    print("No live subdomains found (httpx_subdomains had no results).")
        else:
            print("Invalid.")
