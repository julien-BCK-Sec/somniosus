#!/usr/bin/env python3
from __future__ import annotations

import argparse
import os
from typing import Any, Dict

from core.helpers import normalize_domain_target, check_tools
from core.paths import make_run_paths
from core.state import State
from core.registry import execute_tools, write_tool_results
from core.reporting import export_report_md
from core.io import write_json
from core.plugins import build_registry
from core.llm import analyze_with_llm
from core.interactive import run_interactive_loop
from dataclasses import asdict
from core.hybrid.build_report_data import build_report_data
from core.hybrid.render_report_md import render_report_md
from core.hybrid.llm_input import build_llm_input
from core.hybrid.llm_appendix import render_llm_md
from core.hybrid.llm_guardrails import sanitize_llm_obj



DEFAULT_OLLAMA_URL = os.environ.get("OLLAMA_URL", "http://localhost:11434/v1/chat/completions")
DEFAULT_MODEL = "llama3.1"
DEFAULT_TEMPERATURE = 0.1

PROFILES = {
    "safe": ["nmap", "httpx_main", "crtsh", "subfinder", "dns_enum", "whois", "httpx_subdomains"],
    "thorough": ["nmap", "httpx_main", "crtsh", "subfinder", "dns_enum", "dnssec", "ssl_enum", "httpx_subdomains", "katana", "httpx_katana"],
}

# Full mode: thorough + all interactive tools, no prompts, tld-preset all, include-subdomains
FULL_TOOLS = [
    "nmap", "httpx_main", "crtsh", "subfinder", "dns_enum", "dnssec", "ssl_enum",
    "httpx_subdomains", "katana", "httpx_katana",
    "dnstwist", "tldx", "whois_tldx", "whois", "nuclei", "ffuf",
]

# Full-quiet: same as full but skip nuclei, ffuf, katana, httpx_katana (no heavy scanning)
FULL_QUIET_TOOLS = [
    "nmap", "httpx_main", "crtsh", "subfinder", "dns_enum", "dnssec", "ssl_enum",
    "httpx_subdomains",
    "dnstwist", "tldx", "whois_tldx", "whois",
]


SINGLE_TOOL_MAP = {
    "nmap": ["nmap"],
    "httpx": ["nmap", "httpx_main"],
    "crtsh": ["crtsh"],
    "subfinder": ["subfinder"],
    "httpx_subdomains": ["subfinder", "httpx_subdomains"],
    "dns_enum": ["nmap", "dns_enum"],
    "dnssec": ["nmap", "dnssec"],
    "ssl_enum": ["nmap", "ssl_enum"],
    "katana": ["nmap", "httpx_main", "katana"],
    "httpx_katana": ["nmap", "httpx_main", "katana", "httpx_katana"],
    "nuclei": ["nmap", "httpx_main", "nuclei"],
    "dnstwist": ["dnstwist"],
    "tldx": ["tldx"],
    "whois": ["whois"],
    "whois_tldx": ["tldx", "whois_tldx"],
    "ffuf": ["nmap", "httpx_main", "ffuf"],
}

def print_banner():
    banner = r"""
   ███████╗ ██████╗ ███╗   ███╗███╗   ██╗██╗ ██████╗ ███████╗██╗   ██╗███████╗
   ██╔════╝██╔═══██╗████╗ ████║████╗  ██║██║██╔═══██╗██╔════╝██║   ██║██╔════╝
   ███████╗██║   ██║██╔████╔██║██╔██╗ ██║██║██║   ██║███████╗██║   ██║███████╗
   ╚════██║██║   ██║██║╚██╔╝██║██║╚██╗██║██║██║   ██║╚════██║██║   ██║╚════██║
   ███████║╚██████╔╝██║ ╚═╝ ██║██║ ╚████║██║╚██████╔╝███████║╚██████╔╝███████║
   ╚══════╝ ╚═════╝ ╚═╝     ╚═╝╚═╝  ╚═══╝╚═╝ ╚═════╝ ╚══════╝ ╚═════╝ ╚══════╝

   Somniosus — Deep Enumeration Engine
   Deterministic Recon | Structured Findings | Constrained AI
"""
    print(banner)


def main() -> None:
    parser = argparse.ArgumentParser(description="AI-Pentest enum orchestrator (plugin-based).")

    parser.add_argument("target", nargs="?", help="Target domain or IP")
    parser.add_argument("-u", "--url", default=DEFAULT_OLLAMA_URL, help="Ollama API URL")
    parser.add_argument("-m", "--model", default=DEFAULT_MODEL, help="Ollama model name")
    parser.add_argument("-t", "--temperature", type=float, default=DEFAULT_TEMPERATURE, help="Model temperature")

    parser.add_argument("--no-ai", action="store_true", help="Skip AI; only run tools and save JSON.")
    parser.add_argument("--quiet", action="store_true", help="Don't print summary to stdout.")
    parser.add_argument("--check", action="store_true", help="Check tool dependencies and exit.")

    parser.add_argument(
        "--profile",
        choices=["safe", "thorough"],
        default="safe",
        help="safe = low-noise; thorough = same baseline but enables more interactive options.",
    )

    parser.add_argument("--timestamp", action="store_true", default=True)
    parser.add_argument("--no-timestamp", dest="timestamp", action="store_false")
    parser.add_argument("--no-latest-link", action="store_true")

    parser.add_argument(
        "--run",
        choices=["nmap", "httpx", "crtsh", "subfinder", "dns_enum", "httpx_subdomains", "dnssec", "dnstwist", "tldx", "whois", "whois_tldx", "ssl_enum", "katana", "httpx_katana", "nuclei", "ffuf"],
        help="Run a single tool (and its dependencies) then exit.",
    )
    parser.add_argument("--interactive", action="store_true")
    parser.add_argument(
        "--include-subdomains",
        action="store_true",
        help="Include subdomains in heavy scanning (nuclei, ffuf, katana). Default: httpx probes subdomains; nuclei/ffuf/katana stay on CLI target only.",
    )
    parser.add_argument(
        "--full",
        action="store_true",
        help="Run everything with no prompts: thorough profile, subdomains, all TLDs, nuclei, ffuf, dnstwist, etc. No interactive menu.",
    )
    parser.add_argument(
        "--full-quiet",
        action="store_true",
        help="Like --full but skip nuclei, ffuf, katana, httpx_katana. Discovery + tldx + dnstwist + whois only.",
    )
    parser.add_argument("--max-subdomains", type=int, default=50)
    parser.add_argument(
        "--tlds",
        type=str,
        default=None,
        help="Comma-separated TLDs for tldx (e.g. com,io,org,tech,info,biz,xyz). Default: com,io,org,net,ai,dev,app,co.",
    )
    parser.add_argument(
        "--tld-preset",
        type=str,
        default=None,
        help="tldx preset (tech, cheap, popular, etc.). Use 'tldx show-tld-presets' to list. Overrides --tlds if set.",
    )

    args = parser.parse_args()

    if args.check:
        check_tools()
        return

    if args.run and not args.target:
        parser.error("target required when using --run")
    if not args.target:
        parser.error("target required unless --check is used")

    if args.full or args.full_quiet:
        args.interactive = True  # allow interactive_only tools to run
        args.include_subdomains = True
        if not args.tld_preset:
            args.tld_preset = "all"

    target = normalize_domain_target(args.target)
    paths = make_run_paths(target, timestamp=args.timestamp, no_latest_link=args.no_latest_link)

    container: Dict[str, Any] = {"findings": {}, "extras": {}, "llm": {}}
    state = State(target=target, container=container)

    reg = build_registry()

    # Single tool mode
    if args.run:
        args.no_ai = True
        args.interactive = True  # allow interactive-only tools
        execute_tools(reg, SINGLE_TOOL_MAP[args.run], state, paths, args)
        write_tool_results(paths, state)
        return

    # Interactive: menu first, no tools run until user picks
    if args.interactive and not args.full and not args.full_quiet:
        run_interactive_loop(reg=reg, state=state, paths=paths, args=args)
        return

    # Non-interactive: baseline pipeline (or full tools when --full / --full-quiet)
    if args.full:
        profile_tools = list(FULL_TOOLS)
    elif args.full_quiet:
        profile_tools = list(FULL_QUIET_TOOLS)
    else:
        profile_tools = list(PROFILES[args.profile])
    execute_tools(reg, profile_tools, state, paths, args)
    write_tool_results(paths, state)

    # --- Build deterministic truth model + deterministic report ---
    tool_results_dict = {k: asdict(v) for k, v in state.tool_results.items()}

    report_data = build_report_data(
        target=target,
        run_id=paths.base.name,
        profile=args.profile,
        findings=container.get("findings", {}),
        extras=container.get("extras", {}),
        tool_results=tool_results_dict,
        tools_run=profile_tools,
        tools_skipped=[],
    )

    write_json(paths.base / "report_data.json", report_data.to_dict())
    (paths.base / "report.md").write_text(render_report_md(report_data), encoding="utf-8")

    # Legacy report exporter (kept during transition)
    export_report_md(
        paths.base,
        container.get("findings", {}),
        container.get("extras", {}),
        {},  # legacy AI sections not used here; keep deterministic
        tool_results=tool_results_dict,
        output_name="report_legacy.md",
    )

    # --- Constrained AI appendix (from sanitized truth model only) ---
    if not args.no_ai:
        llm_input = build_llm_input(report_data)
        write_json(paths.base / "llm_input.json", llm_input)

        try:
            raw, llm_obj = analyze_with_llm(llm_input, args.url, args.model, args.temperature)


            (paths.base / "llm_raw.txt").write_text(raw, encoding="utf-8")
            write_json(paths.base / "llm_raw.json", llm_obj)

            llm_obj_s = sanitize_llm_obj(llm_obj)
            write_json(paths.base / "llm.json", llm_obj_s)

            (paths.base / "llm.md").write_text(render_llm_md(llm_obj_s), encoding="utf-8")

        except Exception as e:
            # AI should never break deterministic reporting
            (paths.base / "llm_error.txt").write_text(str(e), encoding="utf-8")

    if not args.quiet:
        print(f"\nTarget: {target}")
        print(f"Saved: {paths.base/'findings.json'}")

        if (paths.base / "report.md").exists():
            print(f"Saved: {paths.base/'report.md'}")
        if (paths.base / "report_legacy.md").exists():
            print(f"Saved: {paths.base/'report_legacy.md'}")
        if (paths.base / "report_data.json").exists():
            print(f"Saved: {paths.base/'report_data.json'}")
        if (paths.base / "llm_input.json").exists():
            print(f"Saved: {paths.base/'llm_input.json'}")
        if (paths.base / "llm_raw.json").exists():
            print(f"Saved: {paths.base/'llm_raw.json'}")
        if (paths.base / "llm.json").exists():
            print(f"Saved: {paths.base/'llm.json'}")
        if (paths.base / "llm.md").exists():
            print(f"Saved: {paths.base/'llm.md'}")
        if (paths.base / "llm_error.txt").exists():
            print(f"Saved: {paths.base/'llm_error.txt'}")

        print("")


if __name__ == "__main__":
    print_banner()
    main()
