# core/reporting.py
from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Tuple

from core.helpers import dedupe_findings


def export_report_md(
    run_dir: Path,
    findings: Dict[str, Any],
    extras: Dict[str, Any] | None,
    llm_obj: Dict[str, Any] | None,
    tool_results: Dict[str, Any] | None = None,
    output_name: str = "report.md",
) -> Path:
    p = run_dir / output_name
    extras = extras or {}
    llm_obj = llm_obj or {}
    tool_results = tool_results or {}

    target = findings.get("target", "unknown")
    open_ports = findings.get("open_ports", [])
    all_findings = findings.get("findings", [])

    # --- helpers: robust extraction across changing shapes ---

    def _tr(name: str) -> Dict[str, Any]:
        obj = tool_results.get(name)
        if isinstance(obj, dict):
            return obj
        # If caller passed ToolResult objects, tolerate that:
        try:
            return obj.__dict__  # type: ignore[attr-defined]
        except Exception:
            return {}

    def _status(tr: Dict[str, Any]) -> str:
        if not tr:
            return "not recorded"
        if tr.get("skipped"):
            return "skipped"
        if tr.get("ok"):
            return "ran"
        return "failed"

    def _count(tr: Dict[str, Any]) -> str:
        c = tr.get("count")
        return "—" if c is None else str(c)

    def _reason(tr: Dict[str, Any]) -> str:
        r = tr.get("reason") or ""
        return r if r else "—"

    def _httpx_records() -> List[Dict[str, Any]]:
        hx = extras.get("httpx_main")
        if not isinstance(hx, dict):
            return []
        # Common shapes we’ve seen:
        # 1) adapter output: {"httpx":[...]}
        if isinstance(hx.get("httpx"), list):
            return [x for x in hx["httpx"] if isinstance(x, dict)]
        # 2) tool_results embedded inside extras (some setups put run meta here)
        data = hx.get("data")
        if isinstance(data, dict) and isinstance(data.get("httpx"), list):
            return [x for x in data["httpx"] if isinstance(x, dict)]
        # 3) older shapes
        if isinstance(hx.get("results"), list):
            # might be strings/urls
            out: List[Dict[str, Any]] = []
            for x in hx["results"]:
                if isinstance(x, dict):
                    out.append(x)
                elif isinstance(x, str):
                    out.append({"url": x})
            return out
        if isinstance(hx.get("urls"), list):
            out: List[Dict[str, Any]] = []
            for x in hx["urls"]:
                if isinstance(x, str):
                    out.append({"url": x})
            return out
        return []

    def _subdomains() -> List[str]:
        sf = extras.get("subfinder")
        if isinstance(sf, dict) and isinstance(sf.get("subdomains"), list):
            return [str(x) for x in sf["subdomains"] if x is not None]
        return []

    def ports_table() -> str:
        if not open_ports:
            return "_No open ports recorded._\n"
        rows = ["| Port | Proto | Service | Product |", "|---:|:---:|---|---|"]
        for x in open_ports:
            rows.append(
                f"| {x.get('port','')} | {x.get('protocol','')} | {x.get('service','')} | {x.get('product','')} |"
            )
        return "\n".join(rows) + "\n"

    def findings_table() -> str:
        if not all_findings:
            return "_No findings recorded._\n"
        deduped = dedupe_findings(all_findings)
        rows = ["| Source | Severity | Title | Evidence |", "|---|---|---|---|"]
        for f in deduped:
            if not isinstance(f, dict):
                continue
            sev = f.get("severity", "unknown")
            title = f.get("title", "")
            src = f.get("source", "")
            ev = ""
            if isinstance(f.get("evidence"), dict):
                ev = f["evidence"].get("matched_at") or f["evidence"].get("url") or ""
            ev = ev or f.get("matched_at", "")
            rows.append(f"| {src} | {sev} | {title} | {ev} |")
        return "\n".join(rows) + "\n"

    def tool_summary_table() -> str:
        if not tool_results:
            return "_No tool execution metadata recorded._\n"
        rows = ["| Tool | Status | Count | Notes |", "|---|---|---:|---|"]
        # keep deterministic ordering based on what ran/was requested; stable sort by tool name is fine
        for name in sorted(tool_results.keys()):
            tr = _tr(name)
            rows.append(f"| {name} | {_status(tr)} | {_count(tr)} | {_reason(tr)} |")
        return "\n".join(rows) + "\n"

    def tool_narrative_sections() -> str:
        """Short deterministic 'analyst notebook' style per-tool blurbs."""
        sections: List[str] = []
        now = datetime.now().isoformat(timespec="seconds")

        # nmap
        tr = _tr("nmap")
        sections.append("### nmap — Network Enumeration\n")
        if not tr:
            sections.append("_No execution record._\n")
        elif tr.get("skipped"):
            sections.append(f"_Skipped:_ {tr.get('reason','')}\n")
        else:
            port_count = tr.get("count")
            sections.append(f"- Open TCP/UDP services recorded: {port_count if port_count is not None else 'unknown'}\n")
            if open_ports:
                top = ", ".join(str(p.get("port")) for p in open_ports[:10] if isinstance(p, dict))
                if top:
                    sections.append(f"- Open ports: {top}\n")
            else:
                sections.append("- No open ports recorded in findings.\n")
        sections.append("")

        # httpx_main
        tr = _tr("httpx_main")
        sections.append("### httpx_main — Web Service Validation\n")
        if not tr:
            sections.append("_No execution record._\n")
        elif tr.get("skipped"):
            sections.append(f"_Skipped:_ {tr.get('reason','')}\n")
        else:
            hx = _httpx_records()
            sections.append(f"- Live URLs observed: {len(hx)}\n")
            if hx:
                # show first few as structured bullets
                for r in hx[:5]:
                    url = r.get("url") or r.get("input") or ""
                    status = r.get("status_code")
                    title = r.get("title")
                    server = r.get("webserver") or r.get("server")
                    bits = [b for b in [url, f"status={status}" if status is not None else "", f"title={title}" if title else "", f"server={server}" if server else ""] if b]
                    sections.append(f"- " + " | ".join(bits) + "\n")
            else:
                sections.append("- No httpx records were parsed.\n")
        sections.append("")

        # crtsh
        tr = _tr("crtsh")
        if tr:
            sections.append("### crtsh — Certificate Transparency (Passive)\n")
            if tr.get("skipped"):
                sections.append(f"_Skipped:_ {tr.get('reason','')}\n")
            else:
                c = tr.get("count")
                sections.append(f"- Subdomains from CT logs: {c if c is not None else 'unknown'}\n")
            sections.append("")

        # dns_enum
        tr = _tr("dns_enum")
        if tr:
            sections.append("### dns_enum — DNS Record Enumeration\n")
            if tr.get("skipped"):
                sections.append(f"_Skipped:_ {tr.get('reason','')}\n")
            else:
                data = tr.get("data")
                if isinstance(data, dict):
                    recs = data.get("records", {})
                    total = sum(len(v) for v in recs.values() if isinstance(v, list))
                    sections.append(f"- Records enumerated: {total}\n")
                    if data.get("axfr_success"):
                        sections.append("- AXFR zone transfer succeeded (see raw output)\n")
                else:
                    c = tr.get("count")
                    sections.append(f"- Records: {c if c is not None else 'unknown'}\n")
            sections.append("")

        # subfinder
        tr = _tr("subfinder")
        if tr:
            sections.append("### subfinder — Subdomain Enumeration\n")
            if tr.get("skipped"):
                sections.append(f"_Skipped:_ {tr.get('reason','')}\n")
            else:
                c = tr.get("count")
                sections.append(f"- Subdomains recorded (incl. crtsh merge): {c if c is not None else 'unknown'}\n")
            sections.append("")

        # katana
        tr = _tr("katana")
        sections.append("### katana — Crawling\n")
        if not tr:
            sections.append("_No execution record._\n")
        elif tr.get("skipped"):
            sections.append(f"_Skipped:_ {tr.get('reason','')}\n")
        else:
            c = tr.get("count")
            sections.append(f"- Discovered URLs recorded: {c if c is not None else 'unknown'}\n")
        sections.append("")

        # httpx_katana
        tr = _tr("httpx_katana")
        sections.append("### httpx_katana — Validation of Discovered URLs\n")
        if not tr:
            sections.append("_No execution record._\n")
        elif tr.get("skipped"):
            sections.append(f"_Skipped:_ {tr.get('reason','')}\n")
        else:
            c = tr.get("count")
            sections.append(f"- Validated URLs recorded: {c if c is not None else 'unknown'}\n")
        sections.append("")

        # ffuf
        tr = _tr("ffuf")
        if tr:
            sections.append("### ffuf — Content Discovery\n")
            if tr.get("skipped"):
                sections.append(f"_Skipped:_ {tr.get('reason','')}\n")
            else:
                sections.append(f"- Hits recorded: {_count(tr)}\n")
                # If your adapter stores a short list, surface it if present
                data = tr.get("data")
                if isinstance(data, dict):
                    runs = data.get("runs")
                    if isinstance(runs, list) and runs:
                        first = runs[0]
                        if isinstance(first, dict):
                            d = first.get("data")
                            if isinstance(d, dict) and isinstance(d.get("results"), list):
                                for r in d["results"][:10]:
                                    if isinstance(r, dict):
                                        sections.append(f"- {r.get('status')} {r.get('url')} (len={r.get('length')})\n")
            sections.append("")

        # whois (if present)
        tr = _tr("whois")
        if tr:
            sections.append("### whois — Domain Registration Metadata\n")
            if tr.get("skipped"):
                sections.append(f"_Skipped:_ {tr.get('reason','')}\n")
            else:
                data = tr.get("data")
                if isinstance(data, dict):
                    reg = data.get("registrar")
                    created = data.get("creation_date")
                    expiry = data.get("expiry_date")
                    ns = data.get("nameservers", [])
                    if reg:
                        sections.append(f"- Registrar: {reg}\n")
                    if created:
                        sections.append(f"- Creation: {created}\n")
                    if expiry:
                        sections.append(f"- Expiry: {expiry}\n")
                    if ns:
                        sections.append(f"- Nameservers: {len(ns)}\n")
                else:
                    c = tr.get("count")
                    sections.append(f"- Records: {c if c is not None else 'unknown'}\n")
            sections.append("")

        # tldx (if present)
        tr = _tr("tldx")
        if tr:
            sections.append("### tldx — TLD Enumeration\n")
            if tr.get("skipped"):
                sections.append(f"_Skipped:_ {tr.get('reason','')}\n")
            else:
                data = tr.get("data")
                if isinstance(data, dict):
                    reg = data.get("registered_count", 0)
                    avail = data.get("available_count", 0)
                    sections.append(f"- Found: {reg} registered, {avail} available\n")
                else:
                    c = tr.get("count")
                    sections.append(f"- Domains found: {c if c is not None else 'unknown'}\n")
            sections.append("")

        # whois_tldx (if present)
        tr = _tr("whois_tldx")
        if tr:
            sections.append("### whois_tldx — WHOIS on TLD Variations\n")
            if tr.get("skipped"):
                sections.append(f"_Skipped:_ {tr.get('reason','')}\n")
            else:
                data = tr.get("data")
                if isinstance(data, dict):
                    domains = data.get("domains", [])
                    sections.append(f"- Domains queried: {len(domains)}\n")
                    for d in domains[:10]:
                        if isinstance(d, dict):
                            dom = d.get("domain", "")
                            reg = d.get("registrar", "")
                            created = d.get("creation_date", "")
                            line = f"- {dom}"
                            if reg:
                                line += f" — {reg}"
                            if created:
                                line += f" (created: {created})"
                            sections.append(line + "\n")
                else:
                    c = tr.get("count")
                    sections.append(f"- Domains: {c if c is not None else 'unknown'}\n")
            sections.append("")

        # dnstwist (if present)
        tr = _tr("dnstwist")
        if tr:
            sections.append("### dnstwist — Domain Permutation / Typosquatting\n")
            if tr.get("skipped"):
                sections.append(f"_Skipped:_ {tr.get('reason','')}\n")
            else:
                c = tr.get("count")
                sections.append(f"- Registered permutations found: {c if c is not None else 'unknown'}\n")
                data = tr.get("data")
                if isinstance(data, dict):
                    reg = data.get("registered", [])
                    whois_enabled = data.get("whois", False)
                    if whois_enabled:
                        sections.append("- WHOIS lookups: enabled\n")
                    if isinstance(reg, list) and reg:
                        for r in reg[:5]:
                            if isinstance(r, dict):
                                dom = r.get("domain", "")
                                fuzzer = r.get("fuzzer", "")
                                line = f"- {dom} ({fuzzer})"
                                if r.get("whois_registrar"):
                                    line += f" — registrar: {r.get('whois_registrar')}"
                                if r.get("whois_created"):
                                    line += f" — created: {r.get('whois_created')}"
                                sections.append(line + "\n")
            sections.append("")

        # nuclei (if present)
        tr = _tr("nuclei")
        if tr:
            sections.append("### nuclei — Template Scan\n")
            if tr.get("skipped"):
                sections.append(f"_Skipped:_ {tr.get('reason','')}\n")
            else:
                sections.append(f"- Matches recorded: {_count(tr)}\n")
            sections.append("")

        return "".join(sections)

    # --- build report content ---

    content: List[str] = []
    content.append("# AI-Pentest Report\n")
    content.append(f"**Target:** `{target}`\n")
    content.append(f"**Run folder:** `{run_dir}`\n")
    content.append(f"**Generated:** `{datetime.now().isoformat(timespec='seconds')}`\n")

    # Deterministic executive summary (minimal, factual)
    content.append("## Executive Summary\n")
    content.append(f"- Open ports recorded: {len(open_ports)}\n")
    content.append(f"- Findings recorded: {len(dedupe_findings(all_findings))}\n")
    content.append(f"- Subdomains recorded: {len(_subdomains())}\n")
    content.append(f"- httpx_main records: {len(_httpx_records())}\n")

    # Tool run narrative
    content.append("\n## Tool Execution Summary\n")
    content.append(tool_summary_table())

    content.append("\n## Tool Notes\n")
    content.append(tool_narrative_sections())

    # Existing sections (kept)
    content.append("## Open Ports\n")
    content.append(ports_table())

    content.append("## Subdomains\n")
    subs = _subdomains()
    if subs:
        content.append("\n".join(f"- {d}" for d in subs) + "\n")
    else:
        content.append("_None found._\n")

    def _dns_records() -> Dict[str, List[str]]:
        de = extras.get("dns_enum")
        if not isinstance(de, dict) or de.get("skipped"):
            return {}
        return de.get("records", {}) or {}

    dns_recs = _dns_records()
    if dns_recs:
        content.append("## DNS Records\n")
        for rtype, values in sorted(dns_recs.items()):
            if isinstance(values, list) and values:
                content.append(f"**{rtype}:** " + ", ".join(str(v) for v in values[:20]) + "\n")
        content.append("")

    def _dnstwist_registered() -> List[Dict[str, Any]]:
        de = extras.get("dnstwist")
        if not isinstance(de, dict) or de.get("skipped"):
            return []
        return de.get("registered", []) or []

    def _tldx_results() -> List[Dict[str, Any]]:
        tx = extras.get("tldx")
        if not isinstance(tx, dict) or tx.get("skipped"):
            return []
        return tx.get("results", []) or []

    def _whois_data() -> Dict[str, Any]:
        wh = extras.get("whois")
        if not isinstance(wh, dict) or wh.get("skipped"):
            return {}
        return wh

    whois_data = _whois_data()
    if whois_data and not whois_data.get("skipped"):
        content.append("## Domain Registration (whois)\n")
        reg = whois_data.get("registrar")
        created = whois_data.get("creation_date")
        expiry = whois_data.get("expiry_date")
        ns = whois_data.get("nameservers", [])
        if reg:
            content.append(f"- **Registrar:** {reg}\n")
        if created:
            content.append(f"- **Created:** {created}\n")
        if expiry:
            content.append(f"- **Expires:** {expiry}\n")
        if ns:
            content.append("**Nameservers:**\n")
            for n in ns[:10]:
                content.append(f"- {n}\n")
        content.append("")

    tldx_res = _tldx_results()
    if tldx_res:
        content.append("## TLD Enumeration (tldx)\n")
        registered = [r for r in tldx_res if isinstance(r, dict) and not r.get("available", True)]
        available = [r for r in tldx_res if isinstance(r, dict) and r.get("available", False)]
        # Report only found results (registered + available)
        content.append(f"Found {len(registered)} registered, {len(available)} available.\n")
        if registered:
            content.append("**Registered (taken):**\n")
            for r in registered[:30]:
                content.append(f"- {r.get('domain', '')}\n")
            if len(registered) > 30:
                content.append(f"- _... and {len(registered) - 30} more_\n")
        if available:
            content.append("**Available:**\n")
            for r in available[:30]:
                content.append(f"- {r.get('domain', '')}\n")
            if len(available) > 30:
                content.append(f"- _... and {len(available) - 30} more_\n")
        content.append("")

    def _whois_tldx_results() -> List[Dict[str, Any]]:
        wt = extras.get("whois_tldx")
        if not isinstance(wt, dict) or wt.get("skipped"):
            return []
        return wt.get("domains", []) or []

    whois_tldx_res = _whois_tldx_results()
    if whois_tldx_res:
        content.append("## WHOIS on TLD Variations (whois_tldx)\n")
        for r in whois_tldx_res[:30]:
            if isinstance(r, dict) and r.get("domain"):
                dom = r.get("domain", "")
                reg = r.get("registrar", "")
                created = r.get("creation_date", "")
                expiry = r.get("expiry_date", "")
                line = f"- **{dom}**"
                if reg:
                    line += f" — {reg}"
                if created:
                    line += f" (created: {created})"
                if expiry:
                    line += f" (expires: {expiry})"
                content.append(line + "\n")
        content.append("")

    dnstwist_reg = _dnstwist_registered()
    if dnstwist_reg:
        content.append("## Typosquatting (dnstwist)\n")
        for r in dnstwist_reg[:30]:
            if isinstance(r, dict) and r.get("domain"):
                dom = r.get("domain", "")
                fuzzer = r.get("fuzzer", "")
                line = f"- {dom} ({fuzzer})"
                if r.get("whois_registrar"):
                    line += f" — registrar: {r.get('whois_registrar')}"
                if r.get("whois_created"):
                    line += f" — created: {r.get('whois_created')}"
                content.append(line + "\n")
        content.append("")

    content.append("## HTTPX (Target)\n")
    hx_records = _httpx_records()
    if hx_records:
        # show a compact readable list
        for r in hx_records[:20]:
            url = r.get("url") or r.get("input") or ""
            status = r.get("status_code")
            title = r.get("title")
            line = f"- {url}"
            if status is not None:
                line += f" (status {status})"
            if title:
                line += f" — {title}"
            content.append(line + "\n")
        content.append("")
    else:
        content.append("_No httpx results._\n")

    content.append("## Findings\n")
    content.append(findings_table())

    # Hybrid AI sections (analyst notes style)
    analyst_notes = llm_obj.get("analyst_notes") or llm_obj.get("notes")
    next_steps = llm_obj.get("next_steps") or llm_obj.get("priority_next_steps")

    if analyst_notes:
        content.append("\n## Analyst Notes (AI-assisted)\n")
        if isinstance(analyst_notes, list):
            content.append("\n".join(f"- {x}" for x in analyst_notes) + "\n")
        else:
            content.append(str(analyst_notes) + "\n")

    if next_steps:
        content.append("\n## Next Steps (AI-assisted)\n")
        # tolerate both list[str] and list[{title, why, commands}]
        if isinstance(next_steps, list) and next_steps and isinstance(next_steps[0], dict):
            for i, item in enumerate(next_steps, 1):
                title = item.get("title", "Next step")
                why = item.get("why", "")
                content.append(f"{i}. **{title}**\n")
                if why:
                    content.append(f"   - Why: {why}\n")
                cmds = item.get("commands")
                if isinstance(cmds, list) and cmds:
                    content.append("   - Commands:\n")
                    for c in cmds[:10]:
                        content.append(f"     - `{c}`\n")
        elif isinstance(next_steps, list):
            content.append("\n".join(f"{i}. {x}" for i, x in enumerate(next_steps, 1)) + "\n")
        else:
            content.append(str(next_steps) + "\n")

    # Coverage & limitations (deterministic)
    content.append("\n## Coverage & Limitations\n")
    content.append("- This report reflects automated enumeration only.\n")
    content.append("- No exploitation is attempted by default.\n")
    content.append("- Banner versions may not reflect patch levels; validate manually where relevant.\n")

    p.write_text("\n".join(content), encoding="utf-8")
    return p
