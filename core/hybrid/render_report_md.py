# core/hybrid/render_report_md.py
from __future__ import annotations

from core.hybrid.report_model import ReportData


def render_report_md(report: ReportData) -> str:
    lines: list[str] = []

    lines.append("# AI-Pentest Report (Hybrid v1)")
    lines.append("")
    lines.append(f"**Target:** `{report.target}`")
    lines.append(f"**Run ID:** `{report.run_id}`")
    if report.generated_at:
        lines.append(f"**Generated:** {report.generated_at}")
    lines.append(f"**Profile:** `{report.profile}`")
    lines.append("")

    # Executive Summary (facts only)
    up_hosts = len([h for h in report.hosts if h.status == "up"])
    lines.append("## Executive Summary (Facts Only)")
    lines.append(f"- Hosts: {len(report.hosts)} (up: {up_hosts})")
    lines.append(f"- Services: {len(report.services)}")
    lines.append(f"- Web endpoints: {len(report.web)}")
    lines.append(f"- Subdomains: {len(report.subdomains)}")
    lines.append(f"- Tool-detected findings: {len(report.vulnerabilities)}")
    lines.append("")

    # Tool execution summary
    lines.append("## Tool Execution Summary (Facts)")
    if report.tool_meta:
        for name in sorted(report.tool_meta.keys()):
            meta = report.tool_meta[name]
            rc = meta.returncode
            status = "ok" if (rc is None or rc == 0) else f"exit={rc}"
            lines.append(f"- **{name}**: {status}")
    else:
        lines.append("- (No tool metadata recorded)")
    lines.append("")

    # Open Ports
    lines.append("## Open Ports")
    if report.services:
        lines.append("| Port | Proto | Service | Product |")
        lines.append("|---:|:---:|---|---|")
        for s in sorted(report.services, key=lambda x: (x.host, x.protocol, x.port)):
            lines.append(f"| {s.port} | {s.protocol} | {s.service or ''} | {s.product or ''} |")
    else:
        lines.append("_No open ports recorded._")
    lines.append("")

    # Subdomains
    lines.append("## Subdomains")
    if report.subdomains:
        for d in sorted(set(report.subdomains)):
            lines.append(f"- {d}")
    else:
        lines.append("_None found._")
    lines.append("")

    # DNS Records
    if report.dns_records:
        lines.append("## DNS Records")
        for rtype, values in sorted(report.dns_records.items()):
            if values:
                lines.append(f"**{rtype}:** " + ", ".join(str(v) for v in values[:20]))
        lines.append("")

    # Domain Registration (whois)
    if report.whois and any(report.whois.get(k) for k in ("registrar", "creation_date", "expiry_date", "nameservers")):
        lines.append("## Domain Registration (whois)")
        if report.whois.get("registrar"):
            lines.append(f"- **Registrar:** {report.whois['registrar']}")
        if report.whois.get("creation_date"):
            lines.append(f"- **Created:** {report.whois['creation_date']}")
        if report.whois.get("expiry_date"):
            lines.append(f"- **Expires:** {report.whois['expiry_date']}")
        ns = report.whois.get("nameservers") or []
        if ns:
            lines.append("**Nameservers:**")
            for n in ns[:10]:
                lines.append(f"- {n}")
        lines.append("")

    # TLD Enumeration (registered only — available domains omitted)
    if report.tldx_registered:
        lines.append("## TLD Enumeration (tldx)")
        lines.append(f"Found {len(report.tldx_registered)} registered TLD variations.")
        for r in report.tldx_registered:
            dom = r.get("domain", "")
            if dom:
                lines.append(f"- {dom}")
        lines.append("")

    # WHOIS on TLD Variations
    if report.whois_tldx:
        lines.append("## WHOIS on TLD Variations (whois_tldx)")
        for r in report.whois_tldx:
            dom = r.get("domain", "")
            if not dom:
                continue
            parts = [f"**{dom}**"]
            if r.get("registrar"):
                parts.append(f" — {r['registrar']}")
            if r.get("creation_date"):
                parts.append(f" (created: {r['creation_date']})")
            if r.get("expiry_date"):
                parts.append(f" (expires: {r['expiry_date']})")
            lines.append("- " + "".join(parts))
        lines.append("")

    # Typosquatting (dnstwist)
    if report.dnstwist:
        lines.append("## Typosquatting (dnstwist)")
        for r in report.dnstwist:
            dom = r.get("domain", "")
            fuzzer = r.get("fuzzer", "")
            line = f"- {dom}"
            if fuzzer:
                line += f" ({fuzzer})"
            if r.get("whois_registrar"):
                line += f" — registrar: {r['whois_registrar']}"
            if r.get("whois_created"):
                line += f" — created: {r['whois_created']}"
            lines.append(line)
        lines.append("")

    # HTTPX (Target)
    lines.append("## HTTPX (Target)")
    if report.web:
        for w in report.web[:30]:
            line = f"- {w.url}"
            if w.status_code is not None:
                line += f" (status {w.status_code})"
            if w.title:
                line += f" — {w.title}"
            lines.append(line)
    else:
        lines.append("_No httpx results._")
    lines.append("")

    # Findings
    lines.append("## Findings")
    if report.vulnerabilities:
        lines.append("| Source | Severity | Title |")
        lines.append("|---|---|---|")
        for v in report.vulnerabilities:
            lines.append(f"| {v.source or ''} | {v.severity} | {v.title} |")
    else:
        lines.append("_No findings recorded._")
    lines.append("")

    # Coverage
    lines.append("## Coverage & Limitations (Facts)")
    lines.append(f"- Tools run: {', '.join(report.coverage.tools_run) if report.coverage.tools_run else '(none recorded)'}")
    lines.append(f"- Tools skipped: {', '.join(report.coverage.tools_skipped) if report.coverage.tools_skipped else '(none recorded)'}")
    if report.coverage.limitations:
        lines.append("- Limitations:")
        for lim in report.coverage.limitations:
            lines.append(f"  - {lim}")
    lines.append("")

    # AI appendix placeholder (kept separate)
    lines.append("## Appendix A — AI Analysis & Suggested Next Steps")
    lines.append("_Not generated in this run (or stored separately)._")
    lines.append("")

    return "\n".join(lines)
