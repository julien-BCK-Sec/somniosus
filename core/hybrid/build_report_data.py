# core/hybrid/build_report_data.py
from __future__ import annotations

from dataclasses import asdict
from typing import Any, Dict, List
from urllib.parse import urlparse

from core.hybrid.report_model import (
    Coverage,
    Host,
    ReportData,
    Service,
    ToolMeta,
    WebEndpoint,
)


def _unique_services(services: list[Service]) -> list[Service]:
    seen = set()
    out: list[Service] = []
    for s in services:
        key = (s.host, s.protocol, s.port, s.service, s.product, s.version, s.extrainfo)
        if key in seen:
            continue
        seen.add(key)
        out.append(s)
    return out


def build_report_data(
    *,
    target: str,
    run_id: str,
    profile: str,
    findings: Dict[str, Any],
    extras: Dict[str, Any] | None = None,
    tool_results: Dict[str, Any] | None = None,
    tools_run: list[str] | None = None,
    tools_skipped: list[str] | None = None,
) -> ReportData:
    """
    Deterministic mapping:
      - hosts[] and open_ports[] from findings (your current format)
      - tool_meta from tool_results.json (if provided)
      - coverage from tools_run/tools_skipped
    """
    report = ReportData(
        target=target,
        run_id=run_id,
        generated_at=findings.get("generated_at") or "",  # optional; renderer will tolerate empty
        profile=profile,
    )
    if not report.generated_at:
        # keep it deterministic but allow missing; caller can override by writing generated_at elsewhere
        # (we keep this blank if not present; not a big deal)
        pass

    # Hosts
    for h in findings.get("hosts", []) or []:
        addr = h.get("address") or h.get("ip") or ""
        if not addr:
            continue
        report.hosts.append(Host(address=addr, status=h.get("status", "unknown")))

        # Prefer per-host ports when present
        for p in (h.get("open_ports") or []):
            report.services.append(
                Service(
                    host=addr,
                    protocol=p.get("protocol", "tcp"),
                    port=int(p.get("port")),
                    service=p.get("service"),
                    product=p.get("product"),
                    version=p.get("version"),
                    extrainfo=p.get("extrainfo"),
                    extra={k: v for k, v in p.items() if k not in {"protocol", "port", "service", "product", "version", "extrainfo"}},
                )
            )

    # Fallback: top-level open_ports (applies to target when host list not present)
    if not report.services and findings.get("open_ports"):
        for p in findings.get("open_ports", []) or []:
            report.services.append(
                Service(
                    host=target,
                    protocol=p.get("protocol", "tcp"),
                    port=int(p.get("port")),
                    service=p.get("service"),
                    product=p.get("product"),
                    version=p.get("version"),
                    extrainfo=p.get("extrainfo"),
                    extra={k: v for k, v in p.items() if k not in {"protocol", "port", "service", "product", "version", "extrainfo"}},
                )
            )

    report.services = _unique_services(report.services)

    # Tool meta (from tool_results.json)
    if tool_results:
        for tool_name, obj in tool_results.items():
            # you already do: {k: asdict(v) for k,v in state.tool_results.items()}
            report.tool_meta[tool_name] = ToolMeta(
                name=tool_name,
                command=obj.get("command") or obj.get("cmd"),
                returncode=obj.get("returncode") if obj.get("returncode") is not None else obj.get("exit_code"),
                stdout_path=obj.get("stdout_path"),
                stderr_path=obj.get("stderr_path"),
                notes=obj.get("notes") or [],
            )

    report.coverage = Coverage(
        tools_run=tools_run or [],
        tools_skipped=tools_skipped or [],
        limitations=[
            # keep this short and factual; you can add more deterministic limitations later
            "Results reflect tool output at scan time; no manual validation performed.",
        ],
    )

    # Populate from extras
    extras = extras or {}

    # Subdomains (subfinder + crtsh merge)
    sf = extras.get("subfinder")
    if isinstance(sf, dict) and isinstance(sf.get("subdomains"), list):
        report.subdomains = [str(s) for s in sf["subdomains"] if s is not None]

    # DNS records
    de = extras.get("dns_enum")
    if isinstance(de, dict) and not de.get("skipped"):
        recs = de.get("records") or {}
        if isinstance(recs, dict):
            report.dns_records = {k: list(v) for k, v in recs.items() if isinstance(v, list)}

    # WHOIS (main target)
    wh = extras.get("whois")
    if isinstance(wh, dict) and not wh.get("skipped"):
        report.whois = {
            "registrar": wh.get("registrar"),
            "creation_date": wh.get("creation_date"),
            "expiry_date": wh.get("expiry_date"),
            "nameservers": wh.get("nameservers") or [],
        }

    # tldx — only registered domains (available=false); skip available (adds bloat)
    tx = extras.get("tldx")
    if isinstance(tx, dict) and not tx.get("skipped"):
        results = tx.get("results") or []
        if isinstance(results, list):
            report.tldx_registered = [
                {"domain": r.get("domain")}
                for r in results
                if isinstance(r, dict) and r.get("domain") and r.get("available") is False
            ]

    # whois_tldx
    wt = extras.get("whois_tldx")
    if isinstance(wt, dict) and not wt.get("skipped"):
        domains = wt.get("domains") or []
        if isinstance(domains, list):
            report.whois_tldx = [
                {
                    "domain": d.get("domain"),
                    "registrar": d.get("registrar"),
                    "creation_date": d.get("creation_date"),
                    "expiry_date": d.get("expiry_date"),
                }
                for d in domains
                if isinstance(d, dict) and d.get("domain")
            ]

    # dnstwist
    dn = extras.get("dnstwist")
    if isinstance(dn, dict) and not dn.get("skipped"):
        reg = dn.get("registered") or []
        if isinstance(reg, list):
            report.dnstwist = [
                {
                    "domain": r.get("domain"),
                    "fuzzer": r.get("fuzzer"),
                    "whois_registrar": r.get("whois_registrar"),
                    "whois_created": r.get("whois_created"),
                }
                for r in reg
                if isinstance(r, dict) and r.get("domain")
            ]

    # Web endpoints (httpx_main)
    hx = extras.get("httpx_main")
    if isinstance(hx, dict):
        records: List[Dict[str, Any]] = []
        if isinstance(hx.get("httpx"), list):
            records = [x for x in hx["httpx"] if isinstance(x, dict)]
        elif isinstance(hx.get("data"), dict) and isinstance(hx["data"].get("httpx"), list):
            records = [x for x in hx["data"]["httpx"] if isinstance(x, dict)]
        for r in records:
            url = r.get("url") or r.get("input") or ""
            if not url:
                continue
            try:
                parsed = urlparse(url)
                host = parsed.hostname or r.get("host") or ""
                port = int(parsed.port or r.get("port") or (443 if parsed.scheme == "https" else 80))
                scheme = parsed.scheme or "https"
            except (ValueError, TypeError):
                host = r.get("host", "")
                port = int(r.get("port") or 443)
                scheme = r.get("scheme", "https")
            report.web.append(
                WebEndpoint(
                    url=url,
                    host=host,
                    port=port,
                    scheme=scheme,
                    status_code=r.get("status_code"),
                    title=r.get("title"),
                    technologies=r.get("technologies", [])[:20] if isinstance(r.get("technologies"), list) else [],
                )
            )

    return report
