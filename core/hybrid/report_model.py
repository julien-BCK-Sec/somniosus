# core/hybrid/report_model.py
from __future__ import annotations

from dataclasses import dataclass, field, asdict
from datetime import datetime
from typing import Any, Literal, Optional


Severity = Literal["info", "low", "medium", "high", "critical"]


@dataclass
class ToolMeta:
    name: str
    command: Optional[str] = None
    returncode: Optional[int] = None
    stdout_path: Optional[str] = None
    stderr_path: Optional[str] = None
    notes: list[str] = field(default_factory=list)


@dataclass
class Host:
    address: str
    status: Literal["up", "down", "unknown"] = "unknown"


@dataclass
class Service:
    host: str
    protocol: Literal["tcp", "udp"]
    port: int
    service: Optional[str] = None
    product: Optional[str] = None
    version: Optional[str] = None
    extrainfo: Optional[str] = None
    extra: dict[str, Any] = field(default_factory=dict)


@dataclass
class WebEndpoint:
    url: str
    host: str
    port: int
    scheme: str
    status_code: Optional[int] = None
    title: Optional[str] = None
    technologies: list[str] = field(default_factory=list)
    extra: dict[str, Any] = field(default_factory=dict)


@dataclass
class Vulnerability:
    finding_id: str
    title: str
    severity: Severity
    description: str = ""
    recommendation: str = ""
    systems_affected: list[str] = field(default_factory=list)
    evidence: list[str] = field(default_factory=list)
    cvss_vector: Optional[str] = None
    cvss_score: Optional[float] = None
    source: Optional[str] = None
    tags: list[str] = field(default_factory=list)


@dataclass
class Coverage:
    tools_run: list[str] = field(default_factory=list)
    tools_skipped: list[str] = field(default_factory=list)
    limitations: list[str] = field(default_factory=list)


@dataclass
class ReportData:
    target: str
    run_id: str
    generated_at: str
    profile: str

    hosts: list[Host] = field(default_factory=list)
    services: list[Service] = field(default_factory=list)
    web: list[WebEndpoint] = field(default_factory=list)
    vulnerabilities: list[Vulnerability] = field(default_factory=list)

    tool_meta: dict[str, ToolMeta] = field(default_factory=dict)
    coverage: Coverage = field(default_factory=Coverage)

    # Enumeration data (from extras)
    subdomains: list[str] = field(default_factory=list)
    dns_records: dict[str, list[str]] = field(default_factory=dict)  # rtype -> values
    whois: dict[str, Any] = field(default_factory=dict)  # registrar, creation_date, expiry_date, nameservers
    tldx_registered: list[dict[str, Any]] = field(default_factory=list)  # only registered (available=false)
    whois_tldx: list[dict[str, Any]] = field(default_factory=list)
    dnstwist: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def new_report_data(target: str, run_id: str, profile: str) -> ReportData:
    return ReportData(
        target=target,
        run_id=run_id,
        generated_at=datetime.now().isoformat(timespec="seconds"),
        profile=profile,
    )
