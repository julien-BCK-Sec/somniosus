"""
DNS enumeration via dig: A, AAAA, MX, TXT, NS, CNAME, SOA, and AXFR attempt.

Low-noise, uses standard DNS queries. Requires dig on PATH.
"""
from __future__ import annotations

from pathlib import Path
from urllib.parse import urlparse
from typing import Any, Dict, List

from .runner import run_capture

RECORD_TYPES = ["A", "AAAA", "MX", "TXT", "NS", "CNAME", "SOA"]
TIMEOUT = 15


def _extract_domain(target: str) -> str:
    """Extract domain from target (strip scheme, path, port)."""
    if "://" in target:
        parsed = urlparse(target)
        host = parsed.hostname or target
    else:
        host = target
    if ":" in host:
        host = host.split(":")[0]
    return host.strip().lower()


def _dig_query(domain: str, rtype: str, timeout: int = TIMEOUT) -> tuple[int, str, List[str]]:
    """Run dig +short for given record type. Returns (rc, raw, parsed_lines)."""
    cmd = ["dig", "+short", "+time=5", "+tries=2", domain, rtype]
    rc, stdout, stderr = run_capture(cmd, timeout=timeout)
    lines = [s.strip() for s in stdout.splitlines() if s.strip()]
    return rc, stdout, lines


def _dig_axfr(domain: str, ns: str, timeout: int = TIMEOUT) -> tuple[int, str]:
    """Attempt zone transfer. Returns (rc, raw_output)."""
    cmd = ["dig", "+short", "+time=5", "+tries=1", f"@{ns}", domain, "AXFR"]
    rc, stdout, stderr = run_capture(cmd, timeout=timeout)
    return rc, stdout


def scan(target: str, raw_dir: Path) -> Dict[str, Any]:
    """
    Enumerate DNS records for the target domain.
    Attempts AXFR if NS records are found.

    Writes:
      - raw_dir/dns_enum.txt (combined raw output)

    Returns:
      - target, domain, records (A, AAAA, MX, etc.), axfr_attempted, axfr_success
    """
    raw_dir.mkdir(parents=True, exist_ok=True)
    raw_path = raw_dir / "dns_enum.txt"

    domain = _extract_domain(target)
    if not domain or "." not in domain:
        return {
            "target": target,
            "domain": domain,
            "records": {},
            "axfr_attempted": False,
            "axfr_success": False,
            "raw_file": str(raw_path),
            "ok": False,
            "error": "invalid domain",
        }

    raw_parts: List[str] = []
    records: Dict[str, List[str]] = {}

    for rtype in RECORD_TYPES:
        rc, stdout, lines = _dig_query(domain, rtype)
        raw_parts.append(f"=== {domain} {rtype} ===\n{stdout}")
        if lines:
            records[rtype] = lines

    # Get NS for AXFR attempt
    ns_list: List[str] = []
    if "NS" in records:
        for line in records["NS"]:
            # NS format: "ns1.example.com." or "ns1.example.com"
            ns = line.rstrip(".")
            if ns and ns not in ns_list:
                ns_list.append(ns)

    axfr_attempted = False
    axfr_success = False
    axfr_records: List[str] = []

    if ns_list:
        axfr_attempted = True
        for ns in ns_list[:3]:  # Limit to 3 NS servers
            rc, stdout = _dig_axfr(domain, ns)
            raw_parts.append(f"=== AXFR @{ns} {domain} ===\n{stdout}")
            if rc == 0 and stdout.strip():
                lines = [s.strip() for s in stdout.splitlines() if s.strip()]
                if len(lines) > 1:  # AXFR success typically returns many records
                    axfr_success = True
                    axfr_records = lines[:100]  # Cap for JSON size
                break

    raw_path.write_text("\n".join(raw_parts), encoding="utf-8")

    result: Dict[str, Any] = {
        "target": target,
        "domain": domain,
        "records": records,
        "axfr_attempted": axfr_attempted,
        "axfr_success": axfr_success,
        "raw_file": str(raw_path),
        "ok": True,
    }
    if axfr_records:
        result["axfr_records"] = axfr_records

    return result
