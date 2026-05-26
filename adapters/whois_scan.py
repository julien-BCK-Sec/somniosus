"""
whois — Domain registration metadata lookup.

Passive, low-noise. Returns registrar, creation/expiry dates, nameservers.
Raw output saved for reproducibility; parsed fields for reporting.
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Any, Dict, List
from urllib.parse import urlparse

from .runner import run_capture

TIMEOUT = 60


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


def _parse_whois(raw: str) -> Dict[str, Any]:
    """
    Parse common WHOIS fields. Defensive; output format varies by TLD.
    Returns registrar, creation_date, expiry_date, nameservers, statuses.
    """
    out: Dict[str, Any] = {
        "registrar": None,
        "creation_date": None,
        "expiry_date": None,
        "nameservers": [],
        "statuses": [],
    }

    # Common field patterns (case-insensitive, allow colon or no colon)
    patterns = {
        "registrar": re.compile(r"Registrar:\s*(.+)$", re.I | re.M),
        "creation_date": re.compile(r"Creation\s+Date:\s*(.+)$", re.I | re.M),
        "expiry_date": re.compile(r"(?:Registry\s+)?Expir(?:y|ation)\s+Date:\s*(.+)$", re.I | re.M),
        "updated_date": re.compile(r"Updated\s+Date:\s*(.+)$", re.I | re.M),
    }

    for key in ("registrar", "creation_date", "expiry_date"):
        m = patterns[key].search(raw)
        if m:
            out[key] = m.group(1).strip()

    # Name servers (multiple lines)
    ns_pat = re.compile(r"Name\s+Server:\s*(.+)$", re.I | re.M)
    for m in ns_pat.finditer(raw):
        ns = m.group(1).strip()
        if ns and ns not in out["nameservers"]:
            out["nameservers"].append(ns)

    # Domain status
    status_pat = re.compile(r"Domain\s+Status:\s*(.+?)(?:\s+https://|$)", re.I | re.M)
    for m in status_pat.finditer(raw):
        st = m.group(1).strip()
        if st and st not in out["statuses"]:
            out["statuses"].append(st)

    return out


def scan(target: str, raw_dir: Path) -> Dict[str, Any]:
    """
    Run whois on the target domain, save raw output, return structured result.

    Args:
        target: Domain to query (e.g. scanme.nmap.org)
        raw_dir: Directory for raw output

    Writes:
      - raw_dir/whois.txt (raw whois output)

    Returns:
      - target, raw_file, ok, exit_code, registrar, creation_date, expiry_date, nameservers
    """
    raw_dir.mkdir(parents=True, exist_ok=True)
    raw_path = raw_dir / "whois.txt"

    domain = _extract_domain(target)
    if not domain or "." not in domain:
        return {
            "target": target,
            "raw_file": str(raw_path),
            "ok": False,
            "exit_code": -1,
            "error": "invalid domain",
        }

    cmd = ["whois", domain]
    rc, stdout, stderr = run_capture(cmd, timeout=TIMEOUT)

    raw_path.write_text(stdout + (f"\n# stderr:\n{stderr}" if stderr else ""), encoding="utf-8")

    parsed = _parse_whois(stdout)

    return {
        "target": target,
        "raw_file": str(raw_path),
        "ok": rc == 0,
        "exit_code": rc,
        "registrar": parsed.get("registrar"),
        "creation_date": parsed.get("creation_date"),
        "expiry_date": parsed.get("expiry_date"),
        "nameservers": parsed.get("nameservers", []),
        "statuses": parsed.get("statuses", []),
    }


def scan_many(domains: List[str], raw_dir: Path, *, delay_seconds: float = 1.0) -> Dict[str, Any]:
    """
    Run whois on each domain. Saves raw per domain under raw_dir/whois_tldx/.
    Uses delay between requests to reduce rate-limit risk.

    Args:
        domains: List of domains to query
        raw_dir: Directory for raw output
        delay_seconds: Pause between whois calls

    Returns:
        - domains: list of {domain, ...whois fields}
        - ok: True if all succeeded
        - count: number of domains queried
    """
    import time

    raw_dir.mkdir(parents=True, exist_ok=True)
    tldx_raw = raw_dir / "whois_tldx"
    tldx_raw.mkdir(parents=True, exist_ok=True)

    results: List[Dict[str, Any]] = []
    all_ok = True

    for i, domain in enumerate(domains):
        if i > 0 and delay_seconds > 0:
            time.sleep(delay_seconds)
        domain = domain.strip().lower()
        if not domain or "." not in domain:
            continue
        domain_safe = domain.replace(".", "_")
        single_raw = tldx_raw / f"{domain_safe}.txt"

        cmd = ["whois", domain]
        rc, stdout, stderr = run_capture(cmd, timeout=TIMEOUT)
        single_raw.write_text(
            stdout + (f"\n# stderr:\n{stderr}" if stderr else ""), encoding="utf-8"
        )
        parsed = _parse_whois(stdout)
        results.append({
            "domain": domain,
            "raw_file": str(single_raw),
            "ok": rc == 0,
            "exit_code": rc,
            "registrar": parsed.get("registrar"),
            "creation_date": parsed.get("creation_date"),
            "expiry_date": parsed.get("expiry_date"),
            "nameservers": parsed.get("nameservers", []),
            "statuses": parsed.get("statuses", []),
        })
        if rc != 0:
            all_ok = False

    return {
        "domains": results,
        "ok": all_ok,
        "count": len(results),
        "raw_dir": str(tldx_raw),
    }
