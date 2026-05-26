"""
tldx — TLD enumeration / domain availability research.

Checks which TLD variations of a domain are registered vs available (via RDAP).
Complementary to dnstwist (typosquatting). Interactive-only.
"""
from __future__ import annotations

import json
from pathlib import Path
from urllib.parse import urlparse
from typing import Any, Dict, List

from .runner import run_capture

# Common TLDs for security research
DEFAULT_TLDS = ["com", "io", "org", "net", "ai", "dev", "app", "co"]
TIMEOUT = 300  # 5 min


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


def _base_for_tld(target_domain: str) -> str:
    """Extract base keyword for tldx (remove TLD). e.g. scanme.nmap.org -> scanme.nmap"""
    parts = target_domain.split(".")
    if len(parts) <= 1:
        return target_domain
    return ".".join(parts[:-1])


def scan(target: str, raw_dir: Path, *, tlds: List[str] | None = None) -> Dict[str, Any]:
    """
    Run tldx to check TLD variations of the target domain.

    Args:
        target: Domain to check (e.g. scanme.nmap.org)
        raw_dir: Directory for raw output
        tlds: TLDs to check (default: com, io, org, net, ai, dev, app, co)

    Writes:
      - raw_dir/tldx.json (raw tldx output)

    Returns:
      - target, base, results (list of {domain, available}), registered_count, available_count
    """
    raw_dir.mkdir(parents=True, exist_ok=True)
    raw_path = raw_dir / "tldx.json"

    domain = _extract_domain(target)
    if not domain or "." not in domain:
        return {
            "target": target,
            "base": "",
            "results": [],
            "registered_count": 0,
            "available_count": 0,
            "raw_file": str(raw_path),
            "ok": False,
            "error": "invalid domain",
        }

    base = _base_for_tld(domain)

    # Support preset: tlds = ["__preset__", "tech"] -> --tld-preset tech
    if tlds and len(tlds) == 2 and tlds[0] == "__preset__":
        preset = tlds[1]
        cmd = [
            "tldx",
            base,
            "--tld-preset", preset,
            "-f", "json",
            "--no-color",
        ]
    else:
        tld_list = tlds if tlds else DEFAULT_TLDS
        tld_arg = ",".join(tld_list)
        cmd = [
            "tldx",
            base,
            "-t", tld_arg,
            "-f", "json",
            "--no-color",
        ]

    rc, stdout, stderr = run_capture(cmd, timeout=TIMEOUT)

    if rc != 0:
        raw_path.write_text(json.dumps({"error": stderr[:2000], "stdout": stdout[:2000]}), encoding="utf-8")
        return {
            "target": target,
            "base": base,
            "results": [],
            "registered_count": 0,
            "available_count": 0,
            "raw_file": str(raw_path),
            "ok": False,
            "exit_code": rc,
            "error": stderr[:500] or "tldx failed",
        }

    results: List[Dict[str, Any]] = []
    try:
        data = json.loads(stdout)
        if isinstance(data, list):
            for item in data:
                if isinstance(item, dict) and "domain" in item:
                    results.append({
                        "domain": item.get("domain", ""),
                        "available": item.get("available", False),
                    })
        elif isinstance(data, dict) and "domain" in data:
            results.append({
                "domain": data.get("domain", ""),
                "available": data.get("available", False),
            })
    except json.JSONDecodeError:
        raw_path.write_text(stdout, encoding="utf-8")
        return {
            "target": target,
            "base": base,
            "results": [],
            "registered_count": 0,
            "available_count": 0,
            "raw_file": str(raw_path),
            "ok": False,
            "error": "JSON parse failed",
        }

    raw_path.write_text(stdout, encoding="utf-8")

    registered = [r for r in results if not r.get("available", True)]
    available = [r for r in results if r.get("available", False)]

    return {
        "target": target,
        "base": base,
        "results": results,
        "registered_count": len(registered),
        "available_count": len(available),
        "raw_file": str(raw_path),
        "ok": True,
        "exit_code": rc,
    }
