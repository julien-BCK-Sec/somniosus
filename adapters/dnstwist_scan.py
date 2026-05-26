"""
dnstwist — domain permutation engine for typosquatting / phishing detection.

Generates domain variations (typos, homoglyphs, etc.) and checks which are registered.
Noisy: many DNS lookups. Interactive-only.
"""
from __future__ import annotations

import json
from pathlib import Path
from urllib.parse import urlparse
from typing import Any, Dict, List

from .runner import run_capture

TIMEOUT = 600  # 10 min — can be slow for long domains


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


def scan(target: str, raw_dir: Path, *, whois: bool = False) -> Dict[str, Any]:
    """
    Run dnstwist with --registered --format json.
    Only registered (resolvable) domains are returned to limit output size.

    Args:
        target: Domain to permute
        raw_dir: Directory for raw output
        whois: If True, add --whois for WHOIS lookups (adds extra time)

    Writes:
      - raw_dir/dnstwist.json (raw dnstwist output)

    Returns:
      - target, domain, registered_count, registered (list of {domain, fuzzer, dns_a, ...})
    """
    raw_dir.mkdir(parents=True, exist_ok=True)
    raw_path = raw_dir / "dnstwist.json"

    domain = _extract_domain(target)
    if not domain or "." not in domain:
        return {
            "target": target,
            "domain": domain,
            "registered_count": 0,
            "registered": [],
            "raw_file": str(raw_path),
            "ok": False,
            "error": "invalid domain",
        }

    cmd = [
        "dnstwist",
        "--registered",
        "--format", "json",
        "--output", str(raw_path),
        domain,
    ]
    if whois:
        cmd.insert(-1, "--whois")

    rc, stdout, stderr = run_capture(cmd, timeout=TIMEOUT)

    if rc != 0:
        raw_path.write_text(json.dumps({"error": stderr[:2000], "stdout": stdout[:2000]}), encoding="utf-8")
        return {
            "target": target,
            "domain": domain,
            "registered_count": 0,
            "registered": [],
            "raw_file": str(raw_path),
            "ok": False,
            "exit_code": rc,
            "error": stderr[:500] or "dnstwist failed",
        }

    registered: List[Dict[str, Any]] = []
    if raw_path.exists():
        try:
            data = json.loads(raw_path.read_text(encoding="utf-8"))
            if isinstance(data, list):
                for item in data:
                    if isinstance(item, dict) and item.get("domain"):
                        rec = {
                            "domain": item.get("domain"),
                            "fuzzer": item.get("fuzzer", ""),
                            "dns_a": item.get("dns_a", [])[:5],
                            "dns_aaaa": item.get("dns_aaaa", [])[:5],
                            "dns_mx": item.get("dns_mx", [])[:3],
                        }
                        for k in ("registrar", "whois_registrar"):
                            if item.get(k):
                                rec["whois_registrar"] = item.get(k)
                                break
                        if item.get("creation_date"):
                            rec["whois_created"] = item.get("creation_date")
                        if item.get("expiration_date"):
                            rec["whois_expires"] = item.get("expiration_date")
                        registered.append(rec)
            elif isinstance(data, dict):
                items = data.get("registered", data.get("domains", data.get("results", [])))
                if isinstance(items, list):
                    for item in items:
                        if isinstance(item, dict) and item.get("domain"):
                            rec = {
                                "domain": item.get("domain"),
                                "fuzzer": item.get("fuzzer", ""),
                                "dns_a": (item.get("dns_a") or [])[:5],
                                "dns_aaaa": (item.get("dns_aaaa") or [])[:5],
                                "dns_mx": (item.get("dns_mx") or [])[:3],
                            }
                            for k in ("registrar", "whois_registrar"):
                                if item.get(k):
                                    rec["whois_registrar"] = item.get(k)
                                    break
                            if item.get("creation_date"):
                                rec["whois_created"] = item.get("creation_date")
                            if item.get("expiration_date"):
                                rec["whois_expires"] = item.get("expiration_date")
                            registered.append(rec)
        except (json.JSONDecodeError, OSError) as e:
            return {
                "target": target,
                "domain": domain,
                "registered_count": 0,
                "registered": [],
                "raw_file": str(raw_path),
                "ok": False,
                "error": f"parse error: {e}",
            }

    return {
        "target": target,
        "domain": domain,
        "registered_count": len(registered),
        "registered": registered,
        "raw_file": str(raw_path),
        "ok": True,
        "exit_code": rc,
        "whois": whois,
    }
