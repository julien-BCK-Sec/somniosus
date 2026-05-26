"""
crt.sh certificate transparency subdomain discovery.

Passive, HTTP-based — no binary required. Queries crt.sh API for certificates
matching the target domain and extracts subdomains from name_value fields.
"""
from __future__ import annotations

import json
import time
import urllib.error
import urllib.request
from pathlib import Path
from urllib.parse import urlparse
from typing import Any, Dict, List, Set

CRTSH_URL = "https://crt.sh/?q=%25.{domain}&output=json"
TIMEOUT = 30
MAX_RETRIES = 2  # retry on 5xx; total attempts = 1 + MAX_RETRIES
RETRY_DELAY_S = 5


def _extract_domain(target: str) -> str:
    """Extract base domain from target (strip scheme, path, port)."""
    if "://" in target:
        parsed = urlparse(target)
        host = parsed.hostname or target
    else:
        host = target
    # Strip port if present
    if ":" in host:
        host = host.split(":")[0]
    return host.strip().lower()


def _is_subdomain_of(name: str, base_domain: str) -> bool:
    """True if name is the base domain or a subdomain of it."""
    name = name.strip().lower()
    if name.startswith("*."):
        name = name[2:]
    if name == base_domain:
        return True
    return name.endswith("." + base_domain)


def scan(target: str, raw_dir: Path) -> Dict[str, Any]:
    """
    Query crt.sh for certificates matching the target domain.
    Extract unique subdomains from name_value fields.

    Writes:
      - raw_dir/crtsh.json (raw API response)

    Returns:
      - target, subdomains, count, raw_file, ok, error (if any)
    """
    raw_dir.mkdir(parents=True, exist_ok=True)
    raw_path = raw_dir / "crtsh.json"

    domain = _extract_domain(target)
    if not domain or "." not in domain:
        return {
            "target": target,
            "domain": domain,
            "subdomains": [],
            "count": 0,
            "raw_file": str(raw_path),
            "ok": False,
            "error": "invalid domain",
        }

    url = CRTSH_URL.format(domain=domain)
    subdomains: Set[str] = set()
    last_error: Exception | None = None

    for attempt in range(1 + MAX_RETRIES):
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "Somniosus/1.0"})
            with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
                data = resp.read().decode("utf-8", errors="replace")
            last_error = None
            break
        except urllib.error.HTTPError as e:
            last_error = e
            if 500 <= e.code < 600 and attempt < MAX_RETRIES:
                time.sleep(RETRY_DELAY_S)
                continue
            raw_path.write_text(json.dumps({"error": str(e.code), "url": url}), encoding="utf-8")
            return {
                "target": target,
                "domain": domain,
                "subdomains": [],
                "count": 0,
                "raw_file": str(raw_path),
                "ok": False,
                "error": f"HTTP {e.code}",
            }
        except urllib.error.URLError as e:
            last_error = e
            if attempt < MAX_RETRIES:
                time.sleep(RETRY_DELAY_S)
                continue
            raw_path.write_text(json.dumps({"error": str(e.reason), "url": url}), encoding="utf-8")
            return {
                "target": target,
                "domain": domain,
                "subdomains": [],
                "count": 0,
                "raw_file": str(raw_path),
                "ok": False,
                "error": str(e.reason) or "connection failed",
            }
        except Exception as e:
            last_error = e
            if attempt < MAX_RETRIES:
                time.sleep(RETRY_DELAY_S)
                continue
            raw_path.write_text(json.dumps({"error": str(e), "url": url}), encoding="utf-8")
            return {
                "target": target,
                "domain": domain,
                "subdomains": [],
                "count": 0,
                "raw_file": str(raw_path),
                "ok": False,
                "error": str(e),
            }
    else:
        # All retries exhausted
        if isinstance(last_error, urllib.error.HTTPError):
            raw_path.write_text(json.dumps({"error": str(last_error.code), "url": url}), encoding="utf-8")
            return {
                "target": target,
                "domain": domain,
                "subdomains": [],
                "count": 0,
                "raw_file": str(raw_path),
                "ok": False,
                "error": f"HTTP {last_error.code} (after {1 + MAX_RETRIES} attempts)",
            }
        raise last_error  # type: ignore[misc]

    if last_error is not None:
        raise last_error  # type: ignore[misc]

    # Save raw response
    raw_path.write_text(data, encoding="utf-8")

    # Parse JSON and extract subdomains
    try:
        entries: List[Dict[str, Any]] = json.loads(data)
    except json.JSONDecodeError as e:
        return {
            "target": target,
            "domain": domain,
            "subdomains": [],
            "count": 0,
            "raw_file": str(raw_path),
            "ok": False,
            "error": f"JSON parse: {e}",
        }

    if not isinstance(entries, list):
        entries = [entries] if isinstance(entries, dict) else []

    for entry in entries:
        if not isinstance(entry, dict):
            continue
        name_value = entry.get("name_value") or entry.get("common_name") or ""
        for part in name_value.replace("\n", ",").split(","):
            name = part.strip().lower()
            if not name or name.startswith("*"):
                continue
            if name.startswith("*."):
                name = name[2:]
            if _is_subdomain_of(name, domain):
                subdomains.add(name)

    deduped: List[str] = sorted(subdomains)

    return {
        "target": target,
        "domain": domain,
        "subdomains": deduped,
        "count": len(deduped),
        "raw_file": str(raw_path),
        "ok": True,
    }
