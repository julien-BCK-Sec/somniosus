# core/helpers.py
from __future__ import annotations

import shutil
from urllib.parse import urlparse


def is_full_mode(args) -> bool:
    """True when --full, --full-quiet, or interactive bundle: no per-tool prompts."""
    return bool(getattr(args, "full", False)) or bool(getattr(args, "full_quiet", False)) or bool(getattr(args, "interactive_bundle", False))


def tool_available(tool: str) -> bool:
    return shutil.which(tool) is not None


def looks_like_ip(target: str) -> bool:
    if not target:
        return False
    parts = target.split(".")
    if len(parts) == 4 and all(p.isdigit() and 0 <= int(p) <= 255 for p in parts):
        return True
    return ":" in target  # crude ipv6 heuristic


def normalize_domain_target(target: str) -> str:
    if "://" in target:
        u = urlparse(target)
        return u.hostname or target
    return target


def open_tcp_ports(nmap_obj: dict) -> set[int]:
    ports: set[int] = set()
    for p in nmap_obj.get("open_ports", []):
        if p.get("protocol") == "tcp" and isinstance(p.get("port"), int):
            ports.add(p["port"])
    return ports


def has_web_ports(nmap_obj: dict) -> bool:
    web = {80, 443, 8000, 8080, 8443, 8888, 3000, 5000}
    return len(open_tcp_ports(nmap_obj) & web) > 0


def has_dns_port(nmap_obj: dict) -> bool:
    """True if TCP or UDP port 53 appears open (DNS)."""
    if not nmap_obj:
        return False
    for p in nmap_obj.get("open_ports", []) or []:
        if isinstance(p, dict) and p.get("port") == 53:
            return True
    return False

def check_tools() -> None:
    required = ["nmap"]
    optional = ["httpx", "dig", "subfinder", "nuclei", "katana", "ffuf", "dnstwist", "tldx", "whois"]


    print("\nTool check:")
    for t in required:
        print(f"  {'✓' if tool_available(t) else '✗'} {t} (required)")
    for t in optional:
        print(f"  {'✓' if tool_available(t) else '—'} {t} (optional)")
    print()

# --- Findings deduplication ---

from typing import Any, Dict, Iterable, List

SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}


def _evidence_key(f: Dict[str, Any]) -> str:
    """Extract stable evidence identifier for grouping."""
    ev = f.get("evidence")
    if isinstance(ev, dict):
        return str(ev.get("matched_at") or ev.get("url") or "")
    return str(f.get("matched_at") or "")


def dedupe_findings(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Group findings by (source, evidence). When multiple findings share the same
    target/evidence, keep one row with highest severity and a combined title.

    Does not modify findings.json; use at report-render time only.
    """
    if not findings:
        return []

    groups: Dict[tuple, List[Dict[str, Any]]] = {}
    for f in findings:
        if not isinstance(f, dict):
            continue
        src = f.get("source") or ""
        ev = _evidence_key(f)
        key = (src, ev)
        groups.setdefault(key, []).append(f)

    out: List[Dict[str, Any]] = []
    for (src, ev), group in groups.items():
        if len(group) == 1:
            out.append(group[0])
            continue
        # Pick representative: highest severity (critical > high > medium > low > info)
        best = max(
            group,
            key=lambda x: SEVERITY_ORDER.get((x.get("severity") or "").lower(), -1),
        )
        # Build combined title
        primary = best.get("title") or ""
        suffix = f" (+{len(group) - 1} related)"
        merged = {**best, "title": primary + suffix, "severity": best.get("severity", "unknown")}
        out.append(merged)

    return out


# --- Web asset propagation helpers (additive) ---


def _dedupe_preserve_order(items: Iterable[str]) -> List[str]:
    seen = set()
    out: List[str] = []
    for x in items:
        if not x or x in seen:
            continue
        seen.add(x)
        out.append(x)
    return out


def _host_from_url(url: str) -> str | None:
    """Extract hostname from URL (http(s)://host/path or bare host)."""
    if not url or not isinstance(url, str):
        return None
    s = url.strip()
    if "://" in s:
        try:
            parsed = urlparse(s)
            return (parsed.hostname or "").lower() or None
        except Exception:
            return None
    # Bare host
    return s.split("/", 1)[0].split(":", 1)[0].lower() or None


def is_host_in_scope(host: str | None, target: str) -> bool:
    """True if host equals target (normalized). Used when scope is restricted to CLI target (default)."""
    if not host or not target:
        return False
    return _host_from_url(host) == _host_from_url(target)


def filter_urls_by_scope(urls: List[str], target: str) -> List[str]:
    """Keep only URLs whose host equals target. Used when scope is restricted to CLI target (default)."""
    if not target:
        return []
    target_host = _host_from_url(target)
    if not target_host:
        return []
    out: List[str] = []
    for u in urls:
        if not u:
            continue
        h = _host_from_url(u)
        if h and h == target_host:
            out.append(u)
    return out


def ensure_web_bucket(state) -> dict:
    """
    Ensures canonical web bucket exists under:
      state.container["extras"]["web"]

    Shape:
      {
        "roots": [],
        "live": [],
        "sources": {},
        "urls": {"discovered": [], "validated": []}
      }
    """
    extras = state.container.setdefault("extras", {})
    web = extras.setdefault("web", {})
    web.setdefault("roots", [])
    web.setdefault("live", [])
    web.setdefault("sources", {})
    urls = web.setdefault("urls", {})
    urls.setdefault("discovered", [])
    urls.setdefault("validated", [])
    return web


def web_add_source(state, tool: str, urls: List[str], *, kind: str) -> None:
    """
    Adds URLs into canonical extras["web"] bucket + provenance.

    kind:
      - "roots"      -> web["roots"]
      - "live"       -> web["live"]
      - "discovered" -> web["urls"]["discovered"]
      - "validated"  -> web["urls"]["validated"]
    """
    web = ensure_web_bucket(state)

    # provenance
    existing_src = web["sources"].get(tool, [])
    web["sources"][tool] = _dedupe_preserve_order(existing_src + list(urls))

    # canonical buckets
    if kind in ("roots", "live"):
        web[kind] = _dedupe_preserve_order(list(web.get(kind, [])) + list(urls))
        return

    if kind in ("discovered", "validated"):
        web["urls"][kind] = _dedupe_preserve_order(list(web["urls"].get(kind, [])) + list(urls))
        return

    raise ValueError(f"unknown kind: {kind}")
