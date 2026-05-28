# core/helpers.py
from __future__ import annotations

import shutil
import subprocess
from typing import Any, Dict, Iterable, List
from urllib.parse import urlparse

# TCP ports treated as web for httpx probing (aligned with has_web_ports).
WEB_TCP_PORTS = frozenset({80, 443, 8000, 8080, 8443, 8888, 3000, 5000})


def is_full_mode(args) -> bool:
    """True when --full, --full-quiet, or interactive bundle: no per-tool prompts."""
    return bool(getattr(args, "full", False)) or bool(getattr(args, "full_quiet", False)) or bool(getattr(args, "interactive_bundle", False))


def tool_available(tool: str) -> bool:
    return shutil.which(tool) is not None


def projectdiscovery_httpx_available() -> bool:
    """
    True when `httpx` on PATH is ProjectDiscovery's probe (not Python's httpx CLI).
    """
    path = shutil.which("httpx")
    if not path:
        return False
    try:
        proc = subprocess.run(
            [path, "-h"],
            capture_output=True,
            text=True,
            timeout=15,
            check=False,
        )
        help_text = f"{proc.stdout or ''}\n{proc.stderr or ''}"
        return "-json" in help_text and "-tech-detect" in help_text
    except (OSError, subprocess.TimeoutExpired):
        return False


def looks_like_ip(target: str) -> bool:
    if not target:
        return False
    parts = target.split(".")
    if len(parts) == 4 and all(p.isdigit() and 0 <= int(p) <= 255 for p in parts):
        return True
    return ":" in target  # crude ipv6 heuristic


def _explicit_port_from_target(target: str) -> int | None:
    s = (target or "").strip()
    if not s:
        return None
    if "://" in s:
        port = urlparse(s).port
        return port if port is not None else None
    if ":" in s and not looks_like_ip(s.split(":", 1)[0]):
        # host:port (not IPv6)
        _, port_str = s.rsplit(":", 1)
        if port_str.isdigit():
            return int(port_str)
    return None


def normalize_domain_target(target: str) -> str:
    """Hostname or host:port; strips URL scheme when present."""
    if "://" in target:
        u = urlparse(target)
        host = u.hostname or target
        if u.port is not None:
            return f"{host}:{u.port}"
        return host
    return target.strip()


def open_tcp_ports(nmap_obj: dict) -> set[int]:
    ports: set[int] = set()
    for p in nmap_obj.get("open_ports", []):
        if p.get("protocol") == "tcp" and isinstance(p.get("port"), int):
            ports.add(p["port"])
    return ports


def has_web_ports(nmap_obj: dict) -> bool:
    return len(open_tcp_ports(nmap_obj) & set(WEB_TCP_PORTS)) > 0


def httpx_probe_urls(target: str, nmap_obj: dict | None = None) -> List[str]:
    """
    Build http(s) URLs for ProjectDiscovery httpx from nmap web ports and/or
  explicit port in target (e.g. juice.local:3000 or http://host:3000/).
    """
    host = _host_from_url(target) or target.strip()
    if not host:
        return []

    explicit = _explicit_port_from_target(target)
    ports: set[int] = set()
    if nmap_obj:
        ports |= open_tcp_ports(nmap_obj) & set(WEB_TCP_PORTS)
    if explicit is not None:
        ports.add(explicit)
    if not ports:
        ports = {80, 443}

    urls: List[str] = []
    for port in sorted(ports):
        if port == 80:
            urls.append(f"http://{host}")
        elif port == 443:
            urls.append(f"https://{host}")
        else:
            urls.append(f"http://{host}:{port}")
            if port in (8443, 4443):
                urls.append(f"https://{host}:{port}")

    return _dedupe_preserve_order(urls)


def httpx_subdomain_probe_urls(subdomains: List[str], nmap_obj: dict | None = None) -> List[str]:
    """Probe URLs for discovered subdomains (uses same non-80/443 ports as nmap when only those are open)."""
    extra_ports = sorted(open_tcp_ports(nmap_obj or {}) & set(WEB_TCP_PORTS) - {80, 443})
    only_alt = bool(extra_ports) and not (open_tcp_ports(nmap_obj or {}) & {80, 443})

    out: List[str] = []
    for sub in subdomains:
        s = str(sub).strip()
        if not s:
            continue
        if only_alt:
            for p in extra_ports:
                out.append(f"http://{s}:{p}")
        else:
            out.append(f"http://{s}")
            out.append(f"https://{s}")
    return _dedupe_preserve_order(out)


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
    optional = ["dig", "subfinder", "nuclei", "katana", "ffuf", "dnstwist", "tldx", "whois"]

    print("\nTool check:")
    for t in required:
        print(f"  {'✓' if tool_available(t) else '✗'} {t} (required)")
    if projectdiscovery_httpx_available():
        print("  ✓ httpx (ProjectDiscovery)")
    elif tool_available("httpx"):
        print("  ✗ httpx (wrong binary — install github.com/projectdiscovery/httpx)")
    else:
        print("  — httpx (optional, not installed)")
    for t in optional:
        print(f"  {'✓' if tool_available(t) else '—'} {t} (optional)")
    print()

# --- Findings deduplication ---

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
