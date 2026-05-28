from __future__ import annotations

import json
import shutil
import subprocess
import time
from pathlib import Path
from typing import Any, Dict, List


def available() -> bool:
    return shutil.which("katana") is not None


def _url_from_katana_record(obj: Dict[str, Any]) -> str | None:
    """
    Extract a request URL from a katana -jsonl line.
    Current katana uses request.endpoint; older output may use top-level url.
    """
    if not isinstance(obj, dict):
        return None

    url = obj.get("url")
    if isinstance(url, str) and url.strip():
        return url.strip()

    req = obj.get("request")
    if isinstance(req, dict):
        endpoint = req.get("endpoint")
        if isinstance(endpoint, str) and endpoint.strip():
            return endpoint.strip()

    return None


def _host_from_url(url: str) -> str | None:
    try:
        return url.split("://", 1)[1].split("/", 1)[0].lower() or None
    except (IndexError, AttributeError):
        return None


def parse_katana_jsonl(jsonl_path: Path) -> tuple[List[str], List[str]]:
    """Parse katana JSONL into deduplicated URLs and hosts."""
    urls: List[str] = []
    hosts: set[str] = set()

    if not jsonl_path.exists():
        return [], []

    with jsonl_path.open("r", encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue

            url = _url_from_katana_record(obj)
            if not url:
                continue

            urls.append(url)
            host = _host_from_url(url)
            if host:
                hosts.add(host)

    return sorted(set(urls)), sorted(hosts)


def scan(
    targets: List[str],
    raw_dir: Path,
    *,
    depth: int = 2,
    concurrency: int = 10,
    run_timeout_s: int = 600,
) -> Dict[str, Any]:

    raw_dir.mkdir(parents=True, exist_ok=True)

    jsonl_path = raw_dir / "katana.jsonl"
    stderr_path = raw_dir / "katana.stderr.txt"

    cmd = [
        "katana",
        "-list", "-",
        "-d", str(depth),
        "-c", str(concurrency),
        "-jsonl",
        "-silent",
        "-o", str(jsonl_path),
    ]

    start = time.time()

    try:
        proc = subprocess.run(
            cmd,
            input="\n".join(targets),
            text=True,
            capture_output=True,
            timeout=run_timeout_s,
            shell=False,
        )
    except subprocess.TimeoutExpired:
        return {
            "ok": False,
            "tool": "katana",
            "error": "timeout",
        }

    stderr_path.write_text(proc.stderr or "", encoding="utf-8")

    duration = time.time() - start

    if proc.returncode != 0:
        return {
            "ok": False,
            "tool": "katana",
            "exit_code": proc.returncode,
            "duration_s": duration,
            "raw": {
                "stderr": str(stderr_path.relative_to(raw_dir.parent)),
            },
            "error": "non-zero exit",
        }

    urls, hosts = parse_katana_jsonl(jsonl_path)

    return {
        "ok": True,
        "tool": "katana",
        "cmd": cmd,
        "exit_code": proc.returncode,
        "duration_s": duration,
        "raw": {
            "jsonl": str(jsonl_path.relative_to(raw_dir.parent)),
            "stderr": str(stderr_path.relative_to(raw_dir.parent)),
        },
        "data": {
            "urls": urls,
            "hosts": hosts,
            "count": len(urls),
        },
    }
