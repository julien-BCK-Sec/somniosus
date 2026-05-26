from __future__ import annotations

import json
import shutil
import subprocess
import time
from pathlib import Path
from typing import Any, Dict, List


def available() -> bool:
    return shutil.which("katana") is not None


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

    # Parse JSONL
    urls = []
    hosts = set()

    if jsonl_path.exists():
        with jsonl_path.open("r", encoding="utf-8", errors="replace") as f:
            for line in f:
                try:
                    obj = json.loads(line.strip())
                except Exception:
                    continue

                url = obj.get("url")
                if not url:
                    continue

                urls.append(url)

                try:
                    host = url.split("://", 1)[1].split("/", 1)[0]
                    hosts.add(host)
                except Exception:
                    pass

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
            "urls": sorted(set(urls)),
            "hosts": sorted(hosts),
            "count": len(set(urls)),
        },
    }
