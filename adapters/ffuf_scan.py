from __future__ import annotations

import json
import shutil
import subprocess
import time
from pathlib import Path
from typing import Any, Dict


def available() -> bool:
    return shutil.which("ffuf") is not None


def scan(
    base_url: str,
    wordlist: Path,
    raw_dir: Path,
    *,
    threads: int = 20,
    run_timeout_s: int = 900,
) -> Dict[str, Any]:

    raw_dir.mkdir(parents=True, exist_ok=True)

    host = base_url.replace("://", "_").replace("/", "_")
    json_path = raw_dir / f"ffuf_{host}.json"
    stderr_path = raw_dir / f"ffuf_{host}.stderr.txt"

    url = base_url.rstrip("/") + "/FUZZ"

    cmd = [
        "ffuf",
        "-u", url,
        "-w", str(wordlist),
        "-t", str(threads),
        "-mc", "200,204,301,302,307,308,401,403",
        "-ac",
        "-of", "json",
        "-o", str(json_path),
    ]

    start = time.time()

    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=run_timeout_s,
            shell=False,
        )
    except subprocess.TimeoutExpired:
        return {"ok": False, "tool": "ffuf", "error": "timeout"}

    stderr_path.write_text(proc.stderr or "", encoding="utf-8")
    duration = time.time() - start

    if proc.returncode != 0:
        return {
            "ok": False,
            "tool": "ffuf",
            "exit_code": proc.returncode,
            "duration_s": duration,
        }

    results = []
    if json_path.exists():
        try:
            data = json.loads(json_path.read_text())
            for entry in data.get("results", []):
                results.append({
                    "url": entry.get("url"),
                    "status": entry.get("status"),
                    "length": entry.get("length"),
                })
        except Exception:
            pass

    return {
        "ok": True,
        "tool": "ffuf",
        "cmd": cmd,
        "exit_code": proc.returncode,
        "duration_s": duration,
        "raw": {
            "json": str(json_path.relative_to(raw_dir.parent)),
            "stderr": str(stderr_path.relative_to(raw_dir.parent)),
        },
        "data": {
            "base_url": base_url,
            "results": results,
            "count": len(results),
        },
    }
