from pathlib import Path
from typing import Any, Dict, List, Optional
import json
import shutil
import subprocess

from .runner import run_with_stdin_capture


def _is_projectdiscovery_httpx() -> bool:
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


def _wrong_httpx_message() -> str:
    return (
        "httpx on PATH is not ProjectDiscovery's probe (expected flags like -json, -tech-detect). "
        "Install: https://github.com/projectdiscovery/httpx — avoid Python's httpx package on PATH."
    )


def scan(
    target: str,
    outdir: Path,
    inputs: Optional[List[str]] = None,
    label: str = "httpx",
) -> Dict[str, Any]:
    """
    Run httpx and return parsed JSON lines.
    Writes raw output to outdir/{label}.jsonl.

    Returns:
      {
        "target": "...",
        "httpx": [ ...parsed json lines... ],
        "count": <int>,
        "raw_file": "<path>",
        "returncode": <int>,
        "stderr": "<truncated>",
        "probe_urls": [...],
        "ok": <bool>
      }
    """
    outdir.mkdir(parents=True, exist_ok=True)
    out_path = outdir / f"{label}.jsonl"

    if not _is_projectdiscovery_httpx():
        return {
            "target": target,
            "httpx": [],
            "count": 0,
            "raw_file": str(out_path),
            "returncode": -1,
            "stderr": _wrong_httpx_message(),
            "probe_urls": inputs or [],
            "ok": False,
        }

    if inputs is None:
        # Plugins should pass explicit probe URLs (see core.helpers.httpx_probe_urls).
        host = target.split(":", 1)[0] if ":" in target else target
        inputs = [f"http://{host}", f"https://{host}"]

    probe_urls = list(inputs)

    cmd = [
        "httpx",
        "-json",
        "-title",
        "-tech-detect",
        "-status-code",
        "-server",
        "-tls-grab",
        "-follow-redirects",
        "-silent",
    ]

    stdin_text = "\n".join(probe_urls) + "\n" if probe_urls else ""

    rc, stdout, stderr = run_with_stdin_capture(cmd, stdin_text)

    out_path.write_text(stdout)

    records: List[Dict[str, Any]] = []
    for line in stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
            if isinstance(obj, dict):
                records.append(obj)
        except json.JSONDecodeError:
            continue

    return {
        "target": target,
        "httpx": records,
        "count": len(records),
        "raw_file": str(out_path),
        "returncode": rc,
        "stderr": (stderr[:2000] if isinstance(stderr, str) else ""),
        "probe_urls": probe_urls,
        "ok": rc == 0,
    }
