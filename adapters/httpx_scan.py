from pathlib import Path
from typing import Any, Dict, List, Optional
import json

from .runner import run_with_stdin_capture


def _to_httpx_inputs(target: str) -> List[str]:
    # Probe both schemes (httpx will handle redirects)
    return [f"http://{target}", f"https://{target}"]


def scan(target: str, outdir: Path, inputs: Optional[List[str]] = None, label: str = "httpx") -> Dict[str, Any]:
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
        "stderr": "<truncated>"
      }
    """
    outdir.mkdir(parents=True, exist_ok=True)
    out_path = outdir / f"{label}.jsonl"

    if inputs is None:
        inputs = _to_httpx_inputs(target)

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

    stdin_text = "\n".join(inputs) + "\n"

    rc, stdout, stderr = run_with_stdin_capture(cmd, stdin_text)

    # Always write whatever stdout we got (even if empty) for consistency
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
    }
