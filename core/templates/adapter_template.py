"""
Adapter template for Somniosus.
Copy to adapters/<tool>_scan.py and replace TOOL, tool_scan, TOOL_BINARY.
Adapter responsibility: execute tool, save raw output to raw_dir, return structured dict.
Use adapters.runner (run_capture, run_with_stdin_capture) — never subprocess directly in plugins.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any, Dict

from adapters.runner import run_capture


def scan(target: str, raw_dir: Path) -> Dict[str, Any]:
    """
    Execute tool, store raw output under raw_dir, return structured result.
    """
    raw_dir.mkdir(parents=True, exist_ok=True)
    out_path = raw_dir / "TOOL.txt"

    cmd = ["TOOL_BINARY", "-silent", target]
    rc, stdout, stderr = run_capture(cmd, timeout=300)

    out_path.write_text(stdout)

    return {
        "target": target,
        "raw_file": str(out_path),
        "returncode": rc,
        "stderr": (stderr[:2000] if isinstance(stderr, str) else ""),
        # Add tool-specific parsed fields here
    }
