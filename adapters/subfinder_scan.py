from pathlib import Path
from typing import Any, Dict, List
from .runner import run_capture


def scan(target: str, outdir: Path) -> Dict[str, Any]:
    """
    Run subfinder and return discovered subdomains.

    Writes:
      - outdir/subdomains.txt (raw stdout)
    """
    outdir.mkdir(parents=True, exist_ok=True)
    out_path = outdir / "subdomains.txt"

    cmd = ["subfinder", "-silent", "-d", target]
    rc, stdout, stderr = run_capture(cmd)

    # Always write stdout (even if empty) so the run folder is consistent
    out_path.write_text(stdout)

    subs: List[str] = []
    for line in stdout.splitlines():
        s = line.strip()
        if s:
            subs.append(s)

    # de-dup preserving order
    seen = set()
    deduped = []
    for s in subs:
        if s in seen:
            continue
        seen.add(s)
        deduped.append(s)

    return {
        "target": target,
        "subdomains": deduped,
        "count": len(deduped),
        "raw_file": str(out_path),
        "returncode": rc,
        "stderr": (stderr[:2000] if isinstance(stderr, str) else ""),
    }
