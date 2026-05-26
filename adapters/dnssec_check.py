from pathlib import Path
from typing import Any, Dict

from .runner import run


def scan(domain: str, outdir: Path) -> Dict[str, Any]:
    """
    Check DNSSEC-related records with dig +dnssec.
    Writes raw output to outdir/dnssec.txt.
    """
    outdir.mkdir(parents=True, exist_ok=True)
    out_path = outdir / "dnssec.txt"

    # +dnssec requests DNSSEC records; we’re not fully validating here—just collecting evidence
    cmd = ["dig", "+dnssec", domain]
    raw = run(cmd)
    out_path.write_text(raw)

    return {"domain": domain, "raw_file": str(out_path)}
