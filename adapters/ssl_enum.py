from pathlib import Path
from typing import Any, Dict

from .runner import run


def scan(target: str, outdir: Path, port: int = 443) -> Dict[str, Any]:
    """
    Run nmap ssl-enum-ciphers on a target:port.
    Writes raw output to outdir/ssl_enum.txt.
    """
    outdir.mkdir(parents=True, exist_ok=True)
    out_path = outdir / "ssl_enum.txt"

    cmd = ["nmap", "--script", "ssl-enum-ciphers", "-p", str(port), target]
    raw = run(cmd)
    out_path.write_text(raw)

    return {"target": target, "port": port, "raw_file": str(out_path)}
