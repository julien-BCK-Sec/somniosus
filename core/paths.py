# core/paths.py
from __future__ import annotations

import os
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from core.io import ensure_dir


@dataclass
class RunPaths:
    target: str
    target_dir: Path
    base: Path
    raw: Path


def make_run_paths(target: str, timestamp: bool, no_latest_link: bool) -> RunPaths:
    target_dir = Path("results") / target.replace("/", "_")
    ensure_dir(target_dir)

    if timestamp:
        stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        base = target_dir / stamp
    else:
        base = target_dir

    ensure_dir(base)
    raw = base / "raw"
    ensure_dir(raw)

    if timestamp and not no_latest_link:
        latest = target_dir / "latest"
        try:
            if latest.is_symlink() or latest.exists():
                latest.unlink()
            os.symlink(base.name, latest)  # relative link to <timestamp>
        except OSError:
            pass

    return RunPaths(target=target, target_dir=target_dir, base=base, raw=raw)
