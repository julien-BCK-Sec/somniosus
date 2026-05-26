import subprocess
import json
from collections import Counter
from pathlib import Path
from typing import Optional, Dict, Any, List


def _safe_jsonl_read(path: Path, limit: int = 20000) -> List[Dict[str, Any]]:
    """
    Read nuclei JSONL defensively. `limit` is a safety valve to avoid runaway memory use.
    """
    items: List[Dict[str, Any]] = []
    if not path.exists():
        return items

    with path.open("r", errors="replace") as f:
        for i, line in enumerate(f):
            if i >= limit:
                break
            line = line.strip()
            if not line:
                continue
            try:
                o = json.loads(line)
                if isinstance(o, dict):
                    items.append(o)
            except Exception:
                continue
    return items


def _summarize(matches: List[Dict[str, Any]]) -> Dict[str, Any]:
    sev = Counter()
    templates = Counter()
    types = Counter()

    for m in matches:
        info = m.get("info") if isinstance(m.get("info"), dict) else {}
        s = (info.get("severity") or m.get("severity") or "unknown")
        s = str(s).strip().lower()
        sev[s] += 1

        tid = m.get("template-id") or m.get("templateID") or m.get("template") or "unknown"
        templates[str(tid)] += 1

        t = m.get("type") or "unknown"
        types[str(t)] += 1

    return {
        "severity_counts": dict(sev),
        "top_templates": [{"template_id": k, "count": v} for k, v in templates.most_common(15)],
        "type_counts": dict(types),
    }


def scan(
    *,
    inputs: List[str],
    raw_dir: Path,
    severity: str = "low,medium,high,critical",
    concurrency: int = 25,
    rate_limit: int = 50,
    timeout: Optional[int] = None,
) -> Dict[str, Any]:
    """
    Runs nuclei and writes JSONL output to raw_dir/nuclei.jsonl.

    STRICT API (no legacy / positional args):
      - inputs: list of targets (URLs/hosts). If 1 target -> nuclei -u. If >1 -> nuclei -l.
      - raw_dir: directory to store nuclei artifacts for this run.

    Artifacts:
      - raw_dir/nuclei.jsonl         nuclei JSONL output
      - raw_dir/nuclei_inputs.txt    (only in list mode) input targets file

    Returns a wrapper dict:
      - mode: "single" or "list"
      - inputs_count
      - input_file (only in list mode)
      - severity
      - raw_file
      - count
      - returncode
      - summary
      - stderr/stdout (truncated)
      - cmd
    """
    # Normalize and validate inputs
    norm: List[str] = [str(x).strip() for x in (inputs or []) if str(x).strip()]
    if not norm:
        return {
            "skipped": True,
            "reason": "no inputs provided",
            "mode": "none",
            "inputs_count": 0,
            "severity": severity,
        }

    raw_dir.mkdir(parents=True, exist_ok=True)
    out_path = raw_dir / "nuclei.jsonl"

    # Overwrite within a single run folder
    if out_path.exists():
        out_path.unlink()

    mode = "single" if len(norm) == 1 else "list"
    input_file: Optional[Path] = None

    cmd = [
        "nuclei",
        "-severity", severity,
        "-jsonl",
        "-o", str(out_path),
        "-silent",
        "-c", str(concurrency),
        "-rl", str(rate_limit),
    ]

    if mode == "single":
        cmd.extend(["-u", norm[0]])
    else:
        input_file = raw_dir / "nuclei_inputs.txt"
        if input_file.exists():
            input_file.unlink()
        input_file.write_text("\n".join(norm) + "\n", encoding="utf-8")
        cmd.extend(["-l", str(input_file)])

    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        rc = proc.returncode
    except FileNotFoundError:
        return {
            "skipped": True,
            "reason": "nuclei not found in PATH",
            "mode": mode,
            "inputs_count": len(norm),
            "input_file": str(input_file) if input_file else None,
            "severity": severity,
            "cmd": cmd,
        }
    except subprocess.TimeoutExpired:
        # Partial output may exist; still summarize if possible.
        rc = 124
        proc = None

    # Parse JSONL + summarize
    matches: List[Dict[str, Any]] = []
    count = 0
    if out_path.exists():
        matches = _safe_jsonl_read(out_path)
        count = len(matches)

    summary = _summarize(matches) if matches else {"severity_counts": {}, "top_templates": [], "type_counts": {}}

    stderr = ""
    stdout = ""
    if proc is not None:
        stderr = proc.stderr[:2000] if isinstance(proc.stderr, str) else ""
        stdout = proc.stdout[:2000] if isinstance(proc.stdout, str) else ""

    return {
        "mode": mode,
        "inputs_count": len(norm),
        "input_file": str(input_file) if input_file else None,
        "severity": severity,
        "raw_file": str(out_path),
        "count": count,
        "returncode": rc,
        "summary": summary,
        "stderr": stderr,
        "stdout": stdout,
        "cmd": cmd,
    }
