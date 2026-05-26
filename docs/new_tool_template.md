# Somniosus New Tool Templates

Use these templates when creating new tools so architecture remains consistent.

Adapters execute tools.
Plugins orchestrate tools.

Never mix responsibilities.

---

# Adapter Template
Location: `adapters/<tool>_scan.py`

Use `adapters.runner.run_capture` or `run_with_stdin_capture` — never raw subprocess in adapters.

```python
from __future__ import annotations

from pathlib import Path
from typing import Any, Dict

from .runner import run_capture


def scan(target: str, raw_dir: Path) -> Dict[str, Any]:
    """
    Execute tool, store raw output under raw_dir, return structured result.
    """
    raw_dir.mkdir(parents=True, exist_ok=True)
    out_path = raw_dir / "<tool>.txt"

    cmd = ["<tool_binary>", "-silent", target]
    rc, stdout, stderr = run_capture(cmd, timeout=300)

    out_path.write_text(stdout)

    return {
        "target": target,
        "raw_file": str(out_path),
        "returncode": rc,
        "stderr": (stderr[:2000] if isinstance(stderr, str) else ""),
        # Add tool-specific parsed fields here
    }
```

---

# Plugin Template
Location: `core/plugins/<tool>.py`

Plugins receive `(state, paths, args)`. Use `paths.raw` for adapter, `paths.base` for JSON output.
Registry writes `ToolResult.to_extras()` to `state.container["extras"]` — plugin just returns `ToolResult`.

```python
from __future__ import annotations

from datetime import datetime

from core.helpers import tool_available
from core.io import write_json
from core.registry import Tool
from core.state import State, ToolResult
from core.paths import RunPaths
from adapters import <tool>_scan


class <Tool>Tool(Tool):
    name = "<tool>"
    requires = set()  # e.g. {"nmap"} if needs port scan first
    provides = {"<tool>"}
    interactive_only = False  # True for noisy/intrusive tools

    def available(self) -> bool:
        return tool_available("<tool_binary>")

    def should_run(self, state: State, args) -> bool:
        if getattr(args, "profile", "safe") != "thorough":
            return False
        return True

    def run(self, state: State, paths: RunPaths, args) -> ToolResult:
        start = datetime.now().isoformat(timespec="seconds")

        if not self.available():
            return ToolResult(tool=self.name, ok=True, skipped=True,
                reason="<tool_binary> not available", started_at=start, ended_at=start)
        if not self.should_run(state, args):
            return ToolResult(tool=self.name, ok=True, skipped=True,
                reason="skipped by profile", started_at=start, ended_at=start)

        result = <tool>_scan.scan(state.target, paths.raw)
        write_json(paths.base / "<tool>.json", result)

        end = datetime.now().isoformat(timespec="seconds")
        return ToolResult(tool=self.name, ok=result.get("returncode", 1) == 0,
            count=result.get("count"), data=result, started_at=start, ended_at=end)
```

---

# Parser Template (if needed)
Location: `core/<tool>_parser.py` or inline in adapter

Use when tool output needs structured parsing (JSONL, XML). Keep deterministic and defensive.

```python
def parse_raw(text: str) -> List[Dict[str, Any]]:
    items = []
    for line in text.strip().splitlines():
        try:
            obj = json.loads(line.strip())
            if isinstance(obj, dict):
                items.append(obj)
        except json.JSONDecodeError:
            continue
    return items
```
