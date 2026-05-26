# core/registry.py
from __future__ import annotations

from dataclasses import asdict
from typing import Dict, List, Set

from core.io import write_json
from core.paths import RunPaths
from core.state import State, ToolResult


class Tool:
    name: str = "tool"
    requires: Set[str] = set()
    provides: Set[str] = set()
    interactive_only: bool = False

    def available(self) -> bool:
        return True

    def should_run(self, state: State, args) -> bool:
        return True

    def run(self, state: State, paths: RunPaths, args) -> ToolResult:
        raise NotImplementedError


class Registry:
    def __init__(self) -> None:
        self.tools: Dict[str, Tool] = {}

    def register(self, tool: Tool) -> None:
        self.tools[tool.name] = tool

    def get(self, name: str) -> Tool:
        return self.tools[name]

    def plan(self, names: List[str]) -> List[Tool]:
        remaining = [self.tools[n] for n in names if n in self.tools]
        planned: List[Tool] = []
        provided: Set[str] = set()

        for _ in range(50):
            if not remaining:
                break
            progress = False
            for t in list(remaining):
                if t.requires.issubset(provided):
                    planned.append(t)
                    provided |= t.provides
                    remaining.remove(t)
                    progress = True
            if not progress:
                planned.extend(remaining)
                break

        return planned


def execute_tools(reg: Registry, names: List[str], state: State, paths: RunPaths, args) -> None:
    from datetime import datetime

    # Record unknown tools requested in the profile list
    for n in names:
        if n not in reg.tools:
            ts = datetime.now().isoformat(timespec="seconds")
            tr = ToolResult(
                tool=n,
                ok=True,
                skipped=True,
                reason="not registered",
                started_at=ts,
                ended_at=ts,
            )
            state.tool_results[n] = tr
            state.container["extras"][n] = tr.to_extras()

    for tool in reg.plan(names):
        # If interactive-only but interactive mode is off, record skip instead of silently continuing
        if tool.interactive_only and not getattr(args, "interactive", False):
            ts = datetime.now().isoformat(timespec="seconds")
            tr = ToolResult(
                tool=tool.name,
                ok=True,
                skipped=True,
                reason="interactive-only (run with --interactive)",
                started_at=ts,
                ended_at=ts,
            )
            state.tool_results[tool.name] = tr
            state.container["extras"][tool.name] = tr.to_extras()
            continue

        tr = tool.run(state, paths, args)
        state.tool_results[tool.name] = tr
        state.container["extras"][tool.name] = tr.to_extras()



def write_tool_results(paths: RunPaths, state: State) -> None:
    write_json(paths.base / "tool_results.json", {k: asdict(v) for k, v in state.tool_results.items()})
