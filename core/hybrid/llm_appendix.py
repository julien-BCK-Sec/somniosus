# core/hybrid/llm_appendix.py
from __future__ import annotations

from typing import Any, Dict


def render_llm_md(llm_obj: Dict[str, Any]) -> str:
    """
    Accepts whatever analyze_with_llm returns (dict).
    Renders a stable markdown appendix.
    """
    lines: list[str] = []
    lines.append("# Appendix A — AI Analysis & Suggested Next Steps")
    lines.append("")
    lines.append("_This appendix is AI-assisted and is not the authoritative source of scan facts._")
    lines.append("")

    analysis = (
        llm_obj.get("analysis")
        or llm_obj.get("analyst_notes")
        or llm_obj.get("notes")
        or llm_obj.get("summary")
        or llm_obj.get("observations")
    )

    next_steps = (
        llm_obj.get("suggested_next_steps")
        or llm_obj.get("next_steps")
        or llm_obj.get("priority_next_steps")
    )

    # Some models return analysis as a dict like {"bullets":[...]} or {"text":"..."}
    if isinstance(analysis, dict):
        analysis = analysis.get("bullets") or analysis.get("items") or analysis.get("text")

    lines.append("## Analysis")
    if not analysis:
        lines.append("_No analysis produced._")
    elif isinstance(analysis, list):
        for x in analysis:
            lines.append(f"- {x}")
    else:
        lines.append(str(analysis))
    lines.append("")

    lines.append("## Suggested Next Steps")
    if not next_steps:
        lines.append("_No next steps produced._")
    elif isinstance(next_steps, list) and next_steps and isinstance(next_steps[0], dict):
        for item in next_steps:
            title = item.get("title", "Next step")
            why = item.get("why", "")
            prio = item.get("priority", "P?")  # allow optional
            lines.append(f"- **{prio} — {title}**")
            if why:
                lines.append(f"  - Why: {why}")
            cmds = item.get("commands")
            if isinstance(cmds, list) and cmds:
                lines.append("  - Commands:")
                for c in cmds[:10]:
                    lines.append(f"    - `{c}`")
    elif isinstance(next_steps, list):
        for x in next_steps:
            lines.append(f"- {x}")
    else:
        lines.append(str(next_steps))
    lines.append("")

    return "\n".join(lines)
