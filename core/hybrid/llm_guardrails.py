# core/hybrid/llm_guardrails.py
from __future__ import annotations

from typing import Any, Dict

BANNED_PHRASES = [
    "misconfigured or vulnerable settings",
    "vulnerable settings",
    "known vulnerabilities",
    "is vulnerable",
    "definitely vulnerable",
    "likely vulnerable",
]

REPLACEMENTS = {
    "misconfigured or vulnerable settings": "settings that warrant review/hardening",
    "vulnerable settings": "settings that warrant review/hardening",
    "known vulnerabilities": "an older version; verify patch level and exposure",
    "is vulnerable": "may warrant verification of patch level and configuration",
    "likely vulnerable": "may warrant verification of patch level and configuration",
    "definitely vulnerable": "should be validated for patch level and configuration",
}


def sanitize_llm_obj(llm_obj: Dict[str, Any]) -> Dict[str, Any]:
    """
    Best-effort: rewrite risky claims into neutral language.
    We do NOT add new information; only soften claims.
    """
    def scrub_text(s: str) -> str:
        out = s
        for bad in BANNED_PHRASES:
            if bad in out:
                out = out.replace(bad, REPLACEMENTS.get(bad, "may require verification"))
                out = out.replace("may have configuration that may", "may have configuration that")
                out = out.replace("may have settings that may", "may have settings that")
        return out

    def walk(x: Any) -> Any:
        if isinstance(x, str):
            return scrub_text(x)
        if isinstance(x, list):
            return [walk(i) for i in x]
        if isinstance(x, dict):
            return {k: walk(v) for k, v in x.items()}
        return x

    return walk(llm_obj)
