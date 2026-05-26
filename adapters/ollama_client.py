import json
import re
import urllib.request
import urllib.error
from typing import Any, Dict, Optional


def generate(
    prompt: str,
    url: str,
    model: str,
    temperature: float = 0.1,
    timeout: int = 300,
) -> str:
    """
    Call an Ollama OpenAI-compatible chat completions endpoint:
      http://HOST:11434/v1/chat/completions

    Returns the assistant message content (string).
    Raises RuntimeError with details on HTTP errors or unexpected payloads.
    """
    payload: Dict[str, Any] = {
        "model": model,
        "messages": [{"role": "user", "content": prompt}],
        "temperature": temperature,
        "stream": False,
    }

    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=data,
        headers={"Content-Type": "application/json"},
        method="POST",
    )

    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", errors="replace") if hasattr(e, "read") else ""
        raise RuntimeError(f"Ollama HTTPError {e.code}: {e.reason}\nBody:\n{body[:800]}") from e
    except urllib.error.URLError as e:
        raise RuntimeError(f"Ollama connection error: {e}") from e

    try:
        obj = json.loads(raw)
    except json.JSONDecodeError as e:
        raise RuntimeError(f"Ollama returned non-JSON response:\n{raw[:800]}") from e

    # OpenAI-compatible shape: choices[0].message.content
    try:
        return obj["choices"][0]["message"]["content"]
    except Exception as e:
        raise RuntimeError(f"Unexpected Ollama response JSON:\n{json.dumps(obj, indent=2)[:1200]}") from e


def _extract_json_object(text: str) -> Optional[str]:
    """
    Best-effort extraction of a JSON object from arbitrary text.
    Handles common cases like markdown fences and preambles.
    Returns a JSON string or None.
    """
    if not text or not text.strip():
        return None

    t = text.strip()

    # Strip ```json fences
    if t.startswith("```"):
        # remove first fence line
        t = re.sub(r"^```[a-zA-Z]*\s*", "", t)
        # remove trailing fence
        t = re.sub(r"\s*```$", "", t).strip()

    # If it's already JSON
    if t.startswith("{") and t.endswith("}"):
        return t

    # Find first {...} block (greedy enough for typical outputs)
    m = re.search(r"\{.*\}", t, flags=re.DOTALL)
    if m:
        return m.group(0).strip()

    return None


def parse_json_or_repair(
    text: str,
    url: str,
    model: str,
    temperature: float = 0.1,
    max_repairs: int = 2,
) -> dict:
    """
    Parse JSON from the model output. If parsing fails:
      - Try extracting a JSON object from the text
      - Ask the model to re-output valid JSON only
    If it still fails, raise a helpful error with snippets.
    """
    # 1) direct parse
    try:
        return json.loads(text)
    except Exception:
        pass

    # 2) extract JSON from noisy text
    extracted = _extract_json_object(text)
    if extracted:
        try:
            return json.loads(extracted)
        except Exception:
            pass

    last = text

    # 3) repair loop
    for _ in range(max_repairs):
        repair_prompt = (
            "Return VALID JSON ONLY.\n"
            "No markdown, no commentary, no code fences.\n"
            "The JSON must start with { and end with }.\n\n"
            "CONTENT TO FIX:\n"
            f"{last}"
        )
        repaired = generate(repair_prompt, url, model, temperature=temperature)

        # Try direct parse
        try:
            return json.loads(repaired)
        except Exception:
            pass

        # Try extract again
        extracted = _extract_json_object(repaired)
        if extracted:
            try:
                return json.loads(extracted)
            except Exception:
                pass

        last = repaired

    # 4) give up with useful debug info
    snippet_in = (text or "")[:400].replace("\n", "\\n")
    snippet_last = (last or "")[:400].replace("\n", "\\n")
    raise RuntimeError(
        "Model did not return valid JSON after repair attempts.\n"
        f"Original snippet: {snippet_in}\n"
        f"Last snippet: {snippet_last}\n"
        "Tip: lower temperature, shorten prompt, or switch model (qwen2.5 is often cleaner for JSON)."
    )
