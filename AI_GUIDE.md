# AI Contributor Guide (Somniosus)

This file is written for AI coding assistants (LLMs/agents) working on this repository. It describes the project architecture, invariants, conventions, and secure coding guidelines so changes remain consistent, safe, and maintainable.

---

## Purpose

Somniosus is a modular enumeration framework that orchestrates external security tools via a plugin system, optionally runs an LLM analysis, and writes reproducible artifacts under `results/`.

Primary goals:

* Keep the CLI thin.
* Keep orchestration logic in `core/`.
* Keep external tool execution/parsing in `adapters/`.
* Produce stable, reproducible run artifacts.
* Keep LLM output evidence-based (no guessing).

Non-goals:

* This is not an exploitation framework.
* Avoid adding intrusive/high-noise scanning by default.

---

## High-Level Architecture

Layers:

1. **CLI**: `somniosus.py`

* Parses args
* Selects profile / tool set
* Builds plugin registry
* Executes tools via registry
* Optional LLM analysis
* Exports report
* Delegates interactive behavior to `core/interactive.py`

2. **Core**: `core/`

* Orchestration engine + shared state + reporting + LLM integration
* `core/plugins/` contains tool-specific orchestration logic

3. **Adapters**: `adapters/`

* Wraps external binaries/APIs (nmap, httpx, subfinder, nuclei, dig/openssl, LLM client, etc.)
* Responsible for subprocess execution, raw artifact saving, parsing, and returning structured output

---

## Directory Map

* `somniosus.py`: CLI entrypoint (should remain small). Defines PROFILES, FULL_TOOLS, FULL_QUIET_TOOLS.
* `core/registry.py`: plugin execution engine
* `core/state.py`: shared state object (container for `findings`, `extras`, `llm` + convenience fields)
* `core/paths.py`: creates run folders (timestamped) and manages `latest` symlink
* `core/io.py`: JSON read/write and directory helpers
* `core/reporting.py`: legacy Markdown report export
* `core/llm.py`: prompt + model call + JSON parsing
* `core/helpers.py`: small utilities (normalize target, check tools, determine web ports, `filter_urls_by_scope`, `is_full_mode`, etc.)
* `core/nuclei_parser.py`: nuclei JSONL parsing to structured findings
* `core/interactive.py`: interactive menu loop
* `core/plugins/*`: plugin modules (orchestration logic)
* `core/hybrid/`: deterministic report model + LLM pipeline
  * `report_model.py`: dataclasses (ReportData, Service, Vulnerability, etc.)
  * `build_report_data.py`: maps findings → ReportData
  * `render_report_md.py`: renders ReportData to markdown
  * `llm_input.py`: builds sanitized LLM input from ReportData
  * `llm_appendix.py`: renders LLM output to markdown
  * `llm_guardrails.py`: sanitizes LLM output (banned phrases, neutral language)
* `adapters/runner.py`: subprocess helpers (run_capture, run_with_stdin_capture)
* `adapters/*`: external tool wrappers (execution + parsing). crtsh_scan retries on 5xx (2 retries, 5s delay).
* `results/`: run output (typically not committed to git)

---

## Output Contract

### Run folder layout

Each run writes to:

`results/<target>/<timestamp>/`

Expected outputs:

* `findings.json` (primary structured results)
* `tool_results.json` (per-tool execution metadata)
* `report.md` (deterministic hybrid report)
* `report_data.json` (structured report model)
* `report_legacy.md` (legacy format, during transition)
* `raw/` directory (unmodified tool output: xml/jsonl/txt)
* Optional LLM artifacts:

  * `llm_input.json` (sanitized input to LLM)
  * `llm_raw.txt`, `llm_raw.json` (unfiltered model output)
  * `llm.json` (sanitized structured output)
  * `llm.md` (rendered appendix)

### Container shape

`state.container` is a dict with keys:

* `findings`: dict (baseline structured results, typically from nmap, plus merged findings list)
* `extras`: dict (tool outputs/metadata not part of baseline findings)
* `llm`: dict (LLM summary and next steps)

Plugins should populate:

* `findings` for baseline + merged findings
* `extras[<tool_name>]` for tool outputs / metadata
* `llm` only through `core/llm.py`

---

## Core Engineering Rules

### Rule 1 — Keep CLI Thin

Do not add tool-specific logic to `somniosus.py`.

* Add/update a plugin in `core/plugins/`.
* Add/update an adapter in `adapters/`.

### Rule 2 — Plugins orchestrate, adapters execute

**Plugins** decide:

* prerequisites/dependencies (nmap/web ports/subdomains/etc.)
* whether to run (availability + profile + current state)
* where outputs go in state/container

**Adapters** implement:

* subprocess calls
* raw artifact saving
* parsing tool output to a structured dict

### Rule 3 — Reproducible artifacts

* Always save raw artifacts to `run_dir/raw/`.
* Always write structured JSON outputs into the run folder.
* Use stable file names (avoid random names).

### Rule 4 — Default behavior is safe

* The `safe` profile must stay low-noise.
* Intrusive tools must be opt-in (interactive or a separate profile).
* **Scope**: By default, heavy tools (nuclei, ffuf, katana) scan only the CLI target. httpx probes subdomains (light checks). Use `--include-subdomains` to expand heavy tools to subdomains.

### Rule 5 — Evidence-based LLM

Prompts and post-processing must:

* discourage guessing
* avoid claiming vulnerabilities without proof
* prioritize low-noise validation and enumeration

If adding new LLM fields:

* update schema/expectations in `core/llm.py`
* ensure report export tolerates missing fields

---

## Run Modes

* **Profiles**: `safe` (nmap, httpx, crtsh, subfinder, dns_enum, whois, httpx_subdomains), `thorough` (+ dnssec, ssl_enum, katana, httpx_katana).
* **--include-subdomains**: Expands nuclei, ffuf, katana to subdomain URLs. Default: heavy tools stay on CLI target only.
* **--full**: Runs FULL_TOOLS (thorough + dnstwist, tldx, whois_tldx, whois, nuclei, ffuf) with no prompts. Sets tld-preset all, include_subdomains.
* **--full-quiet**: Same as --full but skips nuclei, ffuf, katana, httpx_katana (FULL_QUIET_TOOLS).
* **--interactive**: After baseline, shows menu of preset bundles (Discovery, Vuln scan, All). User picks one; tools run without prompts. Uses `interactive_bundle` flag so `is_full_mode(args)` skips per-tool prompts.

## How to Add a New External Tool

Example: add `feroxbuster` (opt-in).

1. Add adapter: `adapters/ferox_scan.py`

* implement `scan(target, raw_dir, ...) -> dict`
* save raw output to `raw/ferox.txt` or `raw/ferox.json`
* return a minimal structure, e.g.:

  * `{"count": int, "results": [...], "raw_file": "raw/ferox.txt"}`

2. Add plugin: `core/plugins/ferox.py`

* define a plugin class with:

  * `name = "ferox"`
  * `requires = {...}` if needed
  * `provides = {...}`
* implement:

  * `available()` checks for the binary on PATH
  * `should_run()` gates based on state/profile
  * `run()` calls adapter, writes `ferox.json`, stores in `extras["ferox"]`

3. Register plugin

* add it to `core/plugins/__init__.py` (or registry builder)

4. Gating

* by default: interactive-only or `thorough`, not `safe`

---

## Naming Conventions

* Plugin `name` should match:

  * `extras` key
  * `tool_results.json` entry name
  * output file stem (e.g., `httpx.json`, `subfinder.json`)

Avoid multiple names for the same capability.

---

## Testing Checklist (Must Pass)

1. Compile:

```bash
python3 -m py_compile somniosus.py $(find core adapters -name "*.py" -type f)
```

2. Tool check:

```bash
./somniosus.py --check
```

3. Baseline run (no AI):

```bash
./somniosus.py scanme.nmap.org --no-ai --profile safe
```

4. AI run (if LLM is available):

```bash
./somniosus.py scanme.nmap.org --profile safe -u $OLLAMA_URL
```

5. Validate outputs exist:

* `findings.json`
* `tool_results.json`
* `report.md`
* `raw/` artifacts

---

## Common Pitfalls

* Putting subprocess calls inside plugins (should be in adapters)
* Writing outputs outside the run directory
* Overwriting results without timestamp unless explicitly requested
* Assuming tool output shapes (defensively handle missing keys)
* Allowing LLM output to claim vulns without evidence
* Adding noisy scanning to `safe` profile

---

# Secure Coding Guidelines (Project-Wide)

These guidelines apply to all new code and refactors.

## 1) Subprocess safety

**Never** build shell commands with string concatenation.

* Use `subprocess.run([...], shell=False, ...)`.
* If you must use a shell (avoid), treat all inputs as untrusted.

Validate user-controlled values before passing to external tools:

* target strings
* ports
* paths
* severity lists

Prefer:

* whitelists over blacklists
* explicit `Path` joins over raw string paths

## 2) Input validation & normalization

* Normalize targets early (domain vs URL vs IP).
* Reject obviously invalid targets.
* Keep normalization logic in `core/helpers.py`.

## 3) Path handling

* Use `pathlib.Path` everywhere.
* Write only within the run directory (`paths.base` / `paths.raw`).
* Do not trust filenames derived from tool output.

## 4) Least privilege behavior

* Do not require root by default.
* Avoid writing outside the repo.
* Avoid network noise in `safe`.

## 5) Error handling

* Adapters should return structured error info (e.g., `{ok: false, error: ...}`) or raise a controlled exception that plugins catch.
* Plugins should record failures in `tool_results.json` rather than crashing the run.
* Make failures visible in the report.

## 6) Logging & sensitive data

* Avoid logging secrets (tokens, credentials, session cookies).
* If you ever add support for auth headers/cookies, redact them in logs and outputs.
* Keep `llm_raw.txt` and `llm.json` free of secrets.

## 7) Deterministic outputs

* Keep output schemas stable.
* Report generator must tolerate missing optional fields.
* Prefer additive schema changes over breaking changes.

## 8) LLM safety / prompt injection hygiene

Assume tool output may contain untrusted strings (headers, HTML, banners).

* Do not let untrusted content become instructions.
* Prompts must instruct the model to treat all embedded data as untrusted.
* `core/hybrid/llm_guardrails.py` sanitizes LLM output:

  * replaces banned phrases (e.g. "known vulnerabilities") with neutral language
  * walks the output structure to scrub risky claims

## 9) Dependency hygiene

* Keep dependencies minimal.
* Prefer stdlib.
* If adding a dependency, document why and pin versions if needed.

## 10) Security posture of new modules

When adding a plugin/adapter, include:

* clear gating logic (`safe` vs interactive)
* clear traffic expectations in help text
* a default configuration that is low-noise

---

## Recommended Repo Hygiene

* Add `__pycache__/`, `*.pyc`, and `results/` to `.gitignore`.
* Consider a `Makefile` or `scripts/` for:

  * lint
  * compile check
  * smoke tests

---

## Suggested Next Improvements (Safe)

* Auto-discover plugins (import modules from `core/plugins/`)
* Standardize tool result schemas across adapters
* Add structured logging with levels
* Add correlation/deduping across tools
* Add CI mode that never prompts
