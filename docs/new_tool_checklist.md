# Somniosus New Tool Checklist

Use this checklist whenever adding a new tool to Somniosus. The goal is consistent, reproducible artifacts, stable schemas, and safe-by-default behavior.

Somniosus is under active development, so changes should remain reversible and easy to validate via smoke runs and stored results.

---

## 0) Decide the tool category
- [ ] Passive / low-noise (ok for `safe` profile)
- [ ] Active but reasonable (default for `thorough`)
- [ ] Intrusive / high-noise (opt-in only, never default in `safe`)

Record the decision in the plugin docstring and ensure `should_run()` enforces it.

---

## 1) Adapter requirements (`adapters/<tool>.py`)
Adapter responsibility: execute tool, save raw output, return structured result.

### Execution safety
- [ ] Uses `subprocess.run([...], shell=False)` (no shell)
- [ ] Sets a timeout
- [ ] Captures stdout/stderr
- [ ] Handles non-zero exit codes without crashing the whole run

### Artifact handling
- [ ] Saves raw output under `run_dir/raw/`
- [ ] Uses stable filenames
- [ ] Writes only inside the run directory
- [ ] Includes timing metadata
- [ ] Returns structured dict output

### Minimum structured result fields
- [ ] `tool`
- [ ] `ok`
- [ ] `exit_code`
- [ ] `artifacts`
- [ ] deterministic `summary` counters

---

## 2) Parser requirements (if needed)
- [ ] Deterministic output
- [ ] Defensive parsing
- [ ] Handles missing/malformed data gracefully
- [ ] Parser output documented

---

## 3) Plugin requirements (`core/plugins/<tool>.py`)
Plugin responsibility: orchestration and state integration.

- [ ] Defines metadata (`name`, `requires`, `provides`)
- [ ] `available()` checks prerequisites
- [ ] `should_run()` respects profiles
- [ ] Calls adapter only (no subprocess here)
- [ ] Writes results to `state.extras[tool]`
- [ ] Findings merge cleanly into global findings
- [ ] Deterministic info available for reporting

---

## 4) Reporting integration
- [ ] Appears in Tool Execution Summary
- [ ] Appears in Enumeration Results
- [ ] Coverage updated correctly
- [ ] Findings reference raw evidence

### Hybrid v1 rules
- [ ] LLM input uses sanitized summaries only
- [ ] No raw tool output leaks to prompts
- [ ] No vulnerability claims without evidence

---

## 5) Registration
- [ ] Plugin registered
- [ ] Tool visible in `--check`
- [ ] CLI/help updated if needed

---

## 6) Tests
Tests should not require network access.

### Parser tests
- [ ] Valid input parses correctly
- [ ] Missing fields handled
- [ ] Malformed input safe

### Findings merge tests
- [ ] No schema breakage
- [ ] Deduplication works
- [ ] Deterministic ordering

### Guardrail tests
- [ ] Sanitization prevents raw leakage
- [ ] Prompt injection strings do not propagate

---

## 7) Local verification
Before considering tool integration complete:

- [ ] `python -m compileall .`
- [ ] Lint/tests pass
- [ ] Smoke run works:
      ./somniosus.py <known_target> --profile safe --no-ai
- [ ] Artifacts correctly appear in timestamped run directory

---

## 8) Documentation notes
Add:
- Tool purpose
- Profiles where tool runs
- Artifacts produced
- Output schema explanation
