# Somniosus

> Deep-water enumeration. Deterministic core. Constrained intelligence.

Somniosus is a modular reconnaissance and enumeration framework designed for structured, reproducible security analysis.

Named after the deep-sea sleeper shark genus, Somniosus reflects the philosophy of the tool:

* Quiet execution
* Methodical inspection
* Long-lived architecture
* Depth over noise

Somniosus is not an AI vulnerability oracle.
It is a deterministic scanning engine with a controlled interpretation layer.

---

# CLI Entry Point

The CLI entry point has been renamed:

```
somniosus.py
```

Example usage:

```bash
./somniosus.py example.com --profile safe
```

---

# Architecture Overview

Somniosus separates responsibilities into layers:

```
CLI (somniosus.py)
    ↓
Core Orchestration (core/)
    ↓
Plugins (core/plugins/)
    ↓
Adapters (adapters/)
    ↓
External Tools (nmap, httpx, nuclei, etc.)
```

Each layer has a clearly defined boundary.
No layer performs another layer’s responsibility.

---

# Project Structure

```
Somniosus/
│
├── somniosus.py            # CLI entrypoint
│
├── core/                   # Application / orchestration layer
│   ├── registry.py         # Executes plugins + dependency/order handling
│   ├── state.py            # Runtime state container
│   ├── paths.py            # Run directory management (timestamp, latest link)
│   ├── io.py               # JSON read/write, directory helpers
│   ├── reporting.py        # Legacy Markdown report generation
│   ├── llm.py              # LLM interaction layer
│   ├── helpers.py          # Utilities (target normalization, tool checks, etc.)
│   ├── nuclei_parser.py    # Nuclei JSONL parsing
│   ├── interactive.py      # Interactive menu loop
│   ├── hybrid/             # Deterministic report + LLM pipeline
│   │   ├── report_model.py
│   │   ├── build_report_data.py
│   │   ├── render_report_md.py
│   │   ├── llm_input.py
│   │   ├── llm_appendix.py
│   │   └── llm_guardrails.py
│   └── plugins/            # Tool orchestration plugins
│       ├── nmap.py
│       ├── httpx.py
│       ├── crtsh.py
│       ├── dns_enum.py
│       ├── dnstwist.py
│       ├── tldx.py
│       ├── whois.py
│       ├── whois_tldx.py
│       ├── subfinder.py
│       ├── dnssec.py
│       ├── ssl_enum.py
│       ├── katana.py
│       ├── httpx_katana.py
│       ├── nuclei.py
│       └── ffuf.py
│
├── adapters/               # Infrastructure adapters
│   ├── runner.py           # Subprocess helpers
│   ├── nmap_scan.py
│   ├── httpx_scan.py
│   ├── crtsh_scan.py
│   ├── dns_enum_scan.py
│   ├── dnstwist_scan.py
│   ├── tldx_scan.py
│   ├── whois_scan.py
│   ├── subfinder_scan.py
│   ├── dnssec_check.py
│   ├── ssl_enum.py
│   ├── nuclei_scan.py
│   ├── katana_scan.py
│   ├── ffuf_scan.py
│   └── ollama_client.py
│
├── results/                # Per-target run artifacts
│
└── README.md
```

---

# Architectural Principles

## Deterministic First

Enumeration produces facts.
Structured state stores evidence.
Reports are generated from reproducible artifacts.

## Constrained Intelligence

The LLM layer:

* Interprets findings
* Suggests next steps
* Does not invent vulnerabilities
* Does not restate raw data blindly

All raw model output is preserved for auditability.

## Clean Boundaries

* CLI handles argument parsing and execution flow
* Plugins handle orchestration logic
* Adapters handle subprocess execution and parsing
* Core handles state and reporting

---

# Output Structure

Each run creates:

```
results/<target>/<timestamp>/
  findings.json
  tool_results.json
  report.md
  report_data.json
  report_legacy.md
  raw/
  llm_input.json      # (if AI enabled)
  llm_raw.txt
  llm_raw.json
  llm.json
  llm.md
```

* `raw/` contains original scanner output
* `findings.json` contains normalized structured results
* `tool_results.json` records plugin execution state
* `report.md` is the deterministic hybrid report
* `report_data.json` is the structured report model
* `llm.json` contains sanitized AI interpretation
* `llm_raw.txt` preserves unfiltered model output

All artifacts are reproducible and versionable.

---

# Running Somniosus

## Dependency Check

```bash
./somniosus.py --check
```

## Profiles

| Profile | Tools |
|---------|-------|
| **safe** | nmap, httpx_main, crtsh, subfinder, dns_enum, whois, httpx_subdomains |
| **thorough** | safe + dnssec, ssl_enum, katana, httpx_katana |

## Scope (default: CLI target only for heavy tools)

By default, **httpx** probes the main target and discovered subdomains (light connection checks). **Heavy tools** (nuclei, ffuf, katana) scan only the domain passed on the command line.

To include subdomains in nuclei, ffuf, and katana:

```bash
./somniosus.py example.com --profile safe --include-subdomains
```

## Full Modes (no prompts)

**--full** — Run everything with no prompts: thorough profile, subdomains, all TLDs, nuclei, ffuf, dnstwist, whois_tldx, etc. No interactive menu.

```bash
./somniosus.py example.com --full --no-ai
```

- Uses `tld-preset all` for tldx (hundreds of TLDs)
- Includes WHOIS in dnstwist
- Add `--no-ai` to skip the LLM step

**--full-quiet** — Same as --full but skips nuclei, ffuf, katana, httpx_katana. Discovery + tldx + dnstwist + whois only:

```bash
./somniosus.py example.com --full-quiet --no-ai
```

## Interactive Mode

Use `--interactive` to show the menu **first** (no tools run until you pick):

```bash
./somniosus.py example.com --interactive
```

1. **Baseline** — nmap, httpx_main, crtsh, subfinder, dns_enum, whois, httpx_subdomains
2. **Baseline + Discovery** — + dnssec, ssl_enum, dnstwist, tldx, whois_tldx, whois
3. **Baseline + Discovery + Vuln Scan** — + nuclei, ffuf
4. **Full Attack Mode** — + katana, httpx_katana, nuclei, ffuf

Before the scan runs, you're asked: *Include subdomains in active scans?* and *Run AI analysis?* Use `--no-ai` to skip the AI prompt entirely. Typosquats and TLD variations are discovery-only (never actively scanned).

**Full tldx scan** — Pass `--tld-preset all` for the Discovery options:

```bash
./somniosus.py example.com --interactive --tld-preset all
```

## Single-Tool Mode

Run one tool (and its dependencies) then exit:

```bash
./somniosus.py example.com --run httpx
./somniosus.py example.com --run subfinder
./somniosus.py example.com --run tldx --tld-preset all
```

## TLD Enumeration (tldx)

tldx checks which TLD variations of a domain are registered vs available (via RDAP).

**Default TLDs:** com, io, org, net, ai, dev, app, co

**Custom TLDs** (comma-separated):
```bash
./somniosus.py yourdomain.com --run tldx --tlds com,io,org,tech,info,biz,xyz
```

**Preset** (tech, cheap, popular, etc.):
```bash
./somniosus.py yourdomain.com --run tldx --tld-preset tech
```

**All TLDs** (hundreds; takes several minutes):
```bash
./somniosus.py yourdomain.com --run tldx --tld-preset all
```

List presets: `tldx show-tld-presets`

Reports show only **found** results (registered + available), not every TLD checked.

## External Services

**crt.sh** — Certificate Transparency subdomain discovery. The crt.sh API can occasionally return 502/503. The adapter retries up to 2 times (3 attempts total) with a 5-second delay before failing.

## With AI (custom LLM endpoint)

```bash
./somniosus.py example.com --profile safe \
  -u http://192.168.211.74:11434/v1/chat/completions
```

## Optional: Default LLM via environment variable

```bash
export OLLAMA_URL="http://192.168.211.74:11434/v1/chat/completions"
./somniosus.py example.com --profile safe
```

---

# CLI Reference

| Flag | Description |
|------|-------------|
| `--profile safe` \| `thorough` | Tool set (default: safe) |
| `--include-subdomains` | Include subdomains in nuclei, ffuf, katana |
| `--full` | Run everything, no prompts, tld-preset all |
| `--full-quiet` | Like --full but skip nuclei, ffuf, katana |
| `--interactive` | Show optional tools menu after baseline |
| `--run <tool>` | Run single tool and exit |
| `--no-ai` | Skip LLM analysis |
| `--tlds <list>` | Comma-separated TLDs for tldx |
| `--tld-preset <name>` | tldx preset (tech, cheap, all, etc.) |
| `--max-subdomains <n>` | Limit subdomains for httpx_subdomains (default: 50) |

See `docs/CLI_MODES.md` for a detailed reference.

---

# Extending Somniosus

To add a new tool:

1. Create an adapter in `adapters/`
2. Create a plugin in `core/plugins/`
3. Register the plugin

No modifications required in the CLI or orchestration engine.

---

# Design Goals

* Thin CLI
* Modular plugins
* Strict adapter boundaries
* Reproducible artifacts
* Guarded LLM integration
* Zero hallucinated findings
* Audit-friendly architecture

---

Somniosus moves slowly.
But it goes deep.
