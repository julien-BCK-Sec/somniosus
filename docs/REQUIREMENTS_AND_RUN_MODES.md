# Somniosus — Requirements & Run Modes

---

## Interactive Mode

```bash
./somniosus.py example.com --interactive
```

| Choice | Scan |
|--------|------|
| 1 | **Baseline** — nmap, httpx_main, crtsh, subfinder, dns_enum, whois, httpx_subdomains |
| 2 | **Baseline + Discovery** — + dnssec, ssl_enum, dnstwist, tldx, whois_tldx |
| 3 | **Baseline + Discovery + Vuln Scan** — + nuclei, ffuf |
| 4 | **Full Attack Mode** — + katana, httpx_katana, nuclei, ffuf |
| r | Re-run AI/report (if scan already done) |
| q | Quit |

**Flags**

| Flag | Description |
|------|-------------|
| `--no-ai` | Skip AI analysis (no prompt) |
| `--include-subdomains` | Include subdomains in nuclei, ffuf, katana |
| `--tld-preset <name>` | tldx preset (tech, cheap, all, etc.) |
| `--max-subdomains <n>` | Limit subdomains for httpx_subdomains (default: 50) |

**Example**

```bash
./somniosus.py example.com --interactive --no-ai --tld-preset all
```

Before the scan: *Include subdomains in active scans?* and *Run AI analysis?* Typosquats and TLD variations are discovery-only (never actively scanned).

---

## Tools Needed to Run

### Python

- **Python 3.10+** (standard library only; no pip packages required)

### Required

| Tool | Purpose |
|------|---------|
| **nmap** | Port scanning, service detection |

### Optional (per profile / mode)

| Tool | Purpose |
|------|---------|
| **httpx** | HTTP probing, title/tech detection |
| **dig** | DNS record enumeration |
| **subfinder** | Subdomain discovery |
| **whois** | Domain registration metadata |
| **nuclei** | Vulnerability template scanning |
| **katana** | Web crawler |
| **ffuf** | Content discovery / fuzzing |
| **dnstwist** | Typosquatting / domain permutations |
| **tldx** | TLD enumeration (RDAP) |

### No Binary Required

- **crt.sh** — Certificate Transparency (built-in HTTP API)

### AI (Optional)

- **Ollama** or OpenAI-compatible API. Use `--no-ai` to skip.

### Dependency Check

```bash
./somniosus.py --check
```

---

## Appendix — Full Run Modes

### Profile-Based

```bash
./somniosus.py example.com --profile safe
./somniosus.py example.com --profile thorough
```

| Profile | Tools |
|---------|-------|
| **safe** | nmap, httpx_main, crtsh, subfinder, dns_enum, whois, httpx_subdomains |
| **thorough** | safe + dnssec, ssl_enum, katana, httpx_katana |

### Full Modes (No Prompts)

**--full** — All tools including nuclei, ffuf, dnstwist, tldx, whois_tldx.

```bash
./somniosus.py example.com --full --no-ai
```

**--full-quiet** — Same as --full but skips nuclei, ffuf, katana, httpx_katana.

```bash
./somniosus.py example.com --full-quiet --no-ai
```

### Single-Tool Mode

```bash
./somniosus.py example.com --run nmap
./somniosus.py example.com --run tldx --tld-preset all
```

Available: `nmap`, `httpx`, `crtsh`, `subfinder`, `dns_enum`, `httpx_subdomains`, `dnssec`, `dnstwist`, `tldx`, `whois`, `whois_tldx`, `ssl_enum`, `katana`, `httpx_katana`, `nuclei`, `ffuf`

### Scope & Options

- **--include-subdomains** — Expands nuclei, ffuf, katana to subdomain URLs
- **--tlds** — Comma-separated TLDs for tldx (e.g. `com,io,org,tech`)
- **--tld-preset** — tldx preset (tech, cheap, popular, all). List: `tldx show-tld-presets`
- **-u / --url** — AI endpoint (default: `http://localhost:11434/v1/chat/completions`)
- **OLLAMA_URL** — Environment variable for AI endpoint

### Output

Each run creates `results/<target>/<timestamp>/` with:

- `findings.json`, `tool_results.json`, `report.md`, `report_data.json`
- `raw/` — Original scanner output
- `llm_input.json`, `llm.json`, `llm.md` — (if AI enabled)
