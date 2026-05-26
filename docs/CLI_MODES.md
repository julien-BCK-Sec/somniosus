# CLI Modes and Scope

Quick reference for run modes, scope, and external service behavior.

---

## Profiles

| Profile | Tools |
|---------|-------|
| **safe** | nmap, httpx_main, crtsh, subfinder, dns_enum, whois, httpx_subdomains |
| **thorough** | safe + dnssec, ssl_enum, katana, httpx_katana |

---

## Scope

**Default:** Heavy tools (nuclei, ffuf, katana) scan only the CLI target. httpx probes the main target and discovered subdomains (light connection checks).

**--include-subdomains:** Expands nuclei, ffuf, katana to subdomain URLs.

---

## Full Modes (no prompts)

| Flag | Tools | Notes |
|------|-------|-------|
| **--full** | thorough + dnstwist, tldx, whois_tldx, whois, nuclei, ffuf | tld-preset all, include-subdomains |
| **--full-quiet** | thorough (no katana) + dnstwist, tldx, whois_tldx, whois | Skips nuclei, ffuf, katana, httpx_katana |

Both set `--include-subdomains` and `--tld-preset all` implicitly. No interactive menu.

---

## Interactive Mode

`--interactive` shows the menu **first** — no tools run until you pick.

| Choice | Scan |
|--------|------|
| 1 | Baseline |
| 2 | Baseline + Discovery |
| 3 | Baseline + Discovery + Vuln Scan |
| 4 | Full Attack Mode |
| r | Re-run AI/report |
| q | Quit |

Before scan: *Include subdomains?* and *Run AI analysis?* Use `--no-ai` to skip AI entirely. Typosquats/TLDs never actively scanned.

---

## External Services

**crt.sh** — Certificate Transparency API. Retries on 5xx/connection errors: 2 retries (3 attempts total), 5-second delay between attempts.
