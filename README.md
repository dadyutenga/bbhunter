<p align="center">
  <pre align="center">
  ██████╗ ██████╗ ██╗  ██╗██╗   ██╗███╗   ██╗████████╗███████╗██████╗
  ██╔══██╗██╔══██╗██║  ██║██║   ██║████╗  ██║╚══██╔══╝██╔════╝██╔══██╗
  ██████╔╝██████╔╝███████║██║   ██║██╔██╗ ██║   ██║   █████╗  ██████╔╝
  ██╔══██╗██╔══██╗██╔══██║██║   ██║██║╚██╗██║   ██║   ██╔══╝  ██╔══██╗
  ██████╔╝██████╔╝██║  ██║╚██████╔╝██║ ╚████║   ██║   ███████╗██║  ██║
  ╚═════╝ ╚═════╝ ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝   ╚═╝   ╚══════╝╚═╝  ╚═╝
  </pre>
</p>

<p align="center">
  <strong>Bug Bounty Hunter CLI — Recon · Scan · Payloads · AI Analysis · Reports</strong>
</p>

<p align="center">
  <a href="#features">Features</a> •
  <a href="#installation">Installation</a> •
  <a href="#usage">Usage</a> •
  <a href="#modules">Modules</a> •
  <a href="#ai-integration">AI Integration</a> •
  <a href="#contributing">Contributing</a>
</p>

---

## Overview

**BBHunter** is a lightweight, zero-dependency Python CLI tool built for bug bounty hunters and security researchers. It streamlines the reconnaissance-to-report workflow by combining subdomain enumeration, vulnerability scanning, payload generation, AI-powered analysis, and professional report writing into a single command-line application.

BBHunter requires **no external Python packages** — it runs entirely on the Python standard library, making it easy to deploy on any system with Python 3 installed.

---

## Features

| Module | Description |
|---|---|
| **Recon** | Multi-threaded subdomain enumeration with DNS resolution, HTTP/HTTPS probing, and TLS certificate analysis |
| **Scan** | Security header checks, sensitive path discovery (34+ paths), CORS misconfiguration detection, cookie flag analysis, and TLS expiry warnings |
| **Payloads** | 100+ ready-to-use payloads across 7 vulnerability types (XSS, SQLi, SSRF, LFI, Open Redirect, SSTI, XXE) |
| **AI Analyzer** | Send scan results to Claude or GPT-4 for prioritized findings, exploit path suggestions, and business impact analysis |
| **Report Writer** | Interactive CLI that generates professional Markdown bug bounty reports with auto-filled CVSS scores and remediation advice |

---

## Tech Stack

| Component | Details |
|---|---|
| **Language** | Python 3 |
| **Dependencies** | None — pure Python standard library |
| **Concurrency** | `concurrent.futures.ThreadPoolExecutor` |
| **AI Providers** | OpenAI (GPT-4o-mini) · Anthropic (Claude 3.5 Haiku) |
| **Output Formats** | JSON (recon/scan) · TXT (payloads) · Markdown (reports) |

---

## Installation

### Prerequisites

- **Python 3.6+** (no additional packages required)
- *(Optional)* `nslookup` for DNS TXT record queries
- *(Optional)* API keys for AI analysis (OpenAI or Anthropic)

### Setup

```bash
# Clone the repository
git clone https://github.com/dadyutenga/bbhunter.git
cd bbhunter

# Verify Python is available
python3 --version

# Run BBHunter
python3 bbhunter.py --help
```

No `pip install`, virtual environments, or build steps are needed.

---

## Environment Variables

| Variable | Required | Description |
|---|---|---|
| `ANTHROPIC_API_KEY` | For AI module | Your Anthropic API key for Claude analysis |
| `OPENAI_API_KEY` | For AI module | Your OpenAI API key for GPT-4 analysis |
| `BBHUNTER_AI_MAX_TOKENS` | No | Max tokens for AI responses (default: `1200`) |
| `BBHUNTER_AI_MAX_PROMPT_CHARS` | No | Max prompt size sent to AI (default: `12000`) |

```bash
# Set API keys (choose one or both)
export ANTHROPIC_API_KEY="sk-ant-..."
export OPENAI_API_KEY="sk-..."
```

---

## Usage

```
python3 bbhunter.py [command] [options] -o [output_dir]
```

All commands accept an optional `-o / --output` flag to set the output directory (default: `./bbhunter_output`).

---

## Modules

### 1. Recon — Subdomain Enumeration & DNS

Enumerate subdomains, resolve DNS, probe HTTP/HTTPS endpoints, and extract TLS and DNS TXT records.

```bash
# Basic recon
python3 bbhunter.py recon -d example.com

# Recon with 100 threads and custom output
python3 bbhunter.py recon -d example.com -t 100 -o ./results
```

| Option | Description |
|---|---|
| `-d, --domain` | Target domain (required) |
| `-t, --threads` | Number of threads (default: `50`) |
| `-o, --output` | Output directory |

**Output:** `[output_dir]/[domain]_recon.json`

<details>
<summary><strong>Example Output (JSON)</strong></summary>

```json
{
  "domain": "example.com",
  "timestamp": "2025-01-15 10:30:00",
  "subdomains": [
    {
      "fqdn": "www.example.com",
      "ip": "93.184.216.34",
      "http": { "status": 200, "server": "ECAcc (dcd/7D5A)" },
      "https": { "status": 200, "server": "ECAcc (dcd/7D5A)" }
    },
    {
      "fqdn": "api.example.com",
      "ip": "93.184.216.35",
      "http": { "status": 301, "server": "nginx" },
      "https": { "status": 200, "server": "nginx" }
    }
  ],
  "dns_txt": ["v=spf1 include:_spf.google.com ~all"]
}
```

</details>

---

### 2. Scan — Vulnerability Scanner

Checks security headers, discovers sensitive paths, detects CORS misconfigurations, analyzes cookie flags, and verifies TLS certificate expiry.

```bash
# Scan a URL
python3 bbhunter.py scan -u https://example.com

# Scan and save results
python3 bbhunter.py scan -u https://example.com -o ./results
```

| Option | Description |
|---|---|
| `-u, --url` | Target URL (required) |
| `-o, --output` | Output directory |

**Checks performed:**
- 7 security headers (HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy, X-XSS-Protection)
- Technology disclosure via `Server` and `X-Powered-By` headers
- 34+ sensitive paths (`.env`, `.git/config`, `wp-config.php`, admin panels, API docs, Spring Boot Actuator endpoints, database backups, etc.)
- CORS misconfiguration (wildcard origin, reflected origin with credentials)
- Cookie flag analysis (HttpOnly, Secure, SameSite)
- TLS certificate expiry warning (< 30 days)

**Severity levels:** `CRITICAL` · `HIGH` · `MEDIUM` · `LOW` · `INFO`

**Output:** `[output_dir]/scan_[host].json`

---

### 3. Payloads — Payload Generator

Generate ready-to-use payloads for manual testing across 7 vulnerability classes.

```bash
# List all available payload types
python3 bbhunter.py payloads --list

# Generate all XSS payloads
python3 bbhunter.py payloads -t xss

# Generate SQLi bypass payloads and save to file
python3 bbhunter.py payloads -t sqli -c bypass -o ./results
```

| Option | Description |
|---|---|
| `-t, --type` | Vulnerability type (required unless `--list`) |
| `-c, --category` | Category: `basic` / `bypass` / `blind` / `all` (default: `all`) |
| `--list` | List all available types |
| `-o, --output` | Output directory |

**Supported vulnerability types:**

| Type | Categories | Description |
|---|---|---|
| `xss` | basic, bypass, blind | Cross-Site Scripting |
| `sqli` | basic, bypass, blind | SQL Injection |
| `ssrf` | basic, bypass | Server-Side Request Forgery |
| `lfi` | basic, bypass | Local File Inclusion |
| `open_redirect` | basic | Open Redirect |
| `ssti` | basic | Server-Side Template Injection |
| `xxe` | basic | XML External Entity |

**Output:** `[output_dir]/payloads_[type].txt`

---

### 4. AI Analyzer — AI-Powered Vulnerability Analysis

Send scan results to Claude or GPT-4 for automated prioritized analysis with exploit path suggestions and business impact context.

```bash
# Analyze a scan result file
python3 bbhunter.py ai-analyze -f ./results/scan_example.com.json

# Auto-analyze the latest scan in the output folder
python3 bbhunter.py ai-analyze --auto -o ./results

# Scan a URL then analyze automatically
python3 bbhunter.py ai-analyze -u https://example.com --auto -o ./results
```

| Option | Description |
|---|---|
| `-f, --file` | Path to scan JSON results |
| `-u, --url` | Target URL to scan first (use with `--auto`) |
| `--auto` | Auto use latest scan JSON or scan URL first |
| `-o, --output` | Output directory |

> **Note:** Requires either `ANTHROPIC_API_KEY` or `OPENAI_API_KEY` to be set.

---

### 5. Report Writer — Bug Bounty Report Generator

Interactive CLI that walks you through writing a professional bug bounty report with auto-generated CVSS scores and remediation advice.

```bash
# Launch the interactive report writer
python3 bbhunter.py report

# Specify output folder
python3 bbhunter.py report -o ./my_reports
```

The report writer prompts you for:
- Program name and your handle
- Vulnerability type and severity
- Affected URL and vulnerable parameter
- Summary, PoC payload, and steps to reproduce

It auto-fills:
- Impact description based on vulnerability type
- CVSS score and vector based on severity
- Remediation advice

**Supported vulnerability types:** `xss` · `sqli` · `ssrf` · `lfi` · `idor` · `cors` · `ssti` · `xxe` · `other`

**Severity levels:** `critical` · `high` · `medium` · `low`

**Output:** `[output_dir]/report_[type]_[date].md`

---

## Workflow Example

A typical end-to-end bug bounty workflow:

```bash
# Step 1: Recon the target domain
python3 bbhunter.py recon -d example.com -o ./hunt

# Step 2: Scan a discovered subdomain
python3 bbhunter.py scan -u https://admin.example.com -o ./hunt

# Step 3: Analyze findings with AI
python3 bbhunter.py ai-analyze --auto -o ./hunt

# Step 4: Generate relevant payloads
python3 bbhunter.py payloads -t xss -c bypass -o ./hunt

# Step 5: Write the bug bounty report
python3 bbhunter.py report -o ./hunt
```

---

## Output Files

All output is saved to the specified output directory (default: `./bbhunter_output/`):

| File | Command | Format |
|---|---|---|
| `[domain]_recon.json` | `recon` | JSON |
| `scan_[host].json` | `scan` | JSON |
| `payloads_[type].txt` | `payloads` | Text |
| `report_[type]_[date].md` | `report` | Markdown |

---

## Project Structure

```
bbhunter/
├── bbhunter.py              # Main CLI application (all modules)
├── bbhunter_commands.txt    # Command reference guide
├── bbhunter_roadmap.md      # Feature roadmap for v2.0
├── bbhunter_output/         # Default output directory
└── README.md                # This file
```

---

## Roadmap

BBHunter v2.0 plans include:

- 🔍 Certificate transparency (crt.sh) integration
- 🌐 Shodan API integration
- 🧬 Nuclei template support
- 🛡️ WAF detection and bypass techniques
- 📜 JavaScript analysis for hidden endpoints
- 🐛 CVE matching against discovered technologies
- 🤖 Enhanced AI prompt chaining
- 📊 HTML report generation
- 🔄 Distributed scanning support

See [`bbhunter_roadmap.md`](bbhunter_roadmap.md) for the full roadmap.

---

## Contributing

Contributions are welcome! To get started:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/your-feature`)
3. Make your changes
4. Test locally (`python3 bbhunter.py --help`)
5. Submit a pull request

---

## Disclaimer

BBHunter is intended for **authorized security testing only**. Always obtain proper permission before scanning any target. The authors are not responsible for any misuse of this tool.

---

## License

This project is open source. See the repository for license details.

---

## Suggested GitHub Topics

<!-- 
Add these as repository topics in GitHub Settings → Topics:

bug-bounty, bug-bounty-tools, security, penetration-testing, reconnaissance,
vulnerability-scanner, python, cli-tool, subdomain-enumeration, xss, sqli,
ssrf, payload-generator, security-headers, cors, ai-security, openai,
cybersecurity, ethical-hacking, infosec
-->

`bug-bounty` · `bug-bounty-tools` · `security` · `penetration-testing` · `reconnaissance` · `vulnerability-scanner` · `python` · `cli-tool` · `subdomain-enumeration` · `payload-generator` · `security-headers` · `ai-security` · `cybersecurity` · `ethical-hacking` · `infosec`
