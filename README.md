
# BBRecon

> **Professional Bug Bounty Toolkit v5.1.0**

BBRecon is an asynchronous reconnaissance and OSINT framework built for Bug Bounty Hunters, Penetration Testers, and Security Researchers. It automates asset discovery, fingerprinting, vulnerability detection, OSINT enrichment, and report generation.

---

# Features

## Asset Discovery
- Passive subdomain enumeration (subfinder, amass, assetfinder — run concurrently)
- DNS brute-force via massdns (falls back to a built-in wordlist if seclists isn't installed)
- Live host probing with Wappalyzer technology fingerprinting
- URL discovery (waybackurls, gau, katana)
- Port scanning (naabu) + Nmap deep scan on discovered ports

## Vulnerability Detection
- Tech-aware Nuclei scanning per live host (template tags selected from fingerprinted stack)
- Marker-based reflected XSS (concurrent, evidence files saved per finding)
- Error-based SQL injection
- Regex-based secrets scanning (AWS/Google/GitHub/Slack keys, JWTs, Stripe/Twilio tokens, private keys)

## OSINT (--skip-osint to disable)
- 20 Integrated Async OSINT Modules
- Certificate Transparency
- DNSSEC Validation
- SPF / DKIM / DMARC Validation
- Firewall Detection
- Domain Reputation
- security.txt Detection
- Typosquat Detection

## Reporting
- Scan history stored in SQLite — each scan diffs against the previous one for the same domain (--diff-only)
- Self-contained HTML report (report.html)
- Per-scan state.json snapshot
- Raw txt outputs (subdomains, live hosts, URLs, ports, findings)

---

# 12-Phase Reconnaissance Pipeline

1. Target Initialization
2. Passive Enumeration
3. Active Enumeration
4. Live Host Detection
5. HTTP Fingerprinting
6. Port Scanning
7. DNS Enumeration
8. Technology Detection
9. Vulnerability Detection
10. SQLite Storage
11. OSINT Posture Assessment
12. Report Generation

---

# Installation

## Supported Platforms

- Kali Linux (Recommended)
- Ubuntu 22.04+
- Debian 12+
- Parrot OS
- macOS (limited external tool support)

---

## Clone Repository

```bash
git clone https://github.com/utsavbheda/BBRecon.git
cd BBRecon
```

---

## Python Requirements

Python 3.10 or newer is recommended.

Create a virtual environment:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install aiohttp>=3.8.0 aiosqlite>=0.17.0 python-Wappalyzer>=0.3.1 dnspython>=2.4.0
```

Install Python dependencies:

```bash
pip install -r requirements.txt
```

---

## Kali Linux Dependencies

```bash
sudo apt update

sudo apt install -y \
python3 python3-pip python3-venv \
git curl jq sqlite3 nmap whois dnsutils \
amass assetfinder subfinder httpx gau katana \
nuclei wafw00f
```

Optional tools (recommended if available):

- massdns
- dnsx
- naabu
- ffuf

Update Nuclei templates:

```bash
nuclei -update-templates
```

---

## Verify Installation

```bash
python3 BBRecon.py tools
```

This command checks whether supported external tools are installed and available.

---
## Go-based recon tools

```bash
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/tomnomnom/assetfinder@latest
go install github.com/owasp-amass/amass/v4/...@master
go install github.com/tomnomnom/waybackurls@latest
go install github.com/lc/gau/v2/cmd/gau@latest
go install github.com/projectdiscovery/katana/cmd/katana@latest
go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install github.com/projectdiscovery/httpx/cmd/httpx@latest

echo 'export PATH=$PATH:$HOME/go/bin' >> ~/.zshrc   # or ~/.bashrc
source ~/.zshrc
```
---

# Usage

```bash
# Basic scan (bare domain or full URL both work — scheme/path auto-stripped)
python3 BBRecon.py scan example.com
python3 BBRecon.py scan https://example.com

# Skip specific scanners
python3 BBRecon.py scan example.com --skip-xss --skip-sqli --skip-secrets

# Skip the 6 OSINT-derived posture checks (takeover, CORS, open redirect, git/env exposure, DNS health)
python3 BBRecon.py scan example.com --skip-osint

# No nuclei (fastest scan)
python3 BBRecon.py scan example.com --no-nuclei

# Stealth mode (slower, T2 nmap timing, lower request rate)
python3 BBRecon.py scan example.com --stealth

# Show diff vs previous scan of this domain (full scan still runs)
python3 BBRecon.py scan example.com --diff-only

# Custom output directory
python3 BBRecon.py scan example.com --output ./my_results

# Debug logging (every liveness/probe/DNS failure logged)
BBRECON_DEBUG=1 python3 BBRecon.py scan example.com

# Check external tool availability
python3 BBRecon.py tools

# View / initialize config
python3 BBRecon.py config show
python3 BBRecon.py config init
```

---

# Output

BBRecon generates:

- SQLite Database
- JSON Report
- CSV Report
- Markdown Report
- Log Files

---

# Database

Main tables include:

- targets
- subdomains
- live_hosts
- ports
- dns_records
- technologies
- http_headers
- ssl_certificates
- takeover_findings
- cors_findings
- redirect_findings
- git_exposure_findings
- env_file_findings
- dns_health
- osint_results

---

# Roadmap

- HTML Dashboard
- Docker Support
- REST API
- Plugin SDK
- Distributed Scanning
- Shodan Integration
- Censys Integration
- Screenshot Engine

---

# Disclaimer

Use BBRecon only against systems you own or are explicitly authorized to test. The authors and contributors are not responsible for misuse.

---

# License

Add your preferred open-source license (MIT or Apache-2.0 recommended) — not yet specified in this repository.