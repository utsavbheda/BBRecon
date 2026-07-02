
# BBRecon

> **Professional Bug Bounty Toolkit v5.1.0**

BBRecon is an asynchronous reconnaissance and OSINT framework built for Bug Bounty Hunters, Penetration Testers, and Security Researchers. It automates asset discovery, fingerprinting, vulnerability detection, OSINT enrichment, and report generation.

---

# Features

## Asset Discovery
- Passive & Active Subdomain Enumeration
- Live Host Detection
- DNS Enumeration
- Reverse DNS / WHOIS / ASN Lookup
- HTTP Fingerprinting
- Port Scanning
- SSL Certificate Analysis
- Technology Detection
- JavaScript Endpoint Discovery

## Vulnerability Detection
- Subdomain Takeover Detection
- CORS Misconfiguration
- Open Redirect Detection
- Git Repository Exposure
- Environment File Exposure
- DNS Health Analysis
- Security Header Analysis
- SSL Expiry Detection

## OSINT
- 20 Integrated Async OSINT Modules
- Certificate Transparency
- DNSSEC Validation
- SPF / DKIM / DMARC Validation
- Firewall Detection
- Domain Reputation
- security.txt Detection
- Typosquat Detection

## Reporting
- SQLite Database
- JSON Export
- CSV Export
- Markdown Reports

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

Python 3.11 or newer is recommended.

Create a virtual environment:

```bash
python3 -m venv .venv
source .venv/bin/activate
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
python3 bbrecon_03072026.py tools
```

This command checks whether supported external tools are installed and available.

---

# Usage

```bash
python3 bbrecon_03072026.py scan example.com

python3 bbrecon_03072026.py scan https://example.com

python3 bbrecon_03072026.py scan example.com --skip-xss --skip-sqli

python3 bbrecon_03072026.py scan example.com --stealth --diff-only

python3 bbrecon_03072026.py tools

python3 bbrecon_03072026.py config show
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

Use BBRecon only on systems that you own or are explicitly authorized to test.

---

# License

Add your preferred open-source license (MIT or Apache-2.0 recommended).
