# BBRecon

# Professional Bug Bounty Toolkit v5.1.0

BBRecon is an automated reconnaissance and OSINT framework for bug bounty hunting and penetration testing. It performs end-to-end asset discovery, fingerprinting, vulnerability checks, OSINT enrichment, and report generation.

> **Version:** v5.1.0

## CLI Preview

> If the screenshot is stored alongside this README, GitHub will render it automatically.

![BBRecon CLI](Screenshot%202026-07-02%20163726.png)

## Features

### Asset Discovery

- Passive Subdomain Enumeration
- Active Subdomain Enumeration
- Live Host Detection
- DNS Enumeration
- Reverse DNS Lookup
- ASN / WHOIS Lookup
- SSL Certificate Collection
- Port Scanning
- HTTP Fingerprinting
- Technology Detection
- JavaScript Endpoint Discovery

### Vulnerability Detection

- Subdomain Takeover
- CORS Misconfiguration
- Open Redirect
- Git Repository Exposure
- Environment File Exposure
- Security Header Analysis
- SSL Expiry Detection

### OSINT

- Certificate Transparency
- DNSSEC Validation
- Zone Transfer Detection
- SPF / DKIM / DMARC Validation
- security.txt Detection
- Firewall Detection
- Domain Reputation
- Cookie Analysis
- Typosquat Detection

### Reporting

- SQLite Database
- JSON Export
- CSV Export
- Markdown Reports

## Recon Pipeline

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

## Example Usage

```bash
python3 bbrecon_03072026.py scan example.com
python3 bbrecon_03072026.py scan https://example.com
python3 bbrecon_03072026.py scan example.com --skip-xss --skip-sqli
python3 bbrecon_03072026.py scan example.com --stealth --diff-only
python3 bbrecon_03072026.py tools
python3 bbrecon_03072026.py config show
```

## Database

Core tables include:

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
- whois
- certificate_transparency
- reputation
- firewall_detection

## Requirements

- Python 3.11+
- aiohttp
- aiosqlite
- dnspython
- python-Wappalyzer

## Roadmap

- HTML Dashboard
- Docker Support
- REST API
- Plugin SDK
- Shodan Integration
- Censys Integration
- Screenshot Engine
- Notification System
