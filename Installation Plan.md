# BBRecon v5.1.0 — Kali Linux Install Guide

Target file: `bbrecon_02072026.py`

---

## Prerequisites

Kali Linux (2023+). Python 3.10+ (ships with Kali). Go 1.21+ required for Go tools.

---

## Step 1 — System packages

```bash
sudo apt update && sudo apt install -y \
    python3 python3-pip python3-venv \
    nmap git curl wget golang \
    libpcap-dev build-essential \
    whois
```

`whois` is new vs prior install docs — required for the WHOIS registrar/creation-date
lookup inside `run_dns_health_check`. It is now registered in `ToolChecker.TOOLS`,
so `bbrecon tools` will correctly flag it as missing/available.

Verify:
```bash
python3 --version   # need 3.10+
go version          # need 1.21+
whois --version
```

---

## Step 2 — Get the tool

```bash
mkdir -p ~/tools/bbrecon
cp bbrecon_02072026.py ~/tools/bbrecon/
cd ~/tools/bbrecon
```

---

## Step 3 — Python virtual environment

```bash
python3 -m venv venv
source venv/bin/activate
```

---

## Step 4 — Python dependencies

```bash
pip install --upgrade pip
pip install \
    aiohttp>=3.8.0 \
    aiosqlite>=0.17.0 \
    python-Wappalyzer>=0.3.1 \
    dnspython>=2.4.0
```

`dnspython` is **new** vs the v4.x install docs — required by `run_dns_health_check`
(SPF/DMARC TXT lookups, DNSSEC DNSKEY presence check, AXFR zone-transfer attempt,
CNAME resolution in `run_subdomain_takeover`). Import is guarded
(`_DNSPYTHON_AVAILABLE`); the tool will still run without it, but those specific
checks silently degrade to `"-"` / `"Not signed"` / skipped rather than crashing.
Install it anyway — degraded DNS posture data is close to useless for a bug bounty
recon pass.

`aiofiles` and `beautifulsoup4` are **not** dependencies of this file (removed in
the v4.1.0 bugfix pass — dead imports). Do not install them expecting bbrecon to
use them.

Verify install:
```bash
python3 -c "import aiohttp, aiosqlite, dns.resolver; print('Python deps OK')"
```

---

## Step 5 — Go path setup

```bash
echo 'export PATH=$PATH:$HOME/go/bin' >> ~/.zshrc
source ~/.zshrc
```

---

## Step 6 — Go-based recon tools

```bash
# Subdomain enumeration
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/tomnomnom/assetfinder@latest
go install github.com/owasp-amass/amass/v4/...@master

# URL discovery
go install github.com/tomnomnom/waybackurls@latest
go install github.com/lc/gau/v2/cmd/gau@latest
go install github.com/projectdiscovery/katana/cmd/katana@latest

# Port scanning
go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest

# Vuln scanning
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest

# HTTP probing (optional — not called directly but good to have)
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
```

Verify:
```bash
for tool in subfinder assetfinder waybackurls gau katana naabu nuclei httpx; do
    which $tool && echo "$tool OK" || echo "$tool MISSING"
done
```

---

## Step 7 — Nuclei templates (required for nuclei to work)

```bash
nuclei -update-templates
```

---

## Step 8 — massdns (DNS brute-force)

```bash
cd /tmp
git clone https://github.com/blechschmidt/massdns.git
cd massdns
make
sudo cp bin/massdns /usr/local/bin/
massdns --version
```

---

## Step 9 — SecLists wordlist (optional, improves massdns coverage)

```bash
sudo apt install -y seclists
# or
git clone https://github.com/danielmiessler/SecLists.git /usr/share/seclists
```

---

## Step 10 — Verify everything

```bash
cd ~/tools/bbrecon
source venv/bin/activate
python3 bbrecon_02072026.py tools
```

Expected output: table showing which tools are available vs missing — should
now include `whois` as a row (previously silently absent from this table).

---

## Step 11 — Init config

```bash
python3 bbrecon_02072026.py config init
```

Creates `~/.bbrecon/config.json` with defaults (28 fields — unchanged field
count from v5.0.0; Pair 5 added zero new Config fields).

Optional — edit config to add webhooks / GitHub token / stealth mode:
```bash
nano ~/.bbrecon/config.json
```

Key fields to set (webhook/dork fields exist but are NOT yet wired — U7/U8
still unimplemented, see handoff):
```json
{
  "slack_webhook": "https://hooks.slack.com/...",
  "discord_webhook": "https://discord.com/api/webhooks/...",
  "github_token": "ghp_...",
  "nuclei_severity": "low,medium,high,critical",
  "massdns_rate": 5000
}
```

---

## Step 12 — Run first scan

```bash
# Full scan (12-phase pipeline, includes Argus-derived posture checks)
python3 bbrecon_02072026.py scan example.com

# Skip heavy scanners for a fast recon-only run
python3 bbrecon_02072026.py scan example.com --skip-xss --skip-sqli --skip-secrets

# Skip the 6 Argus-derived checks (takeover, CORS, open redirect, git/env
# exposure, DNS/mail/cert posture) — NEW flag vs v5.0.0
python3 bbrecon_02072026.py scan example.com --skip-argus

# Stealth mode (slower, lower noise)
python3 bbrecon_02072026.py scan example.com --stealth

# No nuclei (fastest)
python3 bbrecon_02072026.py scan example.com --no-nuclei

# Only show new assets vs last scan
python3 bbrecon_02072026.py scan example.com --diff-only

# Custom output dir
python3 bbrecon_02072026.py scan example.com -o ./my_results

# Debug logging (every liveness/probe/DNS failure logged)
BBRECON_DEBUG=1 python3 bbrecon_02072026.py scan example.com
```

**Caution before trusting Argus-derived results:** the 6 Argus-derived checks
(takeover, CORS, open redirect, git exposure, env file exposure, DNS health)
have not been validated against live network traffic as of this build — only
structurally (syntax, DB round-trip, dataclass logic). Run one supervised scan
against an authorized test target before relying on their output for a real
engagement. See project handoff for details.

---

## Output locations

```
~/.bbrecon/bbrecon.db          ← SQLite (17 tables: 11 original + 6 Argus-derived)
~/.bbrecon/config.json         ← Config (28 fields)
./bbrecon_output/<domain>/<ts>/
    subdomains.txt
    live_hosts.txt
    urls_all.txt
    urls_with_params.txt
    ports.txt
    xss_findings.txt
    sqli_findings.txt
    secret_findings.txt
    xss_evidence/              ← HTML evidence files per XSS hit
    nuclei_*.json              ← Per-host nuclei output
    diff_<ts>.json             ← New assets vs last scan
    state.json                 ← Scan state snapshot (includes new finding counts)
    report.html                ← Full HTML report (open in browser)
    nmap_scan.*                ← Nmap output (if nmap ran)
```

Note: the 6 new Argus-derived finding types (takeover, CORS, redirect, git
exposure, env file, DNS health) are persisted to the DB and included in
`target.vulnerabilities` for count purposes, but `report.html` has **no
dedicated section** for them yet — cosmetic gap, data is not lost, just not
rendered. Check the DB or `state.json` counts directly if you need those
numbers without opening the report.

---

## Quick alias (optional)

```bash
echo "alias bbrecon='cd ~/tools/bbrecon && source venv/bin/activate && python3 bbrecon_02072026.py'" >> ~/.zshrc
source ~/.zshrc

# Then just run:
bbrecon scan example.com
```

---

## Minimum viable install (if time is short)

Gets you a working partial scan (no DNS brute, no nuclei per-host, no Argus
posture checks — those need dnspython + whois):

```bash
sudo apt install -y python3 python3-pip nmap
pip install aiohttp aiosqlite python-Wappalyzer
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/tomnomnom/waybackurls@latest
go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
python3 bbrecon_02072026.py scan example.com --no-nuclei --skip-argus
```

---

## Troubleshooting

| Problem | Fix |
|---------|-----|
| `ModuleNotFoundError: aiohttp` | `pip install aiohttp` — make sure venv is active |
| `ModuleNotFoundError: dns` | `pip install dnspython` — Argus DNS health checks degrade silently without it, don't skip it |
| `subfinder: command not found` | `export PATH=$PATH:$HOME/go/bin` then re-run |
| `nuclei: no templates` | Run `nuclei -update-templates` |
| `massdns: command not found` | See Step 8 — needs manual build |
| `whois` missing from `bbrecon tools` output row but WHOIS field always `-` in DNS health | Install: `sudo apt install whois` |
| Wappalyzer regex warning | Safe to ignore — suppressed in code |
| `Permission denied` on naabu | `sudo setcap cap_net_raw+ep $(which naabu)` |
| Scan output dir collision | Two scans same domain same second — just wait 1s |
| `--skip-argus` results missing from report.html even without the flag | Expected — no HTML report cards for Argus findings yet, check DB/state.json |
