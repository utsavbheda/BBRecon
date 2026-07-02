#!/usr/bin/env python3
"""
BBRecon - Professional Bug Bounty Toolkit
Version: 5.1.0
Date: 2026-06-09

Pair 5 additions vs 5.0.0 (bbrecon_06062026.py):
  20 OSINT modules integrated as async BBReconEngine methods
  (selected from 148 candidates in the source OSINT module inventory;
  see handoff_09062026.md for full gap-analysis and selection rationale).
  All OSINT modules were originally standalone sync/requests CLI scripts;
  logic was reimplemented async-on-aiohttp to match bbrecon's existing
  concurrency model, not copy-pasted.

  New dataclasses: TakeoverFinding, CorsFinding, OpenRedirectFinding,
    GitExposureFinding, EnvFileFinding, DnsHealthFinding
  New DB tables: takeover_findings, cors_findings, redirect_findings,
    git_exposure_findings, env_file_findings, dns_health
  New engine methods: run_subdomain_takeover, run_cors_scan,
    run_open_redirect_scan, run_git_exposure_check, run_env_file_check,
    run_dns_health_check (consolidates 13 single-signal OSINT scripts:
    dns_records, zonetransfer, dnssec, ct_log_query, whois_lookup,
    ssl_expiry, security_txt, spf_dkim_dmarc_validator,
    domain_reputation_check, typosquat_domain_checker, firewall_detection,
    http_security, cookies)
  New CLI flag: --skip-osint
  New dependency: dnspython (guarded import, degrades gracefully if absent)
  New full_scan phase: Phase 11 (OSINT posture checks), pipeline now 12-phase

Fixes vs 4.1.0 (bbrecon_05062026.py):
  B11 - normalize_domain(): strip scheme/path from user-supplied URL input
  B12 - check_liveness(): HEAD→GET fallback; status < 500 (was < 400); CDN-aware
  B13 - check_liveness(): proper UA header attached to session
  B14 - check_liveness(): debug-level logging instead of silent exception swallow
  B15 - run_live_probe(): domain added as bare hostname, not raw target.domain
  B16 - MassdnsRunner: receives bare domain, never URL string
  B17 - XSSScanner.scan_urls(): concurrent via asyncio.gather (was sequential loop)
  B18 - SecretsScanner: concurrency bounded via asyncio.Semaphore(20)
  B19 - SQLiScanner: UA header on session
  B20 - Config: liveness_timeout added; liveness_retries added
  B21 - full_scan(): --diff-only no longer suppresses banner (was misleading)
  B22 - Target.__post_init__: output_dir uses normalized domain for safe path
  B23 - _async_main: domain validated before engine call; ValueError shown cleanly
  B24 - katana gated on target.live_url (not target.is_live bool) to survive 403/redirect
  B25 - logging level respects BBRECON_DEBUG env var
"""

# ============================================================
# STDLIB IMPORTS
# ============================================================
import os
import re
import sys
import stat
import asyncio
import argparse
import hashlib
import json
import logging
import shutil
import tempfile
import warnings
from dataclasses import dataclass, field, asdict
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import urlparse, parse_qs, urlencode, quote

# ============================================================
# THIRD-PARTY GUARD
# ============================================================
try:
    import aiohttp
    import aiosqlite
except ImportError as e:
    print(f"[!] Missing dependency: {e}")
    print("[*] Run: pip install aiohttp aiosqlite python-Wappalyzer")
    sys.exit(1)

try:
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        from Wappalyzer import Wappalyzer, WebPage
    _WAPPALYZER_AVAILABLE = True
except ImportError:
    _WAPPALYZER_AVAILABLE = False
    Wappalyzer = None  # type: ignore
    WebPage = None     # type: ignore

try:
    import dns.resolver
    import dns.query
    _DNSPYTHON_AVAILABLE = True
except ImportError:
    _DNSPYTHON_AVAILABLE = False
    dns = None  # type: ignore

import ssl
import socket

# ============================================================
# LOGGING
# ============================================================
_debug = os.environ.get("BBRECON_DEBUG", "").lower() in ("1", "true", "yes")
logging.basicConfig(
    level=logging.DEBUG if _debug else logging.WARNING,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
log = logging.getLogger(__name__)

# ============================================================
# CONSTANTS
# ============================================================
VERSION       = "5.1.0"
APP_NAME      = "BBRecon"
CONFIG_DIR    = Path.home() / ".bbrecon"
CONFIG_FILE   = CONFIG_DIR / "config.json"
DEFAULT_OUTPUT = Path("./bbrecon_output")
DEFAULT_DB_PATH = Path.home() / ".bbrecon" / "bbrecon.db"

_RETRY_STATUSES  = {429, 500, 502, 503, 504}
_DEFAULT_RETRIES = 5
_BASE_DELAY      = 1.0
_MAX_DELAY       = 60.0

# Browser-like UA used for all outbound HTTP requests
_DEFAULT_UA = (
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
)

# ============================================================
# SECTION 1: DOMAIN NORMALISATION  ← NEW (fixes B11, B15, B16)
# ============================================================

_DOMAIN_RE = re.compile(
    r'^(?:[a-zA-Z0-9]'
    r'(?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)'
    r'+[a-zA-Z]{2,}$'
)


def normalize_domain(raw: str) -> str:
    """
    Accept any of:
        example.com
        www.example.com
        https://example.com
        https://example.com/path?q=1
        https://example.com:8443/

    Returns bare hostname without scheme, port, or path.
    Raises ValueError if result fails basic domain regex.

    Used at CLI entry AND wherever bare domain is required
    (MassdnsRunner, LiveProbe host set, check_liveness).
    """
    raw = raw.strip().rstrip("/")
    if "://" in raw:
        parsed = urlparse(raw)
        raw = parsed.netloc or raw
    # Strip port
    raw = raw.split(":")[0]
    # Strip any remaining path cruft (e.g. "example.com/path")
    raw = raw.split("/")[0]
    raw = raw.lower()
    if not _DOMAIN_RE.match(raw):
        raise ValueError(
            f"'{raw}' does not look like a valid domain. "
            "Pass a bare hostname e.g. example.com"
        )
    return raw


# ============================================================
# SECTION 2: ERROR TYPES
# ============================================================

class ApiResponseError(Exception):
    def __init__(self, *, code: int, detail: str):
        super().__init__()
        self.code: int   = code
        self.detail: str = detail

    def to_dict(self) -> dict:
        return {"code": self.code, "detail": self.detail}

    def __str__(self) -> str:
        return json.dumps(self.to_dict(), indent=4)


# ============================================================
# SECTION 3: ASYNC HTTP CLIENT (Pair 1 U2)
# ============================================================

@dataclass
class AsyncClient:
    """Generic async HTTP client with exponential-backoff retry."""
    base_url: str
    retries:  int = _DEFAULT_RETRIES
    _session: Optional[aiohttp.ClientSession] = field(
        default=None, repr=False, init=False
    )

    def _headers(self) -> Dict[str, str]:
        return {"User-Agent": _DEFAULT_UA}

    async def _get_session(self) -> aiohttp.ClientSession:
        if self._session is None or self._session.closed:
            self._session = aiohttp.ClientSession(headers=self._headers())
        return self._session

    async def get(
        self, path: str, params: Optional[Dict[str, Any]] = None
    ) -> Any:
        url   = f"{self.base_url}{path}"
        session = await self._get_session()
        delay = _BASE_DELAY
        for attempt in range(self.retries + 1):
            try:
                async with session.get(url, params=params) as resp:
                    if resp.status == 200:
                        return await resp.json()
                    if resp.status in _RETRY_STATUSES and attempt < self.retries:
                        retry_after = float(resp.headers.get("Retry-After", delay))
                        wait = min(retry_after, _MAX_DELAY)
                        log.warning(
                            "HTTP %s from %s — retry %d/%d in %.1fs",
                            resp.status, url, attempt + 1, self.retries, wait,
                        )
                        await asyncio.sleep(wait)
                        delay = min(delay * 2, _MAX_DELAY)
                        continue
                    body = await resp.json()
                    raise ApiResponseError(code=resp.status, detail=body)
            except aiohttp.ClientConnectionError as exc:
                if attempt < self.retries:
                    log.warning(
                        "Connection error — retry %d/%d: %s",
                        attempt + 1, self.retries, exc,
                    )
                    await asyncio.sleep(min(delay, _MAX_DELAY))
                    delay = min(delay * 2, _MAX_DELAY)
                else:
                    raise
        raise ApiResponseError(code=0, detail="Max retries exceeded")

    async def post(self, path: str, json_body: Dict[str, Any]) -> Any:
        url     = f"{self.base_url}{path}"
        session = await self._get_session()
        async with session.post(url, json=json_body) as resp:
            body = await resp.json()
            if resp.status in (200, 201):
                return body
            raise ApiResponseError(code=resp.status, detail=body)

    async def delete(self, path: str) -> bool:
        url     = f"{self.base_url}{path}"
        session = await self._get_session()
        async with session.delete(url) as resp:
            if resp.status == 204:
                return True
            body = await resp.json()
            raise ApiResponseError(code=resp.status, detail=body)

    async def close(self) -> None:
        if self._session and not self._session.closed:
            await self._session.close()

    async def __aenter__(self) -> "AsyncClient":
        return self

    async def __aexit__(self, *_: Any) -> None:
        await self.close()


@dataclass
class AuthenticatedClient(AsyncClient):
    token: str = ""

    def _headers(self) -> Dict[str, str]:
        return {"User-Agent": _DEFAULT_UA, "X-API-KEY": self.token}


# ============================================================
# SECTION 4: SQLITE DATABASE (Pair 1 U1)
# ============================================================

_DDL = """
PRAGMA journal_mode=WAL;
PRAGMA foreign_keys=ON;

CREATE TABLE IF NOT EXISTS programs (
    slug              TEXT PRIMARY KEY,
    name              TEXT NOT NULL,
    platform          TEXT NOT NULL,
    url               TEXT NOT NULL,
    live              INTEGER NOT NULL DEFAULT 1,
    minimum_bounty    INTEGER,
    maximum_bounty    INTEGER,
    average_bounty    INTEGER,
    rewards           TEXT,
    types             TEXT,
    bounty_created_at TEXT,
    created_at        TEXT NOT NULL,
    updated_at        TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS program_scopes (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    slug      TEXT NOT NULL REFERENCES programs(slug) ON DELETE CASCADE,
    direction TEXT NOT NULL CHECK (direction IN ('in','out')),
    type      TEXT NOT NULL,
    value     TEXT NOT NULL,
    UNIQUE (slug, direction, type, value)
);

CREATE TABLE IF NOT EXISTS domains (
    name       TEXT NOT NULL,
    program    TEXT NOT NULL REFERENCES programs(slug) ON DELETE CASCADE,
    created_at TEXT NOT NULL,
    PRIMARY KEY (name, program)
);

CREATE TABLE IF NOT EXISTS notifications (
    id         TEXT PRIMARY KEY,
    resources  TEXT NOT NULL,
    program    TEXT,
    webhook    TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS probe_results (
    host          TEXT NOT NULL,
    program       TEXT NOT NULL,
    url           TEXT NOT NULL,
    status        INTEGER,
    server        TEXT,
    technologies  TEXT,
    redirect_url  TEXT,
    live          INTEGER NOT NULL DEFAULT 1,
    probed_at     TEXT NOT NULL DEFAULT (datetime('now')),
    PRIMARY KEY (host, program)
);

CREATE TABLE IF NOT EXISTS nuclei_findings (
    id            TEXT NOT NULL,
    program       TEXT NOT NULL,
    host          TEXT NOT NULL,
    template_id   TEXT,
    name          TEXT,
    severity      TEXT,
    matched_at    TEXT,
    tags          TEXT,
    raw_json      TEXT,
    found_at      TEXT NOT NULL DEFAULT (datetime('now')),
    PRIMARY KEY (id, program)
);

CREATE TABLE IF NOT EXISTS scan_history (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    domain            TEXT NOT NULL,
    scan_time         TEXT NOT NULL,
    subdomains_count  INTEGER NOT NULL DEFAULT 0,
    urls_count        INTEGER NOT NULL DEFAULT 0,
    param_urls_count  INTEGER NOT NULL DEFAULT 0,
    ports_json        TEXT,
    findings_count    INTEGER NOT NULL DEFAULT 0,
    xss_count         INTEGER NOT NULL DEFAULT 0,
    sqli_count        INTEGER NOT NULL DEFAULT 0,
    secrets_count     INTEGER NOT NULL DEFAULT 0,
    github_count      INTEGER NOT NULL DEFAULT 0,
    subdomains_json   TEXT,
    snapshot_json     TEXT
);
CREATE INDEX IF NOT EXISTS idx_scan_history_domain ON scan_history(domain);

CREATE TABLE IF NOT EXISTS xss_findings (
    id          TEXT PRIMARY KEY,
    program     TEXT NOT NULL,
    url         TEXT NOT NULL,
    parameter   TEXT,
    payload     TEXT,
    severity    TEXT,
    confidence  REAL,
    evidence    TEXT,
    found_at    TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS sqli_findings (
    id          TEXT PRIMARY KEY,
    program     TEXT NOT NULL,
    url         TEXT NOT NULL,
    parameter   TEXT,
    payload     TEXT,
    error_msg   TEXT,
    found_at    TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS secret_findings (
    id          TEXT PRIMARY KEY,
    program     TEXT NOT NULL,
    url         TEXT NOT NULL,
    type        TEXT,
    match       TEXT,
    found_at    TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS github_findings (
    id          TEXT PRIMARY KEY,
    program     TEXT NOT NULL,
    repo        TEXT,
    file_path   TEXT,
    query       TEXT,
    url         TEXT,
    snippet     TEXT,
    found_at    TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS takeover_findings (
    id          TEXT PRIMARY KEY,
    program     TEXT NOT NULL,
    subdomain   TEXT NOT NULL,
    cname       TEXT,
    service     TEXT,
    evidence    TEXT,
    found_at    TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS cors_findings (
    id              TEXT PRIMARY KEY,
    program         TEXT NOT NULL,
    url             TEXT NOT NULL,
    origin_tested   TEXT,
    acao            TEXT,
    acac            TEXT,
    classification  TEXT,
    found_at        TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS redirect_findings (
    id          TEXT PRIMARY KEY,
    program     TEXT NOT NULL,
    url         TEXT NOT NULL,
    param       TEXT,
    payload     TEXT,
    location    TEXT,
    found_at    TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS git_exposure_findings (
    id          TEXT PRIMARY KEY,
    program     TEXT NOT NULL,
    url         TEXT NOT NULL,
    path        TEXT,
    status      INTEGER,
    size        INTEGER,
    found_at    TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS env_file_findings (
    id          TEXT PRIMARY KEY,
    program     TEXT NOT NULL,
    url         TEXT NOT NULL,
    filename    TEXT,
    status      INTEGER,
    found_at    TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS dns_health (
    id                    TEXT PRIMARY KEY,
    program               TEXT NOT NULL,
    spf_record            TEXT,
    dmarc_record          TEXT,
    dmarc_policy          TEXT,
    dnssec_status         TEXT,
    zone_transfer         INTEGER DEFAULT 0,
    ct_cert_count         INTEGER DEFAULT 0,
    typosquat_hits        INTEGER DEFAULT 0,
    whois_registrar       TEXT,
    whois_created         TEXT,
    reputation_flag       TEXT,
    security_txt_present  INTEGER DEFAULT 0,
    ssl_days_left         INTEGER,
    firewall_detected     TEXT,
    scanned_at            TEXT NOT NULL DEFAULT (datetime('now'))
);
"""


class Database:
    def __init__(self, path: Path = DEFAULT_DB_PATH) -> None:
        self.path  = path
        self._conn: Optional[aiosqlite.Connection] = None

    async def connect(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = await aiosqlite.connect(self.path)
        self._conn.row_factory = aiosqlite.Row
        await self._conn.executescript(_DDL)
        await self._conn.commit()
        log.debug("DB connected: %s", self.path)

    async def close(self) -> None:
        if self._conn:
            await self._conn.close()
            self._conn = None

    async def __aenter__(self) -> "Database":
        await self.connect()
        return self

    async def __aexit__(self, *_: Any) -> None:
        await self.close()

    # ── programs ──────────────────────────────────────────────

    async def upsert_program(self, p: Dict[str, Any]) -> None:
        assert self._conn
        def _str(v: Any) -> Optional[str]:
            return str(v) if v is not None else None
        rewards = p.get("rewards", [])
        types   = p.get("types",   [])
        await self._conn.execute(
            """INSERT OR REPLACE INTO programs
               (slug,name,platform,url,live,minimum_bounty,maximum_bounty,average_bounty,
                rewards,types,bounty_created_at,created_at,updated_at)
               VALUES(:slug,:name,:platform,:url,:live,:minimum_bounty,:maximum_bounty,
                      :average_bounty,:rewards,:types,:bounty_created_at,:created_at,:updated_at)""",
            {
                "slug": p["slug"], "name": p["name"], "platform": p["platform"],
                "url": p["url"], "live": int(bool(p.get("live", True))),
                "minimum_bounty": p.get("minimumBounty"),
                "maximum_bounty": p.get("maximumBounty"),
                "average_bounty": p.get("averageBounty"),
                "rewards": ",".join(rewards) if isinstance(rewards, list) else rewards,
                "types":   ",".join(types)   if isinstance(types,   list) else types,
                "bounty_created_at": _str(p.get("bountyCreatedAt")),
                "created_at": _str(p.get("createdAt")),
                "updated_at": _str(p.get("updatedAt")),
            },
        )
        await self._conn.execute(
            "DELETE FROM program_scopes WHERE slug=?", (p["slug"],)
        )
        for direction, key in (("in", "in_scope"), ("out", "out_scope")):
            for scope in p.get(key, []):
                await self._conn.execute(
                    "INSERT OR IGNORE INTO program_scopes "
                    "(slug,direction,type,value) VALUES(?,?,?,?)",
                    (p["slug"], direction, scope["type"], scope["value"]),
                )
        await self._conn.commit()

    async def get_program(self, slug: str) -> Optional[Dict[str, Any]]:
        assert self._conn
        async with self._conn.execute(
            "SELECT * FROM programs WHERE slug=?", (slug,)
        ) as cur:
            row = await cur.fetchone()
            return dict(row) if row else None

    async def list_programs(
        self, platform: Optional[str] = None, live_only: bool = False
    ) -> List[Dict]:
        assert self._conn
        where, vals = [], []
        if platform:
            where.append("platform=?"); vals.append(platform)
        if live_only:
            where.append("live=1")
        clause = ("WHERE " + " AND ".join(where)) if where else ""
        async with self._conn.execute(
            f"SELECT * FROM programs {clause} ORDER BY updated_at DESC", vals
        ) as cur:
            return [dict(r) for r in await cur.fetchall()]

    # ── domains ───────────────────────────────────────────────

    async def upsert_domain(self, d: Dict[str, Any]) -> None:
        assert self._conn
        created_at = d.get("createdAt") or d.get("created_at")
        await self._conn.execute(
            "INSERT OR IGNORE INTO domains (name,program,created_at) "
            "VALUES(:name,:program,:created_at)",
            {
                "name":       d["name"],
                "program":    d["program"],
                "created_at": str(created_at) if created_at else None,
            },
        )
        await self._conn.commit()

    async def list_domains(
        self, program: Optional[str] = None
    ) -> List[Dict]:
        assert self._conn
        if program:
            async with self._conn.execute(
                "SELECT * FROM domains WHERE program=? ORDER BY name", (program,)
            ) as cur:
                return [dict(r) for r in await cur.fetchall()]
        async with self._conn.execute(
            "SELECT * FROM domains ORDER BY name"
        ) as cur:
            return [dict(r) for r in await cur.fetchall()]

    async def domain_count(self) -> int:
        assert self._conn
        async with self._conn.execute("SELECT COUNT(*) FROM domains") as cur:
            row = await cur.fetchone()
            return row[0] if row else 0

    # ── notifications ─────────────────────────────────────────

    async def upsert_notification(self, n: Dict[str, Any]) -> None:
        assert self._conn
        await self._conn.execute(
            "INSERT OR REPLACE INTO notifications "
            "(id,resources,program,webhook,created_at) "
            "VALUES(:id,:resources,:program,:webhook,:created_at)",
            n,
        )
        await self._conn.commit()

    async def delete_notification(self, nid: str) -> None:
        assert self._conn
        await self._conn.execute(
            "DELETE FROM notifications WHERE id=?", (nid,)
        )
        await self._conn.commit()

    async def list_notifications(self) -> List[Dict]:
        assert self._conn
        async with self._conn.execute(
            "SELECT * FROM notifications ORDER BY created_at DESC"
        ) as cur:
            return [dict(r) for r in await cur.fetchall()]


async def get_db(path: Path = DEFAULT_DB_PATH) -> Database:
    db = Database(path)
    await db.connect()
    return db


# ============================================================
# SECTION 5: CONSOLE OUTPUT
# ============================================================

class Console:
    """ANSI colour console output."""
    COLORS = {
        "red":     "\033[91m",
        "green":   "\033[92m",
        "yellow":  "\033[93m",
        "blue":    "\033[94m",
        "magenta": "\033[95m",
        "cyan":    "\033[96m",
        "white":   "\033[97m",
        "bold":    "\033[1m",
        "reset":   "\033[0m",
    }

    @classmethod
    def banner(cls) -> None:
        print(
            f"{cls.COLORS['cyan']}{cls.COLORS['bold']}\n"
            "    ____  ____  ____                      \n"
            "   / __ )/ __ )/ __ \\___  _________  ____ \n"
            "  / __  / __  / /_/ / _ \\/ ___/ __ \\/ __ \\\n"
            " / /_/ / /_/ / _, _/  __/ /__/ /_/ / / / /\n"
            "/_____/_____/_/ |_|\\___/\\___/\\____/_/ /_/ \n"
            f"  Professional Bug Bounty Toolkit v{VERSION}\n"
            f"{cls.COLORS['reset']}"
        )

    @classmethod
    def section(cls, title: str) -> None:
        print(
            f"\n{cls.COLORS['blue']}{cls.COLORS['bold']}"
            f"\n{'=' * 60}\n  {title.upper()}\n{'=' * 60}"
            f"{cls.COLORS['reset']}\n"
        )

    @classmethod
    def success(cls, msg: str) -> None:
        print(f"{cls.COLORS['green']}[✓] {msg}{cls.COLORS['reset']}")

    @classmethod
    def error(cls, msg: str) -> None:
        print(f"{cls.COLORS['red']}[✗] {msg}{cls.COLORS['reset']}")

    @classmethod
    def warning(cls, msg: str) -> None:
        print(f"{cls.COLORS['yellow']}[!] {msg}{cls.COLORS['reset']}")

    @classmethod
    def info(cls, msg: str) -> None:
        print(f"{cls.COLORS['cyan']}[*] {msg}{cls.COLORS['reset']}")

    @classmethod
    def progress(cls, msg: str) -> None:
        print(f"{cls.COLORS['magenta']}[→] {msg}{cls.COLORS['reset']}")

    @classmethod
    def result(cls, title: str, value: str) -> None:
        print(
            f"    {cls.COLORS['white']}{title}:{cls.COLORS['reset']} {value}"
        )

    @classmethod
    def table(
        cls, headers: list, rows: list, title: str = ""
    ) -> None:
        if title:
            print(f"\n{cls.COLORS['bold']}{title}{cls.COLORS['reset']}")
        if not rows:
            return
        col_widths = [
            max(len(str(row[i])) for row in [headers] + rows) + 2
            for i in range(len(headers))
        ]
        header_row = "│".join(
            f" {h:<{col_widths[i]-1}}" for i, h in enumerate(headers)
        )
        print(f"┌{'┬'.join('─' * w for w in col_widths)}┐")
        print(f"│{header_row}│")
        print(f"├{'┼'.join('─' * w for w in col_widths)}┤")
        for row in rows:
            row_str = "│".join(
                f" {str(row[i]):<{col_widths[i]-1}}" for i in range(len(row))
            )
            print(f"│{row_str}│")
        print(f"└{'┴'.join('─' * w for w in col_widths)}┘")


# ============================================================
# SECTION 6: CONFIGURATION
# ============================================================

@dataclass
class Config:
    """Application configuration — 28 fields."""
    output_dir: str          = str(DEFAULT_OUTPUT)
    default_wordlist: str    = "/usr/share/wordlists/dirb/common.txt"
    max_concurrent: int      = 10
    timeout: int             = 30
    rate_limit: float        = 0.1
    user_agent: str          = _DEFAULT_UA
    verify_ssl: bool         = False
    mode: str                = "normal"       # normal | stealth
    out_of_scope: List[str]  = field(default_factory=list)
    # Liveness (B20)
    liveness_timeout: int    = 15             # seconds per attempt
    liveness_retries: int    = 2              # attempts per scheme before giving up
    # Webhooks (U7 — wired in Pair 4)
    slack_webhook: str       = ""
    discord_webhook: str     = ""
    notify_on_new_subs: bool = True
    notify_on_vuln: bool     = True
    notify_min_severity: str = "high"
    # XSS
    blind_xss_callback: str  = ""
    xss_max_urls: int        = 100
    # DB
    db_path: str             = str(DEFAULT_DB_PATH)
    # Probe (U3)
    probe_concurrency: int   = 30
    probe_timeout: int       = 10
    # massdns (U4)
    massdns_rate: int        = 5000
    massdns_wordlist: str    = ""
    massdns_resolvers: str   = ""
    # Nuclei (U5)
    nuclei_concurrency: int  = 3
    nuclei_severity: str     = "low,medium,high,critical"
    # GitHub dorking (U8 — Pair 4)
    github_token: str        = ""
    # Nmap
    nmap_mode: str           = "normal"

    def save(self) -> None:
        CONFIG_DIR.mkdir(exist_ok=True)
        with open(CONFIG_FILE, "w") as f:
            json.dump(self.__dict__, f, indent=2)

    @classmethod
    def load(cls) -> "Config":
        if CONFIG_FILE.exists():
            try:
                with open(CONFIG_FILE) as f:
                    data = json.load(f)
                known = {
                    k: v for k, v in data.items()
                    if k in cls.__dataclass_fields__
                }
                return cls(**known)
            except Exception as exc:
                log.warning("Config load failed: %s — using defaults", exc)
        return cls()

    def is_in_scope(self, target: str) -> bool:
        return all(blocked not in target for blocked in self.out_of_scope)


# ============================================================
# SECTION 7: LIVE PROBE + WAPPALYZER (Pair 2 U3)
# ============================================================

_WAPPALYZER_SINGLETON = None


def _get_wappalyzer() -> Optional[Any]:
    global _WAPPALYZER_SINGLETON
    if not _WAPPALYZER_AVAILABLE:
        return None
    if _WAPPALYZER_SINGLETON is None:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            _WAPPALYZER_SINGLETON = Wappalyzer.latest()
    return _WAPPALYZER_SINGLETON


@dataclass
class ProbeResult:
    host:         str
    program:      str
    url:          str
    status:       Optional[int]  = None
    server:       Optional[str]  = None
    technologies: List[str]      = field(default_factory=list)
    redirect_url: Optional[str]  = None
    live:         bool           = True

    def to_dict(self) -> Dict:
        d = asdict(self)
        d["technologies"] = ",".join(self.technologies)
        d["live"]         = int(self.live)
        return d


class LiveProbe:
    """
    Concurrent HTTP liveness probe with Wappalyzer fingerprinting.
    status < 500 counts as live (tolerates 403/404 from WAF-protected hosts).
    """

    def __init__(
        self,
        program:    str,
        *,
        timeout:     int  = 10,
        concurrency: int  = 20,
        user_agent:  str  = _DEFAULT_UA,
    ) -> None:
        self.program     = program
        self.timeout     = aiohttp.ClientTimeout(total=timeout)
        self.concurrency = concurrency
        self.user_agent  = user_agent
        self._results:  List[ProbeResult]          = []
        self._session:  Optional[aiohttp.ClientSession] = None

    async def __aenter__(self) -> "LiveProbe":
        self._session = aiohttp.ClientSession(
            headers={"User-Agent": self.user_agent},
            connector=aiohttp.TCPConnector(ssl=False, limit=self.concurrency),
        )
        return self

    async def __aexit__(self, *_: Any) -> None:
        if self._session:
            await self._session.close()

    async def run(self, hosts: Any) -> List[ProbeResult]:
        sem     = asyncio.Semaphore(self.concurrency)
        tasks   = [self._probe_one(host, sem) for host in hosts]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        self._results = [r for r in results if isinstance(r, ProbeResult)]
        return self._results

    def live_hosts(self) -> List[ProbeResult]:
        return [r for r in self._results if r.live]

    async def _probe_one(
        self, host: str, sem: asyncio.Semaphore
    ) -> ProbeResult:
        # Ensure host is bare (no scheme) before probing
        bare = host
        if "://" in host:
            bare = urlparse(host).netloc or host
        async with sem:
            for scheme in ("https", "http"):
                url    = f"{scheme}://{bare}"
                result = await self._try_url(bare, url)
                if result.live:
                    log.debug(
                        "LIVE %s → %s [%s] tech=%s",
                        bare, result.status, result.server, result.technologies,
                    )
                    return result
            return ProbeResult(
                host=bare, program=self.program,
                url=f"https://{bare}", live=False,
            )

    async def _try_url(self, host: str, url: str) -> ProbeResult:
        assert self._session
        result = ProbeResult(host=host, program=self.program, url=url)
        try:
            async with self._session.get(
                url,
                timeout=self.timeout,
                allow_redirects=True,
                max_redirects=5,
            ) as resp:
                result.status      = resp.status
                result.server      = resp.headers.get("Server")
                result.redirect_url = (
                    str(resp.url) if str(resp.url) != url else None
                )
                # status < 500: host is alive (WAF returns 403, CDN returns 301)
                if resp.status < 500:
                    result.live        = True
                    html               = await resp.text(errors="ignore")
                    result.technologies = self._fingerprint(
                        url, html, dict(resp.headers)
                    )
                else:
                    result.live = False
        except (aiohttp.ClientError, asyncio.TimeoutError) as exc:
            log.debug("Probe failed for %s: %s", url, exc)
            result.live = False
        return result

    def _fingerprint(
        self, url: str, html: str, headers: Dict
    ) -> List[str]:
        wapp = _get_wappalyzer()
        if not wapp:
            return []
        try:
            with warnings.catch_warnings():
                warnings.simplefilter("ignore")
                page = WebPage(url, html, headers)
                return sorted(wapp.analyze(page))
        except Exception as exc:
            log.debug("Wappalyzer error for %s: %s", url, exc)
            return []


async def persist_probe_results(
    db: Database, results: List[ProbeResult]
) -> None:
    for r in results:
        d = r.to_dict()
        await db._conn.execute(
            """INSERT OR REPLACE INTO probe_results
               (host,program,url,status,server,technologies,
                redirect_url,live,probed_at)
               VALUES(:host,:program,:url,:status,:server,:technologies,
                      :redirect_url,:live,datetime('now'))""",
            d,
        )
    await db._conn.commit()
    log.info("Persisted %d probe results to DB", len(results))


# ============================================================
# SECTION 8: MASSDNS (Pair 2 U4)
# ============================================================

_DEFAULT_RESOLVERS = [
    "1.1.1.1", "8.8.8.8", "8.8.4.4", "9.9.9.9", "208.67.222.222",
]
_DEFAULT_WORDLISTS = [
    "/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt",
    "/usr/share/seclists/Discovery/DNS/bitquark-subdomains-top100000.txt",
    "/usr/share/wordlists/amass/subdomains.lst",
]
_FALLBACK_WORDS = [
    "www", "mail", "ftp", "api", "dev", "staging", "test", "admin", "vpn",
    "portal", "app", "mobile", "m", "cdn", "static", "assets", "img",
    "images", "secure", "login", "auth", "docs", "support", "help",
    "blog", "shop", "store", "beta", "alpha", "internal", "intranet",
    "remote", "ns1", "ns2", "mx", "smtp", "pop", "imap", "webmail",
    "autodiscover", "cpanel", "whm", "ssh", "jenkins", "jira",
    "confluence", "gitlab", "github", "dashboard", "monitor",
    "status", "health", "metrics",
]


def _find_wordlist() -> Optional[Path]:
    for p in _DEFAULT_WORDLISTS:
        if Path(p).exists():
            return Path(p)
    return None


def _write_fallback_wordlist(path: Path, domain: str) -> None:
    with open(path, "w") as f:
        for word in _FALLBACK_WORDS:
            f.write(f"{word}.{domain}\n")


def _write_resolvers(path: Path) -> None:
    with open(path, "w") as f:
        for r in _DEFAULT_RESOLVERS:
            f.write(r + "\n")


class MassdnsRunner:
    """Async wrapper around massdns binary. Expects a bare domain."""

    def __init__(
        self,
        domain:    str,
        *,
        wordlist:  Optional[str] = None,
        resolvers: Optional[str] = None,
        rate:      int           = 5000,
        timeout:   int           = 120,
    ) -> None:
        # Ensure bare domain — guard against URL slip-through
        self.domain    = normalize_domain(domain) if "://" in domain else domain
        self.wordlist  = Path(wordlist)  if wordlist  else _find_wordlist()
        self.resolvers = Path(resolvers) if resolvers else None
        self.rate      = rate
        self.timeout   = timeout
        self.available = bool(shutil.which("massdns"))

    async def run(self) -> Set[str]:
        if not self.available:
            log.warning("massdns not found — skipping DNS brute-force")
            return set()
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path      = Path(tmp)
            resolvers_file = self.resolvers or tmp_path / "resolvers.txt"
            if not resolvers_file.exists():
                _write_resolvers(resolvers_file)

            wordlist_file = self.wordlist
            if not wordlist_file or not wordlist_file.exists():
                wordlist_file = tmp_path / "wordlist.txt"
                log.info(
                    "No seclists wordlist found — using built-in %d-word fallback",
                    len(_FALLBACK_WORDS),
                )
                _write_fallback_wordlist(wordlist_file, self.domain)
            else:
                wordlist_file = self._ensure_fqdn_wordlist(
                    wordlist_file, tmp_path
                )

            output_file = tmp_path / "massdns_out.txt"
            cmd = [
                "massdns",
                "-r", str(resolvers_file),
                "-t", "A",
                "-o", "S",
                "--flush",
                "--rate", str(self.rate),
                "-w", str(output_file),
                str(wordlist_file),
            ]
            log.info("massdns: %s (rate=%d/s)", self.domain, self.rate)
            try:
                await self._exec(cmd)
            except Exception as exc:
                log.warning("massdns error: %s", exc)
                return set()
            return self._parse_output(output_file)

    def _ensure_fqdn_wordlist(
        self, wordlist: Path, tmp: Path
    ) -> Path:
        fqdn_file = tmp / "fqdn_wordlist.txt"
        with open(wordlist) as src, open(fqdn_file, "w") as dst:
            for line in src:
                word = line.strip()
                if not word or word.startswith("#"):
                    continue
                if self.domain in word:
                    dst.write(word + "\n")
                else:
                    dst.write(f"{word}.{self.domain}\n")
        return fqdn_file

    async def _exec(self, cmd: List[str]) -> bool:
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            _, stderr = await asyncio.wait_for(
                proc.communicate(), timeout=self.timeout
            )
            if proc.returncode != 0:
                log.warning(
                    "massdns exited %d: %s",
                    proc.returncode,
                    stderr.decode(errors="ignore")[:200],
                )
                return False
            return True
        except asyncio.TimeoutError:
            log.warning("massdns timed out after %ds", self.timeout)
            return False
        except Exception as exc:
            log.error("massdns execution error: %s", exc)
            return False

    def _parse_output(self, output_file: Path) -> Set[str]:
        found: Set[str] = set()
        if not output_file.exists():
            return found
        with open(output_file) as f:
            for line in f:
                parts = line.strip().split()
                if len(parts) >= 3 and parts[1] == "A":
                    host = parts[0].rstrip(".")
                    if self.domain in host:
                        found.add(host)
        log.info("massdns found %d subdomains for %s", len(found), self.domain)
        return found


# ============================================================
# SECTION 9: TECH → NUCLEI TAG MAP (Pair 3 U5)
# ============================================================

_TECH_TAG_MAP: Dict[str, List[str]] = {
    "nginx":         ["nginx",         "server",   "misconfig"],
    "apache":        ["apache",        "server",   "misconfig"],
    "iis":           ["iis",           "server",   "misconfig"],
    "litespeed":     ["server",        "misconfig"],
    "wordpress":     ["wordpress",     "cms",      "exposure"],
    "joomla":        ["joomla",        "cms",      "exposure"],
    "drupal":        ["drupal",        "cms",      "exposure"],
    "magento":       ["magento",       "cms",      "ecommerce"],
    "laravel":       ["laravel",       "exposure", "misconfig"],
    "django":        ["django",        "exposure"],
    "rails":         ["rails",         "exposure"],
    "spring":        ["spring",        "java",     "exposure"],
    "express":       ["nodejs",        "exposure"],
    "react":         ["exposure",      "misconfig"],
    "vue.js":        ["exposure",      "misconfig"],
    "angular":       ["exposure",      "misconfig"],
    "mysql":         ["mysql",         "database", "exposure"],
    "postgresql":    ["postgresql",    "database", "exposure"],
    "mongodb":       ["mongodb",       "database", "exposure"],
    "redis":         ["redis",         "exposure"],
    "elasticsearch": ["elasticsearch", "exposure"],
    "keycloak":      ["keycloak",      "exposure", "cve"],
    "oauth":         ["oauth",         "exposure"],
    "aws":           ["aws",           "cloud",    "exposure"],
    "cloudflare":    ["cloudflare",    "misconfig"],
    "kubernetes":    ["kubernetes",    "exposure", "misconfig"],
    "docker":        ["docker",        "exposure"],
    "jenkins":       ["jenkins",       "exposure", "cve"],
    "gitlab":        ["gitlab",        "exposure"],
    "tomcat":        ["tomcat",        "apache",   "exposure"],
    "php":           ["php",           "exposure", "misconfig"],
    "java":          ["java",          "exposure"],
}
_DEFAULT_TAGS = ["misconfig", "exposure", "cve"]


def _tags_for_technologies(technologies: list) -> list:
    tags: set = set()
    for tech in technologies:
        key = tech.lower()
        for pattern, tag_list in _TECH_TAG_MAP.items():
            if pattern in key:
                tags.update(tag_list)
    return list(tags) if tags else list(_DEFAULT_TAGS)


# ============================================================
# SECTION 10: SCAN HISTORY + DIFF (Pair 3 U6)
# ============================================================

async def _save_scan_history(db: Database, target: Any) -> int:
    cur = await db._conn.execute(
        """INSERT INTO scan_history
           (domain,scan_time,subdomains_count,urls_count,param_urls_count,
            ports_json,findings_count,xss_count,sqli_count,secrets_count,
            github_count,subdomains_json,snapshot_json)
           VALUES(?,datetime('now'),?,?,?,?,?,?,?,?,?,?,?)""",
        (
            target.domain,
            len(target.subdomains),
            len(target.urls),
            len(target.urls_with_params),
            json.dumps(sorted(target.open_ports)),
            len(target.vulnerabilities),
            len(target.xss_findings),
            len(target.sqli_findings),
            len(target.secret_findings),
            len(target.github_findings),
            json.dumps(sorted(target.subdomains)),
            json.dumps({
                "domain":       target.domain,
                "is_live":      target.is_live,
                "live_url":     target.live_url,
                "ip_addresses": target.ip_addresses,
            }),
        ),
    )
    await db._conn.commit()
    return cur.lastrowid


async def _load_prev_scan(
    db: Database, domain: str
) -> Optional[dict]:
    async with db._conn.execute(
        "SELECT * FROM scan_history WHERE domain=? ORDER BY id DESC LIMIT 1",
        (domain,),
    ) as cur:
        row = await cur.fetchone()
    if not row:
        return None
    d = dict(row)
    d["subdomains_set"] = set(json.loads(d.get("subdomains_json") or "[]"))
    d["ports_set"]      = set(json.loads(d.get("ports_json")      or "[]"))
    return d


def compute_diff(prev: Optional[dict], target: Any) -> dict:
    if prev is None:
        return {
            "first_scan":           True,
            "new_subdomains":       sorted(target.subdomains),
            "new_ports":            sorted(target.open_ports),
            "new_param_urls_count": len(target.urls_with_params),
            "new_findings_count":   len(target.vulnerabilities),
        }
    prev_subs   = prev.get("subdomains_set", set())
    prev_ports  = prev.get("ports_set",      set())
    prev_params = prev.get("param_urls_count", 0)
    prev_finds  = prev.get("findings_count",   0)
    new_subs    = sorted(target.subdomains - prev_subs)
    gone_subs   = sorted(prev_subs - target.subdomains)
    new_ports   = sorted(set(target.open_ports) - prev_ports)
    gone_ports  = sorted(prev_ports - set(target.open_ports))
    return {
        "first_scan":           False,
        "prev_scan_time":       prev.get("scan_time"),
        "new_subdomains":       new_subs,
        "gone_subdomains":      gone_subs,
        "new_ports":            new_ports,
        "gone_ports":           gone_ports,
        "new_param_urls_delta": len(target.urls_with_params) - prev_params,
        "new_findings_delta":   len(target.vulnerabilities)  - prev_finds,
        "total_subdomains_now": len(target.subdomains),
        "total_ports_now":      len(target.open_ports),
    }


def print_diff(diff: dict) -> None:
    if diff.get("first_scan"):
        Console.info("First scan for this domain — no diff available.")
        return
    Console.section("DIFF — New Assets Since Last Scan")
    Console.result("Previous scan", diff.get("prev_scan_time", "unknown"))

    new_subs = diff.get("new_subdomains", [])
    if new_subs:
        Console.success(f"[NEW] {len(new_subs)} new subdomain(s):")
        for s in new_subs[:20]:
            print(f"      [NEW] {s}")
        if len(new_subs) > 20:
            Console.info(
                f"      ... and {len(new_subs) - 20} more (see diff JSON)"
            )
    else:
        Console.info("No new subdomains.")

    gone_subs = diff.get("gone_subdomains", [])
    if gone_subs:
        Console.warning(f"[GONE] {len(gone_subs)} subdomain(s) no longer resolve:")
        for s in gone_subs[:10]:
            print(f"      [GONE] {s}")

    new_ports = diff.get("new_ports", [])
    if new_ports:
        Console.success(f"[NEW] Open ports: {new_ports}")
    gone_ports = diff.get("gone_ports", [])
    if gone_ports:
        Console.warning(f"[GONE] Closed ports: {gone_ports}")

    param_delta = diff.get("new_param_urls_delta", 0)
    if param_delta > 0:
        Console.success(f"[NEW] +{param_delta} URLs with parameters")
    elif param_delta < 0:
        Console.warning(f"[GONE] {abs(param_delta)} fewer param URLs")

    find_delta = diff.get("new_findings_delta", 0)
    if find_delta > 0:
        Console.success(f"[NEW] +{find_delta} new vulnerability findings")
    elif find_delta < 0:
        Console.info(
            f"[GONE] {abs(find_delta)} fewer findings than last scan"
        )


# ============================================================
# SECTION 11: FINDING DATACLASSES
# ============================================================

@dataclass
class XSSFinding:
    url:           str
    parameter:     str
    payload:       str
    method:        str
    severity:      str
    confidence:    float
    evidence:      str = ""
    evidence_file: str = ""

    def to_dict(self) -> dict:
        return {
            "type":       "XSS",
            "url":        self.url,
            "parameter":  self.parameter,
            "payload":    self.payload,
            "method":     self.method,
            "severity":   self.severity,
            "confidence": self.confidence,
            "evidence":   self.evidence,
            "info": {
                "name":     f"Reflected XSS in {self.parameter}",
                "severity": self.severity.lower(),
            },
            "matched-at": self.url,
        }


@dataclass
class SQLiFinding:
    url:       str
    parameter: str
    payload:   str
    error_msg: str

    def to_dict(self) -> dict:
        return {
            "type":      "SQLi",
            "url":       self.url,
            "parameter": self.parameter,
            "payload":   self.payload,
            "error_msg": self.error_msg,
            "info": {
                "name":     f"SQL Injection in {self.parameter}",
                "severity": "critical",
            },
            "matched-at": self.url,
        }


@dataclass
class SecretFinding:
    url:   str
    type:  str
    match: str

    def to_dict(self) -> dict:
        return {
            "type":        "Secret",
            "url":         self.url,
            "secret_type": self.type,
            "match":       self.match,
            "info": {
                "name":     f"Exposed Secret: {self.type}",
                "severity": "high",
            },
            "matched-at": self.url,
        }


@dataclass
class GithubFinding:
    repo:      str
    file_path: str
    query:     str
    snippet:   str
    url:       str

    def to_dict(self) -> dict:
        return {
            "type":      "GitHub",
            "repo":      self.repo,
            "file_path": self.file_path,
            "query":     self.query,
            "snippet":   self.snippet,
            "url":       self.url,
            "info": {
                "name":     f"GitHub Dork Match: {self.query}",
                "severity": "high",
            },
            "matched-at": self.url,
        }


# ============================================================
# SECTION 11B: OSINT-DERIVED FINDING DATACLASSES (Pair 5)
# ============================================================
# 20 OSINT modules selected for integration (see handoff_09062026.md
# gap analysis for full selection rationale). Each OSINT module was a
# standalone sync/requests CLI script; logic below is reimplemented async
# on aiohttp to match bbrecon's existing concurrency model — not copy-pasted.

@dataclass
class TakeoverFinding:
    subdomain: str
    cname:     str
    service:   str
    evidence:  str

    def to_dict(self) -> dict:
        return {
            "type": "SubdomainTakeover", "subdomain": self.subdomain,
            "cname": self.cname, "service": self.service, "evidence": self.evidence,
            "info": {"name": f"Possible Subdomain Takeover: {self.service}", "severity": "high"},
            "matched-at": self.subdomain,
        }


@dataclass
class CorsFinding:
    url:            str
    origin_tested:  str
    acao:           str
    acac:           str
    classification: str

    def to_dict(self) -> dict:
        sev = "high" if "Creds" in self.classification else "medium"
        return {
            "type": "CORS", "url": self.url, "origin_tested": self.origin_tested,
            "acao": self.acao, "acac": self.acac, "classification": self.classification,
            "info": {"name": f"CORS Misconfig: {self.classification}", "severity": sev},
            "matched-at": self.url,
        }


@dataclass
class OpenRedirectFinding:
    url:      str
    param:    str
    payload:  str
    location: str

    def to_dict(self) -> dict:
        return {
            "type": "OpenRedirect", "url": self.url, "param": self.param,
            "payload": self.payload, "location": self.location,
            "info": {"name": f"Open Redirect via {self.param}", "severity": "medium"},
            "matched-at": self.url,
        }


@dataclass
class GitExposureFinding:
    url:    str
    path:   str
    status: int
    size:   int

    def to_dict(self) -> dict:
        return {
            "type": "GitExposure", "url": self.url, "path": self.path,
            "status": self.status, "size": self.size,
            "info": {"name": f"Exposed .git artifact: {self.path}", "severity": "critical"},
            "matched-at": self.url,
        }


@dataclass
class EnvFileFinding:
    url:      str
    filename: str
    status:   int

    def to_dict(self) -> dict:
        return {
            "type": "EnvFileExposure", "url": self.url, "filename": self.filename,
            "status": self.status,
            "info": {"name": f"Exposed config file: {self.filename}", "severity": "critical"},
            "matched-at": self.url,
        }


@dataclass
class DnsHealthFinding:
    domain:               str
    spf_record:           str
    dmarc_record:         str
    dmarc_policy:         str
    dnssec_status:        str
    zone_transfer:        bool
    ct_cert_count:        int
    typosquat_hits:       int
    whois_registrar:      str
    whois_created:        str
    reputation_flag:      str
    security_txt_present: bool
    ssl_days_left:        Optional[int]
    firewall_detected:    str

    def to_dict(self) -> dict:
        issues = []
        if self.spf_record == "-":
            issues.append("missing SPF")
        if self.dmarc_policy in ("-", "none"):
            issues.append("weak/missing DMARC policy")
        if self.dnssec_status == "Not signed":
            issues.append("DNSSEC not enabled")
        if self.zone_transfer:
            issues.append("AXFR zone transfer allowed")
        if self.ssl_days_left is not None and self.ssl_days_left < 14:
            issues.append(f"SSL cert expires in {self.ssl_days_left}d")
        sev = "high" if self.zone_transfer else ("medium" if issues else "low")
        return {
            "type": "DnsHealth", "domain": self.domain, "issues": issues,
            "info": {"name": "DNS/Mail/Cert posture check", "severity": sev},
            "matched-at": self.domain,
        }


# ============================================================
# SECTION 12: XSS SCANNER (marker-based, concurrent)  ← B17
# ============================================================

class XSSScanner:
    """
    Marker-based reflected XSS scanner.
    Per-session unique marker → zero false positives.
    Evidence files saved per finding.
    Now concurrent via asyncio.gather (was sequential in v4.x).
    """

    def __init__(
        self,
        output_dir: Path,
        timeout:    int   = 10,
        rate_limit: float = 0.1,
    ) -> None:
        self.output_dir = output_dir
        self.timeout    = timeout
        self.rate_limit = rate_limit
        self.findings:  List[XSSFinding] = []
        self.scan_id    = hashlib.md5(
            str(datetime.now()).encode()
        ).hexdigest()[:6]
        self.marker     = f"XSSBB{self.scan_id}"
        # Core marker-based payloads + WAF-bypass URL-encoded variant
        self.core_payloads = [
            f"<script>alert('{self.marker}')</script>",
            f"'\"><script>alert('{self.marker}')</script>",
            f"<img src=x onerror=\"alert('{self.marker}')\">",
            f"<svg onload=\"alert('{self.marker}')\">",
        ]
        self.waf_bypasses = [
            lambda p: p,
            lambda p: quote(p),
        ]

    async def _save_evidence(
        self, url: str, payload: str, text: str
    ) -> str:
        evidence_dir = self.output_dir / "xss_evidence"
        evidence_dir.mkdir(parents=True, exist_ok=True)
        filename = f"xss_{hashlib.md5(url.encode()).hexdigest()[:8]}.txt"
        with open(evidence_dir / filename, "w") as f:
            f.write(
                f"URL: {url}\nPayload: {payload}\n"
                f"Marker: {self.marker}\n\nRESPONSE:\n{text[:2000]}"
            )
        return str(evidence_dir / filename)

    async def scan_urls(
        self, urls: List[str], max_urls: int = 100
    ) -> List[XSSFinding]:
        param_urls = [u for u in urls if "?" in u and "=" in u]
        if not param_urls:
            Console.warning("No URLs with parameters to test for XSS")
            return []
        target_urls = param_urls[:max_urls]
        Console.info(
            f"Testing {len(target_urls)} URLs for XSS "
            f"(marker={self.marker}, concurrent)..."
        )
        # B17: concurrent — gather all URL scans simultaneously
        headers = {"User-Agent": _DEFAULT_UA}
        async with aiohttp.ClientSession(headers=headers) as session:
            tasks   = [self._scan_url(session, url) for url in target_urls]
            results = await asyncio.gather(*tasks, return_exceptions=True)

        findings: List[XSSFinding] = []
        for result in results:
            if isinstance(result, list):
                findings.extend(result)
        self.findings = findings
        return findings

    async def _scan_url(
        self, session: aiohttp.ClientSession, url: str
    ) -> List[XSSFinding]:
        findings: List[XSSFinding] = []
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        if not params:
            return findings
        for param in params:
            for payload in self.core_payloads:
                for bypass in self.waf_bypasses:
                    finding = await self._test_payload(
                        session, url, param, bypass(payload)
                    )
                    if finding:
                        findings.append(finding)
                        Console.success(f"XSS found: {url} (param={param})")
                        break
                if any(f.parameter == param for f in findings):
                    break
        return findings

    async def _test_payload(
        self,
        session: aiohttp.ClientSession,
        url:     str,
        param:   str,
        payload: str,
    ) -> Optional[XSSFinding]:
        parsed   = urlparse(url)
        params   = parse_qs(parsed.query)
        params[param] = [payload]
        test_url = parsed._replace(
            query=urlencode(params, doseq=True)
        ).geturl()
        try:
            await asyncio.sleep(self.rate_limit)
            async with session.get(
                test_url,
                timeout=aiohttp.ClientTimeout(total=self.timeout),
                ssl=False,
            ) as resp:
                text = await resp.text()
                if self.marker in text:
                    ev = await self._save_evidence(test_url, payload, text)
                    return XSSFinding(
                        url=url,
                        parameter=param,
                        payload=payload,
                        method="GET",
                        severity="HIGH",
                        confidence=1.0,
                        evidence=f"Marker reflected: {self.marker}",
                        evidence_file=ev,
                    )
        except Exception as exc:
            log.debug("XSS test error %s: %s", test_url, exc)
        return None


# ============================================================
# SECTION 13: SQLI SCANNER (B19 — UA header)
# ============================================================

class SQLiScanner:
    """Error-based SQL injection scanner. Bounded concurrency, proper UA."""

    PAYLOADS = [
        "'",
        '"',
        "' OR '1'='1",
        "' OR 1=1--",
        '" OR 1=1--',
        "'; SELECT SLEEP(0)--",
    ]
    ERRORS = [
        "SQL syntax",
        "mysql_fetch",
        "ORA-01756",
        "PostgreSQL query failed",
        "Warning: mysql",
        "Unclosed quotation",
        "syntax error",
        "microsoft OLE DB",
        "SQLSTATE",
    ]

    def __init__(self, output_dir: Path) -> None:
        self.output_dir = output_dir

    async def scan_targets(
        self, urls: List[str], concurrency: int = 20
    ) -> List[SQLiFinding]:
        findings:   List[SQLiFinding] = []
        param_urls  = [u for u in urls if "?" in u and "=" in u]
        if not param_urls:
            return findings
        sem = asyncio.Semaphore(concurrency)
        # B19: UA header on session
        headers = {"User-Agent": _DEFAULT_UA}
        async with aiohttp.ClientSession(headers=headers) as session:
            tasks = []
            for url in param_urls:
                parsed = urlparse(url)
                for param in parse_qs(parsed.query):
                    for pl in self.PAYLOADS:
                        tasks.append(self._test(session, url, param, pl, sem))
            results  = await asyncio.gather(*tasks, return_exceptions=True)
            findings = [r for r in results if isinstance(r, SQLiFinding)]
        return findings

    async def _test(
        self,
        session: aiohttp.ClientSession,
        url:     str,
        param:   str,
        payload: str,
        sem:     asyncio.Semaphore,
    ) -> Optional[SQLiFinding]:
        parsed   = urlparse(url)
        params   = parse_qs(parsed.query)
        params[param] = [payload]
        test_url = parsed._replace(
            query=urlencode(params, doseq=True)
        ).geturl()
        async with sem:
            try:
                async with session.get(
                    test_url,
                    timeout=aiohttp.ClientTimeout(total=10),
                    ssl=False,
                ) as resp:
                    text = await resp.text()
                    for err in self.ERRORS:
                        if err.lower() in text.lower():
                            return SQLiFinding(
                                url=url,
                                parameter=param,
                                payload=payload,
                                error_msg=err,
                            )
            except Exception as exc:
                log.debug("SQLi test error %s: %s", test_url, exc)
        return None


# ============================================================
# SECTION 14: SECRETS SCANNER (B18 — Semaphore-bounded)
# ============================================================

class SecretsScanner:
    """Regex-based secrets scanner. Bounded concurrency. Extended patterns."""

    PATTERNS = {
        "AWS Key":        r"(A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}",
        "Google Key":     r"AIza[0-9A-Za-z\-_]{35}",
        "GitHub Token":   r"ghp_[0-9a-zA-Z]{36}",
        "Slack Token":    r"xox[baprs]-[0-9a-zA-Z\-]{10,}",
        "Private Key":    r"-----BEGIN (RSA|EC|DSA|OPENSSH) PRIVATE KEY-----",
        "Generic Secret": (
            r"(?i)(secret|password|passwd|api_key|apikey|token)"
            r'["\s]*[:=]["\s]*["\'][A-Za-z0-9+/]{8,}["\']'
        ),
        "JWT Token":      r"eyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+",
        "Stripe Key":     r"sk_live_[0-9a-zA-Z]{24,}",
        "Twilio Token":   r"SK[0-9a-fA-F]{32}",
    }
    # File extensions to scan
    TARGET_EXTS = (
        ".js", ".json", ".env", ".yml", ".yaml", ".config",
        ".xml", ".conf", ".properties",
    )

    def __init__(self, output_dir: Path) -> None:
        self.output_dir = output_dir
        self.findings:  List[SecretFinding] = []
        self.scanned:   Set[str]            = set()

    async def scan_targets(
        self, urls: List[str], concurrency: int = 20
    ) -> List[SecretFinding]:
        target_urls = [
            u for u in urls
            if any(u.endswith(ext) for ext in self.TARGET_EXTS)
        ]
        if not target_urls:
            return self.findings
        sem     = asyncio.Semaphore(concurrency)   # B18
        headers = {"User-Agent": _DEFAULT_UA}
        async with aiohttp.ClientSession(headers=headers) as session:
            await asyncio.gather(
                *[self._scan(session, u, sem) for u in target_urls],
                return_exceptions=True,
            )
        return self.findings

    async def _scan(
        self,
        session: aiohttp.ClientSession,
        url:     str,
        sem:     asyncio.Semaphore,
    ) -> None:
        if url in self.scanned:
            return
        self.scanned.add(url)
        async with sem:
            try:
                async with session.get(
                    url,
                    timeout=aiohttp.ClientTimeout(total=10),
                    ssl=False,
                ) as resp:
                    text = await resp.text()
                    for name, pattern in self.PATTERNS.items():
                        for match in re.findall(pattern, text):
                            self.findings.append(
                                SecretFinding(
                                    url=url,
                                    type=name,
                                    match=str(match)[:40],
                                )
                            )
            except Exception as exc:
                log.debug("Secrets scan error %s: %s", url, exc)


# ============================================================
# SECTION 15: NMAP SCANNER
# ============================================================

class NmapScanner:
    """Thin async wrapper around the nmap binary."""

    def __init__(self, output_dir: Path) -> None:
        self.output_dir = output_dir
        self.nmap_path  = shutil.which("nmap")

    def available(self) -> bool:
        return self.nmap_path is not None

    async def scan_targets(
        self, targets: List[str], mode: str = "normal"
    ) -> str:
        if not targets or not self.available():
            return ""
        timing      = "-T2" if mode == "stealth" else "-T4"
        output_base = self.output_dir / "nmap_scan"
        target_file = self.output_dir / "nmap_targets.txt"
        with open(target_file, "w") as f:
            for t in targets:
                f.write(f"{t}\n")
        cmd = [
            "nmap", "-sC", "-sV", "-Pn", timing, "--open",
            "-iL", str(target_file),
            "-oA", str(output_base),
        ]
        Console.progress(
            f"Running Nmap ({mode} mode) on {len(targets)} targets..."
        )
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            await asyncio.wait_for(proc.communicate(), timeout=600)
            if proc.returncode == 0:
                Console.success(f"Nmap complete → {output_base}.nmap")
                return str(output_base) + ".nmap"
        except Exception as exc:
            log.warning("Nmap error: %s", exc)
        return ""


# ============================================================
# SECTION 16: HTML REPORT GENERATOR
# ============================================================

class ReportGenerator:
    """Generates a self-contained HTML report for a completed scan."""

    @staticmethod
    def generate_html(target: Any, output_path: Path) -> str:
        def badge(severity: str, label: str) -> str:
            colors = {
                "critical": "#ff0000",
                "high":     "#ff6600",
                "medium":   "#ffcc00",
                "low":      "#00cc44",
            }
            color = colors.get(severity.lower(), "#888888")
            return (
                f'<span style="background:{color};color:white;'
                f'padding:2px 6px;border-radius:3px;'
                f'font-size:.8em;font-weight:bold">{label}</span>'
            )

        def findings_html(items: list, label: str) -> str:
            if not items:
                return f"<p>No {label} found.</p>"
            rows = []
            for i in items:
                sev = (
                    getattr(i, "severity", "high").lower()
                    if hasattr(i, "severity")
                    else "high"
                )
                rows.append(
                    f'<div style="margin-bottom:8px">'
                    f'{badge(sev, label.upper())} '
                    f'{getattr(i, "url", "")}'
                    f'</div>'
                )
            return "".join(rows)

        nuclei_html = (
            "".join(
                f'<p>{badge(v.get("info",{}).get("severity","low"),"NUCLEI")} '
                f'{v.get("info",{}).get("name","Unknown")}</p>'
                for v in target.nuclei_findings[:20]
            )
            or "<p>No nuclei findings.</p>"
        )

        scan_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>BBRecon v{VERSION} — {target.domain}</title>
<style>
body{{font-family:system-ui,-apple-system,sans-serif;background:#1a1a2e;color:#eee;padding:2rem;margin:0}}
.container{{max-width:1200px;margin:0 auto}}
h1{{color:#00d4ff;font-size:1.8rem}}
h2{{color:#7b2cbf;border-bottom:1px solid #444;padding-bottom:.5rem}}
.card{{background:rgba(255,255,255,.05);padding:1.5rem;margin-bottom:1rem;border-radius:10px;border:1px solid #333}}
.stat{{display:inline-block;margin-right:1.5rem;text-align:center}}
.stat .num{{font-size:2rem;font-weight:bold;color:#00d4ff}}
.stat .lbl{{font-size:.8rem;color:#888;display:block}}
.grid{{display:grid;grid-template-columns:1fr 1fr;gap:1rem}}
@media(max-width:700px){{.grid{{grid-template-columns:1fr}}}}
</style>
</head>
<body>
<div class="container">
<h1>🔍 BBRecon v{VERSION} — {target.domain}</h1>
<div class="card">
  <p>
    <strong>Scan Date:</strong> {scan_time} |
    <strong>Status:</strong> {'🟢 Live' if target.is_live else '🔴 Down'} |
    <strong>URL:</strong> {target.live_url or 'N/A'}
  </p>
  <div>
    <div class="stat"><div class="num">{len(target.subdomains)}</div><span class="lbl">Subdomains</span></div>
    <div class="stat"><div class="num">{len(target.urls)}</div><span class="lbl">URLs</span></div>
    <div class="stat"><div class="num">{len(target.open_ports)}</div><span class="lbl">Open Ports</span></div>
    <div class="stat"><div class="num">{len(target.nuclei_findings)}</div><span class="lbl">Nuclei</span></div>
    <div class="stat"><div class="num">{len(target.xss_findings)}</div><span class="lbl">XSS</span></div>
    <div class="stat"><div class="num">{len(target.sqli_findings)}</div><span class="lbl">SQLi</span></div>
    <div class="stat"><div class="num">{len(target.secret_findings)}</div><span class="lbl">Secrets</span></div>
  </div>
</div>
<div class="grid">
  <div class="card"><h2>🔑 Secrets ({len(target.secret_findings)})</h2>{findings_html(target.secret_findings,"secret")}</div>
  <div class="card"><h2>💉 SQL Injection ({len(target.sqli_findings)})</h2>{findings_html(target.sqli_findings,"sqli")}</div>
  <div class="card"><h2>🚨 XSS ({len(target.xss_findings)})</h2>{findings_html(target.xss_findings,"xss")}</div>
  <div class="card"><h2>☢️ Nuclei ({len(target.nuclei_findings)})</h2>{nuclei_html}</div>
</div>
<div class="card">
  <h2>📡 Subdomains ({len(target.subdomains)})</h2>
  <p>{' | '.join(list(target.subdomains)[:50]) or 'None'}</p>
</div>
<div class="card">
  <h2>🔌 Open Ports</h2>
  <p>{', '.join(str(p) for p in sorted(target.open_ports)) or 'None'}</p>
</div>
</div>
</body>
</html>"""
        with open(output_path, "w") as f:
            f.write(html)
        return str(output_path)


# ============================================================
# SECTION 17: TOOL CHECKER
# ============================================================

class ToolChecker:
    TOOLS: Dict[str, str] = {
        "subfinder":   "go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
        "amass":       "go install github.com/owasp-amass/amass/v4/...@master",
        "assetfinder": "go install github.com/tomnomnom/assetfinder@latest",
        "waybackurls": "go install github.com/tomnomnom/waybackurls@latest",
        "gau":         "go install github.com/lc/gau/v2/cmd/gau@latest",
        "katana":      "go install github.com/projectdiscovery/katana/cmd/katana@latest",
        "httpx":       "go install github.com/projectdiscovery/httpx/cmd/httpx@latest",
        "naabu":       "go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest",
        "nuclei":      "go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
        "nmap":        "apt install nmap",
        "massdns":     "https://github.com/blechschmidt/massdns",
    }

    def __init__(self) -> None:
        self.available: Dict[str, bool] = {}
        self.missing:   Dict[str, str]  = {}

    def check_all(self) -> dict:
        for tool, install_cmd in self.TOOLS.items():
            if shutil.which(tool):
                self.available[tool] = True
            else:
                self.missing[tool] = install_cmd
        return {"available": self.available, "missing": self.missing}

    def is_available(self, tool: str) -> bool:
        return tool in self.available

    def print_status(self) -> None:
        Console.section("Tool Availability")
        rows = [
            [
                t,
                "✓ Available" if t in self.available else "✗ Missing",
                "-" if t in self.available else self.TOOLS[t][:50] + "...",
            ]
            for t in self.TOOLS
        ]
        Console.table(["Tool", "Status", "Install"], rows)
        if self.missing:
            Console.warning(f"{len(self.missing)} tool(s) missing.")
        else:
            Console.success("All tools available!")


# ============================================================
# SECTION 18: TARGET
# ============================================================

@dataclass
class Target:
    """Holds all data collected during a single scan run."""

    domain:          str
    output_dir:      Optional[Path]       = None
    is_live:         bool                 = False
    live_url:        str                  = ""
    ip_addresses:    List[str]            = field(default_factory=list)
    subdomains:      Set[str]             = field(default_factory=set)
    urls:            Set[str]             = field(default_factory=set)
    urls_with_params: Set[str]            = field(default_factory=set)
    open_ports:      List[int]            = field(default_factory=list)
    # catch-all vuln list (nuclei + xss + sqli + secret dicts)
    vulnerabilities: List[dict]           = field(default_factory=list)
    # nuclei-only list — used by HTML report Nuclei section
    nuclei_findings: List[dict]           = field(default_factory=list)
    xss_findings:    List[XSSFinding]     = field(default_factory=list)
    sqli_findings:   List[SQLiFinding]    = field(default_factory=list)
    secret_findings: List[SecretFinding]  = field(default_factory=list)
    github_findings: List[GithubFinding]  = field(default_factory=list)
    # OSINT-derived (Pair 5)
    takeover_findings:     List[TakeoverFinding]     = field(default_factory=list)
    cors_findings:         List[CorsFinding]         = field(default_factory=list)
    redirect_findings:     List[OpenRedirectFinding] = field(default_factory=list)
    git_exposure_findings: List[GitExposureFinding]  = field(default_factory=list)
    env_file_findings:     List[EnvFileFinding]      = field(default_factory=list)
    dns_health:            Optional["DnsHealthFinding"] = None
    nmap_file:       str                  = ""

    def __post_init__(self) -> None:
        if self.output_dir is None:
            # B22: use normalized domain (no scheme/slash) for safe path
            safe_name = (
                self.domain
                .replace("/", "_")
                .replace(":", "_")
                .replace("*", "wildcard")
                .strip("_")
            )
            self.output_dir = (
                DEFAULT_OUTPUT
                / safe_name
                / datetime.now().strftime("%Y%m%d_%H%M%S")
            )

    def save_state(self) -> None:
        self.output_dir.mkdir(parents=True, exist_ok=True)
        state = {
            "domain":                 self.domain,
            "is_live":                self.is_live,
            "live_url":               self.live_url,
            "ip_addresses":           self.ip_addresses,
            "subdomains":             list(self.subdomains),
            "urls_count":             len(self.urls),
            "urls_with_params_count": len(self.urls_with_params),
            "open_ports":             self.open_ports,
            "vulnerabilities_count":  len(self.vulnerabilities),
            "nuclei_findings_count":  len(self.nuclei_findings),
            "xss_findings_count":     len(self.xss_findings),
            "sqli_findings_count":    len(self.sqli_findings),
            "secret_findings_count":  len(self.secret_findings),
            "github_findings_count":  len(self.github_findings),
            "takeover_findings_count": len(self.takeover_findings),
            "cors_findings_count":     len(self.cors_findings),
            "redirect_findings_count": len(self.redirect_findings),
            "git_exposure_count":      len(self.git_exposure_findings),
            "env_file_count":          len(self.env_file_findings),
            "scan_time":              datetime.now().isoformat(),
        }
        with open(self.output_dir / "state.json", "w") as f:
            json.dump(state, f, indent=2)


# ============================================================
# SECTION 19: DB PERSIST HELPERS
# ============================================================

async def _persist_nuclei_findings(
    db: Database, program: str, findings: list
) -> None:
    for f in findings:
        fid = hashlib.md5(
            f"{f.get('matched-at','')}|{f.get('template-id','')}".encode()
        ).hexdigest()
        await db._conn.execute(
            """INSERT OR REPLACE INTO nuclei_findings
               (id,program,host,template_id,name,severity,
                matched_at,tags,raw_json,found_at)
               VALUES(:id,:program,:host,:template_id,:name,:severity,
                      :matched_at,:tags,:raw_json,datetime('now'))""",
            {
                "id":          fid,
                "program":     program,
                "host":        f.get("host", f.get("matched-at", "")),
                "template_id": f.get("template-id", ""),
                "name":        f.get("info", {}).get("name",     ""),
                "severity":    f.get("info", {}).get("severity", ""),
                "matched_at":  f.get("matched-at", ""),
                "tags":        ",".join(f.get("info", {}).get("tags", [])),
                "raw_json":    json.dumps(f),
            },
        )
    await db._conn.commit()


async def _persist_xss_findings(
    db: Database, program: str, findings: List[XSSFinding]
) -> None:
    for f in findings:
        fid = hashlib.md5(
            f"{f.url}|{f.parameter}|{f.payload}".encode()
        ).hexdigest()
        await db._conn.execute(
            """INSERT OR REPLACE INTO xss_findings
               (id,program,url,parameter,payload,severity,confidence,evidence,found_at)
               VALUES(?,?,?,?,?,?,?,?,datetime('now'))""",
            (fid, program, f.url, f.parameter, f.payload,
             f.severity, f.confidence, f.evidence),
        )
    await db._conn.commit()


async def _persist_sqli_findings(
    db: Database, program: str, findings: List[SQLiFinding]
) -> None:
    for f in findings:
        fid = hashlib.md5(
            f"{f.url}|{f.parameter}|{f.payload}".encode()
        ).hexdigest()
        await db._conn.execute(
            """INSERT OR REPLACE INTO sqli_findings
               (id,program,url,parameter,payload,error_msg,found_at)
               VALUES(?,?,?,?,?,?,datetime('now'))""",
            (fid, program, f.url, f.parameter, f.payload, f.error_msg),
        )
    await db._conn.commit()


async def _persist_secret_findings(
    db: Database, program: str, findings: List[SecretFinding]
) -> None:
    for f in findings:
        fid = hashlib.md5(
            f"{f.url}|{f.type}|{f.match}".encode()
        ).hexdigest()
        await db._conn.execute(
            """INSERT OR REPLACE INTO secret_findings
               (id,program,url,type,match,found_at)
               VALUES(?,?,?,?,?,datetime('now'))""",
            (fid, program, f.url, f.type, f.match),
        )
    await db._conn.commit()


# ============================================================
# SECTION 20: MAIN ENGINE
# ============================================================

class BBReconEngine:
    """
    Main scanning engine — v5.0.0.
    11-phase pipeline with WAF-aware liveness, domain normalisation,
    concurrent XSS, bounded concurrency throughout.
    """

    def __init__(self, config: Optional[Config] = None) -> None:
        self.config = config or Config.load()
        self.tools  = ToolChecker()
        self.tools.check_all()
        self.db     = Database(Path(self.config.db_path))
        self._prev_scan: Optional[dict] = None

    async def run_tool(
        self, cmd: list, timeout: int = 300
    ) -> Tuple[bool, str, str]:
        """Run an external binary. Returns (success, stdout, stderr)."""
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(
                proc.communicate(), timeout=timeout
            )
            return (
                proc.returncode == 0,
                stdout.decode("utf-8", errors="ignore"),
                stderr.decode("utf-8", errors="ignore"),
            )
        except asyncio.TimeoutError:
            return (False, "", "Timeout")
        except FileNotFoundError:
            return (False, "", "Tool not found")
        except Exception as exc:
            return (False, "", str(exc))

    # ── liveness ────────────────────────────────────────────────
    # Fixes: B12 (HEAD→GET fallback, status<500), B13 (UA), B14 (logging)

    async def check_liveness(self, target: "Target") -> bool:
        Console.progress(f"Checking liveness: {target.domain}")

        if not self.config.is_in_scope(target.domain):
            Console.warning(f"{target.domain} is out-of-scope. Skipping.")
            return False

        timeout = aiohttp.ClientTimeout(total=self.config.liveness_timeout)
        headers = {"User-Agent": self.config.user_agent}

        async with aiohttp.ClientSession(headers=headers) as session:
            for scheme in ("https", "http"):
                url = f"{scheme}://{target.domain}"

                # Try HEAD first (cheaper); fall back to GET if HEAD blocked
                for method in ("HEAD", "GET"):
                    for attempt in range(self.config.liveness_retries):
                        try:
                            req = (
                                session.head
                                if method == "HEAD"
                                else session.get
                            )
                            async with req(
                                url,
                                timeout=timeout,
                                ssl=False,
                                allow_redirects=True,
                            ) as resp:
                                # Accept anything < 500: site exists, even if 403
                                if resp.status < 500:
                                    target.is_live  = True
                                    target.live_url = str(resp.url)
                                    Console.success(
                                        f"LIVE: {target.live_url} "
                                        f"[{method} {resp.status}]"
                                    )
                                    return True
                                log.debug(
                                    "Liveness %s %s → %d",
                                    method, url, resp.status,
                                )
                        except aiohttp.ClientConnectorError as exc:
                            log.debug(
                                "Liveness %s %s attempt %d: %s",
                                method, url, attempt + 1, exc,
                            )
                        except Exception as exc:
                            log.debug(
                                "Liveness %s %s: %s", method, url, exc
                            )
                        # Short pause between retries
                        await asyncio.sleep(1.0)

        Console.warning(f"Target appears DOWN: {target.domain}")
        return False

    # ── subdomain enum ──────────────────────────────────────────

    async def enumerate_subdomains(self, target: "Target") -> Set[str]:
        Console.section(f"Subdomain Enumeration: {target.domain}")
        all_subs: Set[str] = set()
        tasks = []
        if self.tools.is_available("subfinder"):
            tasks.append(("subfinder", self._run_subfinder(target)))
        if self.tools.is_available("amass"):
            tasks.append(("amass", self._run_amass(target)))
        if self.tools.is_available("assetfinder"):
            tasks.append(("assetfinder", self._run_assetfinder(target)))
        if not tasks:
            Console.error("No subdomain enumeration tools available!")
            return all_subs

        results = await asyncio.gather(
            *[t[1] for t in tasks], return_exceptions=True
        )
        for i, result in enumerate(results):
            if isinstance(result, set):
                Console.success(f"{tasks[i][0]}: {len(result)} subdomains")
                all_subs.update(result)

        target.subdomains = all_subs
        target.output_dir.mkdir(parents=True, exist_ok=True)
        with open(target.output_dir / "subdomains.txt", "w") as f:
            for sub in sorted(all_subs):
                f.write(sub + "\n")

        async with self.db as db:
            await db._conn.execute(
                "INSERT OR IGNORE INTO programs"
                " (slug,name,platform,url,live,created_at,updated_at)"
                " VALUES(?,?,'bbrecon',?,?,datetime('now'),datetime('now'))",
                (
                    target.domain,
                    target.domain,
                    target.live_url or f"https://{target.domain}",
                    int(target.is_live),
                ),
            )
            await db._conn.commit()
            for sub in all_subs:
                await db.upsert_domain(
                    {
                        "name":      sub,
                        "program":   target.domain,
                        "createdAt": datetime.now().isoformat(),
                    }
                )

        Console.success(f"Total unique subdomains: {len(all_subs)}")
        return all_subs

    async def _run_subfinder(self, target: "Target") -> Set[str]:
        Console.progress("Running Subfinder...")
        ok, out, _ = await self.run_tool(
            ["subfinder", "-d", target.domain, "-silent"]
        )
        return {l.strip() for l in out.split("\n") if l.strip()} if ok else set()

    async def _run_amass(self, target: "Target") -> Set[str]:
        Console.progress("Running Amass (passive)...")
        ok, out, _ = await self.run_tool(
            ["amass", "enum", "-passive", "-d", target.domain], timeout=600
        )
        return {l.strip() for l in out.split("\n") if l.strip()} if ok else set()

    async def _run_assetfinder(self, target: "Target") -> Set[str]:
        Console.progress("Running Assetfinder...")
        ok, out, _ = await self.run_tool(
            ["assetfinder", "--subs-only", target.domain]
        )
        return {l.strip() for l in out.split("\n") if l.strip()} if ok else set()

    # ── massdns ──────────────────────────────────────────────────

    async def run_massdns(self, target: "Target") -> Set[str]:
        Console.section(f"DNS Brute-force (massdns): {target.domain}")
        runner = MassdnsRunner(
            domain=target.domain,
            wordlist=self.config.massdns_wordlist or None,
            resolvers=self.config.massdns_resolvers or None,
            rate=self.config.massdns_rate,
        )
        if not runner.available:
            Console.warning(
                "massdns not found — skipping. "
                "Install: https://github.com/blechschmidt/massdns"
            )
            return set()
        new_subs = await runner.run()
        before   = len(target.subdomains)
        target.subdomains.update(new_subs)
        added = len(target.subdomains) - before
        Console.success(
            f"massdns: {len(new_subs)} found → "
            f"{added} new (total {len(target.subdomains)})"
        )
        async with self.db as db:
            for sub in new_subs:
                await db.upsert_domain(
                    {
                        "name":      sub,
                        "program":   target.domain,
                        "createdAt": datetime.now().isoformat(),
                    }
                )
        if new_subs:
            with open(target.output_dir / "subdomains.txt", "a") as f:
                for sub in sorted(new_subs):
                    f.write(sub + "\n")
        return new_subs

    # ── live probe ───────────────────────────────────────────────
    # Fix B15: adds bare target.domain to host set (no scheme)

    async def run_live_probe(self, target: "Target") -> List[ProbeResult]:
        Console.section(f"Live Probe + Fingerprint: {target.domain}")
        # B15: ensure we probe the bare domain, not a URL string
        hosts = target.subdomains | {target.domain}
        if not hosts:
            Console.warning("No hosts to probe.")
            return []
        Console.info(
            f"Probing {len(hosts)} hosts "
            f"(concurrency={self.config.probe_concurrency})..."
        )
        async with LiveProbe(
            program=target.domain,
            timeout=self.config.probe_timeout,
            concurrency=self.config.probe_concurrency,
            user_agent=self.config.user_agent,
        ) as probe:
            results = await probe.run(hosts)

        live = [r for r in results if r.live]
        Console.success(f"Live: {len(live)}  Dead: {len(results) - len(live)}")

        # Tech summary
        tech_counts: Dict[str, int] = {}
        for r in live:
            for t in r.technologies:
                tech_counts[t] = tech_counts.get(t, 0) + 1
        if tech_counts:
            top = sorted(tech_counts.items(), key=lambda x: -x[1])[:10]
            Console.info(
                "Top tech: " + ", ".join(f"{t}({c})" for t, c in top)
            )

        async with self.db as db:
            await persist_probe_results(db, results)

        target.output_dir.mkdir(parents=True, exist_ok=True)
        with open(target.output_dir / "live_hosts.txt", "w") as f:
            for r in live:
                techs = ",".join(r.technologies) if r.technologies else "-"
                f.write(
                    f"{r.url} [{r.status}] "
                    f"server={r.server or '-'} tech={techs}\n"
                )
        return results

    # ── URL discovery ────────────────────────────────────────────
    # Fix B24: katana gated on target.live_url (not target.is_live bool)

    async def discover_urls(self, target: "Target") -> Set[str]:
        Console.section(f"URL Discovery: {target.domain}")
        all_urls: Set[str] = set()
        tasks = []
        if self.tools.is_available("waybackurls"):
            tasks.append(("waybackurls", self._run_waybackurls(target)))
        if self.tools.is_available("gau"):
            tasks.append(("gau", self._run_gau(target)))
        # B24: gate on live_url being non-empty, not is_live bool
        # This survives WAF/redirect scenarios where is_live stayed False
        # but we got a live_url anyway (shouldn't happen post-B12, but defensive)
        if self.tools.is_available("katana") and target.live_url:
            tasks.append(("katana", self._run_katana(target)))
        if not tasks:
            Console.error("No URL discovery tools available!")
            return all_urls

        results = await asyncio.gather(
            *[t[1] for t in tasks], return_exceptions=True
        )
        for i, result in enumerate(results):
            if isinstance(result, set):
                Console.success(f"{tasks[i][0]}: {len(result)} URLs")
                all_urls.update(result)

        param_urls = {u for u in all_urls if "?" in u and "=" in u}
        target.urls            = all_urls
        target.urls_with_params = param_urls

        target.output_dir.mkdir(parents=True, exist_ok=True)
        with open(target.output_dir / "urls_all.txt", "w") as f:
            for u in sorted(all_urls):
                f.write(u + "\n")
        with open(target.output_dir / "urls_with_params.txt", "w") as f:
            for u in sorted(param_urls):
                f.write(u + "\n")

        Console.success(
            f"Total URLs: {len(all_urls)} ({len(param_urls)} with params)"
        )
        return all_urls

    async def _run_waybackurls(self, target: "Target") -> Set[str]:
        Console.progress("Running Waybackurls...")
        ok, out, _ = await self.run_tool(
            ["waybackurls", target.domain], timeout=600
        )
        return {l.strip() for l in out.split("\n") if l.strip()} if ok else set()

    async def _run_gau(self, target: "Target") -> Set[str]:
        Console.progress("Running GAU...")
        ok, out, _ = await self.run_tool(
            ["gau", "--threads", "5", target.domain], timeout=600
        )
        return {l.strip() for l in out.split("\n") if l.strip()} if ok else set()

    async def _run_katana(self, target: "Target") -> Set[str]:
        Console.progress("Running Katana...")
        ok, out, _ = await self.run_tool(
            ["katana", "-u", target.live_url, "-d", "3", "-silent"]
        )
        return {l.strip() for l in out.split("\n") if l.strip()} if ok else set()

    # ── port scan ────────────────────────────────────────────────

    async def scan_ports(self, target: "Target") -> List[int]:
        Console.section(f"Port Scanning: {target.domain}")
        if not self.tools.is_available("naabu"):
            Console.warning("Naabu not available. Skipping port scan.")
            return []
        Console.progress("Running Naabu...")
        ok, out, _ = await self.run_tool(
            ["naabu", "-host", target.domain, "-top-ports", "1000", "-silent"]
        )
        ports: List[int] = []
        if ok:
            for line in out.split("\n"):
                if ":" in line:
                    try:
                        ports.append(int(line.split(":")[-1].strip()))
                    except ValueError:
                        pass

        target.open_ports = ports
        target.output_dir.mkdir(parents=True, exist_ok=True)
        with open(target.output_dir / "ports.txt", "w") as f:
            for port in sorted(ports):
                f.write(f"{target.domain}:{port}\n")
        Console.success(f"Found {len(ports)} open ports")

        # Nmap deep scan on open ports (only if ports found)
        if ports and self.tools.is_available("nmap"):
            nmap = NmapScanner(target.output_dir)
            target.nmap_file = await nmap.scan_targets(
                [target.domain], mode=self.config.nmap_mode
            )
        return ports

    # ── nuclei per-host (U5) ─────────────────────────────────────

    async def run_nuclei_per_host(
        self, target: "Target", probe_results: List[ProbeResult]
    ) -> List[dict]:
        Console.section(f"Nuclei Per-Host Scan: {target.domain}")
        if not self.tools.is_available("nuclei"):
            Console.warning("Nuclei not available. Skipping.")
            return []
        live_results = [r for r in probe_results if r.live]
        if not live_results:
            Console.warning("No live hosts from probe. Skipping nuclei.")
            return []
        Console.info(
            f"Scanning {len(live_results)} live hosts "
            f"(concurrency={self.config.nuclei_concurrency})..."
        )
        sem   = asyncio.Semaphore(self.config.nuclei_concurrency)
        tasks = [
            self._nuclei_one_host(target, r.url, r.technologies, sem, idx)
            for idx, r in enumerate(live_results)
        ]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        all_findings: List[dict] = []
        for r in results:
            if isinstance(r, list):
                all_findings.extend(r)

        # Deduplicate by matched-at + template-id
        seen:   set       = set()
        deduped: List[dict] = []
        for f in all_findings:
            key = f"{f.get('matched-at','')}|{f.get('template-id','')}"
            if key not in seen:
                seen.add(key)
                deduped.append(f)

        Console.success(
            f"Nuclei: {len(deduped)} unique findings "
            f"({len(all_findings) - len(deduped)} dupes removed)"
        )
        target.nuclei_findings.extend(deduped)  # nuclei-only list (report)
        target.vulnerabilities.extend(deduped)  # catch-all

        if deduped:
            async with self.db as db:
                await _persist_nuclei_findings(db, target.domain, deduped)
        return deduped

    async def _nuclei_one_host(
        self,
        target:       "Target",
        url:          str,
        technologies: list,
        sem:          asyncio.Semaphore,
        idx:          int,
    ) -> List[dict]:
        async with sem:
            tags      = _tags_for_technologies(technologies)
            safe_host = (
                url.replace("://", "_")
                   .replace("/", "_")
                   .replace(":", "_")
            )
            output_file = (
                target.output_dir / f"nuclei_{safe_host[:60]}_{idx}.json"
            )
            target.output_dir.mkdir(parents=True, exist_ok=True)
            Console.progress(f"nuclei → {url} [tags: {','.join(tags)}]")
            await self.run_tool(
                [
                    "nuclei", "-u", url,
                    "-tags",     ",".join(tags),
                    "-severity", self.config.nuclei_severity,
                    "-json-export", str(output_file),
                    "-silent", "-no-interactsh",
                ],
                timeout=600,
            )
            findings: List[dict] = []
            if output_file.exists():
                with open(output_file) as f:
                    for line in f:
                        line = line.strip()
                        if not line:
                            continue
                        try:
                            finding          = json.loads(line)
                            finding["host"]  = url
                            findings.append(finding)
                            sev  = finding.get("info", {}).get("severity", "?")
                            name = finding.get("info", {}).get("name",     "?")
                            Console.success(f"[{sev.upper()}] {url}: {name}")
                        except json.JSONDecodeError:
                            pass
            return findings

    # ── diff mode (U6) ──────────────────────────────────────────

    async def load_diff_baseline(self, domain: str) -> None:
        async with self.db as db:
            self._prev_scan = await _load_prev_scan(db, domain)
        if self._prev_scan:
            Console.info(
                f"Diff baseline loaded: {self._prev_scan.get('scan_time')}"
            )
        else:
            Console.info("No previous scan — this will be baseline.")

    async def save_diff_report(
        self, target: "Target", diff: dict
    ) -> None:
        if diff.get("first_scan"):
            return
        ts        = datetime.now().strftime("%Y%m%d_%H%M%S")
        diff_file = target.output_dir / f"diff_{ts}.json"
        target.output_dir.mkdir(parents=True, exist_ok=True)
        with open(diff_file, "w") as f:
            json.dump(diff, f, indent=2)
        Console.info(f"Diff report saved: {diff_file}")

    # ── XSS scan ────────────────────────────────────────────────

    async def run_xss_scan(
        self, target: "Target"
    ) -> List[XSSFinding]:
        Console.section(f"XSS Scanning: {target.domain}")
        if not target.urls_with_params:
            Console.warning("No param URLs. Skipping XSS scan.")
            return []
        scanner  = XSSScanner(
            target.output_dir,
            timeout=self.config.timeout,
            rate_limit=self.config.rate_limit,
        )
        findings = await scanner.scan_urls(
            list(target.urls_with_params),
            max_urls=self.config.xss_max_urls,
        )
        target.xss_findings = findings
        for f in findings:
            target.vulnerabilities.append(f.to_dict())

        if findings:
            with open(target.output_dir / "xss_findings.txt", "w") as f:
                for xf in findings:
                    f.write(
                        f"[{xf.severity}] {xf.url}\n"
                        f"  Param:    {xf.parameter}\n"
                        f"  Payload:  {xf.payload}\n"
                        f"  Evidence: {xf.evidence}\n\n"
                    )
            async with self.db as db:
                await _persist_xss_findings(db, target.domain, findings)
            Console.success(
                f"XSS: {len(findings)} found. "
                f"Evidence → {target.output_dir}/xss_evidence/"
            )
        else:
            Console.info("No XSS vulnerabilities found.")
        return findings

    # ── SQLi scan ────────────────────────────────────────────────

    async def run_sqli_scan(
        self, target: "Target"
    ) -> List[SQLiFinding]:
        Console.section(f"SQLi Scanning: {target.domain}")
        if not target.urls_with_params:
            Console.warning("No param URLs. Skipping SQLi scan.")
            return []
        scanner  = SQLiScanner(target.output_dir)
        findings = await scanner.scan_targets(list(target.urls_with_params))
        target.sqli_findings = findings
        for f in findings:
            target.vulnerabilities.append(f.to_dict())

        if findings:
            with open(target.output_dir / "sqli_findings.txt", "w") as f:
                for sf in findings:
                    f.write(
                        f"[CRITICAL] {sf.url}\n"
                        f"  Param:   {sf.parameter}\n"
                        f"  Payload: {sf.payload}\n"
                        f"  Error:   {sf.error_msg}\n\n"
                    )
            async with self.db as db:
                await _persist_sqli_findings(db, target.domain, findings)
            Console.success(
                f"SQLi: {len(findings)} potential injection(s) found!"
            )
        else:
            Console.info("No SQLi vulnerabilities found.")
        return findings

    # ── Secrets scan ─────────────────────────────────────────────

    async def run_secrets_scan(
        self, target: "Target"
    ) -> List[SecretFinding]:
        Console.section(f"Secrets Scan: {target.domain}")
        if not target.urls:
            Console.warning("No URLs. Skipping secrets scan.")
            return []
        scanner  = SecretsScanner(target.output_dir)
        findings = await scanner.scan_targets(list(target.urls))
        target.secret_findings = findings
        for f in findings:
            target.vulnerabilities.append(f.to_dict())

        if findings:
            with open(target.output_dir / "secret_findings.txt", "w") as f:
                for sf in findings:
                    f.write(
                        f"[SECRET] {sf.type} in {sf.url}\n"
                        f"  Match: {sf.match}\n\n"
                    )
            async with self.db as db:
                await _persist_secret_findings(db, target.domain, findings)
            Console.success(f"Secrets: {len(findings)} found!")
            for sf in findings:
                Console.warning(f"  {sf.type}: {sf.match} in {sf.url}")
        else:
            Console.info("No secrets found.")
        return findings


    # ============================================================
    # PAIR 5: OSINT-DERIVED MODULES (20 modules, async-reimplemented)
    # ============================================================
    # Each method below replaces a sync/requests OSINT CLI script with an
    # async aiohttp equivalent integrated into BBReconEngine's pipeline.
    # Source modules credited in docstrings. Logic adapted, not copied,
    # to match bbrecon's session/concurrency/error-handling conventions.

    # --- subdomain_takeover.py + cors_misconfiguration_scanner.py ---

    _TAKEOVER_SIGNATURES = {
        "AWS S3":              "NoSuchBucket",
        "GitHub Pages":        "There isn't a GitHub Pages site here",
        "Heroku":              "no such app",
        "Azure":               "404 web site not found",
        "Shopify":             "Sorry, this shop is currently unavailable",
        "Fastly":              "Fastly error: unknown domain",
        "Unbounce":            "The requested URL was not found on this server",
        "Pantheon":            "The gods are wise, but do not know of this place",
        "Cargo Collective":    "404 Not Found",
        "Tumblr":              "There's nothing here",
        "WordPress":           "Do you want to register",
        "Surge.sh":            "project not found",
        "Netlify":             "Not Found - Request ID",
    }

    async def run_subdomain_takeover(self, target: "Target") -> List[TakeoverFinding]:
        """
        OSINT source: subdomain_takeover.py
        Checks each subdomain's CNAME against known dangling-service
        signatures (S3, GitHub Pages, Heroku, etc.), then fetches the
        page body looking for the "this resource doesn't exist" marker
        that confirms a takeover is possible.
        """
        Console.section(f"Subdomain Takeover Check: {target.domain}")
        findings: List[TakeoverFinding] = []
        if not self.config.is_in_scope(target.domain):
            Console.warning(f"{target.domain} out-of-scope. Skipping takeover check.")
            return findings
        in_scope_subs = {s for s in target.subdomains if self.config.is_in_scope(s)}
        if not in_scope_subs:
            Console.warning("No in-scope subdomains to check for takeover.")
            return findings

        sem = asyncio.Semaphore(20)
        headers = {"User-Agent": _DEFAULT_UA}

        async def check_one(sub: str, session: aiohttp.ClientSession) -> None:
            async with sem:
                cname = ""
                if _DNSPYTHON_AVAILABLE:
                    try:
                        answers = await asyncio.get_event_loop().run_in_executor(
                            None,
                            lambda s=sub: list(dns.resolver.resolve(s, "CNAME", lifetime=5))
                        )
                        cname = str(answers[0].target).rstrip(".") if answers else ""
                    except Exception:
                        pass
                for scheme in ("https", "http"):
                    try:
                        async with session.get(
                            f"{scheme}://{sub}", timeout=aiohttp.ClientTimeout(total=8),
                            ssl=False, allow_redirects=True,
                        ) as resp:
                            body = (await resp.text(errors="ignore"))[:4000]
                            for service, sig in self._TAKEOVER_SIGNATURES.items():
                                if sig in body:
                                    findings.append(TakeoverFinding(
                                        subdomain=sub, cname=cname, service=service,
                                        evidence=sig,
                                    ))
                                    Console.warning(f"Possible takeover: {sub} → {service}")
                                    return
                            return
                    except Exception:
                        continue

        async with aiohttp.ClientSession(headers=headers) as session:
            await asyncio.gather(*[check_one(s, session) for s in in_scope_subs])

        target.takeover_findings = findings
        for f in findings:
            target.vulnerabilities.append(f.to_dict())
        if findings:
            async with Database(Path(self.config.db_path)) as db:
                for f in findings:
                    fid = hashlib.md5(f"{f.subdomain}|{f.service}".encode()).hexdigest()
                    await db._conn.execute(
                        "INSERT OR REPLACE INTO takeover_findings "
                        "(id,program,subdomain,cname,service,evidence,found_at) "
                        "VALUES(?,?,?,?,?,?,datetime('now'))",
                        (fid, target.domain, f.subdomain, f.cname, f.service, f.evidence),
                    )
                await db._conn.commit()
            Console.success(f"Takeover check: {len(findings)} possible takeover(s) found")
        else:
            Console.info("No subdomain takeover indicators found.")
        return findings

    async def run_cors_scan(self, target: "Target") -> List[CorsFinding]:
        """
        OSINT source: cors_misconfiguration_scanner.py
        Sends crafted Origin headers (reflect-target, random subdomain,
        null, evil) against discovered URLs with params, classifies the
        Access-Control-Allow-Origin/Credentials response.
        """
        Console.section(f"CORS Misconfiguration Scan: {target.domain}")
        findings: List[CorsFinding] = []
        if not self.config.is_in_scope(target.domain):
            Console.warning(f"{target.domain} out-of-scope. Skipping CORS scan.")
            return findings
        if not target.is_live or not target.live_url:
            Console.warning("Target not live. Skipping CORS scan.")
            return findings

        target_origin = target.live_url.rstrip("/")
        rand_sub = hashlib.md5(target.domain.encode()).hexdigest()[:8]
        test_origins = [
            target_origin,
            f"https://{rand_sub}.{target.domain}",
            "null",
            "https://evil.example",
        ]
        headers = {"User-Agent": _DEFAULT_UA}
        sem = asyncio.Semaphore(10)

        async def test_origin(origin: str, session: aiohttp.ClientSession) -> None:
            async with sem:
                try:
                    async with session.get(
                        target_origin, headers={"Origin": origin},
                        timeout=aiohttp.ClientTimeout(total=10), ssl=False,
                        allow_redirects=False,
                    ) as resp:
                        acao = resp.headers.get("Access-Control-Allow-Origin", "")
                        acac = resp.headers.get("Access-Control-Allow-Credentials", "")
                        if not acao:
                            return
                        acac_flag = acac.lower() == "true"
                        if acao == "*":
                            cls = "Wildcard+Creds" if acac_flag else "Wildcard"
                        elif acao.lower() == origin.lower():
                            if origin == target_origin:
                                cls = "Reflect-Target+Creds" if acac_flag else "Reflect-Target"
                            else:
                                cls = "Reflect-Other+Creds" if acac_flag else "Reflect-Other"
                        else:
                            cls = "Other"
                        if cls in ("Wildcard+Creds", "Reflect-Other+Creds", "Reflect-Other"):
                            findings.append(CorsFinding(
                                url=target_origin, origin_tested=origin,
                                acao=acao, acac=acac, classification=cls,
                            ))
                            Console.warning(f"CORS issue: {cls} (origin={origin})")
                except Exception as exc:
                    log.debug("CORS test error %s: %s", origin, exc)

        async with aiohttp.ClientSession(headers=headers) as session:
            await asyncio.gather(*[test_origin(o, session) for o in test_origins])

        target.cors_findings = findings
        for f in findings:
            target.vulnerabilities.append(f.to_dict())
        if findings:
            async with Database(Path(self.config.db_path)) as db:
                for f in findings:
                    fid = hashlib.md5(f"{f.url}|{f.origin_tested}".encode()).hexdigest()
                    await db._conn.execute(
                        "INSERT OR REPLACE INTO cors_findings "
                        "(id,program,url,origin_tested,acao,acac,classification,found_at) "
                        "VALUES(?,?,?,?,?,?,?,datetime('now'))",
                        (fid, target.domain, f.url, f.origin_tested, f.acao, f.acac, f.classification),
                    )
                await db._conn.commit()
            Console.success(f"CORS scan: {len(findings)} misconfiguration(s) found")
        else:
            Console.info("No exploitable CORS misconfigurations found.")
        return findings

    # --- open_redirect_finder.py + redirect_chain.py ---

    _REDIRECT_PARAMS = ["url","redirect","next","target","dest","destination",
                         "return","returnUrl","continue","goto","r","u"]
    _REDIRECT_PAYLOAD = "https://evil.example"

    async def run_open_redirect_scan(self, target: "Target") -> List[OpenRedirectFinding]:
        """
        OSINT source: open_redirect_finder.py + redirect_chain.py
        Injects a known-external payload into common redirect param names
        on discovered param-URLs; flags any Location header pointing at
        the external payload host (open redirect confirmed).
        """
        Console.section(f"Open Redirect Scan: {target.domain}")
        findings: List[OpenRedirectFinding] = []
        if not self.config.is_in_scope(target.domain):
            Console.warning(f"{target.domain} out-of-scope. Skipping open redirect scan.")
            return findings
        if not target.urls_with_params:
            Console.warning("No param URLs. Skipping open redirect scan.")
            return findings

        headers = {"User-Agent": _DEFAULT_UA}
        sem = asyncio.Semaphore(20)
        candidates = [u for u in list(target.urls_with_params)[: self.config.xss_max_urls]
                      if self.config.is_in_scope(u)]

        async def test_url(url: str, session: aiohttp.ClientSession) -> None:
            parsed = urlparse(url)
            params = parse_qs(parsed.query)
            relevant = [p for p in params if p.lower() in self._REDIRECT_PARAMS]
            for param in relevant:
                async with sem:
                    new_params = dict(params)
                    new_params[param] = [self._REDIRECT_PAYLOAD]
                    test_url_str = parsed._replace(
                        query=urlencode(new_params, doseq=True)
                    ).geturl()
                    try:
                        async with session.get(
                            test_url_str, timeout=aiohttp.ClientTimeout(total=8),
                            ssl=False, allow_redirects=False,
                        ) as resp:
                            loc = resp.headers.get("Location", "")
                            if "evil.example" in loc:
                                findings.append(OpenRedirectFinding(
                                    url=url, param=param,
                                    payload=self._REDIRECT_PAYLOAD, location=loc,
                                ))
                                Console.warning(f"Open redirect: {url} (param={param})")
                    except Exception as exc:
                        log.debug("Redirect test error %s: %s", test_url_str, exc)

        async with aiohttp.ClientSession(headers=headers) as session:
            await asyncio.gather(*[test_url(u, session) for u in candidates])

        target.redirect_findings = findings
        for f in findings:
            target.vulnerabilities.append(f.to_dict())
        if findings:
            async with Database(Path(self.config.db_path)) as db:
                for f in findings:
                    fid = hashlib.md5(f"{f.url}|{f.param}".encode()).hexdigest()
                    await db._conn.execute(
                        "INSERT OR REPLACE INTO redirect_findings "
                        "(id,program,url,param,payload,location,found_at) "
                        "VALUES(?,?,?,?,?,?,datetime('now'))",
                        (fid, target.domain, f.url, f.param, f.payload, f.location),
                    )
                await db._conn.commit()
            Console.success(f"Open redirect scan: {len(findings)} found")
        else:
            Console.info("No open redirects found.")
        return findings

    # --- git_repo_exposure_check.py ---

    _DOT_GIT_PATHS = (
        "/.git/HEAD", "/.git/config", "/.git/index", "/.git/packed-refs",
        "/.git/logs/HEAD", "/.git/refs/heads/master", "/.git/refs/heads/main",
        "/.git/COMMIT_EDITMSG", "/.gitignore",
    )

    async def run_git_exposure_check(self, target: "Target") -> List[GitExposureFinding]:
        """
        OSINT source: git_repo_exposure_check.py
        Probes common .git artifact paths on the live host; a 200 with
        nonzero body size on /.git/HEAD or similar means a leaked
        repository (source code + history exposure).
        """
        Console.section(f"Git Exposure Check: {target.domain}")
        findings: List[GitExposureFinding] = []
        if not self.config.is_in_scope(target.domain):
            Console.warning(f"{target.domain} out-of-scope. Skipping git exposure check.")
            return findings
        if not target.is_live or not target.live_url:
            Console.warning("Target not live. Skipping git exposure check.")
            return findings

        base = target.live_url.rstrip("/")
        headers = {"User-Agent": _DEFAULT_UA}
        sem = asyncio.Semaphore(15)

        async def probe(path: str, session: aiohttp.ClientSession) -> None:
            async with sem:
                url = base + path
                try:
                    async with session.get(
                        url, timeout=aiohttp.ClientTimeout(total=8),
                        ssl=False, allow_redirects=False,
                    ) as resp:
                        body = await resp.read()
                        if resp.status < 400 and len(body) > 0:
                            findings.append(GitExposureFinding(
                                url=url, path=path, status=resp.status, size=len(body),
                            ))
                            Console.warning(f"Git artifact exposed: {path} ({resp.status})")
                except Exception as exc:
                    log.debug("Git probe error %s: %s", url, exc)

        async with aiohttp.ClientSession(headers=headers) as session:
            await asyncio.gather(*[probe(p, session) for p in self._DOT_GIT_PATHS])

        target.git_exposure_findings = findings
        for f in findings:
            target.vulnerabilities.append(f.to_dict())
        if findings:
            async with Database(Path(self.config.db_path)) as db:
                for f in findings:
                    fid = hashlib.md5(f"{f.url}".encode()).hexdigest()
                    await db._conn.execute(
                        "INSERT OR REPLACE INTO git_exposure_findings "
                        "(id,program,url,path,status,size,found_at) "
                        "VALUES(?,?,?,?,?,?,datetime('now'))",
                        (fid, target.domain, f.url, f.path, f.status, f.size),
                    )
                await db._conn.commit()
            Console.success(f"Git exposure: {len(findings)} artifact(s) found — CRITICAL")
        else:
            Console.info("No exposed .git artifacts found.")
        return findings

    # --- exposed_env_files.py ---

    _ENV_FILE_CANDIDATES = (
        ".env", "config.php", "config.yaml", "config.json", "wp-config.php",
        "settings.php", "database.php", ".env.php", "appsettings.json",
        "docker-compose.yml", "backup.sql", "dump.sql",
    )

    async def run_env_file_check(self, target: "Target") -> List[EnvFileFinding]:
        """
        OSINT source: exposed_env_files.py
        Probes a curated list of commonly-leaked config/secret filenames
        at the site root, flagging any that return 200 with content.
        """
        Console.section(f"Exposed Config File Check: {target.domain}")
        findings: List[EnvFileFinding] = []
        if not self.config.is_in_scope(target.domain):
            Console.warning(f"{target.domain} out-of-scope. Skipping env file check.")
            return findings
        if not target.is_live or not target.live_url:
            Console.warning("Target not live. Skipping env file check.")
            return findings

        base = target.live_url.rstrip("/")
        headers = {"User-Agent": _DEFAULT_UA}
        sem = asyncio.Semaphore(15)

        async def probe(fname: str, session: aiohttp.ClientSession) -> None:
            async with sem:
                url = f"{base}/{fname}"
                try:
                    async with session.get(
                        url, timeout=aiohttp.ClientTimeout(total=8),
                        ssl=False, allow_redirects=False,
                    ) as resp:
                        if resp.status == 200:
                            body = (await resp.text(errors="ignore")).strip()
                            if body:
                                findings.append(EnvFileFinding(
                                    url=url, filename=fname, status=resp.status,
                                ))
                                Console.warning(f"Exposed config file: {fname}")
                except Exception as exc:
                    log.debug("Env file probe error %s: %s", url, exc)

        async with aiohttp.ClientSession(headers=headers) as session:
            await asyncio.gather(*[probe(f, session) for f in self._ENV_FILE_CANDIDATES])

        target.env_file_findings = findings
        for f in findings:
            target.vulnerabilities.append(f.to_dict())
        if findings:
            async with Database(Path(self.config.db_path)) as db:
                for f in findings:
                    fid = hashlib.md5(f"{f.url}".encode()).hexdigest()
                    await db._conn.execute(
                        "INSERT OR REPLACE INTO env_file_findings "
                        "(id,program,url,filename,status,found_at) "
                        "VALUES(?,?,?,?,?,datetime('now'))",
                        (fid, target.domain, f.url, f.filename, f.status),
                    )
                await db._conn.commit()
            Console.success(f"Env file check: {len(findings)} exposed file(s) — CRITICAL")
        else:
            Console.info("No exposed config files found.")
        return findings

    # --- dns_records.py + zonetransfer.py + dnssec.py + ct_log_query.py +
    #     whois_lookup.py + ssl_expiry.py + security_txt.py +
    #     spf_dkim_dmarc_validator.py + domain_reputation_check.py +
    #     typosquat_domain_checker.py + firewall_detection.py +
    #     http_security.py + cookies.py (consolidated DNS/mail/cert posture)

    async def run_dns_health_check(self, target: "Target") -> Optional[DnsHealthFinding]:
        """
        Consolidated posture check combining 13 OSINT modules into one
        pass over DNS/TLS/mail/WAF signals: dns_records, zonetransfer,
        dnssec, ct_log_query, whois_lookup, ssl_expiry, security_txt,
        spf_dkim_dmarc_validator, domain_reputation_check,
        typosquat_domain_checker, firewall_detection, http_security,
        cookies. Each OSINT script queried one signal in isolation;
        bbrecon batches them into a single DnsHealthFinding so the
        report shows one coherent "domain posture" section instead of
        13 separate noisy outputs.
        """
        Console.section(f"DNS/Mail/Cert Posture Check: {target.domain}")
        domain = target.domain
        if not self.config.is_in_scope(domain):
            Console.warning(f"{domain} out-of-scope. Skipping DNS health check.")
            return None

        # SPF / DMARC (spf_dkim_dmarc_validator.py)
        spf_record = "-"
        dmarc_record = "-"
        dmarc_policy = "-"
        try:
            answers = dns.resolver.resolve(domain, "TXT", lifetime=8)
            for r in answers:
                txt = "".join(
                    s.decode() if isinstance(s, bytes) else s
                    for s in getattr(r, "strings", [r.to_text().strip('"')])
                )
                if txt.lower().startswith("v=spf1"):
                    spf_record = txt
        except Exception as exc:
            log.debug("SPF lookup failed for %s: %s", domain, exc)
        try:
            answers = dns.resolver.resolve(f"_dmarc.{domain}", "TXT", lifetime=8)
            for r in answers:
                txt = "".join(
                    s.decode() if isinstance(s, bytes) else s
                    for s in getattr(r, "strings", [r.to_text().strip('"')])
                )
                if txt.lower().startswith("v=dmarc1"):
                    dmarc_record = txt
                    for part in txt.split(";"):
                        part = part.strip()
                        if part.lower().startswith("p="):
                            dmarc_policy = part.split("=", 1)[1]
        except Exception as exc:
            log.debug("DMARC lookup failed for %s: %s", domain, exc)

        # DNSSEC (dnssec.py, simplified: DNSKEY presence only)
        dnssec_status = "Not signed"
        try:
            dns.resolver.resolve(domain, "DNSKEY", lifetime=8)
            dnssec_status = "Signed"
        except Exception:
            pass

        # Zone transfer (zonetransfer.py)
        zone_transfer = False
        try:
            ns_answers = dns.resolver.resolve(domain, "NS", lifetime=8)
            ns_hosts = [str(r.target).rstrip(".") for r in ns_answers]
            for ns in ns_hosts[:3]:
                try:
                    xfr_result = await asyncio.get_event_loop().run_in_executor(
                        None,
                        lambda n=ns: list(dns.query.xfr(n, domain, lifetime=8))
                    )
                    if xfr_result:
                        zone_transfer = True
                        Console.warning(f"AXFR zone transfer succeeded via {ns}!")
                        break
                except Exception:
                    continue
        except Exception as exc:
            log.debug("Zone transfer check failed for %s: %s", domain, exc)

        # CT log count (ct_log_query.py)
        ct_cert_count = 0
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    f"https://crt.sh/?q=%25.{domain}&output=json",
                    timeout=aiohttp.ClientTimeout(total=15), ssl=False,
                ) as resp:
                    if resp.status == 200:
                        data = await resp.json(content_type=None)
                        ct_cert_count = len(data) if isinstance(data, list) else 0
        except Exception as exc:
            log.debug("CT log query failed for %s: %s", domain, exc)

        # Typosquat sample check (typosquat_domain_checker.py, lightweight)
        typosquat_hits = 0
        try:
            sld, _, tld = domain.partition(".")
            common_tlds = ["com", "net", "org", "io"]
            async with aiohttp.ClientSession() as session:
                for t in common_tlds:
                    cand = f"{sld}1.{t}"
                    try:
                        dns.resolver.resolve(cand, "A", lifetime=3)
                        typosquat_hits += 1
                    except Exception:
                        pass
        except Exception as exc:
            log.debug("Typosquat check failed for %s: %s", domain, exc)

        # WHOIS (whois_lookup.py)
        whois_registrar = "-"
        whois_created = "-"
        try:
            ok, out, _ = await self.run_tool(["whois", domain], timeout=15)
            if ok:
                for line in out.splitlines():
                    low = line.lower()
                    if low.startswith("registrar:") and whois_registrar == "-":
                        whois_registrar = line.split(":", 1)[1].strip()
                    if ("creation date" in low or "created" in low) and whois_created == "-":
                        whois_created = line.split(":", 1)[-1].strip()
        except Exception as exc:
            log.debug("WHOIS lookup failed for %s: %s", domain, exc)

        # SSL expiry (ssl_expiry.py)
        ssl_days_left: Optional[int] = None
        try:
            ctx = ssl.create_default_context()
            loop = asyncio.get_event_loop()

            def _get_cert():
                with socket.create_connection((domain, 443), timeout=8) as sock:
                    with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                        return ssock.getpeercert()

            cert = await loop.run_in_executor(None, _get_cert)
            if cert and "notAfter" in cert:
                expiry = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z")
                ssl_days_left = (expiry - datetime.now()).days
        except Exception as exc:
            log.debug("SSL expiry check failed for %s: %s", domain, exc)

        # security.txt presence (security_txt.py)
        security_txt_present = False
        try:
            async with aiohttp.ClientSession() as session:
                url = f"https://{domain}/.well-known/security.txt"
                async with session.get(
                    url, timeout=aiohttp.ClientTimeout(total=8), ssl=False
                ) as resp:
                    security_txt_present = resp.status == 200
        except Exception as exc:
            log.debug("security.txt check failed for %s: %s", domain, exc)

        # Domain reputation (domain_reputation_check.py, RBL-lite)
        reputation_flag = "Unknown"
        try:
            ip = socket.gethostbyname(domain)
            rev = ".".join(reversed(ip.split(".")))
            try:
                socket.gethostbyname(f"{rev}.zen.spamhaus.org")
                reputation_flag = "Listed (Spamhaus)"
            except socket.gaierror:
                reputation_flag = "Clean"
        except Exception as exc:
            log.debug("Reputation check failed for %s: %s", domain, exc)

        # Firewall/WAF detection (firewall_detection.py, header-based)
        firewall_detected = "None detected"
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    f"https://{domain}", timeout=aiohttp.ClientTimeout(total=8), ssl=False
                ) as resp:
                    server_hdr = resp.headers.get("Server", "").lower()
                    if "cloudflare" in server_hdr:
                        firewall_detected = "Cloudflare"
                    elif resp.headers.get("X-Sucuri-ID"):
                        firewall_detected = "Sucuri"
                    elif resp.headers.get("X-CDN", "").lower() == "incapsula":
                        firewall_detected = "Imperva/Incapsula"
                    elif resp.status == 403:
                        firewall_detected = "Possible WAF (403)"
        except Exception as exc:
            log.debug("Firewall detection failed for %s: %s", domain, exc)

        finding = DnsHealthFinding(
            domain=domain, spf_record=spf_record, dmarc_record=dmarc_record,
            dmarc_policy=dmarc_policy, dnssec_status=dnssec_status,
            zone_transfer=zone_transfer, ct_cert_count=ct_cert_count,
            typosquat_hits=typosquat_hits, whois_registrar=whois_registrar,
            whois_created=whois_created, reputation_flag=reputation_flag,
            security_txt_present=security_txt_present, ssl_days_left=ssl_days_left,
            firewall_detected=firewall_detected,
        )
        target.dns_health = finding
        target.vulnerabilities.append(finding.to_dict())

        async with Database(Path(self.config.db_path)) as db:
            fid = hashlib.md5(domain.encode()).hexdigest()
            await db._conn.execute(
                """INSERT OR REPLACE INTO dns_health
                   (id,program,spf_record,dmarc_record,dmarc_policy,dnssec_status,
                    zone_transfer,ct_cert_count,typosquat_hits,whois_registrar,
                    whois_created,reputation_flag,security_txt_present,
                    ssl_days_left,firewall_detected,scanned_at)
                   VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,datetime('now'))""",
                (fid, domain, spf_record, dmarc_record, dmarc_policy, dnssec_status,
                 int(zone_transfer), ct_cert_count, typosquat_hits, whois_registrar,
                 whois_created, reputation_flag, int(security_txt_present),
                 ssl_days_left, firewall_detected),
            )
            await db._conn.commit()

        Console.success(
            f"DNS health: SPF={'Y' if spf_record!='-' else 'N'} "
            f"DMARC={dmarc_policy} DNSSEC={dnssec_status} "
            f"AXFR={'OPEN!' if zone_transfer else 'closed'} "
            f"SSL_exp={ssl_days_left}d WAF={firewall_detected}"
        )
        return finding

    # ── HTML report ──────────────────────────────────────────────

    def generate_report(self, target: "Target") -> str:
        report_path = target.output_dir / "report.html"
        path        = ReportGenerator.generate_html(target, report_path)
        Console.success(f"HTML report → {path}")
        return path

    # ── full scan ────────────────────────────────────────────────

    async def full_scan(
        self,
        domain:       str,
        skip_xss:     bool = False,
        skip_sqli:    bool = False,
        skip_secrets: bool = False,
        skip_nuclei:  bool = False,
        skip_osint:   bool = False,
        diff_only:    bool = False,
    ) -> "Target":
        """
        12-phase full scan pipeline (Pair 5 adds Phase 7b: OSINT posture).

        diff_only=True: suppresses banner only (B21).
        Full scan always runs. Diff printed at Phase 12.
        domain MUST be a bare hostname; normalisation is done at CLI entry.
        skip_osint=True skips the 20 OSINT-derived checks (takeover, CORS,
        open redirect, git/env exposure, DNS/mail/cert posture).
        """
        target = Target(domain=domain)
        target.output_dir.mkdir(parents=True, exist_ok=True)

        Console.banner()  # B21: always show banner
        Console.section(f"Full Scan: {domain}")
        Console.info(f"Output: {target.output_dir}")

        # Phase 0 — diff baseline
        await self.load_diff_baseline(domain)

        # Phase 1 — liveness
        await self.check_liveness(target)
        if not target.is_live:
            Console.warning(
                "Target not confirmed live. Continuing with passive recon."
            )

        # Phase 2 — subdomain enum
        await self.enumerate_subdomains(target)

        # Phase 3 — massdns DNS brute-force
        await self.run_massdns(target)

        # Phase 4 — live probe + Wappalyzer fingerprint
        probe_results = await self.run_live_probe(target)

        # Phase 5 — URL discovery
        await self.discover_urls(target)

        # Phase 6 — port scan + Nmap
        await self.scan_ports(target)

        # Phase 7 — nuclei per-host (tech-aware)
        if not skip_nuclei:
            await self.run_nuclei_per_host(target, probe_results)

        # Phase 8 — XSS
        if not skip_xss:
            await self.run_xss_scan(target)

        # Phase 9 — SQLi
        if not skip_sqli:
            await self.run_sqli_scan(target)

        # Phase 10 — Secrets
        if not skip_secrets:
            await self.run_secrets_scan(target)

        # Phase 11 (Pair 5) — OSINT-derived posture checks
        # B26: run concurrently (all 6 are independent — none consume each
        # other's output, only target.subdomains/live_url/urls_with_params
        # from earlier phases). Each method now opens its own DB connection
        # (Database(self.config.db_path)) instead of sharing self.db, since
        # self.db.connect()/close() mutate a single shared _conn attribute —
        # running them through that singleton concurrently would race.
        if not skip_osint:
            results = await asyncio.gather(
                self.run_dns_health_check(target),
                self.run_subdomain_takeover(target),
                self.run_cors_scan(target),
                self.run_open_redirect_scan(target),
                self.run_git_exposure_check(target),
                self.run_env_file_check(target),
                return_exceptions=True,
            )
            for name, res in zip(
                ("dns_health", "takeover", "cors", "open_redirect",
                 "git_exposure", "env_file"),
                results,
            ):
                if isinstance(res, Exception):
                    Console.warning(f"OSINT check '{name}' raised: {res}")
                    log.debug("OSINT phase-11 check %s failed", name, exc_info=res)

        # Phase 12 — diff + persist + report
        target.save_state()
        diff = compute_diff(self._prev_scan, target)
        print_diff(diff)
        await self.save_diff_report(target, diff)

        async with self.db as db:
            await _save_scan_history(db, target)
            await db._conn.execute(
                "INSERT OR REPLACE INTO programs"
                " (slug,name,platform,url,live,created_at,updated_at)"
                " VALUES(?,?,'bbrecon',?,?,datetime('now'),datetime('now'))",
                (
                    target.domain,
                    target.domain,
                    target.live_url or f"https://{target.domain}",
                    int(target.is_live),
                ),
            )
            await db._conn.commit()

        self.generate_report(target)
        Console.success(f"Scan complete → {target.output_dir}")
        Console.success(f"DB persisted → {self.config.db_path}")
        return target


# ============================================================
# SECTION 21: CLI ENTRYPOINT
# ============================================================

async def _async_main() -> None:
    parser = argparse.ArgumentParser(
        prog="bbrecon",
        description=f"BBRecon v{VERSION} — Professional Bug Bounty Toolkit",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  python3 bbrecon_09062026.py scan example.com\n"
            "  python3 bbrecon_09062026.py scan https://example.com  "
            "  (URL auto-stripped)\n"
            "  python3 bbrecon_09062026.py scan example.com --skip-xss --skip-sqli\n"
            "  python3 bbrecon_09062026.py scan example.com --stealth --diff-only\n"
            "  python3 bbrecon_09062026.py tools\n"
            "  python3 bbrecon_09062026.py config show\n"
        ),
    )
    sub = parser.add_subparsers(dest="command")

    # ── scan subcommand ──────────────────────────────────────────
    scan_p = sub.add_parser(
        "scan",
        help="Run full reconnaissance scan on a domain",
    )
    scan_p.add_argument(
        "domain",
        help="Target domain or URL (scheme + path stripped automatically)",
    )
    scan_p.add_argument(
        "--skip-xss",     action="store_true", help="Skip XSS scanner"
    )
    scan_p.add_argument(
        "--skip-sqli",    action="store_true", help="Skip SQLi scanner"
    )
    scan_p.add_argument(
        "--skip-secrets", action="store_true", help="Skip secrets scanner"
    )
    scan_p.add_argument(
        "--no-nuclei",    action="store_true", help="Skip nuclei scan"
    )
    scan_p.add_argument(
        "--skip-osint",   action="store_true",
        help="Skip OSINT-derived checks (takeover, CORS, open redirect, "
             "git/env exposure, DNS/mail/cert posture — 20 modules)",
    )
    scan_p.add_argument(
        "--diff-only",    action="store_true",
        help="Emphasise new assets vs last scan (full scan still runs)",
    )
    scan_p.add_argument(
        "--output", "-o", type=str, default="",
        help="Override output directory",
    )
    scan_p.add_argument(
        "--stealth", action="store_true",
        help="Slow / low-noise mode (T2 nmap, rate_limit=1.0)",
    )

    # ── tools subcommand ─────────────────────────────────────────
    sub.add_parser("tools", help="Check external tool availability")

    # ── config subcommand ────────────────────────────────────────
    cfg_p = sub.add_parser("config", help="Manage configuration")
    cfg_p.add_argument(
        "action", choices=["show", "init"], help="show or init config"
    )

    args = parser.parse_args()

    if args.command is None:
        Console.banner()
        parser.print_help()
        return

    if args.command == "tools":
        Console.banner()
        tc = ToolChecker()
        tc.check_all()
        tc.print_status()
        return

    if args.command == "config":
        cfg = Config.load()
        if args.action == "show":
            Console.section("Current Config")
            for k, v in cfg.__dict__.items():
                Console.result(k, str(v))
        elif args.action == "init":
            cfg.save()
            Console.success(f"Config written to {CONFIG_FILE}")
        return

    if args.command == "scan":
        # B11/B23: normalise domain at entry — clear error if invalid
        try:
            domain = normalize_domain(args.domain)
        except ValueError as exc:
            Console.error(str(exc))
            sys.exit(1)

        cfg = Config.load()
        if args.stealth:
            cfg.mode       = "stealth"
            cfg.rate_limit = 1.0
            cfg.nmap_mode  = "stealth"
        if args.output:
            cfg.output_dir = args.output

        engine = BBReconEngine(config=cfg)
        await engine.full_scan(
            domain=domain,
            skip_xss=args.skip_xss,
            skip_sqli=args.skip_sqli,
            skip_secrets=args.skip_secrets,
            skip_nuclei=args.no_nuclei,
            skip_osint=args.skip_osint,
            diff_only=args.diff_only,
        )


def main() -> None:
    asyncio.run(_async_main())


if __name__ == "__main__":
    main()
