#!/usr/bin/env python3
"""
server.py — Self-contained web platform with file server, microblog, and admin dashboard.
Single file, zero third-party dependencies. Python 3.10+ stdlib only.
"""

__version__ = "1.0.0"

# ── SECTION 1: Imports & Constants ─────────────────────────
import argparse
import base64
import configparser
import datetime
import hashlib
import hmac
import html
import io
import json
import logging
import logging.handlers
import mimetypes
import os
import pathlib
import re
import secrets
import shutil
import signal
import socket
import socketserver
import sqlite3
import ssl
import struct
import subprocess
import sys
import textwrap
import threading
import time
import urllib.parse
from email.utils import formatdate
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler

# ── SECTION 2: Configuration ────────────────────────────────

def _utcnow() -> datetime.datetime:
    """Return current UTC time as a naive datetime (no deprecation warning)."""
    return datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)


DEFAULT_CONFIG = {
    "http_port": 8080,
    "https_port": 8443,
    "host": "0.0.0.0",
    "site_name": "offline",
    "registration_open": True,
    "max_file_size_mb": 100,
    "allowed_file_extensions": [],
    "token_expiry_seconds": 86400,
    "rate_limit_requests": 60,
    "rate_limit_window_seconds": 60,
    "default_article_visibility": "public",
}

_config: dict = {}
_config_lock = threading.Lock()
_data_dir = pathlib.Path("data")


def get_config() -> dict:
    with _config_lock:
        return dict(_config)


def set_config(new: dict) -> None:
    global _config
    with _config_lock:
        _config.update(new)
        config_path = _data_dir / "config.json"
        config_path.write_text(json.dumps(_config, indent=2))


def load_or_create_config(data_dir: pathlib.Path) -> dict:
    global _config, _data_dir
    _data_dir = data_dir
    config_path = data_dir / "config.json"
    if config_path.exists():
        with open(config_path) as f:
            _config = {**DEFAULT_CONFIG, **json.load(f)}
    else:
        _config = dict(DEFAULT_CONFIG)
        config_path.write_text(json.dumps(_config, indent=2))
    return _config


def ensure_directories(data_dir: pathlib.Path) -> None:
    for sub in [
        "", "certs", "files", "files/public", "files/private", "logs"
    ]:
        (data_dir / sub).mkdir(parents=True, exist_ok=True)


# Logging setup
_access_logger = logging.getLogger("access")
_error_logger = logging.getLogger("error")


def setup_logging(data_dir: pathlib.Path) -> None:
    fmt = logging.Formatter("%(asctime)s %(message)s")

    console = logging.StreamHandler(sys.stdout)
    console.setLevel(logging.INFO)
    console.setFormatter(fmt)

    access_file = logging.handlers.RotatingFileHandler(
        str(data_dir / "logs" / "access.log"),
        maxBytes=5 * 1024 * 1024, backupCount=3,
    )
    access_file.setLevel(logging.DEBUG)
    access_file.setFormatter(fmt)
    _access_logger.setLevel(logging.DEBUG)
    _access_logger.addHandler(console)
    _access_logger.addHandler(access_file)

    error_file = logging.handlers.RotatingFileHandler(
        str(data_dir / "logs" / "error.log"),
        maxBytes=5 * 1024 * 1024, backupCount=3,
    )
    error_file.setLevel(logging.ERROR)
    error_file.setFormatter(fmt)
    _error_logger.setLevel(logging.ERROR)
    _error_logger.addHandler(error_file)
    _error_logger.addHandler(console)


# ── SECTION 3: Database ─────────────────────────────────────

_db_path: str = ""
_db_lock = threading.Lock()

SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS users (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    username      TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    salt          TEXT NOT NULL,
    role          TEXT NOT NULL DEFAULT 'user',
    group_name    TEXT,
    is_active     INTEGER DEFAULT 1,
    created_at    TEXT NOT NULL,
    last_login    TEXT,
    pw_reset_notice INTEGER DEFAULT 0
);

CREATE TABLE IF NOT EXISTS tokens (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id     INTEGER NOT NULL REFERENCES users(id),
    token_hash  TEXT UNIQUE NOT NULL,
    created_at  TEXT NOT NULL,
    expires_at  TEXT NOT NULL,
    user_agent  TEXT,
    ip_address  TEXT,
    revoked     INTEGER DEFAULT 0
);

CREATE TABLE IF NOT EXISTS files (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    filename     TEXT NOT NULL,
    stored_name  TEXT UNIQUE NOT NULL,
    owner_id     INTEGER REFERENCES users(id),
    size_bytes   INTEGER NOT NULL,
    mime_type    TEXT,
    visibility   TEXT NOT NULL DEFAULT 'public',
    uploaded_at  TEXT NOT NULL,
    description  TEXT
);

CREATE TABLE IF NOT EXISTS articles (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    title        TEXT NOT NULL,
    slug         TEXT UNIQUE NOT NULL,
    body         TEXT NOT NULL,
    author_id    INTEGER NOT NULL REFERENCES users(id),
    visibility   TEXT NOT NULL DEFAULT 'public',
    created_at   TEXT NOT NULL,
    updated_at   TEXT NOT NULL,
    published    INTEGER DEFAULT 1
);

CREATE TABLE IF NOT EXISTS comments (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    article_id  INTEGER NOT NULL REFERENCES articles(id) ON DELETE CASCADE,
    author_id   INTEGER REFERENCES users(id),
    author_name TEXT,
    body        TEXT NOT NULL,
    created_at  TEXT NOT NULL,
    approved    INTEGER DEFAULT 1
);

CREATE TABLE IF NOT EXISTS groups (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    name        TEXT UNIQUE NOT NULL,
    description TEXT,
    created_by  INTEGER REFERENCES users(id),
    created_at  TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS group_members (
    group_id    INTEGER NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
    user_id     INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    PRIMARY KEY (group_id, user_id)
);

CREATE TABLE IF NOT EXISTS messages (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    sender_id   INTEGER NOT NULL REFERENCES users(id),
    recipient_id INTEGER NOT NULL REFERENCES users(id),
    subject     TEXT NOT NULL,
    body        TEXT NOT NULL,
    created_at  TEXT NOT NULL,
    read_at     TEXT,
    deleted_by_sender   INTEGER DEFAULT 0,
    deleted_by_recipient INTEGER DEFAULT 0
);
"""


def init_db(data_dir: pathlib.Path) -> str:
    global _db_path
    _db_path = str(data_dir / "db.sqlite3")
    conn = sqlite3.connect(_db_path)
    conn.executescript(SCHEMA_SQL)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    conn.commit()
    conn.close()
    return _db_path


def get_db() -> sqlite3.Connection:
    conn = sqlite3.connect(_db_path)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def db_execute(sql: str, params: tuple = ()) -> int:
    conn = get_db()
    try:
        cur = conn.execute(sql, params)
        conn.commit()
        return cur.lastrowid
    finally:
        conn.close()


def db_fetchone(sql: str, params: tuple = ()) -> dict | None:
    conn = get_db()
    try:
        row = conn.execute(sql, params).fetchone()
        return dict(row) if row else None
    finally:
        conn.close()


def db_fetchall(sql: str, params: tuple = ()) -> list[dict]:
    conn = get_db()
    try:
        return [dict(r) for r in conn.execute(sql, params).fetchall()]
    finally:
        conn.close()


# ── SECTION 4: Auth & Tokens ────────────────────────────────

PBKDF2_ITERATIONS = 310_000
SALT_LENGTH = 32
ROLE_HIERARCHY = {
    "superadmin": 50,
    "admin": 40,
    "mod": 30,
    "user": 20,
}


def hash_password(password: str, salt: str | None = None) -> tuple[str, str]:
    """Return (base64_hash, hex_salt)."""
    if salt is None:
        salt = secrets.token_hex(SALT_LENGTH)
    raw = hashlib.pbkdf2_hmac(
        "sha256", password.encode(), salt.encode(), PBKDF2_ITERATIONS
    )
    return base64.b64encode(raw).decode(), salt


def verify_password(password: str, stored_hash: str, salt: str) -> bool:
    h, _ = hash_password(password, salt)
    return hmac.compare_digest(h, stored_hash)


def generate_token() -> tuple[str, str]:
    """Return (raw_token, token_hash)."""
    raw = secrets.token_urlsafe(48)
    h = hashlib.sha256(raw.encode()).hexdigest()
    return raw, h


def create_token(
    user_id: int, user_agent: str = "", ip_address: str = ""
) -> str:
    """Create a new token and return the raw token string."""
    raw, h = generate_token()
    cfg = get_config()
    now = _utcnow().isoformat()
    expires = (
        _utcnow()
        + datetime.timedelta(seconds=cfg["token_expiry_seconds"])
    ).isoformat()
    db_execute(
        "INSERT INTO tokens (user_id, token_hash, created_at, expires_at,"
        " user_agent, ip_address) VALUES (?, ?, ?, ?, ?, ?)",
        (user_id, h, now, expires, user_agent, ip_address),
    )
    return raw


def validate_token(raw_token: str) -> dict | None:
    """Return user dict if token is valid, else None."""
    h = hashlib.sha256(raw_token.encode()).hexdigest()
    row = db_fetchone(
        "SELECT t.user_id, t.expires_at, u.* FROM tokens t "
        "JOIN users u ON t.user_id = u.id "
        "WHERE t.token_hash = ? AND t.revoked = 0 AND u.is_active = 1",
        (h,),
    )
    if not row:
        return None
    if row["expires_at"] < _utcnow().isoformat():
        db_execute(
            "UPDATE tokens SET revoked = 1 WHERE token_hash = ?", (h,)
        )
        return None
    return dict(row)


def revoke_token(raw_token: str) -> None:
    h = hashlib.sha256(raw_token.encode()).hexdigest()
    db_execute("UPDATE tokens SET revoked = 1 WHERE token_hash = ?", (h,))


def revoke_all_tokens(user_id: int) -> None:
    db_execute(
        "UPDATE tokens SET revoked = 1 WHERE user_id = ? AND revoked = 0",
        (user_id,),
    )


def generate_csrf(raw_token: str) -> str:
    """Generate a CSRF token from the auth token + current timestamp."""
    ts = str(int(time.time()))
    sig = hmac.new(
        raw_token.encode(), ts.encode(), hashlib.sha256
    ).hexdigest()
    return f"{ts}.{sig}"


def verify_csrf(raw_token: str, csrf: str) -> bool:
    """Verify a CSRF token. Allow up to 4 hours of drift."""
    if not csrf or "." not in csrf:
        return False
    ts_str, sig = csrf.split(".", 1)
    try:
        ts = int(ts_str)
    except ValueError:
        return False
    if abs(time.time() - ts) > 14400:
        return False
    expected = hmac.new(
        raw_token.encode(), ts_str.encode(), hashlib.sha256
    ).hexdigest()
    return hmac.compare_digest(sig, expected)


def role_level(role: str) -> int:
    return ROLE_HIERARCHY.get(role, 10)


def has_role(user: dict | None, min_role: str) -> bool:
    if user is None:
        return False
    return role_level(user.get("role", "user")) >= role_level(min_role)


def validate_username(u: str) -> str | None:
    if not re.match(r'^[a-zA-Z0-9_-]{3,32}$', u):
        return "Username must be 3–32 chars: letters, digits, _ or -"
    return None


def validate_password(p: str) -> str | None:
    if len(p) < 12:
        return "Password must be at least 12 characters"
    if not re.search(r'[A-Z]', p):
        return "Password must contain an uppercase letter"
    if not re.search(r'[a-z]', p):
        return "Password must contain a lowercase letter"
    if not re.search(r'[0-9]', p):
        return "Password must contain a digit"
    return None


def create_default_superadmin() -> str | None:
    """Create default superadmin if none exists. Return password or None."""
    existing = db_fetchone(
        "SELECT id FROM users WHERE role = 'superadmin'"
    )
    if existing:
        return None
    password = secrets.token_urlsafe(16)
    pw_hash, salt = hash_password(password)
    now = _utcnow().isoformat()
    db_execute(
        "INSERT INTO users (username, password_hash, salt, role,"
        " created_at) VALUES (?, ?, ?, 'superadmin', ?)",
        ("admin", pw_hash, salt, now),
    )
    return password


# ── SECTION 5: Rate Limiter ─────────────────────────────────

_rate_store: dict[str, list[float]] = {}
_rate_lock = threading.Lock()
_login_fail_store: dict[str, list[float]] = {}
_login_fail_lock = threading.Lock()
_pw_change_store: dict[str, list[float]] = {}
_pw_change_lock = threading.Lock()
_admin_pw_reset_store: dict[str, list[float]] = {}
_admin_pw_reset_lock = threading.Lock()


def _check_limit(
    store: dict, lock: threading.Lock,
    key: str, max_req: int, window: float
) -> bool:
    now = time.time()
    with lock:
        hits = [t for t in store.get(key, []) if now - t < window]
        if len(hits) >= max_req:
            store[key] = hits
            return False
        hits.append(now)
        store[key] = hits
        return True


def check_rate_limit(ip: str) -> bool:
    cfg = get_config()
    return _check_limit(
        _rate_store, _rate_lock, ip,
        cfg["rate_limit_requests"], cfg["rate_limit_window_seconds"],
    )


def check_login_limit(ip: str) -> bool:
    return _check_limit(
        _login_fail_store, _login_fail_lock, ip, 10, 300
    )


def record_login_failure(ip: str) -> None:
    _check_limit(_login_fail_store, _login_fail_lock, ip, 999, 300)


def check_pw_change_limit(user_id: int) -> bool:
    return _check_limit(
        _pw_change_store, _pw_change_lock, str(user_id), 3, 900
    )


def check_admin_pw_reset_limit(admin_id: int) -> bool:
    return _check_limit(
        _admin_pw_reset_store, _admin_pw_reset_lock,
        str(admin_id), 10, 3600,
    )


# ── SECTION 6: Markdown Renderer ────────────────────────────

def render_markdown(text: str) -> str:
    """Convert Markdown text to HTML. Escapes HTML first for XSS safety."""
    text = html.escape(text)
    lines = text.split("\n")
    out_blocks: list[str] = []
    i = 0
    while i < len(lines):
        line = lines[i]
        # Fenced code blocks
        if line.startswith("```"):
            lang = line[3:].strip()
            code_lines = []
            i += 1
            while i < len(lines) and not lines[i].startswith("```"):
                code_lines.append(lines[i])
                i += 1
            i += 1  # skip closing ```
            code = "\n".join(code_lines)
            cls = f' class="language-{lang}"' if lang else ""
            out_blocks.append(f"<pre><code{cls}>{code}</code></pre>")
            continue
        # Headings
        m = re.match(r'^(#{1,6})\s+(.+)$', line)
        if m:
            lvl = len(m.group(1))
            out_blocks.append(f"<h{lvl}>{_inline(m.group(2))}</h{lvl}>")
            i += 1
            continue
        # Horizontal rule
        if re.match(r'^---+\s*$', line):
            out_blocks.append("<hr>")
            i += 1
            continue
        # Blockquote
        if line.startswith("&gt; ") or line == "&gt;":
            bq_lines = []
            while i < len(lines) and (
                lines[i].startswith("&gt; ") or lines[i] == "&gt;"
            ):
                content = lines[i][5:] if lines[i].startswith("&gt; ") else ""
                bq_lines.append(content)
                i += 1
            out_blocks.append(
                f"<blockquote>{_inline('<br>'.join(bq_lines))}</blockquote>"
            )
            continue
        # Unordered list
        if re.match(r'^[\-\*]\s+', line):
            items = []
            while i < len(lines) and re.match(r'^[\-\*]\s+', lines[i]):
                items.append(
                    f"<li>{_inline(re.sub(r'^[\-\*]\s+', '', lines[i]))}</li>"
                )
                i += 1
            out_blocks.append(f"<ul>{''.join(items)}</ul>")
            continue
        # Ordered list
        if re.match(r'^\d+\.\s+', line):
            items = []
            while i < len(lines) and re.match(r'^\d+\.\s+', lines[i]):
                items.append(
                    f"<li>{_inline(re.sub(r'^\d+\.\s+', '', lines[i]))}</li>"
                )
                i += 1
            out_blocks.append(f"<ol>{''.join(items)}</ol>")
            continue
        # Blank line
        if line.strip() == "":
            i += 1
            continue
        # Paragraph — collect consecutive non-blank lines
        para = []
        while i < len(lines) and lines[i].strip() != "" and not (
            lines[i].startswith("#") or lines[i].startswith("```")
            or lines[i].startswith("&gt; ")
            or re.match(r'^[\-\*]\s+', lines[i])
            or re.match(r'^\d+\.\s+', lines[i])
            or re.match(r'^---+\s*$', lines[i])
        ):
            para.append(lines[i])
            i += 1
        out_blocks.append(f"<p>{_inline('<br>'.join(para))}</p>")
    return "\n".join(out_blocks)


def _inline(text: str) -> str:
    """Apply inline Markdown formatting."""
    # Images: ![alt](url)
    text = re.sub(
        r'!\[([^\]]*)\]\(([^)]+)\)',
        r'<img alt="\1" src="\2">',
        text,
    )
    # Links: [text](url)
    text = re.sub(
        r'\[([^\]]+)\]\(([^)]+)\)',
        r'<a href="\2" rel="noopener noreferrer" target="_blank">\1</a>',
        text,
    )
    # Bold: **text** or __text__
    text = re.sub(r'\*\*(.+?)\*\*', r'<strong>\1</strong>', text)
    text = re.sub(r'__(.+?)__', r'<strong>\1</strong>', text)
    # Italic: *text* or _text_
    text = re.sub(r'\*(.+?)\*', r'<em>\1</em>', text)
    text = re.sub(r'(?<!\w)_(.+?)_(?!\w)', r'<em>\1</em>', text)
    # Inline code: `code`
    text = re.sub(r'`([^`]+)`', r'<code>\1</code>', text)
    return text


def strip_markdown(text: str) -> str:
    """Strip markdown syntax to produce a plain-text snippet."""
    text = re.sub(r'```[\s\S]*?```', '', text)      # fenced code blocks
    text = re.sub(r'^#{1,6}\s+', '', text, flags=re.M)  # headings
    text = re.sub(r'!\[[^\]]*\]\([^)]*\)', '', text)    # images
    text = re.sub(r'\[([^\]]+)\]\([^)]*\)', r'\1', text)  # links → text
    text = re.sub(r'(\*\*|__)(.*?)\1', r'\2', text)  # bold
    text = re.sub(r'(\*|_)(.*?)\1', r'\2', text)     # italic
    text = re.sub(r'`([^`]+)`', r'\1', text)         # inline code
    text = re.sub(r'^[>\-\*]\s+', '', text, flags=re.M)  # blockquotes/lists
    text = re.sub(r'^---+$', '', text, flags=re.M)   # horizontal rules
    text = re.sub(r'\n{2,}', '\n', text).strip()
    return text


# ── SECTION 7: ACL & Permissions ────────────────────────────

def check_visibility(visibility: str, user: dict | None) -> bool:
    """Check if a user can access content with given visibility."""
    if visibility == "public":
        return True
    if user is None:
        return False
    if has_role(user, "admin"):
        return True
    if visibility == "private":
        return True  # any logged-in user
    if visibility.startswith("role:"):
        target_role = visibility[5:]
        return (
            user.get("role") == target_role or has_role(user, "mod")
        )
    if visibility.startswith("group:"):
        target_group = visibility[6:]
        if has_role(user, "admin"):
            return True
        member = db_fetchone(
            "SELECT 1 FROM group_members gm "
            "JOIN groups g ON gm.group_id = g.id "
            "WHERE gm.user_id = ? AND g.name = ?",
            (user["id"], target_group),
        )
        return member is not None
    return False


def filter_visible_articles(
    articles: list[dict], user: dict | None
) -> list[dict]:
    return [a for a in articles if check_visibility(a["visibility"], user)]


def require_role(user: dict | None, min_role: str) -> bool:
    return has_role(user, min_role)


# ── SECTION 8: HTML Templates ───────────────────────────────

_CSS = """
:root {
    --bg: #f8f9fa; --bg2: #ffffff; --text: #212529; --text2: #495057;
    --border: #dee2e6; --accent: #01696f; --accent2: #018a92;
    --success: #198754; --error: #dc3545; --warning: #ffc107;
    --sidebar-bg: #f1f3f5; --shadow: rgba(0,0,0,0.08);
    --code-bg: #e9ecef; --hover: #e9ecef;
}
@media (prefers-color-scheme: dark) {
    :root:not([data-theme="light"]) {
        --bg: #1a1a2e; --bg2: #16213e; --text: #e0e0e0; --text2: #a0a0b0;
        --border: #2a2a4a; --accent: #4f98a3; --accent2: #6bb5c0;
        --sidebar-bg: #16213e; --shadow: rgba(0,0,0,0.3);
        --code-bg: #2a2a4a; --hover: #2a2a4a;
        --success: #2dd573; --error: #ff6b6b; --warning: #ffd93d;
    }
}
[data-theme="dark"] {
    --bg: #1a1a2e; --bg2: #16213e; --text: #e0e0e0; --text2: #a0a0b0;
    --border: #2a2a4a; --accent: #4f98a3; --accent2: #6bb5c0;
    --sidebar-bg: #16213e; --shadow: rgba(0,0,0,0.3);
    --code-bg: #2a2a4a; --hover: #2a2a4a;
    --success: #2dd573; --error: #ff6b6b; --warning: #ffd93d;
}
[data-theme="light"] {
    --bg: #f8f9fa; --bg2: #ffffff; --bg3: #f1f3f5; --text: #212529;
    --text2: #495057; --border: #dee2e6; --accent: #01696f;
    --accent2: #018a92; --sidebar-bg: #f1f3f5; --shadow: rgba(0,0,0,0.08);
    --code-bg: #e9ecef; --hover: #e9ecef;
}
*, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
html { font-size: 16px; }
body {
    font-family: system-ui, -apple-system, 'Segoe UI', sans-serif;
    background: var(--bg); color: var(--text); line-height: 1.6;
    min-height: 100vh; display: flex; flex-direction: column;
}
a { color: var(--accent); text-decoration: none; }
a:hover { color: var(--accent2); text-decoration: underline; }
.container { max-width: 1200px; margin: 0 auto; padding: 0 1rem; width: 100%; }
header {
    background: var(--bg2); border-bottom: 1px solid var(--border);
    padding: 0.75rem 0; box-shadow: 0 1px 3px var(--shadow);
    position: sticky; top: 0; z-index: 100;
}
header .container {
    display: flex; align-items: center; gap: 1rem; flex-wrap: wrap;
}
.logo { font-weight: 700; font-size: 1.2rem; color: var(--accent); }
nav { display: flex; gap: 0.75rem; flex-wrap: wrap; flex: 1; }
nav a { padding: 0.25rem 0.5rem; border-radius: 4px; font-size: 0.9rem; }
nav a:hover { background: var(--hover); text-decoration: none; }
.auth-links { display: flex; gap: 0.5rem; align-items: center; }
.auth-links a, .auth-links span { font-size: 0.9rem; }
.theme-toggle {
    background: none; border: 1px solid var(--border); border-radius: 4px;
    cursor: pointer; padding: 0.25rem 0.5rem; color: var(--text);
    font-size: 0.9rem;
}
.layout { display: flex; flex: 1; gap: 1.5rem; padding: 1.5rem 0; }
.layout.has-sidebar .sidebar {
    width: 220px; flex-shrink: 0; background: var(--sidebar-bg);
    border-radius: 8px; padding: 1rem; border: 1px solid var(--border);
    align-self: flex-start; position: sticky; top: 70px;
}
.sidebar a {
    display: block; padding: 0.4rem 0.6rem; border-radius: 4px;
    font-size: 0.9rem; margin-bottom: 0.2rem;
}
.sidebar a:hover { background: var(--hover); text-decoration: none; }
.sidebar a.active { background: var(--accent); color: #fff; }
.sidebar h3 { font-size: 0.85rem; text-transform: uppercase;
    color: var(--text2); margin-bottom: 0.5rem; letter-spacing: 0.05em; }
main { flex: 1; min-width: 0; }
main h1 { margin-bottom: 1rem; }
main > table, main > .card { margin-top: 1rem; }
main > input[type="search"] { margin-bottom: 1rem; }
footer {
    background: var(--bg2); border-top: 1px solid var(--border);
    padding: 1rem 0; text-align: center; font-size: 0.85rem;
    color: var(--text2); margin-top: auto;
}
.flash {
    padding: 0.75rem 1rem; border-radius: 6px; margin-bottom: 1rem;
    font-size: 0.9rem; animation: fadeIn 0.3s;
}
.flash-success { background: color-mix(in srgb, var(--success) 15%, var(--bg2));
    border: 1px solid var(--success); color: var(--success); }
.flash-error { background: color-mix(in srgb, var(--error) 15%, var(--bg2));
    border: 1px solid var(--error); color: var(--error); }
.flash-warning { background: color-mix(in srgb, var(--warning) 15%, var(--bg2));
    border: 1px solid var(--warning); color: var(--warning); }
@keyframes fadeIn { from { opacity: 0; transform: translateY(-8px); }
    to { opacity: 1; transform: none; } }
.card {
    background: var(--bg2); border: 1px solid var(--border);
    border-radius: 8px; padding: 1.25rem; margin-bottom: 1rem;
    box-shadow: 0 1px 3px var(--shadow);
}
.card h2, .card h3 { margin-bottom: 0.75rem; }
.btn {
    display: inline-block; padding: 0.5rem 1rem; border-radius: 6px;
    border: none; cursor: pointer; font-size: 0.9rem; font-weight: 500;
    text-align: center; transition: opacity 0.2s;
}
.btn:hover { opacity: 0.85; text-decoration: none; color: inherit; }
.btn-primary { background: var(--accent); color: #fff; }
.btn-primary:hover { color: #fff; }
.btn-danger { background: var(--error); color: #fff; }
.btn-danger:hover { color: #fff; }
.btn-secondary { background: var(--border); color: var(--text); }
.btn-sm { padding: 0.3rem 0.6rem; font-size: 0.8rem; }
input[type="text"], input[type="password"],
input[type="search"], input[type="number"], select, textarea {
    width: 100%; padding: 0.5rem 0.75rem; border: 1px solid var(--border);
    border-radius: 6px; background: var(--bg); color: var(--text);
    font-size: 0.9rem; font-family: inherit;
}
textarea { min-height: 200px; resize: vertical; }
input:focus, select:focus, textarea:focus {
    outline: none; border-color: var(--accent);
    box-shadow: 0 0 0 2px color-mix(in srgb, var(--accent) 25%, transparent);
}
label { display: block; font-weight: 500; margin-bottom: 0.3rem;
    font-size: 0.9rem; }
.form-group { margin-bottom: 1rem; }
.form-row { display: grid; grid-template-columns: 1fr 1fr; gap: 1rem; }
table {
    width: 100%; border-collapse: collapse; font-size: 0.9rem;
    background: var(--bg2);
}
th, td { padding: 0.6rem 0.75rem; text-align: left;
    border-bottom: 1px solid var(--border); }
th { font-weight: 600; background: var(--bg); cursor: pointer;
    user-select: none; }
th:hover { background: var(--hover); }
tr:hover { background: var(--hover); }
.badge {
    display: inline-block; padding: 0.15rem 0.5rem; border-radius: 20px;
    font-size: 0.75rem; font-weight: 600;
}
.badge-success { background: var(--success); color: #fff; }
.badge-error { background: var(--error); color: #fff; }
.badge-warning { background: var(--warning); color: #000; }
.badge-info { background: var(--accent); color: #fff; }
.badge-danger { background: var(--error); color: #fff; }
.stats-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
    gap: 1rem; margin-bottom: 1.5rem; }
.stat-card { background: var(--bg2); border: 1px solid var(--border);
    border-radius: 8px; padding: 1.25rem; text-align: center; }
.stat-card .number { font-size: 2rem; font-weight: 700; color: var(--accent); }
.stat-card .label { font-size: 0.85rem; color: var(--text2); }
.pagination { display: flex; gap: 0.5rem; justify-content: center;
    margin-top: 1.5rem; }
.pagination a, .pagination span {
    padding: 0.4rem 0.8rem; border: 1px solid var(--border);
    border-radius: 4px; font-size: 0.9rem;
}
.pagination span { background: var(--accent); color: #fff; border-color: var(--accent); }
.upload-zone {
    border: 2px dashed var(--border); border-radius: 8px;
    padding: 2rem; text-align: center; cursor: pointer;
    transition: border-color 0.2s, background 0.2s;
}
.upload-zone.dragover { border-color: var(--accent); background: var(--hover); }
.upload-zone.has-file { border-color: var(--accent); border-style: solid; }
.upload-zone.has-file p { font-weight: 600; }
.progress-bar { width: 100%; height: 8px; background: var(--border);
    border-radius: 4px; overflow: hidden; margin-top: 0.5rem; display: none; }
.progress-bar .fill { height: 100%; background: var(--accent);
    transition: width 0.3s; width: 0%; }
.editor-wrap { display: grid; grid-template-columns: 1fr 1fr; gap: 1rem; }
.preview-pane {
    border: 1px solid var(--border); border-radius: 6px;
    padding: 1rem; min-height: 200px; overflow: auto;
    background: var(--bg2);
}
.preview-pane h1, .preview-pane h2, .preview-pane h3 { margin: 0.5em 0; }
.preview-pane p { margin: 0.5em 0; }
.preview-pane code { background: var(--code-bg); padding: 0.15em 0.3em;
    border-radius: 3px; font-size: 0.9em; }
.preview-pane pre { background: var(--code-bg); padding: 1em;
    border-radius: 6px; overflow-x: auto; }
.preview-pane pre code { background: none; padding: 0; }
.preview-pane blockquote { border-left: 3px solid var(--accent);
    padding-left: 1em; color: var(--text2); margin: 0.5em 0; }
.preview-pane img { max-width: 100%; border-radius: 6px; }
dialog { border: 1px solid var(--border); border-radius: 8px;
    padding: 1.5rem; background: var(--bg2); color: var(--text);
    max-width: 400px; box-shadow: 0 4px 24px var(--shadow); }
dialog::backdrop { background: rgba(0,0,0,0.4); }
dialog h3 { margin-bottom: 1rem; }
dialog .btn { margin-right: 0.5rem; }
.comment { border-bottom: 1px solid var(--border); padding: 1rem 0; }
.comment-meta { font-size: 0.85rem; color: var(--text2); margin-bottom: 0.3rem; }
.article-meta { font-size: 0.85rem; color: var(--text2); margin-bottom: 1rem; }
.article-list .article-item { margin-bottom: 1.5rem; }
.article-item h3 { margin-bottom: 0.25rem; }
.file-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(280px, 1fr));
    gap: 1rem; }
.file-card { background: var(--bg2); border: 1px solid var(--border);
    border-radius: 8px; padding: 1rem; }
.file-card .name { font-weight: 600; word-break: break-all; }
.file-card .meta { font-size: 0.85rem; color: var(--text2); margin-top: 0.3rem; }
.checkbox-label { display: flex; align-items: center; gap: 0.5rem;
    font-weight: normal; }
@media (max-width: 768px) {
    .layout.has-sidebar { flex-direction: column; }
    .layout.has-sidebar .sidebar { width: 100%; position: static; }
    .form-row { grid-template-columns: 1fr; }
    .editor-wrap { grid-template-columns: 1fr; }
    .stats-grid { grid-template-columns: 1fr 1fr; }
    header .container { gap: 0.5rem; }
    nav { order: 3; width: 100%; }
}
"""

_JS = """
(function(){
// Theme toggle
const html = document.documentElement;
const saved = localStorage.getItem('theme');
if (saved) html.setAttribute('data-theme', saved);
window.toggleTheme = function() {
    const cur = html.getAttribute('data-theme');
    let next;
    if (cur === 'dark') next = 'light';
    else if (cur === 'light') next = 'dark';
    else next = window.matchMedia('(prefers-color-scheme: dark)').matches ? 'light' : 'dark';
    html.setAttribute('data-theme', next);
    localStorage.setItem('theme', next);
};
// Flash auto-dismiss
document.querySelectorAll('.flash').forEach(el => {
    setTimeout(() => { el.style.transition='opacity 0.5s'; el.style.opacity='0';
        setTimeout(() => el.remove(), 500); }, 4000);
});
// Admin table sort
document.querySelectorAll('table.sortable th').forEach((th, idx) => {
    th.addEventListener('click', () => {
        const table = th.closest('table');
        const tbody = table.querySelector('tbody');
        const rows = Array.from(tbody.querySelectorAll('tr'));
        const asc = th.dataset.sort !== 'asc';
        table.querySelectorAll('th').forEach(h => delete h.dataset.sort);
        th.dataset.sort = asc ? 'asc' : 'desc';
        rows.sort((a, b) => {
            const at = a.children[idx]?.textContent.trim() || '';
            const bt = b.children[idx]?.textContent.trim() || '';
            const an = parseFloat(at), bn = parseFloat(bt);
            if (!isNaN(an) && !isNaN(bn)) return asc ? an - bn : bn - an;
            return asc ? at.localeCompare(bt) : bt.localeCompare(at);
        });
        rows.forEach(r => tbody.appendChild(r));
    });
});
// Table search
document.querySelectorAll('input.table-search').forEach(input => {
    input.addEventListener('input', () => {
        const q = input.value.toLowerCase();
        const table = document.querySelector(input.dataset.target);
        if (!table) return;
        table.querySelectorAll('tbody tr').forEach(r => {
            r.style.display = r.textContent.toLowerCase().includes(q) ? '' : 'none';
        });
    });
});
// Upload drag & drop
const zone = document.querySelector('.upload-zone');
if (zone) {
    const input = zone.querySelector('input[type="file"]');
    const label = zone.querySelector('p');
    const showName = () => {
        if (input && input.files.length && label) {
            label.textContent = input.files[0].name;
            zone.classList.add('has-file');
        }
    };
    zone.addEventListener('click', () => input && input.click());
    if (input) input.addEventListener('change', showName);
    zone.addEventListener('dragover', e => { e.preventDefault(); zone.classList.add('dragover'); });
    zone.addEventListener('dragleave', () => zone.classList.remove('dragover'));
    zone.addEventListener('drop', e => {
        e.preventDefault(); zone.classList.remove('dragover');
        if (input && e.dataTransfer.files.length) { input.files = e.dataTransfer.files; showName(); }
    });
}
// Upload progress
const uploadForm = document.getElementById('upload-form');
if (uploadForm) {
    uploadForm.addEventListener('submit', function(e) {
        e.preventDefault();
        const bar = document.querySelector('.progress-bar');
        const fill = bar ? bar.querySelector('.fill') : null;
        if (bar) bar.style.display = 'block';
        const fd = new FormData(this);
        const xhr = new XMLHttpRequest();
        xhr.upload.addEventListener('progress', ev => {
            if (ev.lengthComputable && fill) {
                fill.style.width = Math.round(ev.loaded / ev.total * 100) + '%';
            }
        });
        xhr.addEventListener('load', () => { window.location.href = xhr.responseURL || '/files'; });
        xhr.addEventListener('error', () => { alert('Upload failed'); });
        xhr.open('POST', uploadForm.action);
        xhr.send(fd);
    });
}
// Markdown live preview
const mdInput = document.getElementById('md-input');
const preview = document.getElementById('md-preview');
if (mdInput && preview) {
    let timer;
    mdInput.addEventListener('input', () => {
        clearTimeout(timer);
        timer = setTimeout(() => {
            fetch('/api/preview', {method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},
                body:'text='+encodeURIComponent(mdInput.value)})
            .then(r => r.json()).then(d => { preview.innerHTML = d.html; });
        }, 300);
    });
}
// Confirm dialogs
document.querySelectorAll('[data-confirm]').forEach(el => {
    el.addEventListener('click', e => {
        e.preventDefault();
        const dlg = document.getElementById('confirm-dialog');
        if (!dlg) { if (confirm(el.dataset.confirm)) {
            if (el.tagName === 'A') window.location = el.href;
            else el.closest('form')?.submit();
        } return; }
        dlg.querySelector('.confirm-msg').textContent = el.dataset.confirm;
        const yesBtn = dlg.querySelector('.confirm-yes');
        const newYes = yesBtn.cloneNode(true);
        yesBtn.replaceWith(newYes);
        newYes.addEventListener('click', () => {
            dlg.close();
            if (el.tagName === 'A') window.location = el.href;
            else if (el.tagName === 'BUTTON' || el.tagName === 'INPUT') el.closest('form')?.submit();
        });
        dlg.showModal();
    });
});
document.querySelectorAll('dialog .confirm-no')?.forEach(b =>
    b.addEventListener('click', () => b.closest('dialog').close()));
})();
"""

# Flash cookie helpers
_FLASH_SECRET = secrets.token_bytes(32)


def _encode_flash(msg: str, kind: str = "success") -> str:
    payload = json.dumps({"m": msg, "k": kind})
    sig = hmac.new(_FLASH_SECRET, payload.encode(), hashlib.sha256).hexdigest()[:16]
    return urllib.parse.quote(f"{sig}:{payload}")


def _decode_flash(cookie_val: str) -> tuple[str, str] | None:
    try:
        val = urllib.parse.unquote(cookie_val)
        sig, payload = val.split(":", 1)
        expected = hmac.new(
            _FLASH_SECRET, payload.encode(), hashlib.sha256
        ).hexdigest()[:16]
        if not hmac.compare_digest(sig, expected):
            return None
        d = json.loads(payload)
        return d["m"], d["k"]
    except Exception:
        return None


def _flash_html(flash: tuple[str, str] | None) -> str:
    if not flash:
        return ""
    msg, kind = flash
    return f'<div class="flash flash-{html.escape(kind)}">{html.escape(msg)}</div>'


def _pagination_html(page: int, total: int, per_page: int, base_url: str) -> str:
    total_pages = max(1, (total + per_page - 1) // per_page)
    if total_pages <= 1:
        return ""
    parts = ['<div class="pagination">']
    if page > 1:
        parts.append(f'<a href="{base_url}?page={page - 1}">&laquo; Prev</a>')
    for p in range(1, total_pages + 1):
        if abs(p - page) < 4 or p == 1 or p == total_pages:
            if p == page:
                parts.append(f"<span>{p}</span>")
            else:
                parts.append(f'<a href="{base_url}?page={p}">{p}</a>')
        elif abs(p - page) == 4:
            parts.append("&hellip;")
    if page < total_pages:
        parts.append(f'<a href="{base_url}?page={page + 1}">Next &raquo;</a>')
    parts.append("</div>")
    return "".join(parts)


def _admin_sidebar(active: str = "") -> str:
    links = [
        ("/admin", "Dashboard", "dashboard"),
        ("/admin/users", "Users", "users"),
        ("/admin/files", "Files", "files"),
        ("/admin/articles", "Articles", "articles"),
        ("/admin/comments", "Comments", "comments"),
        ("/admin/groups", "Groups", "groups"),
        ("/admin/config", "Configuration", "config"),
    ]
    pending = db_fetchone(
        "SELECT COUNT(*) as c FROM comments WHERE approved = 0"
    )
    badge_count = pending["c"] if pending else 0
    parts = ['<h3>Admin</h3>']
    for href, label, key in links:
        cls = ' class="active"' if key == active else ""
        badge = ""
        if key == "comments" and badge_count > 0:
            badge = f' <span class="badge badge-warning">{badge_count}</span>'
        parts.append(f'<a href="{href}"{cls}>{label}{badge}</a>')
    return "".join(parts)


def base_template(
    title: str, body: str, user: dict | None = None,
    flash: tuple[str, str] | None = None,
    sidebar: str = "", cfg: dict | None = None,
) -> str:
    if cfg is None:
        cfg = get_config()
    site = html.escape(cfg.get("site_name", "offline"))

    nav_links = '<a href="/">Home</a><a href="/blog">Blog</a><a href="/files">Files</a>'
    if user and has_role(user, "user"):
        nav_links += '<a href="/upload">Upload</a>'
        unread = _unread_count(user["id"])
        badge = f' <span class="badge badge-danger">{unread}</span>' if unread else ""
        nav_links += f'<a href="/messages">Messages{badge}</a>'
    if user and has_role(user, "mod"):
        nav_links += '<a href="/admin">Admin</a>'

    if user:
        auth = (
            f'<span>Hi, <strong>{html.escape(user["username"])}</strong></span>'
            f'<a href="/profile">Profile</a>'
            f'<a href="/logout">Logout</a>'
        )
    else:
        auth = '<a href="/login">Login</a>'
        if cfg.get("registration_open"):
            auth += '<a href="/register">Register</a>'

    layout_cls = "layout has-sidebar" if sidebar else "layout"
    sidebar_html = f'<aside class="sidebar">{sidebar}</aside>' if sidebar else ""

    year = _utcnow().year
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>{html.escape(title)} — {site}</title>
<style>{_CSS}</style>
</head>
<body>
<header><div class="container">
<a href="/" class="logo">{site}</a>
<nav>{nav_links}</nav>
<div class="auth-links">{auth}
<button class="theme-toggle" onclick="toggleTheme()">🌓</button>
</div>
</div></header>
<div class="container"><div class="{layout_cls}">
{sidebar_html}
<main>
{_flash_html(flash)}
{body}
</main>
</div></div>
<footer><div class="container">{site} v{__version__} &copy; {year} · <a href="/fingerprint" style="color:inherit;text-decoration:underline">Certificate</a></div></footer>
<dialog id="confirm-dialog">
<h3>Confirm</h3><p class="confirm-msg"></p>
<div style="margin-top:1rem">
<button class="btn btn-danger confirm-yes">Yes</button>
<button class="btn btn-secondary confirm-no">Cancel</button>
</div></dialog>
<script>{_JS}</script>
</body></html>"""


def error_page(code: int, message: str, user: dict | None = None) -> str:
    body = f'<div class="card"><h2>Error {code}</h2><p>{html.escape(message)}</p></div>'
    return base_template(f"Error {code}", body, user=user)


def format_size(b: int) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if b < 1024:
            return f"{b:.1f} {unit}" if unit != "B" else f"{b} {unit}"
        b /= 1024
    return f"{b:.1f} TB"


def format_time(iso: str | None) -> str:
    if not iso:
        return "—"
    try:
        dt = datetime.datetime.fromisoformat(iso)
        return dt.strftime("%Y-%m-%d %H:%M")
    except Exception:
        return iso


def _visibility_options(selected: str = "public") -> str:
    """Build <option> tags for visibility selectors, including groups."""
    opts = [("public", "Public"), ("private", "Private (login required)")]
    groups = db_fetchall("SELECT name FROM groups ORDER BY name")
    for g in groups:
        opts.append((f'group:{g["name"]}', f'Group: {g["name"]}'))
    out = ""
    for val, label in opts:
        sel = " selected" if val == selected else ""
        out += f'<option value="{html.escape(val)}"{sel}>{html.escape(label)}</option>'
    return out


def _is_valid_visibility(vis: str) -> bool:
    """Check if a visibility value is valid."""
    if vis in ("public", "private"):
        return True
    if vis.startswith("group:"):
        name = vis[6:]
        return db_fetchone("SELECT 1 FROM groups WHERE name = ?", (name,)) is not None
    if vis.startswith("role:"):
        return vis[5:] in ("user", "mod", "admin", "superadmin")
    return False


# ── SECTION 9: Request Handler & Router ─────────────────────

def parse_cookies(header: str) -> dict[str, str]:
    cookies = {}
    for item in header.split(";"):
        item = item.strip()
        if "=" in item:
            k, v = item.split("=", 1)
            cookies[k.strip()] = v.strip()
    return cookies


def parse_query(qs: str) -> dict[str, str]:
    return dict(urllib.parse.parse_qsl(qs))


def parse_form_body(body: bytes, content_type: str = "") -> dict[str, str]:
    """Parse URL-encoded form body."""
    return dict(urllib.parse.parse_qsl(body.decode("utf-8", errors="replace")))


def parse_multipart(body: bytes, boundary: str) -> tuple[dict, dict]:
    """Parse multipart/form-data. Returns (fields, files).
    fields: {name: value}, files: {name: (filename, data, content_type)}
    """
    fields: dict[str, str] = {}
    files: dict[str, tuple[str, bytes, str]] = {}
    sep = f"--{boundary}".encode()
    parts = body.split(sep)
    for part in parts[1:]:
        if part.startswith(b"--"):
            break
        if b"\r\n\r\n" not in part:
            continue
        header_block, content = part.split(b"\r\n\r\n", 1)
        if content.endswith(b"\r\n"):
            content = content[:-2]
        headers_raw = header_block.decode("utf-8", errors="replace")
        disp_match = re.search(
            r'Content-Disposition:\s*form-data;\s*name="([^"]*)"',
            headers_raw, re.IGNORECASE,
        )
        if not disp_match:
            continue
        name = disp_match.group(1)
        fn_match = re.search(r'filename="([^"]*)"', headers_raw)
        if fn_match and fn_match.group(1):
            filename = fn_match.group(1)
            ct_match = re.search(
                r'Content-Type:\s*(.+)', headers_raw, re.IGNORECASE
            )
            ct = ct_match.group(1).strip() if ct_match else "application/octet-stream"
            files[name] = (filename, content, ct)
        else:
            fields[name] = content.decode("utf-8", errors="replace")
    return fields, files


class RequestHandler(BaseHTTPRequestHandler):
    """Custom request handler with routing, auth, and rate limiting."""

    server_version = f"Offline/{__version__}"
    _routes: list[tuple[str, str, "callable"]] = []

    @classmethod
    def register_routes(cls, routes: list[tuple[str, str, "callable"]]) -> None:
        cls._routes = routes

    def log_message(self, format: str, *args) -> None:
        _access_logger.info(
            "%s %s %s %s",
            self.client_address[0], self.command,
            self.path, args[0] if args else "",
        )

    def _get_ip(self) -> str:
        return self.client_address[0]

    def _get_cookies(self) -> dict[str, str]:
        return parse_cookies(self.headers.get("Cookie", ""))

    def _get_raw_token(self) -> str | None:
        cookies = self._get_cookies()
        if "auth_token" in cookies:
            return cookies["auth_token"]
        auth_header = self.headers.get("Authorization", "")
        if auth_header.startswith("Bearer "):
            return auth_header[7:].strip()
        return None

    def _get_user(self) -> dict | None:
        raw = self._get_raw_token()
        if not raw:
            return None
        return validate_token(raw)

    def _get_flash(self) -> tuple[str, str] | None:
        cookies = self._get_cookies()
        if "flash" in cookies:
            return _decode_flash(cookies["flash"])
        return None

    def _read_body(self) -> bytes:
        length = int(self.headers.get("Content-Length", 0))
        return self.rfile.read(length) if length > 0 else b""

    def _send(self, code: int, body: str, content_type: str = "text/html",
              headers: dict | None = None, cookies: list[str] | None = None) -> None:
        data = body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", f"{content_type}; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "strict-origin-when-cross-origin")
        self.send_header(
            "Content-Security-Policy",
            "default-src 'self'; style-src 'self' 'unsafe-inline'; "
            "script-src 'self' 'unsafe-inline'",
        )
        if headers:
            for k, v in headers.items():
                self.send_header(k, v)
        if cookies:
            for c in cookies:
                self.send_header("Set-Cookie", c)
        self.end_headers()
        self.wfile.write(data)

    def _send_html(self, code: int, body: str,
                   cookies: list[str] | None = None) -> None:
        self._send(code, body, cookies=cookies)

    def _send_json(self, code: int, data: dict) -> None:
        self._send(code, json.dumps(data), content_type="application/json")

    def _redirect(self, location: str, flash_msg: str = "",
                  flash_kind: str = "success") -> None:
        self.send_response(303)
        self.send_header("Location", location)
        if flash_msg:
            self.send_header(
                "Set-Cookie",
                f"flash={_encode_flash(flash_msg, flash_kind)}; "
                f"Path=/; HttpOnly; SameSite=Strict; Max-Age=10",
            )
        self.send_header("Content-Length", "0")
        self.end_headers()

    def _send_file(self, filepath: str, filename: str, mime: str,
                   size: int) -> None:
        self.send_response(200)
        self.send_header("Content-Type", mime)
        self.send_header(
            "Content-Disposition",
            f'attachment; filename="{filename}"',
        )
        self.send_header("Content-Length", str(size))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        with open(filepath, "rb") as f:
            while True:
                chunk = f.read(65536)
                if not chunk:
                    break
                self.wfile.write(chunk)

    def _clear_flash_cookie(self) -> list[str]:
        return ["flash=; Path=/; Max-Age=0"]

    def _handle(self, method: str) -> None:
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path.rstrip("/") or "/"
        query = parse_query(parsed.query)

        ip = self._get_ip()
        if not check_rate_limit(ip):
            self._send_html(
                429,
                error_page(429, "Too many requests. Please slow down."),
            )
            return

        for route_method, pattern, handler in self._routes:
            if route_method != method:
                continue
            m = re.fullmatch(pattern, path)
            if m:
                try:
                    handler(self, query=query, match=m)
                except Exception as e:
                    _error_logger.error(
                        "Handler error: %s %s — %s", method, path, e,
                        exc_info=True,
                    )
                    self._send_html(
                        500,
                        error_page(500, "Internal server error."),
                    )
                return

        self._send_html(404, error_page(404, "Page not found."))

    def do_GET(self) -> None:
        self._handle("GET")

    def do_POST(self) -> None:
        self._handle("POST")

    def do_HEAD(self) -> None:
        self._handle("GET")


# ── SECTION 10: Route Handlers ──────────────────────────────

def handle_home(h: RequestHandler, **kw) -> None:
    user = h._get_user()
    flash = h._get_flash()
    cfg = get_config()
    articles = db_fetchall(
        "SELECT a.*, u.username FROM articles a "
        "JOIN users u ON a.author_id = u.id "
        "WHERE a.published = 1 ORDER BY a.created_at DESC LIMIT 10"
    )
    articles = filter_visible_articles(articles, user)[:5]
    all_files = db_fetchall(
        "SELECT * FROM files ORDER BY uploaded_at DESC LIMIT 20"
    )
    files = [f for f in all_files if check_visibility(f["visibility"], user)][:6]
    art_html = ""
    for a in articles:
        art_html += (
            f'<div class="article-item"><h3><a href="/blog/{html.escape(a["slug"])}">'
            f'{html.escape(a["title"])}</a></h3>'
            f'<div class="article-meta">by {html.escape(a["username"])} · '
            f'{format_time(a["created_at"])}</div></div>'
        )
    files_html = ""
    for f in files:
        files_html += (
            f'<div class="file-card"><div class="name">'
            f'<a href="/files/{html.escape(f["stored_name"])}">'
            f'{html.escape(f["filename"])}</a></div>'
            f'<div class="meta">{format_size(f["size_bytes"])} · '
            f'{format_time(f["uploaded_at"])}</div></div>'
        )
    body = (
        f'<div class="card"><h2>Recent Articles</h2>'
        f'{art_html if art_html else "<p>No articles yet.</p>"}'
        f'<p style="margin-top:1rem"><a href="/blog">View all &rarr;</a></p></div>'
        f'<div class="card"><h2>Recent Files</h2>'
        f'<div class="file-grid">{files_html}</div>'
        f'{("<p>No files yet.</p>" if not files_html else "")}'
        f'<p style="margin-top:1rem"><a href="/files">Browse all &rarr;</a></p></div>'
    )
    h._send_html(
        200,
        base_template("Home", body, user=user, flash=flash, cfg=cfg),
        cookies=h._clear_flash_cookie(),
    )


def handle_fingerprint(h: RequestHandler, **kw) -> None:
    fp = get_cert_fingerprint(_data_dir)
    body = (
        '<h1>Certificate Fingerprint</h1><div class="card">'
        '<p>This server uses a <strong>self-signed TLS certificate</strong>. '
        'Verify the fingerprint below matches what the server administrator shared with you.</p>'
        f'<pre style="word-break:break-all;white-space:pre-wrap;padding:1rem;'
        f'background:var(--bg);border-radius:6px;border:1px solid var(--border);'
        f'font-size:0.95rem">{html.escape(fp)}</pre>'
        '<p style="margin-top:1rem;color:var(--text2);font-size:0.9rem">'
        'The administrator can also see this fingerprint in the server console output.</p></div>'
    )
    user = h._get_user()
    h._send_html(200, base_template("Certificate Fingerprint", body, user=user))


def handle_blog_list(h: RequestHandler, **kw) -> None:
    user = h._get_user()
    flash = h._get_flash()
    query = kw.get("query", {})
    page = max(1, int(query.get("page", 1)))
    per_page = 20
    all_articles = db_fetchall(
        "SELECT a.*, u.username FROM articles a "
        "JOIN users u ON a.author_id = u.id "
        "WHERE a.published = 1 ORDER BY a.created_at DESC"
    )
    visible = filter_visible_articles(all_articles, user)
    total = len(visible)
    start = (page - 1) * per_page
    page_articles = visible[start:start + per_page]
    art_html = ""
    for a in page_articles:
        snippet = strip_markdown(a["body"])
        snippet = snippet[:200] + "…" if len(snippet) > 200 else snippet
        art_html += (
            f'<div class="article-item"><h3><a href="/blog/{html.escape(a["slug"])}">'
            f'{html.escape(a["title"])}</a></h3>'
            f'<div class="article-meta">by {html.escape(a["username"])} · '
            f'{format_time(a["created_at"])} · '
            f'<span class="badge badge-info">{html.escape(a["visibility"])}</span></div>'
            f'<p>{html.escape(snippet)}</p></div>'
        )
    body = (
        f'<h1>Blog</h1><div class="article-list" style="margin-top:1rem">'
        f'{art_html if art_html else "<p>No articles yet.</p>"}'
        f'</div>{_pagination_html(page, total, per_page, "/blog")}'
    )
    h._send_html(
        200,
        base_template("Blog", body, user=user, flash=flash),
        cookies=h._clear_flash_cookie(),
    )


def handle_blog_detail(h: RequestHandler, **kw) -> None:
    user = h._get_user()
    flash = h._get_flash()
    slug = kw["match"].group(1)
    article = db_fetchone(
        "SELECT a.*, u.username FROM articles a "
        "JOIN users u ON a.author_id = u.id WHERE a.slug = ?",
        (slug,),
    )
    if not article or (not article["published"] and not has_role(user, "mod")):
        h._send_html(404, error_page(404, "Article not found.", user))
        return
    if not check_visibility(article["visibility"], user):
        h._send_html(403, error_page(403, "Access denied.", user))
        return
    comments = db_fetchall(
        "SELECT c.*, u.username as user_name FROM comments c "
        "LEFT JOIN users u ON c.author_id = u.id "
        "WHERE c.article_id = ? AND c.approved = 1 "
        "ORDER BY c.created_at ASC",
        (article["id"],),
    )
    rendered = render_markdown(article["body"])
    comments_html = ""
    for c in comments:
        name = html.escape(c.get("user_name") or c.get("author_name") or "Anonymous")
        comments_html += (
            f'<div class="comment"><div class="comment-meta">'
            f'<strong>{name}</strong> · {format_time(c["created_at"])}</div>'
            f'<div>{html.escape(c["body"])}</div></div>'
        )
    raw_token = h._get_raw_token() or ""
    csrf = generate_csrf(raw_token) if raw_token else ""
    comment_form = ""
    if article["visibility"] == "public" or user:
        name_field = ""
        if not user:
            name_field = (
                '<div class="form-group"><label>Your Name</label>'
                '<input type="text" name="author_name" required></div>'
            )
        comment_form = (
            f'<h3 style="margin-top:1.5rem">Leave a Comment</h3>'
            f'<form method="POST" action="/blog/{html.escape(slug)}/comment">'
            f'<input type="hidden" name="csrf_token" value="{csrf}">'
            f'{name_field}'
            f'<div class="form-group"><label>Comment</label>'
            f'<textarea name="body" rows="4" required></textarea></div>'
            f'<button type="submit" class="btn btn-primary">Post Comment</button>'
            f'</form>'
        )
    body = (
        f'<article class="card"><h1>{html.escape(article["title"])}</h1>'
        f'<div class="article-meta">by {html.escape(article["username"])} · '
        f'{format_time(article["created_at"])}'
        f'{" · Updated " + format_time(article["updated_at"]) if article["updated_at"] != article["created_at"] else ""}'
        f'</div><div class="preview-pane" style="border:none;padding:0">'
        f'{rendered}</div></article>'
        f'<div class="card"><h2>Comments ({len(comments)})</h2>'
        f'{comments_html if comments_html else "<p>No comments yet.</p>"}'
        f'{comment_form}</div>'
    )
    h._send_html(
        200,
        base_template(article["title"], body, user=user, flash=flash),
        cookies=h._clear_flash_cookie(),
    )


def handle_post_comment(h: RequestHandler, **kw) -> None:
    user = h._get_user()
    slug = kw["match"].group(1)
    article = db_fetchone("SELECT * FROM articles WHERE slug = ?", (slug,))
    if not article:
        h._send_html(404, error_page(404, "Article not found."))
        return
    body_bytes = h._read_body()
    form = parse_form_body(body_bytes)
    raw_token = h._get_raw_token() or ""
    if raw_token and not verify_csrf(raw_token, form.get("csrf_token", "")):
        h._redirect(f"/blog/{slug}", "Invalid request.", "error")
        return
    comment_body = form.get("body", "").strip()
    if not comment_body:
        h._redirect(f"/blog/{slug}", "Comment cannot be empty.", "error")
        return
    now = _utcnow().isoformat()
    if user:
        db_execute(
            "INSERT INTO comments (article_id, author_id, author_name, body,"
            " created_at) VALUES (?, ?, ?, ?, ?)",
            (article["id"], user["id"], user["username"], comment_body, now),
        )
    else:
        author_name = form.get("author_name", "").strip() or "Anonymous"
        db_execute(
            "INSERT INTO comments (article_id, author_name, body, created_at)"
            " VALUES (?, ?, ?, ?)",
            (article["id"], author_name, comment_body, now),
        )
    h._redirect(f"/blog/{slug}", "Comment posted!")


def handle_file_list(h: RequestHandler, **kw) -> None:
    user = h._get_user()
    flash = h._get_flash()
    query = kw.get("query", {})
    page = max(1, int(query.get("page", 1)))
    per_page = 20
    all_files = db_fetchall(
        "SELECT f.*, u.username FROM files f "
        "LEFT JOIN users u ON f.owner_id = u.id "
        "ORDER BY f.uploaded_at DESC"
    )
    visible = [f for f in all_files if check_visibility(f["visibility"], user)]
    total = len(visible)
    start = (page - 1) * per_page
    page_files = visible[start:start + per_page]
    files_html = ""
    for f in page_files:
        files_html += (
            f'<div class="file-card"><div class="name">'
            f'<a href="/files/{html.escape(f["stored_name"])}">'
            f'{html.escape(f["filename"])}</a></div>'
            f'<div class="meta">{format_size(f["size_bytes"])} · '
            f'{html.escape(f.get("username") or "Unknown")} · '
            f'{format_time(f["uploaded_at"])} · '
            f'<span class="badge badge-info">{html.escape(f["visibility"])}</span>'
            f'</div>'
            f'{("<div class=meta>" + html.escape(f["description"]) + "</div>") if f.get("description") else ""}'
            f'</div>'
        )
    body = (
        f'<h1>Files</h1>'
        f'<div class="file-grid" style="margin-top:1rem">'
        f'{files_html if files_html else "<p>No files available.</p>"}</div>'
        f'{_pagination_html(page, total, per_page, "/files")}'
    )
    h._send_html(
        200,
        base_template("Files", body, user=user, flash=flash),
        cookies=h._clear_flash_cookie(),
    )


def handle_file_download(h: RequestHandler, **kw) -> None:
    user = h._get_user()
    stored = kw["match"].group(1)
    frow = db_fetchone("SELECT * FROM files WHERE stored_name = ?", (stored,))
    if not frow:
        h._send_html(404, error_page(404, "File not found.", user))
        return
    if not check_visibility(frow["visibility"], user):
        h._send_html(403, error_page(403, "Access denied.", user))
        return
    sub = "private" if frow["visibility"] != "public" else "public"
    filepath = str(_data_dir / "files" / sub / frow["stored_name"])
    if not os.path.isfile(filepath):
        filepath = str(_data_dir / "files" / ("private" if sub == "public" else "public") / frow["stored_name"])
    if not os.path.isfile(filepath):
        h._send_html(404, error_page(404, "File missing from disk.", user))
        return
    h._send_file(
        filepath, frow["filename"],
        frow["mime_type"] or "application/octet-stream", frow["size_bytes"],
    )


# ── SECTION 11: File Upload & Download ──────────────────────

def handle_upload_form(h: RequestHandler, **kw) -> None:
    user = h._get_user()
    if not user:
        h._redirect("/login", "Please log in to upload files.", "warning")
        return
    flash = h._get_flash()
    raw_token = h._get_raw_token() or ""
    csrf = generate_csrf(raw_token)
    cfg = get_config()
    ext_note = ""
    if cfg["allowed_file_extensions"]:
        exts = ", ".join(cfg["allowed_file_extensions"])
        ext_note = f'<p class="meta">Allowed types: {html.escape(exts)}</p>'
    body = (
        f'<h1>Upload File</h1><div class="card">'
        f'<form method="POST" action="/upload" enctype="multipart/form-data" id="upload-form">'
        f'<input type="hidden" name="csrf_token" value="{csrf}">'
        f'<div class="upload-zone"><input type="file" name="file" required '
        f'style="display:none"><p>Click or drag a file here to upload</p>'
        f'<p class="meta">Max size: {cfg["max_file_size_mb"]} MB</p>'
        f'{ext_note}</div>'
        f'<div class="progress-bar"><div class="fill"></div></div>'
        f'<div class="form-group" style="margin-top:1rem">'
        f'<label>Description (optional)</label>'
        f'<input type="text" name="description"></div>'
        f'<div class="form-group"><label>Visibility</label>'
        f'<select name="visibility">{_visibility_options()}</select></div>'
        f'<button type="submit" class="btn btn-primary">Upload</button></form></div>'
    )
    h._send_html(
        200,
        base_template("Upload", body, user=user, flash=flash),
        cookies=h._clear_flash_cookie(),
    )


def handle_upload(h: RequestHandler, **kw) -> None:
    user = h._get_user()
    if not user:
        h._redirect("/login", "Please log in.", "warning")
        return
    cfg = get_config()
    content_type = h.headers.get("Content-Type", "")
    content_length = int(h.headers.get("Content-Length", 0))
    max_bytes = cfg["max_file_size_mb"] * 1024 * 1024
    if content_length > max_bytes + 4096:
        h._read_body()
        h._redirect("/upload", f"File too large (max {cfg['max_file_size_mb']} MB).", "error")
        return
    if "boundary=" not in content_type:
        h._redirect("/upload", "Invalid upload.", "error")
        return
    boundary = content_type.split("boundary=")[1].strip()
    if boundary.startswith('"') and boundary.endswith('"'):
        boundary = boundary[1:-1]
    body = h._read_body()
    fields, files = parse_multipart(body, boundary)
    raw_token = h._get_raw_token() or ""
    if not verify_csrf(raw_token, fields.get("csrf_token", "")):
        h._redirect("/upload", "Invalid request.", "error")
        return
    if "file" not in files:
        h._redirect("/upload", "No file selected.", "error")
        return
    filename, data, fct = files["file"]
    if len(data) > max_bytes:
        h._redirect("/upload", f"File too large (max {cfg['max_file_size_mb']} MB).", "error")
        return
    ext = filename.rsplit(".", 1)[-1].lower() if "." in filename else ""
    if cfg["allowed_file_extensions"] and ext not in cfg["allowed_file_extensions"]:
        h._redirect(
            "/upload",
            f"File type .{ext} not allowed.",
            "error",
        )
        return
    stored_name = secrets.token_hex(16) + ("." + ext if ext else "")
    visibility = fields.get("visibility", "public")
    if not _is_valid_visibility(visibility):
        visibility = "public"
    sub = "public" if visibility == "public" else "private"
    filepath = _data_dir / "files" / sub / stored_name
    filepath.write_bytes(data)
    now = _utcnow().isoformat()
    mime = mimetypes.guess_type(filename)[0] or "application/octet-stream"
    db_execute(
        "INSERT INTO files (filename, stored_name, owner_id, size_bytes, "
        "mime_type, visibility, uploaded_at, description) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        (filename, stored_name, user["id"], len(data), mime,
         visibility, now, fields.get("description", "")),
    )
    _access_logger.info("UPLOAD user_id=%s file=%s size=%s", user["id"], stored_name, len(data))
    h._redirect("/files", "File uploaded successfully!")


def handle_login_form(h: RequestHandler, **kw) -> None:
    user = h._get_user()
    if user:
        h._redirect("/")
        return
    flash = h._get_flash()
    body = (
        '<h1>Login</h1><div class="card">'
        '<form method="POST" action="/login">'
        '<div class="form-group"><label>Username</label>'
        '<input type="text" name="username" required autofocus></div>'
        '<div class="form-group"><label>Password</label>'
        '<input type="password" name="password" required></div>'
        '<button type="submit" class="btn btn-primary">Login</button></form></div>'
    )
    h._send_html(
        200,
        base_template("Login", body, flash=flash),
        cookies=h._clear_flash_cookie(),
    )


def handle_login(h: RequestHandler, **kw) -> None:
    ip = h._get_ip()
    if not check_login_limit(ip):
        h._redirect("/login", "Too many failed attempts. Try again later.", "error")
        return
    body = h._read_body()
    form = parse_form_body(body)
    username = form.get("username", "").strip()
    password = form.get("password", "")
    user = db_fetchone(
        "SELECT * FROM users WHERE username = ? AND is_active = 1",
        (username,),
    )
    if not user or not verify_password(password, user["password_hash"], user["salt"]):
        record_login_failure(ip)
        h._redirect("/login", "Invalid username or password.", "error")
        return
    raw_token = create_token(
        user["id"],
        user_agent=h.headers.get("User-Agent", ""),
        ip_address=ip,
    )
    db_execute(
        "UPDATE users SET last_login = ? WHERE id = ?",
        (_utcnow().isoformat(), user["id"]),
    )
    _access_logger.info("LOGIN user_id=%s ip=%s", user["id"], ip)
    cookies = [
        f"auth_token={raw_token}; Path=/; HttpOnly; Secure; SameSite=Strict; "
        f"Max-Age={get_config()['token_expiry_seconds']}",
    ]
    if user.get("pw_reset_notice"):
        db_execute("UPDATE users SET pw_reset_notice = 0 WHERE id = ?", (user["id"],))
        cookies.append(
            f"flash={_encode_flash('Your password was recently reset by an administrator. If this was unexpected, contact support.', 'warning')}; "
            f"Path=/; HttpOnly; SameSite=Strict; Max-Age=10"
        )
        h.send_response(303)
        h.send_header("Location", "/")
        for c in cookies:
            h.send_header("Set-Cookie", c)
        h.send_header("Content-Length", "0")
        h.end_headers()
    else:
        h.send_response(303)
        h.send_header("Location", "/")
        for c in cookies:
            h.send_header("Set-Cookie", c)
        flash_c = f"flash={_encode_flash('Welcome back, ' + username + '!')}; Path=/; HttpOnly; SameSite=Strict; Max-Age=10"
        h.send_header("Set-Cookie", flash_c)
        h.send_header("Content-Length", "0")
        h.end_headers()


def handle_logout(h: RequestHandler, **kw) -> None:
    raw = h._get_raw_token()
    if raw:
        revoke_token(raw)
    h.send_response(303)
    h.send_header("Location", "/")
    h.send_header("Set-Cookie", "auth_token=; Path=/; Max-Age=0")
    flash_c = f"flash={_encode_flash('Logged out.')}; Path=/; HttpOnly; SameSite=Strict; Max-Age=10"
    h.send_header("Set-Cookie", flash_c)
    h.send_header("Content-Length", "0")
    h.end_headers()


def handle_register_form(h: RequestHandler, **kw) -> None:
    cfg = get_config()
    if not cfg.get("registration_open"):
        h._send_html(403, error_page(403, "Registration is closed."))
        return
    user = h._get_user()
    if user:
        h._redirect("/")
        return
    flash = h._get_flash()
    body = (
        '<h1>Register</h1><div class="card">'
        '<form method="POST" action="/register">'
        '<div class="form-group"><label>Username (3–32 chars)</label>'
        '<input type="text" name="username" required></div>'
        '<div class="form-group"><label>Password (≥12 chars, upper+lower+digit)</label>'
        '<input type="password" name="password" required></div>'
        '<div class="form-group"><label>Confirm Password</label>'
        '<input type="password" name="confirm_password" required></div>'
        '<button type="submit" class="btn btn-primary">Register</button></form></div>'
    )
    h._send_html(
        200,
        base_template("Register", body, flash=flash),
        cookies=h._clear_flash_cookie(),
    )


def handle_register(h: RequestHandler, **kw) -> None:
    cfg = get_config()
    if not cfg.get("registration_open"):
        h._send_html(403, error_page(403, "Registration is closed."))
        return
    body = h._read_body()
    form = parse_form_body(body)
    username = form.get("username", "").strip()
    password = form.get("password", "")
    confirm = form.get("confirm_password", "")
    err = validate_username(username)
    if not err:
        err = validate_password(password)
    if not err and password != confirm:
        err = "Passwords do not match"
    if not err:
        existing = db_fetchone(
            "SELECT id FROM users WHERE username = ?",
            (username,),
        )
        if existing:
            err = "Username already taken"
    if err:
        h._redirect("/register", err, "error")
        return
    pw_hash, salt = hash_password(password)
    now = _utcnow().isoformat()
    db_execute(
        "INSERT INTO users (username, password_hash, salt, role, created_at)"
        " VALUES (?, ?, ?, 'user', ?)",
        (username, pw_hash, salt, now),
    )
    _access_logger.info("REGISTER username=%s", username)
    h._redirect("/login", "Account created! Please log in.", "success")


def handle_profile(h: RequestHandler, **kw) -> None:
    user = h._get_user()
    if not user:
        h._redirect("/login", "Please log in.", "warning")
        return
    flash = h._get_flash()
    raw_token = h._get_raw_token() or ""
    csrf = generate_csrf(raw_token)
    sessions = db_fetchall(
        "SELECT id, user_agent, ip_address, created_at, expires_at "
        "FROM tokens WHERE user_id = ? AND revoked = 0 "
        "ORDER BY created_at DESC",
        (user["id"],),
    )
    sess_html = ""
    for s in sessions:
        sess_html += (
            f'<tr><td>{html.escape(s.get("ip_address") or "—")}</td>'
            f'<td>{html.escape((s.get("user_agent") or "")[:60])}</td>'
            f'<td>{format_time(s["created_at"])}</td>'
            f'<td>{format_time(s["expires_at"])}</td></tr>'
        )
    body = (
        f'<h1>Profile</h1><div class="card">'
        f'<p><strong>Username:</strong> {html.escape(user["username"])}</p>'
        f'<p><strong>Role:</strong> <span class="badge badge-info">'
        f'{html.escape(user["role"])}</span></p>'
        f'<p><strong>Member since:</strong> {format_time(user["created_at"])}</p>'
        f'<p style="margin-top:1rem">'
        f'<a href="/profile/change-password" class="btn btn-secondary">Change Password</a></p>'
        f'</div>'
        f'<div class="card"><h2>Active Sessions</h2>'
        f'<table class="sortable"><thead><tr><th>IP</th><th>Browser</th>'
        f'<th>Created</th><th>Expires</th></tr></thead>'
        f'<tbody>{sess_html}</tbody></table>'
        f'<form method="POST" action="/profile/logout-all" style="margin-top:1rem">'
        f'<input type="hidden" name="csrf_token" value="{csrf}">'
        f'<button type="submit" class="btn btn-danger" '
        f'data-confirm="Sign out from all devices?">Logout All Devices</button>'
        f'</form></div>'
    )
    h._send_html(
        200,
        base_template("Profile", body, user=user, flash=flash),
        cookies=h._clear_flash_cookie(),
    )


def handle_logout_all(h: RequestHandler, **kw) -> None:
    user = h._get_user()
    if not user:
        h._redirect("/login")
        return
    body = h._read_body()
    form = parse_form_body(body)
    raw_token = h._get_raw_token() or ""
    if not verify_csrf(raw_token, form.get("csrf_token", "")):
        h._redirect("/profile", "Invalid request.", "error")
        return
    revoke_all_tokens(user["id"])
    new_token = create_token(
        user["id"],
        user_agent=h.headers.get("User-Agent", ""),
        ip_address=h._get_ip(),
    )
    h.send_response(303)
    h.send_header("Location", "/profile")
    h.send_header(
        "Set-Cookie",
        f"auth_token={new_token}; Path=/; HttpOnly; Secure; SameSite=Strict; "
        f"Max-Age={get_config()['token_expiry_seconds']}",
    )
    flash_c = f"flash={_encode_flash('All other sessions signed out.')}; Path=/; HttpOnly; SameSite=Strict; Max-Age=10"
    h.send_header("Set-Cookie", flash_c)
    h.send_header("Content-Length", "0")
    h.end_headers()


def handle_change_password_form(h: RequestHandler, **kw) -> None:
    user = h._get_user()
    if not user:
        h._redirect("/login", "Please log in.", "warning")
        return
    flash = h._get_flash()
    raw_token = h._get_raw_token() or ""
    csrf = generate_csrf(raw_token)
    body = (
        '<h1>Change Password</h1><div class="card">'
        '<form method="POST" action="/profile/change-password">'
        f'<input type="hidden" name="csrf_token" value="{csrf}">'
        '<div class="form-group"><label>Current Password</label>'
        '<input type="password" name="current_password" required></div>'
        '<div class="form-group"><label>New Password (≥12 chars, upper+lower+digit)</label>'
        '<input type="password" name="new_password" required></div>'
        '<div class="form-group"><label>Confirm New Password</label>'
        '<input type="password" name="confirm_password" required></div>'
        '<button type="submit" class="btn btn-primary">Change Password</button></form></div>'
    )
    h._send_html(
        200,
        base_template("Change Password", body, user=user, flash=flash),
        cookies=h._clear_flash_cookie(),
    )


def handle_change_password(h: RequestHandler, **kw) -> None:
    user = h._get_user()
    if not user:
        h._redirect("/login")
        return
    if not check_pw_change_limit(user["id"]):
        h._redirect(
            "/profile/change-password",
            "Too many attempts. Try again in 15 minutes.", "error",
        )
        return
    body_bytes = h._read_body()
    form = parse_form_body(body_bytes)
    raw_token = h._get_raw_token() or ""
    if not verify_csrf(raw_token, form.get("csrf_token", "")):
        h._redirect("/profile/change-password", "Invalid request.", "error")
        return
    current = form.get("current_password", "")
    new_pw = form.get("new_password", "")
    confirm = form.get("confirm_password", "")
    fresh_user = db_fetchone("SELECT * FROM users WHERE id = ?", (user["id"],))
    if not fresh_user or not verify_password(current, fresh_user["password_hash"], fresh_user["salt"]):
        h._redirect("/profile/change-password", "Current password is incorrect.", "error")
        return
    err = validate_password(new_pw)
    if err:
        h._redirect(f"/profile/change-password", err, "error")
        return
    if new_pw != confirm:
        h._redirect("/profile/change-password", "Passwords do not match.", "error")
        return
    if current == new_pw:
        h._redirect("/profile/change-password", "New password must differ from current.", "error")
        return
    pw_hash, salt = hash_password(new_pw)
    db_execute(
        "UPDATE users SET password_hash = ?, salt = ? WHERE id = ?",
        (pw_hash, salt, user["id"]),
    )
    revoke_all_tokens(user["id"])
    new_token = create_token(
        user["id"],
        user_agent=h.headers.get("User-Agent", ""),
        ip_address=h._get_ip(),
    )
    _access_logger.info(
        "PASSWORD_CHANGE user_id=%s by=self ip=%s", user["id"], h._get_ip()
    )
    h.send_response(303)
    h.send_header("Location", "/profile")
    h.send_header(
        "Set-Cookie",
        f"auth_token={new_token}; Path=/; HttpOnly; Secure; SameSite=Strict; "
        f"Max-Age={get_config()['token_expiry_seconds']}",
    )
    flash_c = f"flash={_encode_flash('Password changed. All other sessions have been signed out.')}; Path=/; HttpOnly; SameSite=Strict; Max-Age=10"
    h.send_header("Set-Cookie", flash_c)
    h.send_header("Content-Length", "0")
    h.end_headers()


def handle_api_preview(h: RequestHandler, **kw) -> None:
    body = h._read_body()
    form = parse_form_body(body)
    text = form.get("text", "")
    rendered = render_markdown(text)
    h._send_json(200, {"html": rendered})


# ── SECTION 11b: Messaging / Mailbox ───────────────────────

def _unread_count(user_id: int) -> int:
    row = db_fetchone(
        "SELECT COUNT(*) AS c FROM messages "
        "WHERE recipient_id = ? AND read_at IS NULL AND deleted_by_recipient = 0",
        (user_id,),
    )
    return row["c"] if row else 0


def handle_messages_inbox(h: RequestHandler, **kw) -> None:
    user = h._get_user()
    if not user:
        h._redirect("/login", "Please log in.", "warning")
        return
    flash = h._get_flash()
    messages = db_fetchall(
        "SELECT m.*, u.username AS sender_name FROM messages m "
        "JOIN users u ON m.sender_id = u.id "
        "WHERE m.recipient_id = ? AND m.deleted_by_recipient = 0 "
        "ORDER BY m.created_at DESC",
        (user["id"],),
    )
    rows = ""
    for m in messages:
        unread_cls = ' style="font-weight:600"' if not m["read_at"] else ""
        rows += (
            f'<tr{unread_cls}>'
            f'<td>{html.escape(m["sender_name"])}</td>'
            f'<td><a href="/messages/{m["id"]}">{html.escape(m["subject"])}</a></td>'
            f'<td>{format_time(m["created_at"])}</td>'
            f'<td>{"✓" if m["read_at"] else "●"}</td></tr>'
        )
    body = (
        f'<h1>Inbox</h1>'
        f'<p style="margin-bottom:1rem">'
        f'<a href="/messages/compose" class="btn btn-primary">New Message</a> '
        f'<a href="/messages/sent" class="btn btn-secondary">Sent</a></p>'
        f'<table class="sortable"><thead><tr>'
        f'<th>From</th><th>Subject</th><th>Date</th><th>Status</th>'
        f'</tr></thead><tbody>'
        f'{rows or "<tr><td colspan=4>No messages.</td></tr>"}'
        f'</tbody></table>'
    )
    h._send_html(
        200,
        base_template("Inbox", body, user=user, flash=flash),
        cookies=h._clear_flash_cookie(),
    )


def handle_messages_sent(h: RequestHandler, **kw) -> None:
    user = h._get_user()
    if not user:
        h._redirect("/login", "Please log in.", "warning")
        return
    flash = h._get_flash()
    messages = db_fetchall(
        "SELECT m.*, u.username AS recipient_name FROM messages m "
        "JOIN users u ON m.recipient_id = u.id "
        "WHERE m.sender_id = ? AND m.deleted_by_sender = 0 "
        "ORDER BY m.created_at DESC",
        (user["id"],),
    )
    rows = ""
    for m in messages:
        rows += (
            f'<tr>'
            f'<td>{html.escape(m["recipient_name"])}</td>'
            f'<td><a href="/messages/{m["id"]}">{html.escape(m["subject"])}</a></td>'
            f'<td>{format_time(m["created_at"])}</td>'
            f'<td>{"Read" if m["read_at"] else "Unread"}</td></tr>'
        )
    body = (
        f'<h1>Sent Messages</h1>'
        f'<p style="margin-bottom:1rem">'
        f'<a href="/messages" class="btn btn-secondary">← Inbox</a> '
        f'<a href="/messages/compose" class="btn btn-primary">New Message</a></p>'
        f'<table class="sortable"><thead><tr>'
        f'<th>To</th><th>Subject</th><th>Date</th><th>Status</th>'
        f'</tr></thead><tbody>'
        f'{rows or "<tr><td colspan=4>No sent messages.</td></tr>"}'
        f'</tbody></table>'
    )
    h._send_html(
        200,
        base_template("Sent Messages", body, user=user, flash=flash),
        cookies=h._clear_flash_cookie(),
    )


def handle_messages_compose(h: RequestHandler, **kw) -> None:
    user = h._get_user()
    if not user:
        h._redirect("/login", "Please log in.", "warning")
        return
    flash = h._get_flash()
    raw_token = h._get_raw_token() or ""
    csrf = generate_csrf(raw_token)
    query = kw.get("query", {})
    prefill_to = html.escape(query.get("to", ""))
    prefill_subject = html.escape(query.get("subject", ""))
    users = db_fetchall(
        "SELECT username FROM users WHERE id != ? AND is_active = 1 ORDER BY username",
        (user["id"],),
    )
    user_opts = "".join(
        f'<option value="{html.escape(u["username"])}">'
        for u in users
    )
    body = (
        f'<h1>New Message</h1><div class="card">'
        f'<form method="POST" action="/messages/compose">'
        f'<input type="hidden" name="csrf_token" value="{csrf}">'
        f'<div class="form-group"><label>To</label>'
        f'<input type="text" name="to" list="user-list" value="{prefill_to}" required '
        f'placeholder="Username">'
        f'<datalist id="user-list">{user_opts}</datalist></div>'
        f'<div class="form-group"><label>Subject</label>'
        f'<input type="text" name="subject" value="{prefill_subject}" required '
        f'maxlength="200"></div>'
        f'<div class="form-group"><label>Message</label>'
        f'<textarea name="body" required rows="8" '
        f'style="min-height:150px"></textarea></div>'
        f'<button type="submit" class="btn btn-primary">Send</button> '
        f'<a href="/messages" class="btn btn-secondary">Cancel</a>'
        f'</form></div>'
    )
    h._send_html(
        200,
        base_template("New Message", body, user=user, flash=flash),
        cookies=h._clear_flash_cookie(),
    )


def handle_messages_send(h: RequestHandler, **kw) -> None:
    user = h._get_user()
    if not user:
        h._redirect("/login", "Please log in.", "warning")
        return
    body = h._read_body()
    form = parse_form_body(body)
    raw_token = h._get_raw_token() or ""
    if not verify_csrf(raw_token, form.get("csrf_token", "")):
        h._redirect("/messages/compose", "Invalid request.", "error")
        return
    to_username = form.get("to", "").strip()
    subject = form.get("subject", "").strip()
    msg_body = form.get("body", "").strip()
    if not to_username or not subject or not msg_body:
        h._redirect("/messages/compose", "All fields are required.", "error")
        return
    if len(subject) > 200:
        subject = subject[:200]
    recipient = db_fetchone(
        "SELECT id FROM users WHERE username = ? AND is_active = 1",
        (to_username,),
    )
    if not recipient:
        h._redirect("/messages/compose", f"User '{to_username}' not found.", "error")
        return
    if recipient["id"] == user["id"]:
        h._redirect("/messages/compose", "You cannot message yourself.", "error")
        return
    now = _utcnow().isoformat()
    db_execute(
        "INSERT INTO messages (sender_id, recipient_id, subject, body, created_at)"
        " VALUES (?, ?, ?, ?, ?)",
        (user["id"], recipient["id"], subject, msg_body, now),
    )
    h._redirect("/messages/sent", "Message sent!")


def handle_messages_read(h: RequestHandler, **kw) -> None:
    user = h._get_user()
    if not user:
        h._redirect("/login", "Please log in.", "warning")
        return
    mid = int(kw["match"].group(1))
    msg = db_fetchone(
        "SELECT m.*, "
        "s.username AS sender_name, r.username AS recipient_name "
        "FROM messages m "
        "JOIN users s ON m.sender_id = s.id "
        "JOIN users r ON m.recipient_id = r.id "
        "WHERE m.id = ?",
        (mid,),
    )
    if not msg:
        h._redirect("/messages", "Message not found.", "error")
        return
    is_sender = msg["sender_id"] == user["id"]
    is_recipient = msg["recipient_id"] == user["id"]
    if not is_sender and not is_recipient and not has_role(user, "admin"):
        h._redirect("/messages", "Access denied.", "error")
        return
    if (is_sender and msg["deleted_by_sender"]) or (is_recipient and msg["deleted_by_recipient"]):
        h._redirect("/messages", "Message not found.", "error")
        return
    # Mark as read
    if is_recipient and not msg["read_at"]:
        now = _utcnow().isoformat()
        db_execute("UPDATE messages SET read_at = ? WHERE id = ?", (now, mid))
    raw_token = h._get_raw_token() or ""
    csrf = generate_csrf(raw_token)
    flash = h._get_flash()
    direction = "from" if is_recipient else "to"
    other = msg["sender_name"] if is_recipient else msg["recipient_name"]
    reply_link = ""
    if is_recipient:
        re_subject = msg["subject"] if msg["subject"].startswith("Re: ") else f'Re: {msg["subject"]}'
        reply_link = (
            f'<a href="/messages/compose?to={html.escape(msg["sender_name"])}'
            f'&subject={html.escape(re_subject)}" class="btn btn-primary">Reply</a> '
        )
    body = (
        f'<h1>{html.escape(msg["subject"])}</h1>'
        f'<div class="card">'
        f'<p><strong>{direction.title()}:</strong> {html.escape(other)} · '
        f'{format_time(msg["created_at"])}</p>'
        f'<hr style="border:0;border-top:1px solid var(--border);margin:1rem 0">'
        f'<div style="white-space:pre-wrap">{html.escape(msg["body"])}</div></div>'
        f'<div style="margin-top:1rem">'
        f'{reply_link}'
        f'<a href="/messages" class="btn btn-secondary">← Back</a> '
        f'<form method="POST" action="/messages/{mid}/delete" style="display:inline">'
        f'<input type="hidden" name="csrf_token" value="{csrf}">'
        f'<button type="submit" class="btn btn-danger" '
        f'data-confirm="Delete this message?">Delete</button></form></div>'
    )
    h._send_html(
        200,
        base_template(msg["subject"], body, user=user, flash=flash),
        cookies=h._clear_flash_cookie(),
    )


def handle_messages_delete(h: RequestHandler, **kw) -> None:
    user = h._get_user()
    if not user:
        h._redirect("/login", "Please log in.", "warning")
        return
    mid = int(kw["match"].group(1))
    body = h._read_body()
    form = parse_form_body(body)
    raw_token = h._get_raw_token() or ""
    if not verify_csrf(raw_token, form.get("csrf_token", "")):
        h._redirect("/messages", "Invalid request.", "error")
        return
    msg = db_fetchone("SELECT * FROM messages WHERE id = ?", (mid,))
    if not msg:
        h._redirect("/messages", "Message not found.", "error")
        return
    if msg["sender_id"] == user["id"]:
        db_execute("UPDATE messages SET deleted_by_sender = 1 WHERE id = ?", (mid,))
    elif msg["recipient_id"] == user["id"]:
        db_execute("UPDATE messages SET deleted_by_recipient = 1 WHERE id = ?", (mid,))
    else:
        h._redirect("/messages", "Access denied.", "error")
        return
    updated = db_fetchone("SELECT * FROM messages WHERE id = ?", (mid,))
    if updated and updated["deleted_by_sender"] and updated["deleted_by_recipient"]:
        db_execute("DELETE FROM messages WHERE id = ?", (mid,))
    h._redirect("/messages", "Message deleted.")


# ── SECTION 12: Admin Handlers ──────────────────────────────

def _require_admin(h: RequestHandler) -> dict | None:
    user = h._get_user()
    if not user or not has_role(user, "mod"):
        h._redirect("/login", "Admin access required.", "error")
        return None
    return user


def handle_admin_dashboard(h: RequestHandler, **kw) -> None:
    user = _require_admin(h)
    if not user:
        return
    flash = h._get_flash()
    stats = {
        "users": db_fetchone("SELECT COUNT(*) as c FROM users")["c"],
        "files": db_fetchone("SELECT COUNT(*) as c FROM files")["c"],
        "articles": db_fetchone("SELECT COUNT(*) as c FROM articles")["c"],
        "comments": db_fetchone("SELECT COUNT(*) as c FROM comments")["c"],
    }
    recent_uploads = db_fetchall(
        "SELECT f.filename, f.uploaded_at, u.username FROM files f "
        "LEFT JOIN users u ON f.owner_id = u.id "
        "ORDER BY f.uploaded_at DESC LIMIT 10"
    )
    recent_comments = db_fetchall(
        "SELECT c.body, c.created_at, c.author_name, u.username FROM comments c "
        "LEFT JOIN users u ON c.author_id = u.id "
        "ORDER BY c.created_at DESC LIMIT 10"
    )
    recent_logins = db_fetchall(
        "SELECT username, last_login FROM users WHERE last_login IS NOT NULL "
        "ORDER BY last_login DESC LIMIT 5"
    )
    upload_rows = "".join(
        f'<tr><td>{html.escape(u["filename"])}</td>'
        f'<td>{html.escape(u.get("username") or "—")}</td>'
        f'<td>{format_time(u["uploaded_at"])}</td></tr>'
        for u in recent_uploads
    )
    comment_rows = "".join(
        f'<tr><td>{html.escape((c.get("username") or c.get("author_name") or "Anon"))}</td>'
        f'<td>{html.escape(c["body"][:80])}</td>'
        f'<td>{format_time(c["created_at"])}</td></tr>'
        for c in recent_comments
    )
    login_rows = "".join(
        f'<tr><td>{html.escape(l["username"])}</td>'
        f'<td>{format_time(l["last_login"])}</td></tr>'
        for l in recent_logins
    )
    body = (
        f'<h1>Admin Dashboard</h1>'
        f'<div class="stats-grid">'
        f'<div class="stat-card"><div class="number">{stats["users"]}</div>'
        f'<div class="label">Users</div></div>'
        f'<div class="stat-card"><div class="number">{stats["files"]}</div>'
        f'<div class="label">Files</div></div>'
        f'<div class="stat-card"><div class="number">{stats["articles"]}</div>'
        f'<div class="label">Articles</div></div>'
        f'<div class="stat-card"><div class="number">{stats["comments"]}</div>'
        f'<div class="label">Comments</div></div></div>'
        f'<div class="card"><h2>Recent Uploads</h2>'
        f'<table><thead><tr><th>File</th><th>User</th><th>Date</th></tr></thead>'
        f'<tbody>{upload_rows or "<tr><td colspan=3>None</td></tr>"}</tbody></table></div>'
        f'<div class="card"><h2>Recent Comments</h2>'
        f'<table><thead><tr><th>Author</th><th>Comment</th><th>Date</th></tr></thead>'
        f'<tbody>{comment_rows or "<tr><td colspan=3>None</td></tr>"}</tbody></table></div>'
        f'<div class="card"><h2>Recent Logins</h2>'
        f'<table><thead><tr><th>User</th><th>Last Login</th></tr></thead>'
        f'<tbody>{login_rows or "<tr><td colspan=2>None</td></tr>"}</tbody></table></div>'
    )
    h._send_html(
        200,
        base_template(
            "Admin", body, user=user, flash=flash,
            sidebar=_admin_sidebar("dashboard"),
        ),
        cookies=h._clear_flash_cookie(),
    )


def handle_admin_users(h: RequestHandler, **kw) -> None:
    user = h._get_user()
    if not user or not has_role(user, "admin"):
        h._redirect("/login", "Access denied.", "error")
        return
    flash = h._get_flash()
    users = db_fetchall("SELECT * FROM users ORDER BY id")
    rows = ""
    for u in users:
        actions = ""
        if u["role"] != "superadmin" or user["role"] == "superadmin":
            actions += (
                f'<a href="/admin/users/{u["id"]}/edit" class="btn btn-sm btn-secondary">Edit</a> '
            )
        if user["role"] == "superadmin" and u["id"] != user["id"]:
            actions += (
                f'<form method="POST" action="/admin/users/{u["id"]}/delete" style="display:inline">'
                f'<button type="submit" class="btn btn-sm btn-danger" '
                f'data-confirm="Delete user {html.escape(u["username"])}?">Delete</button></form>'
            )
        rows += (
            f'<tr><td>{u["id"]}</td><td>{html.escape(u["username"])}</td>'
            f'<td><span class="badge badge-info">{html.escape(u["role"])}</span></td>'
            f'<td>{html.escape(u.get("group_name") or "—")}</td>'
            f'<td>{"✓" if u["is_active"] else "✗"}</td>'
            f'<td>{format_time(u.get("last_login"))}</td>'
            f'<td>{actions}</td></tr>'
        )
    raw_token = h._get_raw_token() or ""
    csrf = generate_csrf(raw_token)
    create_form = (
        f'<div class="card"><h2>Create User</h2>'
        f'<form method="POST" action="/admin/users/create">'
        f'<input type="hidden" name="csrf_token" value="{csrf}">'
        f'<div class="form-row">'
        f'<div class="form-group"><label>Username</label>'
        f'<input type="text" name="username" required></div></div>'
        f'<div class="form-row">'
        f'<div class="form-group"><label>Password</label>'
        f'<input type="password" name="password" required></div>'
        f'<div class="form-group"><label>Role</label>'
        f'<select name="role"><option value="user">User</option>'
        f'<option value="mod">Mod</option>'
        f'<option value="admin">Admin</option></select></div></div>'
        f'<button type="submit" class="btn btn-primary">Create User</button></form></div>'
    )
    body = (
        f'<h1>User Management</h1>'
        f'<input type="search" class="table-search" data-target="#users-table" '
        f'placeholder="Search users…" style="margin-bottom:1rem">'
        f'<table class="sortable" id="users-table"><thead><tr>'
        f'<th>ID</th><th>Username</th><th>Role</th>'
        f'<th>Group</th><th>Active</th><th>Last Login</th><th>Actions</th>'
        f'</tr></thead><tbody>{rows}</tbody></table>'
        f'<div style="margin-top:1.5rem">{create_form}</div>'
    )
    h._send_html(
        200,
        base_template(
            "Users", body, user=user, flash=flash,
            sidebar=_admin_sidebar("users"),
        ),
        cookies=h._clear_flash_cookie(),
    )


def handle_admin_create_user(h: RequestHandler, **kw) -> None:
    user = h._get_user()
    if not user or not has_role(user, "admin"):
        h._redirect("/login", "Access denied.", "error")
        return
    body = h._read_body()
    form = parse_form_body(body)
    raw_token = h._get_raw_token() or ""
    if not verify_csrf(raw_token, form.get("csrf_token", "")):
        h._redirect("/admin/users", "Invalid request.", "error")
        return
    username = form.get("username", "").strip()
    password = form.get("password", "")
    role = form.get("role", "user")
    if role not in ("user", "mod", "admin"):
        role = "user"
    if user["role"] != "superadmin" and role == "admin":
        role = "mod"
    err = validate_username(username)
    if not err:
        err = validate_password(password)
    if not err:
        existing = db_fetchone(
            "SELECT id FROM users WHERE username = ?",
            (username,),
        )
        if existing:
            err = "Username already taken"
    if err:
        h._redirect("/admin/users", err, "error")
        return
    pw_hash, salt = hash_password(password)
    now = _utcnow().isoformat()
    db_execute(
        "INSERT INTO users (username, password_hash, salt, role, created_at)"
        " VALUES (?, ?, ?, ?, ?)",
        (username, pw_hash, salt, role, now),
    )
    h._redirect("/admin/users", f"User '{username}' created!")


def handle_admin_edit_user_form(h: RequestHandler, **kw) -> None:
    admin = h._get_user()
    if not admin or not has_role(admin, "admin"):
        h._redirect("/login", "Access denied.", "error")
        return
    uid = int(kw["match"].group(1))
    target = db_fetchone("SELECT * FROM users WHERE id = ?", (uid,))
    if not target:
        h._redirect("/admin/users", "User not found.", "error")
        return
    if target["role"] == "superadmin" and admin["role"] != "superadmin":
        h._redirect("/admin/users", "Cannot edit superadmin.", "error")
        return
    flash = h._get_flash()
    raw_token = h._get_raw_token() or ""
    csrf = generate_csrf(raw_token)
    groups = db_fetchall("SELECT * FROM groups ORDER BY name")
    group_opts = '<option value="">None</option>' + "".join(
        f'<option value="{html.escape(g["name"])}"'
        f'{" selected" if target.get("group_name") == g["name"] else ""}>'
        f'{html.escape(g["name"])}</option>'
        for g in groups
    )
    role_opts = ""
    for r in ["user", "mod", "admin"]:
        sel = " selected" if target["role"] == r else ""
        role_opts += f'<option value="{r}"{sel}>{r}</option>'
    if admin["role"] == "superadmin":
        sel = " selected" if target["role"] == "superadmin" else ""
        role_opts += f'<option value="superadmin"{sel}>superadmin</option>'
    active_chk = " checked" if target["is_active"] else ""
    body = (
        f'<h1>Edit User: {html.escape(target["username"])}</h1>'
        f'<div class="card">'
        f'<form method="POST" action="/admin/users/{uid}/edit">'
        f'<input type="hidden" name="csrf_token" value="{csrf}">'
        f'<div class="form-group"><label>Role</label>'
        f'<select name="role">{role_opts}</select></div>'
        f'<div class="form-group"><label>Group</label>'
        f'<select name="group_name">{group_opts}</select></div>'
        f'<div class="form-group"><label class="checkbox-label">'
        f'<input type="checkbox" name="is_active" value="1"{active_chk}> Active</label></div>'
        f'<button type="submit" class="btn btn-primary">Save</button></form></div>'
        f'<div class="card"><h2>Reset Password</h2>'
        f'<form method="POST" action="/admin/users/{uid}/change-password">'
        f'<input type="hidden" name="csrf_token" value="{csrf}">'
        f'<div class="form-group"><label>New Password</label>'
        f'<input type="password" name="new_password" required></div>'
        f'<div class="form-group"><label>Confirm Password</label>'
        f'<input type="password" name="confirm_password" required></div>'
        f'<div class="form-group"><label class="checkbox-label">'
        f'<input type="checkbox" name="notify_user" value="1" checked> '
        f'Notify user on next login</label></div>'
        f'<button type="submit" class="btn btn-danger">Reset Password</button></form></div>'
    )
    h._send_html(
        200,
        base_template(
            f"Edit {target['username']}", body, user=admin, flash=flash,
            sidebar=_admin_sidebar("users"),
        ),
        cookies=h._clear_flash_cookie(),
    )


def handle_admin_edit_user(h: RequestHandler, **kw) -> None:
    admin = h._get_user()
    if not admin or not has_role(admin, "admin"):
        h._redirect("/login", "Access denied.", "error")
        return
    uid = int(kw["match"].group(1))
    body_bytes = h._read_body()
    form = parse_form_body(body_bytes)
    raw_token = h._get_raw_token() or ""
    if not verify_csrf(raw_token, form.get("csrf_token", "")):
        h._redirect("/admin/users", "Invalid request.", "error")
        return
    target = db_fetchone("SELECT * FROM users WHERE id = ?", (uid,))
    if not target:
        h._redirect("/admin/users", "User not found.", "error")
        return
    if target["role"] == "superadmin" and admin["role"] != "superadmin":
        h._redirect("/admin/users", "Cannot edit superadmin.", "error")
        return
    role = form.get("role", target["role"])
    if role == "superadmin" and admin["role"] != "superadmin":
        role = target["role"]
    group_name = form.get("group_name", "") or None
    is_active = 1 if form.get("is_active") else 0
    db_execute(
        "UPDATE users SET role = ?, group_name = ?, is_active = ? WHERE id = ?",
        (role, group_name, is_active, uid),
    )
    h._redirect("/admin/users", f"User updated!")


def handle_admin_delete_user(h: RequestHandler, **kw) -> None:
    admin = h._get_user()
    if not admin or admin["role"] != "superadmin":
        h._redirect("/admin/users", "Only superadmin can delete users.", "error")
        return
    uid = int(kw["match"].group(1))
    h._read_body()
    if uid == admin["id"]:
        h._redirect("/admin/users", "Cannot delete yourself.", "error")
        return
    db_execute("DELETE FROM tokens WHERE user_id = ?", (uid,))
    db_execute("DELETE FROM group_members WHERE user_id = ?", (uid,))
    db_execute("DELETE FROM users WHERE id = ?", (uid,))
    h._redirect("/admin/users", "User deleted.")


def handle_admin_change_user_password(h: RequestHandler, **kw) -> None:
    admin = h._get_user()
    if not admin or not has_role(admin, "admin"):
        h._redirect("/login", "Access denied.", "error")
        return
    uid = int(kw["match"].group(1))
    if not check_admin_pw_reset_limit(admin["id"]):
        h._redirect(
            f"/admin/users/{uid}/edit",
            "Too many resets. Try again in an hour.", "error",
        )
        return
    body_bytes = h._read_body()
    form = parse_form_body(body_bytes)
    raw_token = h._get_raw_token() or ""
    if not verify_csrf(raw_token, form.get("csrf_token", "")):
        h._redirect(f"/admin/users/{uid}/edit", "Invalid request.", "error")
        return
    target = db_fetchone("SELECT * FROM users WHERE id = ?", (uid,))
    if not target:
        h._redirect("/admin/users", "User not found.", "error")
        return
    if target["role"] in ("admin", "superadmin") and admin["role"] != "superadmin":
        h._redirect("/admin/users", "Cannot reset this user's password.", "error")
        return
    new_pw = form.get("new_password", "")
    confirm = form.get("confirm_password", "")
    err = validate_password(new_pw)
    if err:
        h._redirect(f"/admin/users/{uid}/edit", err, "error")
        return
    if new_pw != confirm:
        h._redirect(f"/admin/users/{uid}/edit", "Passwords do not match.", "error")
        return
    pw_hash, salt = hash_password(new_pw)
    notify = 1 if form.get("notify_user") else 0
    db_execute(
        "UPDATE users SET password_hash = ?, salt = ?, pw_reset_notice = ? WHERE id = ?",
        (pw_hash, salt, notify, uid),
    )
    revoke_all_tokens(uid)
    _access_logger.info(
        "PASSWORD_CHANGE user_id=%s by=%s ip=%s", uid, admin["id"], h._get_ip()
    )
    h._redirect("/admin/users", f"Password reset for {target['username']}.")


def handle_admin_files(h: RequestHandler, **kw) -> None:
    user = h._get_user()
    if not user or not has_role(user, "admin"):
        h._redirect("/login", "Access denied.", "error")
        return
    flash = h._get_flash()
    files = db_fetchall(
        "SELECT f.*, u.username FROM files f "
        "LEFT JOIN users u ON f.owner_id = u.id ORDER BY f.uploaded_at DESC"
    )
    raw_token = h._get_raw_token() or ""
    csrf = generate_csrf(raw_token)
    rows = ""
    for f in files:
        rows += (
            f'<tr><td>{f["id"]}</td>'
            f'<td>{html.escape(f["filename"])}</td>'
            f'<td>{format_size(f["size_bytes"])}</td>'
            f'<td>{html.escape(f.get("username") or "—")}</td>'
            f'<td><span class="badge badge-info">{html.escape(f["visibility"])}</span></td>'
            f'<td>{format_time(f["uploaded_at"])}</td>'
            f'<td>'
            f'<form method="POST" action="/admin/files/{f["id"]}/acl" style="display:inline">'
            f'<input type="hidden" name="csrf_token" value="{csrf}">'
            f'<select name="visibility" style="width:auto;display:inline;padding:0.2rem">'
            f'{_visibility_options(f["visibility"])}'
            f'</select>'
            f'<button type="submit" class="btn btn-sm btn-secondary">Set</button></form> '
            f'<form method="POST" action="/admin/files/{f["id"]}/delete" style="display:inline">'
            f'<input type="hidden" name="csrf_token" value="{csrf}">'
            f'<button type="submit" class="btn btn-sm btn-danger" '
            f'data-confirm="Delete {html.escape(f["filename"])}?">Del</button></form>'
            f'</td></tr>'
        )
    body = (
        f'<h1>File Management</h1>'
        f'<input type="search" class="table-search" data-target="#files-table" '
        f'placeholder="Search files…" style="margin-bottom:1rem">'
        f'<table class="sortable" id="files-table"><thead><tr>'
        f'<th>ID</th><th>Name</th><th>Size</th><th>Owner</th>'
        f'<th>Visibility</th><th>Uploaded</th><th>Actions</th>'
        f'</tr></thead><tbody>{rows}</tbody></table>'
    )
    h._send_html(
        200,
        base_template(
            "Files", body, user=user, flash=flash,
            sidebar=_admin_sidebar("files"),
        ),
        cookies=h._clear_flash_cookie(),
    )


def handle_admin_delete_file(h: RequestHandler, **kw) -> None:
    user = h._get_user()
    if not user or not has_role(user, "admin"):
        h._redirect("/login", "Access denied.", "error")
        return
    fid = int(kw["match"].group(1))
    h._read_body()
    frow = db_fetchone("SELECT * FROM files WHERE id = ?", (fid,))
    if frow:
        for sub in ("public", "private"):
            fp = _data_dir / "files" / sub / frow["stored_name"]
            if fp.exists():
                fp.unlink()
        db_execute("DELETE FROM files WHERE id = ?", (fid,))
    h._redirect("/admin/files", "File deleted.")


def handle_admin_file_acl(h: RequestHandler, **kw) -> None:
    user = h._get_user()
    if not user or not has_role(user, "admin"):
        h._redirect("/login", "Access denied.", "error")
        return
    fid = int(kw["match"].group(1))
    body = h._read_body()
    form = parse_form_body(body)
    raw_token = h._get_raw_token() or ""
    if not verify_csrf(raw_token, form.get("csrf_token", "")):
        h._redirect("/admin/files", "Invalid request.", "error")
        return
    vis = form.get("visibility", "public")
    frow = db_fetchone("SELECT * FROM files WHERE id = ?", (fid,))
    if frow:
        old_sub = "public" if frow["visibility"] == "public" else "private"
        new_sub = "public" if vis == "public" else "private"
        if old_sub != new_sub:
            src = _data_dir / "files" / old_sub / frow["stored_name"]
            dst = _data_dir / "files" / new_sub / frow["stored_name"]
            if src.exists():
                shutil.move(str(src), str(dst))
        db_execute("UPDATE files SET visibility = ? WHERE id = ?", (vis, fid))
    h._redirect("/admin/files", "Visibility updated.")


def handle_admin_articles(h: RequestHandler, **kw) -> None:
    user = h._get_user()
    if not user or not has_role(user, "mod"):
        h._redirect("/login", "Access denied.", "error")
        return
    flash = h._get_flash()
    articles = db_fetchall(
        "SELECT a.*, u.username FROM articles a "
        "JOIN users u ON a.author_id = u.id ORDER BY a.created_at DESC"
    )
    rows = ""
    for a in articles:
        pub = '<span class="badge badge-success">Yes</span>' if a["published"] else '<span class="badge badge-error">No</span>'
        rows += (
            f'<tr><td>{a["id"]}</td><td>{html.escape(a["title"])}</td>'
            f'<td>{html.escape(a["username"])}</td>'
            f'<td><span class="badge badge-info">{html.escape(a["visibility"])}</span></td>'
            f'<td>{pub}</td><td>{format_time(a["created_at"])}</td>'
            f'<td><a href="/admin/articles/{a["id"]}/edit" class="btn btn-sm btn-secondary">Edit</a> '
            f'<form method="POST" action="/admin/articles/{a["id"]}/delete" style="display:inline">'
            f'<button type="submit" class="btn btn-sm btn-danger" '
            f'data-confirm="Delete article?">Del</button></form></td></tr>'
        )
    body = (
        f'<h1>Articles</h1>'
        f'<p><a href="/admin/articles/create" class="btn btn-primary">New Article</a></p>'
        f'<table class="sortable" style="margin-top:1rem"><thead><tr>'
        f'<th>ID</th><th>Title</th><th>Author</th><th>Visibility</th>'
        f'<th>Published</th><th>Created</th><th>Actions</th></tr></thead>'
        f'<tbody>{rows}</tbody></table>'
    )
    h._send_html(
        200,
        base_template(
            "Articles", body, user=user, flash=flash,
            sidebar=_admin_sidebar("articles"),
        ),
        cookies=h._clear_flash_cookie(),
    )


def handle_admin_create_article_form(h: RequestHandler, **kw) -> None:
    user = h._get_user()
    if not user or not has_role(user, "mod"):
        h._redirect("/login", "Access denied.", "error")
        return
    flash = h._get_flash()
    raw_token = h._get_raw_token() or ""
    csrf = generate_csrf(raw_token)
    cfg = get_config()
    body = (
        f'<h1>New Article</h1><div class="card">'
        f'<form method="POST" action="/admin/articles/create">'
        f'<input type="hidden" name="csrf_token" value="{csrf}">'
        f'<div class="form-group"><label>Title</label>'
        f'<input type="text" name="title" required></div>'
        f'<div class="form-group"><label>Slug (URL path)</label>'
        f'<input type="text" name="slug" required placeholder="my-article-title"></div>'
        f'<div class="form-row"><div class="form-group"><label>Visibility</label>'
        f'<select name="visibility">{_visibility_options()}</select></div>'
        f'<div class="form-group"><label>Published</label>'
        f'<select name="published"><option value="1">Yes</option>'
        f'<option value="0">Draft</option></select></div></div>'
        f'<div class="form-group"><label>Body (Markdown)</label>'
        f'<div class="editor-wrap">'
        f'<textarea id="md-input" name="body" required></textarea>'
        f'<div class="preview-pane" id="md-preview"><p style="color:var(--text2)">'
        f'Preview will appear here…</p></div></div></div>'
        f'<button type="submit" class="btn btn-primary">Create Article</button></form></div>'
    )
    h._send_html(
        200,
        base_template(
            "New Article", body, user=user, flash=flash,
            sidebar=_admin_sidebar("articles"),
        ),
        cookies=h._clear_flash_cookie(),
    )


def handle_admin_create_article(h: RequestHandler, **kw) -> None:
    user = h._get_user()
    if not user or not has_role(user, "mod"):
        h._redirect("/login", "Access denied.", "error")
        return
    body_bytes = h._read_body()
    form = parse_form_body(body_bytes)
    raw_token = h._get_raw_token() or ""
    if not verify_csrf(raw_token, form.get("csrf_token", "")):
        h._redirect("/admin/articles", "Invalid request.", "error")
        return
    title = form.get("title", "").strip()
    slug = form.get("slug", "").strip().lower()
    slug = re.sub(r'[^a-z0-9-]', '-', slug).strip('-')
    body_text = form.get("body", "").strip()
    visibility = form.get("visibility", "public")
    published = int(form.get("published", 1))
    if not title or not slug or not body_text:
        h._redirect("/admin/articles/create", "All fields required.", "error")
        return
    existing = db_fetchone("SELECT id FROM articles WHERE slug = ?", (slug,))
    if existing:
        h._redirect("/admin/articles/create", "Slug already exists.", "error")
        return
    now = _utcnow().isoformat()
    db_execute(
        "INSERT INTO articles (title, slug, body, author_id, visibility, "
        "created_at, updated_at, published) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        (title, slug, body_text, user["id"], visibility, now, now, published),
    )
    h._redirect("/admin/articles", f"Article '{title}' created!")


def handle_admin_edit_article_form(h: RequestHandler, **kw) -> None:
    user = h._get_user()
    if not user or not has_role(user, "mod"):
        h._redirect("/login", "Access denied.", "error")
        return
    aid = int(kw["match"].group(1))
    article = db_fetchone("SELECT * FROM articles WHERE id = ?", (aid,))
    if not article:
        h._redirect("/admin/articles", "Article not found.", "error")
        return
    if not has_role(user, "mod") and article["author_id"] != user["id"]:
        h._redirect("/admin/articles", "Access denied.", "error")
        return
    flash = h._get_flash()
    raw_token = h._get_raw_token() or ""
    csrf = generate_csrf(raw_token)
    vis_opts = _visibility_options(article["visibility"])
    pub_opts = ""
    for val, lab in [("1", "Yes"), ("0", "Draft")]:
        sel = " selected" if str(article["published"]) == val else ""
        pub_opts += f'<option value="{val}"{sel}>{lab}</option>'
    body = (
        f'<h1>Edit: {html.escape(article["title"])}</h1><div class="card">'
        f'<form method="POST" action="/admin/articles/{aid}/edit">'
        f'<input type="hidden" name="csrf_token" value="{csrf}">'
        f'<div class="form-group"><label>Title</label>'
        f'<input type="text" name="title" value="{html.escape(article["title"])}" required></div>'
        f'<div class="form-row"><div class="form-group"><label>Visibility</label>'
        f'<select name="visibility">{vis_opts}</select></div>'
        f'<div class="form-group"><label>Published</label>'
        f'<select name="published">{pub_opts}</select></div></div>'
        f'<div class="form-group"><label>Body (Markdown)</label>'
        f'<div class="editor-wrap">'
        f'<textarea id="md-input" name="body" required>{html.escape(article["body"])}</textarea>'
        f'<div class="preview-pane" id="md-preview"></div></div></div>'
        f'<button type="submit" class="btn btn-primary">Save</button></form></div>'
    )
    h._send_html(
        200,
        base_template(
            f"Edit Article", body, user=user, flash=flash,
            sidebar=_admin_sidebar("articles"),
        ),
        cookies=h._clear_flash_cookie(),
    )


def handle_admin_edit_article(h: RequestHandler, **kw) -> None:
    user = h._get_user()
    if not user or not has_role(user, "mod"):
        h._redirect("/login", "Access denied.", "error")
        return
    aid = int(kw["match"].group(1))
    body_bytes = h._read_body()
    form = parse_form_body(body_bytes)
    raw_token = h._get_raw_token() or ""
    if not verify_csrf(raw_token, form.get("csrf_token", "")):
        h._redirect("/admin/articles", "Invalid request.", "error")
        return
    article = db_fetchone("SELECT * FROM articles WHERE id = ?", (aid,))
    if not article:
        h._redirect("/admin/articles", "Not found.", "error")
        return
    title = form.get("title", article["title"]).strip()
    body_text = form.get("body", article["body"]).strip()
    visibility = form.get("visibility", article["visibility"])
    published = int(form.get("published", article["published"]))
    now = _utcnow().isoformat()
    db_execute(
        "UPDATE articles SET title=?, body=?, visibility=?, published=?, "
        "updated_at=? WHERE id=?",
        (title, body_text, visibility, published, now, aid),
    )
    h._redirect("/admin/articles", "Article updated!")


def handle_admin_delete_article(h: RequestHandler, **kw) -> None:
    user = h._get_user()
    if not user or not has_role(user, "mod"):
        h._redirect("/login", "Access denied.", "error")
        return
    aid = int(kw["match"].group(1))
    h._read_body()
    db_execute("DELETE FROM comments WHERE article_id = ?", (aid,))
    db_execute("DELETE FROM articles WHERE id = ?", (aid,))
    h._redirect("/admin/articles", "Article deleted.")


def handle_admin_groups(h: RequestHandler, **kw) -> None:
    user = h._get_user()
    if not user or not has_role(user, "admin"):
        h._redirect("/login", "Access denied.", "error")
        return
    flash = h._get_flash()
    groups = db_fetchall(
        "SELECT g.*, u.username as creator, "
        "(SELECT COUNT(*) FROM group_members gm WHERE gm.group_id = g.id) as member_count "
        "FROM groups g LEFT JOIN users u ON g.created_by = u.id ORDER BY g.name"
    )
    raw_token = h._get_raw_token() or ""
    csrf = generate_csrf(raw_token)
    rows = ""
    for g in groups:
        members = db_fetchall(
            "SELECT u.username, u.id FROM group_members gm "
            "JOIN users u ON gm.user_id = u.id WHERE gm.group_id = ?",
            (g["id"],),
        )
        member_list = ", ".join(html.escape(m["username"]) for m in members) or "—"
        rows += (
            f'<tr><td>{g["id"]}</td><td>{html.escape(g["name"])}</td>'
            f'<td>{html.escape(g.get("description") or "—")}</td>'
            f'<td>{g["member_count"]}</td><td style="font-size:0.85rem">{member_list}</td>'
            f'<td>'
            f'<a href="/admin/groups/{g["id"]}/members" class="btn btn-sm btn-secondary">Members</a>'
            f'</td></tr>'
        )
    body = (
        f'<h1>Groups</h1>'
        f'<div class="card"><h2>Create Group</h2>'
        f'<form method="POST" action="/admin/groups/create">'
        f'<input type="hidden" name="csrf_token" value="{csrf}">'
        f'<div class="form-row">'
        f'<div class="form-group"><label>Name</label>'
        f'<input type="text" name="name" required></div>'
        f'<div class="form-group"><label>Description</label>'
        f'<input type="text" name="description"></div></div>'
        f'<button type="submit" class="btn btn-primary">Create</button></form></div>'
        f'<table class="sortable" style="margin-top:1rem"><thead><tr>'
        f'<th>ID</th><th>Name</th><th>Description</th><th>Members</th>'
        f'<th>Member List</th><th>Actions</th></tr></thead>'
        f'<tbody>{rows}</tbody></table>'
    )
    h._send_html(
        200,
        base_template(
            "Groups", body, user=user, flash=flash,
            sidebar=_admin_sidebar("groups"),
        ),
        cookies=h._clear_flash_cookie(),
    )


def handle_admin_create_group(h: RequestHandler, **kw) -> None:
    user = h._get_user()
    if not user or not has_role(user, "admin"):
        h._redirect("/login", "Access denied.", "error")
        return
    body = h._read_body()
    form = parse_form_body(body)
    raw_token = h._get_raw_token() or ""
    if not verify_csrf(raw_token, form.get("csrf_token", "")):
        h._redirect("/admin/groups", "Invalid request.", "error")
        return
    name = form.get("name", "").strip()
    desc = form.get("description", "").strip()
    if not name:
        h._redirect("/admin/groups", "Name required.", "error")
        return
    existing = db_fetchone("SELECT id FROM groups WHERE name = ?", (name,))
    if existing:
        h._redirect("/admin/groups", "Group already exists.", "error")
        return
    now = _utcnow().isoformat()
    db_execute(
        "INSERT INTO groups (name, description, created_by, created_at) "
        "VALUES (?, ?, ?, ?)",
        (name, desc, user["id"], now),
    )
    h._redirect("/admin/groups", f"Group '{name}' created!")


def handle_admin_group_members_form(h: RequestHandler, **kw) -> None:
    user = h._get_user()
    if not user or not has_role(user, "admin"):
        h._redirect("/login", "Access denied.", "error")
        return
    gid = int(kw["match"].group(1))
    group = db_fetchone("SELECT * FROM groups WHERE id = ?", (gid,))
    if not group:
        h._redirect("/admin/groups", "Group not found.", "error")
        return
    flash = h._get_flash()
    raw_token = h._get_raw_token() or ""
    csrf = generate_csrf(raw_token)
    members = db_fetchall(
        "SELECT u.id, u.username FROM group_members gm "
        "JOIN users u ON gm.user_id = u.id WHERE gm.group_id = ?",
        (gid,),
    )
    all_users = db_fetchall("SELECT id, username FROM users ORDER BY username")
    member_ids = {m["id"] for m in members}
    member_html = ""
    for m in members:
        member_html += (
            f'<div style="display:flex;align-items:center;gap:0.5rem;margin-bottom:0.3rem">'
            f'<span>{html.escape(m["username"])}</span>'
            f'<form method="POST" action="/admin/groups/{gid}/members" style="display:inline">'
            f'<input type="hidden" name="csrf_token" value="{csrf}">'
            f'<input type="hidden" name="action" value="remove">'
            f'<input type="hidden" name="user_id" value="{m["id"]}">'
            f'<button type="submit" class="btn btn-sm btn-danger">Remove</button></form></div>'
        )
    user_opts = "".join(
        f'<option value="{u["id"]}">{html.escape(u["username"])}</option>'
        for u in all_users if u["id"] not in member_ids
    )
    body = (
        f'<h1>Group: {html.escape(group["name"])}</h1>'
        f'<div class="card"><h2>Current Members</h2>'
        f'{member_html or "<p>No members.</p>"}</div>'
        f'<div class="card"><h2>Add Member</h2>'
        f'<form method="POST" action="/admin/groups/{gid}/members">'
        f'<input type="hidden" name="csrf_token" value="{csrf}">'
        f'<input type="hidden" name="action" value="add">'
        f'<div class="form-group"><label>User</label>'
        f'<select name="user_id">{user_opts}</select></div>'
        f'<button type="submit" class="btn btn-primary">Add</button></form></div>'
    )
    h._send_html(
        200,
        base_template(
            f"Group Members", body, user=user, flash=flash,
            sidebar=_admin_sidebar("groups"),
        ),
        cookies=h._clear_flash_cookie(),
    )


def handle_admin_group_members(h: RequestHandler, **kw) -> None:
    user = h._get_user()
    if not user or not has_role(user, "admin"):
        h._redirect("/login", "Access denied.", "error")
        return
    gid = int(kw["match"].group(1))
    body = h._read_body()
    form = parse_form_body(body)
    raw_token = h._get_raw_token() or ""
    if not verify_csrf(raw_token, form.get("csrf_token", "")):
        h._redirect(f"/admin/groups/{gid}/members", "Invalid request.", "error")
        return
    action = form.get("action", "")
    uid = int(form.get("user_id", 0))
    if action == "add" and uid:
        try:
            db_execute(
                "INSERT INTO group_members (group_id, user_id) VALUES (?, ?)",
                (gid, uid),
            )
        except sqlite3.IntegrityError:
            pass
        h._redirect(f"/admin/groups/{gid}/members", "Member added.")
    elif action == "remove" and uid:
        db_execute(
            "DELETE FROM group_members WHERE group_id = ? AND user_id = ?",
            (gid, uid),
        )
        h._redirect(f"/admin/groups/{gid}/members", "Member removed.")
    else:
        h._redirect(f"/admin/groups/{gid}/members", "Invalid action.", "error")


def handle_admin_config_form(h: RequestHandler, **kw) -> None:
    user = h._get_user()
    if not user or user["role"] != "superadmin":
        h._redirect("/login", "Superadmin access required.", "error")
        return
    flash = h._get_flash()
    cfg = get_config()
    raw_token = h._get_raw_token() or ""
    csrf = generate_csrf(raw_token)
    reg_chk = " checked" if cfg.get("registration_open") else ""
    exts = ", ".join(cfg.get("allowed_file_extensions", []))
    body = (
        f'<h1>Configuration</h1><div class="card">'
        f'<form method="POST" action="/admin/config">'
        f'<input type="hidden" name="csrf_token" value="{csrf}">'
        f'<div class="form-row">'
        f'<div class="form-group"><label>Site Name</label>'
        f'<input type="text" name="site_name" value="{html.escape(cfg.get("site_name", ""))}"></div>'
        f'<div class="form-group"><label>Host</label>'
        f'<input type="text" name="host" value="{html.escape(cfg.get("host", "0.0.0.0"))}"></div></div>'
        f'<div class="form-row">'
        f'<div class="form-group"><label>HTTP Port</label>'
        f'<input type="number" name="http_port" value="{cfg.get("http_port", 8080)}"></div>'
        f'<div class="form-group"><label>HTTPS Port</label>'
        f'<input type="number" name="https_port" value="{cfg.get("https_port", 8443)}"></div></div>'
        f'<div class="form-row">'
        f'<div class="form-group"><label>Max File Size (MB)</label>'
        f'<input type="number" name="max_file_size_mb" value="{cfg.get("max_file_size_mb", 100)}"></div>'
        f'<div class="form-group"><label>Token Expiry (seconds)</label>'
        f'<input type="number" name="token_expiry_seconds" value="{cfg.get("token_expiry_seconds", 86400)}"></div></div>'
        f'<div class="form-row">'
        f'<div class="form-group"><label>Rate Limit (requests)</label>'
        f'<input type="number" name="rate_limit_requests" value="{cfg.get("rate_limit_requests", 60)}"></div>'
        f'<div class="form-group"><label>Rate Limit Window (seconds)</label>'
        f'<input type="number" name="rate_limit_window_seconds" value="{cfg.get("rate_limit_window_seconds", 60)}"></div></div>'
        f'<div class="form-group"><label>Allowed File Extensions (comma-separated, empty = all)</label>'
        f'<input type="text" name="allowed_file_extensions" value="{html.escape(exts)}" '
        f'placeholder="jpg, png, pdf"></div>'
        f'<div class="form-group"><label>Default Article Visibility</label>'
        f'<select name="default_article_visibility">'
        f'{_visibility_options(cfg.get("default_article_visibility", "public"))}'
        f'</select></div>'
        f'<div class="form-group"><label class="checkbox-label">'
        f'<input type="checkbox" name="registration_open" value="1"{reg_chk}> '
        f'Registration Open</label></div>'
        f'<button type="submit" class="btn btn-primary">Save Configuration</button></form></div>'
    )
    h._send_html(
        200,
        base_template(
            "Configuration", body, user=user, flash=flash,
            sidebar=_admin_sidebar("config"),
        ),
        cookies=h._clear_flash_cookie(),
    )


def handle_admin_config(h: RequestHandler, **kw) -> None:
    user = h._get_user()
    if not user or user["role"] != "superadmin":
        h._redirect("/login", "Superadmin access required.", "error")
        return
    body = h._read_body()
    form = parse_form_body(body)
    raw_token = h._get_raw_token() or ""
    if not verify_csrf(raw_token, form.get("csrf_token", "")):
        h._redirect("/admin/config", "Invalid request.", "error")
        return
    exts_raw = form.get("allowed_file_extensions", "").strip()
    exts = [e.strip().lower() for e in exts_raw.split(",") if e.strip()] if exts_raw else []
    new_cfg = {
        "site_name": form.get("site_name", "offline").strip(),
        "host": form.get("host", "0.0.0.0").strip(),
        "http_port": int(form.get("http_port", 8080)),
        "https_port": int(form.get("https_port", 8443)),
        "max_file_size_mb": int(form.get("max_file_size_mb", 100)),
        "token_expiry_seconds": int(form.get("token_expiry_seconds", 86400)),
        "rate_limit_requests": int(form.get("rate_limit_requests", 60)),
        "rate_limit_window_seconds": int(form.get("rate_limit_window_seconds", 60)),
        "allowed_file_extensions": exts,
        "default_article_visibility": form.get("default_article_visibility", "public"),
        "registration_open": bool(form.get("registration_open")),
    }
    set_config(new_cfg)
    h._redirect("/admin/config", "Configuration saved!")


def handle_admin_comments(h: RequestHandler, **kw) -> None:
    user = h._get_user()
    if not user or not has_role(user, "mod"):
        h._redirect("/login", "Access denied.", "error")
        return
    flash = h._get_flash()
    comments = db_fetchall(
        "SELECT c.*, a.title as article_title, a.slug, u.username "
        "FROM comments c JOIN articles a ON c.article_id = a.id "
        "LEFT JOIN users u ON c.author_id = u.id "
        "ORDER BY c.approved ASC, c.created_at DESC"
    )
    raw_token = h._get_raw_token() or ""
    csrf = generate_csrf(raw_token)
    rows = ""
    for c in comments:
        name = html.escape(c.get("username") or c.get("author_name") or "Anonymous")
        status = ('<span class="badge badge-success">Approved</span>'
                  if c["approved"] else '<span class="badge badge-warning">Pending</span>')
        approve_btn = ""
        if not c["approved"]:
            approve_btn = (
                f'<form method="POST" action="/admin/comments/{c["id"]}/approve" style="display:inline">'
                f'<input type="hidden" name="csrf_token" value="{csrf}">'
                f'<button class="btn btn-sm btn-primary">Approve</button></form> '
            )
        rows += (
            f'<tr><td>{name}</td>'
            f'<td><a href="/blog/{html.escape(c["slug"])}">'
            f'{html.escape(c["article_title"][:40])}</a></td>'
            f'<td>{html.escape(c["body"][:80])}</td>'
            f'<td>{status}</td>'
            f'<td>{format_time(c["created_at"])}</td>'
            f'<td>{approve_btn}'
            f'<form method="POST" action="/admin/comments/{c["id"]}/delete" style="display:inline">'
            f'<input type="hidden" name="csrf_token" value="{csrf}">'
            f'<button class="btn btn-sm btn-danger" '
            f'data-confirm="Delete this comment?">Del</button></form></td></tr>'
        )
    body = (
        f'<h1>Comments</h1>'
        f'<table class="sortable"><thead><tr>'
        f'<th>Author</th><th>Article</th><th>Comment</th>'
        f'<th>Status</th><th>Date</th><th>Actions</th></tr></thead>'
        f'<tbody>{rows or "<tr><td colspan=6>No comments.</td></tr>"}</tbody></table>'
    )
    h._send_html(
        200,
        base_template(
            "Comments", body, user=user, flash=flash,
            sidebar=_admin_sidebar("comments"),
        ),
        cookies=h._clear_flash_cookie(),
    )


def handle_admin_approve_comment(h: RequestHandler, **kw) -> None:
    user = h._get_user()
    if not user or not has_role(user, "mod"):
        h._redirect("/login", "Access denied.", "error")
        return
    cid = int(kw["match"].group(1))
    h._read_body()
    db_execute("UPDATE comments SET approved = 1 WHERE id = ?", (cid,))
    h._redirect("/admin/comments", "Comment approved.")


def handle_admin_delete_comment(h: RequestHandler, **kw) -> None:
    user = h._get_user()
    if not user or not has_role(user, "mod"):
        h._redirect("/login", "Access denied.", "error")
        return
    cid = int(kw["match"].group(1))
    h._read_body()
    db_execute("DELETE FROM comments WHERE id = ?", (cid,))
    h._redirect("/admin/comments", "Comment deleted.")


# ── SECTION 13: TLS & Server Bootstrap ──────────────────────

def generate_tls_cert(data_dir: pathlib.Path) -> None:
    cert = data_dir / "certs" / "cert.pem"
    key = data_dir / "certs" / "key.pem"
    if cert.exists() and key.exists():
        return
    print("[*] Generating self-signed TLS certificate…")
    try:
        subprocess.run(
            [
                "openssl", "req", "-x509", "-newkey", "rsa:4096",
                "-keyout", str(key), "-out", str(cert),
                "-days", "3650", "-nodes",
                "-subj", "/CN=localhost",
            ],
            check=True, capture_output=True,
        )
        print("[✓] Certificate created.")
    except FileNotFoundError:
        print(
            "[✗] ERROR: 'openssl' not found. Install OpenSSL and try again.",
            file=sys.stderr,
        )
        sys.exit(1)
    except subprocess.CalledProcessError as e:
        print(f"[✗] Certificate generation failed: {e.stderr.decode()}", file=sys.stderr)
        sys.exit(1)


def get_cert_fingerprint(data_dir: pathlib.Path) -> str:
    cert = data_dir / "certs" / "cert.pem"
    try:
        result = subprocess.run(
            ["openssl", "x509", "-in", str(cert), "-noout", "-fingerprint", "-sha256"],
            capture_output=True, text=True, check=True,
        )
        return result.stdout.strip().split("=", 1)[-1]
    except Exception:
        return "(unavailable)"


def http_redirect_page(https_port: int, fingerprint: str) -> str:
    """Generate the HTTP info page that explains the self-signed cert."""
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Secure Connection Required</title>
<style>
:root {{ --bg: #f8f9fa; --text: #212529; --accent: #01696f; --card: #fff; --border: #dee2e6; }}
@media (prefers-color-scheme: dark) {{
    :root {{ --bg: #1a1a2e; --text: #e0e0e0; --accent: #4f98a3; --card: #16213e; --border: #2a2a4a; }}
}}
body {{ font-family: system-ui, -apple-system, sans-serif; background: var(--bg);
    color: var(--text); display: flex; justify-content: center; align-items: center;
    min-height: 100vh; margin: 0; padding: 1rem; }}
.box {{ background: var(--card); border: 1px solid var(--border); border-radius: 12px;
    padding: 2rem; max-width: 600px; width: 100%; box-shadow: 0 4px 24px rgba(0,0,0,0.1); }}
h1 {{ color: var(--accent); margin-bottom: 1rem; }}
.fp {{ background: var(--bg); padding: 0.75rem; border-radius: 6px; font-family: monospace;
    font-size: 0.85rem; word-break: break-all; margin: 1rem 0; border: 1px solid var(--border); }}
.btn {{ display: inline-block; padding: 0.75rem 1.5rem; background: var(--accent); color: #fff;
    border-radius: 6px; text-decoration: none; font-weight: 600; font-size: 1.1rem; margin-top: 1rem; }}
details {{ margin-top: 1rem; }} summary {{ cursor: pointer; font-weight: 600; color: var(--accent); }}
details p {{ margin: 0.5rem 0; font-size: 0.9rem; }}
</style>
</head>
<body>
<div class="box">
<h1>🔒 This server uses HTTPS</h1>
<p>This server uses a <strong>self-signed TLS certificate</strong>. Your browser will show a
security warning — this is expected for self-hosted servers.</p>
<div class="fp"><strong>Certificate SHA-256 Fingerprint:</strong><br>{fingerprint}</div>
<p>Verify the fingerprint above matches what the server administrator shared with you.</p>
<a class="btn" href="https://{{host}}:{https_port}/" id="go">→ Continue to HTTPS</a>
<details><summary>How to trust this certificate</summary>
<p><strong>Chrome:</strong> Click Advanced → Proceed to site. To permanently trust: chrome://settings/security → Manage certificates → Import cert.pem.</p>
<p><strong>Firefox:</strong> Click Advanced → Accept the Risk. Firefox stores the exception per-site.</p>
<p><strong>Safari:</strong> Click "Show Details" → "visit this website". To permanently trust: open cert.pem in Keychain Access → set to "Always Trust".</p>
<p><strong>iOS:</strong> Navigate to the HTTPS URL in Safari → allow the profile → Settings → General → About → Certificate Trust Settings → enable.</p>
<p><strong>Android:</strong> Download cert.pem → Settings → Security → Install certificate.</p>
</details>
</div>
<script>
document.getElementById('go').href = 'https://' + location.hostname + ':{https_port}/';
</script>
</body></html>"""


class HTTPRedirectHandler(BaseHTTPRequestHandler):
    """Serves the HTTP info page that points users to HTTPS."""

    server_version = f"Offline/{__version__}"
    https_port = 8443
    fingerprint = ""

    def log_message(self, format, *args):
        _access_logger.info(
            "HTTP %s %s %s %s", self.client_address[0],
            self.command, self.path, args[0] if args else "",
        )

    def do_GET(self):
        page = http_redirect_page(self.https_port, self.fingerprint)
        data = page.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    do_HEAD = do_GET
    do_POST = do_GET


class ThreadedTCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = True
    daemon_threads = True


# ── SECTION 14: Startup & CLI ───────────────────────────────

ROUTES = [
    # Public
    ("GET",  r"/",                                 handle_home),
    ("GET",  r"/blog",                             handle_blog_list),
    ("GET",  r"/blog/([a-zA-Z0-9_-]+)",            handle_blog_detail),
    ("POST", r"/blog/([a-zA-Z0-9_-]+)/comment",    handle_post_comment),
    ("GET",  r"/files",                            handle_file_list),
    ("GET",  r"/files/([a-zA-Z0-9_.]+)",           handle_file_download),
    ("GET",  r"/upload",                           handle_upload_form),
    ("POST", r"/upload",                           handle_upload),
    ("GET",  r"/login",                            handle_login_form),
    ("POST", r"/login",                            handle_login),
    ("GET",  r"/logout",                           handle_logout),
    ("GET",  r"/register",                         handle_register_form),
    ("POST", r"/register",                         handle_register),
    # Profile
    ("GET",  r"/profile",                          handle_profile),
    ("POST", r"/profile/logout-all",               handle_logout_all),
    ("GET",  r"/profile/change-password",          handle_change_password_form),
    ("POST", r"/profile/change-password",          handle_change_password),
    # Messages
    ("GET",  r"/messages",                         handle_messages_inbox),
    ("GET",  r"/messages/sent",                    handle_messages_sent),
    ("GET",  r"/messages/compose",                 handle_messages_compose),
    ("POST", r"/messages/compose",                 handle_messages_send),
    ("GET",  r"/messages/(\d+)",                   handle_messages_read),
    ("POST", r"/messages/(\d+)/delete",            handle_messages_delete),
    # Fingerprint
    ("GET",  r"/fingerprint",                      handle_fingerprint),
    # API
    ("POST", r"/api/preview",                      handle_api_preview),
    # Admin
    ("GET",  r"/admin",                            handle_admin_dashboard),
    ("GET",  r"/admin/users",                      handle_admin_users),
    ("POST", r"/admin/users/create",               handle_admin_create_user),
    ("GET",  r"/admin/users/(\d+)/edit",           handle_admin_edit_user_form),
    ("POST", r"/admin/users/(\d+)/edit",           handle_admin_edit_user),
    ("POST", r"/admin/users/(\d+)/delete",         handle_admin_delete_user),
    ("POST", r"/admin/users/(\d+)/change-password", handle_admin_change_user_password),
    ("GET",  r"/admin/files",                      handle_admin_files),
    ("POST", r"/admin/files/(\d+)/delete",         handle_admin_delete_file),
    ("POST", r"/admin/files/(\d+)/acl",            handle_admin_file_acl),
    ("GET",  r"/admin/articles",                   handle_admin_articles),
    ("GET",  r"/admin/articles/create",            handle_admin_create_article_form),
    ("POST", r"/admin/articles/create",            handle_admin_create_article),
    ("GET",  r"/admin/articles/(\d+)/edit",        handle_admin_edit_article_form),
    ("POST", r"/admin/articles/(\d+)/edit",        handle_admin_edit_article),
    ("POST", r"/admin/articles/(\d+)/delete",      handle_admin_delete_article),
    ("GET",  r"/admin/groups",                     handle_admin_groups),
    ("POST", r"/admin/groups/create",              handle_admin_create_group),
    ("GET",  r"/admin/groups/(\d+)/members",       handle_admin_group_members_form),
    ("POST", r"/admin/groups/(\d+)/members",       handle_admin_group_members),
    ("GET",  r"/admin/config",                     handle_admin_config_form),
    ("POST", r"/admin/config",                     handle_admin_config),
    ("GET",  r"/admin/comments",                   handle_admin_comments),
    ("POST", r"/admin/comments/(\d+)/approve",     handle_admin_approve_comment),
    ("POST", r"/admin/comments/(\d+)/delete",      handle_admin_delete_comment),
]


def cli_create_user(data_dir: pathlib.Path) -> None:
    """Interactive user creation."""
    ensure_directories(data_dir)
    load_or_create_config(data_dir)
    init_db(data_dir)
    import getpass
    username = input("Username: ").strip()
    password = getpass.getpass("Password: ")
    role = input("Role (user/mod/admin/superadmin) [user]: ").strip() or "user"
    err = validate_username(username) or validate_password(password)
    if err:
        print(f"Error: {err}")
        sys.exit(1)
    pw_hash, salt = hash_password(password)
    now = _utcnow().isoformat()
    try:
        db_execute(
            "INSERT INTO users (username, password_hash, salt, role, created_at)"
            " VALUES (?, ?, ?, ?, ?)",
            (username, pw_hash, salt, role, now),
        )
        print(f"User '{username}' created with role '{role}'.")
    except sqlite3.IntegrityError:
        print("Error: Username already exists.")
        sys.exit(1)


def cli_reset_password(data_dir: pathlib.Path, username: str) -> None:
    """Reset a user's password to a random value."""
    ensure_directories(data_dir)
    load_or_create_config(data_dir)
    init_db(data_dir)
    user = db_fetchone("SELECT id FROM users WHERE username = ?", (username,))
    if not user:
        print(f"User '{username}' not found.")
        sys.exit(1)
    new_pw = secrets.token_urlsafe(16)
    pw_hash, salt = hash_password(new_pw)
    db_execute(
        "UPDATE users SET password_hash = ?, salt = ? WHERE id = ?",
        (pw_hash, salt, user["id"]),
    )
    revoke_all_tokens(user["id"])
    print(f"Password reset for '{username}'. New password: {new_pw}")


def main() -> None:
    parser = argparse.ArgumentParser(
        description=f"Offline v{__version__} — self-contained web platform"
    )
    parser.add_argument("--host", help="Bind address (default: from config)")
    parser.add_argument("--http-port", type=int, help="HTTP port")
    parser.add_argument("--https-port", type=int, help="HTTPS port")
    parser.add_argument("--data-dir", type=str, default="data", help="Data directory")
    parser.add_argument("--create-user", action="store_true", help="Create a user interactively")
    parser.add_argument("--reset-password", metavar="USER", help="Reset password for user")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    args = parser.parse_args()

    data_dir = pathlib.Path(args.data_dir)

    if args.create_user:
        cli_create_user(data_dir)
        return
    if args.reset_password:
        cli_reset_password(data_dir, args.reset_password)
        return

    # Bootstrap
    ensure_directories(data_dir)
    cfg = load_or_create_config(data_dir)
    setup_logging(data_dir)
    init_db(data_dir)

    # Default superadmin
    sa_password = create_default_superadmin()

    # TLS cert
    generate_tls_cert(data_dir)
    fingerprint = get_cert_fingerprint(data_dir)

    # Apply CLI overrides
    host = args.host or cfg.get("host", "0.0.0.0")
    http_port = args.http_port or cfg.get("http_port", 8080)
    https_port = args.https_port or cfg.get("https_port", 8443)

    # Register routes
    RequestHandler.register_routes(ROUTES)

    # HTTP server (redirect page)
    HTTPRedirectHandler.https_port = https_port
    HTTPRedirectHandler.fingerprint = fingerprint
    http_server = ThreadedTCPServer((host, http_port), HTTPRedirectHandler)

    # HTTPS server
    https_server = ThreadedTCPServer((host, https_port), RequestHandler)
    ssl_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ssl_ctx.load_cert_chain(
        str(data_dir / "certs" / "cert.pem"),
        str(data_dir / "certs" / "key.pem"),
    )
    https_server.socket = ssl_ctx.wrap_socket(
        https_server.socket, server_side=True,
    )

    # Startup banner
    print("=" * 60)
    print(f"  Offline v{__version__}")
    print(f"  HTTP:  http://{host}:{http_port}/")
    print(f"  HTTPS: https://{host}:{https_port}/")
    print(f"  Cert fingerprint: {fingerprint}")
    print("=" * 60)
    if sa_password:
        print()
        print("!" * 60)
        print("  ⚠  FIRST RUN — DEFAULT ADMIN ACCOUNT CREATED")
        print("!" * 60)
        print(f"  Username : admin")
        print(f"  Password : {sa_password}")
        print()
        print("  Save these credentials now — they will NOT be shown again.")
        print("  Change the password immediately after first login:")
        print("    Profile → Change Password")
        print("  Or reset via CLI:")
        print(f"    python server.py --reset-password admin")
        print("!" * 60)
        print()

    # Start server threads
    http_thread = threading.Thread(target=http_server.serve_forever, daemon=True)
    https_thread = threading.Thread(target=https_server.serve_forever, daemon=True)
    http_thread.start()
    https_thread.start()

    _access_logger.info("Server started on %s (HTTP:%d, HTTPS:%d)", host, http_port, https_port)

    # Graceful shutdown
    stop_event = threading.Event()

    def shutdown_handler(signum, frame):
        print("\n[*] Shutting down…")
        _access_logger.info("Server shutting down")
        http_server.shutdown()
        https_server.shutdown()
        stop_event.set()

    signal.signal(signal.SIGINT, shutdown_handler)
    signal.signal(signal.SIGTERM, shutdown_handler)

    stop_event.wait()
    print("[✓] Shutdown complete.")


if __name__ == "__main__":
    main()
