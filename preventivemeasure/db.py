import hashlib
import json
import os
import secrets
import sqlite3
import sys
import time
from contextlib import contextmanager
from pathlib import Path

DATA_DIR = Path(os.environ.get("PM_DATA", Path.cwd() / "data")).resolve()
DB_PATH = DATA_DIR / "preventivemeasure.sqlite3"

SCHEMA = """
CREATE TABLE IF NOT EXISTS targets(
  id INTEGER PRIMARY KEY, name TEXT NOT NULL, kind TEXT NOT NULL, location TEXT NOT NULL DEFAULT '',
  enabled INTEGER NOT NULL DEFAULT 1, created_at REAL NOT NULL, last_scan REAL, last_error TEXT,
  meta TEXT NOT NULL DEFAULT '{}');
CREATE TABLE IF NOT EXISTS components(
  id INTEGER PRIMARY KEY, target_id INTEGER NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
  ecosystem TEXT NOT NULL, name TEXT NOT NULL, version TEXT NOT NULL DEFAULT '', source TEXT NOT NULL DEFAULT '',
  vendor TEXT, product TEXT, manual INTEGER NOT NULL DEFAULT 0, ignored INTEGER NOT NULL DEFAULT 0,
  active INTEGER NOT NULL DEFAULT 1, nvd_checked REAL, seen_at REAL NOT NULL,
  UNIQUE(target_id, ecosystem, name, version, source));
CREATE INDEX IF NOT EXISTS ix_comp_product ON components(product);
CREATE TABLE IF NOT EXISTS vulns(
  id TEXT PRIMARY KEY, aliases TEXT NOT NULL DEFAULT '[]', summary TEXT NOT NULL DEFAULT '',
  details TEXT NOT NULL DEFAULT '', cvss REAL, severity TEXT NOT NULL DEFAULT 'UNKNOWN', vector TEXT,
  cwes TEXT NOT NULL DEFAULT '[]', refs TEXT NOT NULL DEFAULT '[]', published TEXT, modified TEXT,
  source TEXT NOT NULL, status TEXT, raw TEXT NOT NULL DEFAULT '{}');
CREATE TABLE IF NOT EXISTS vuln_cpes(
  vuln_id TEXT NOT NULL REFERENCES vulns(id) ON DELETE CASCADE, vendor TEXT NOT NULL, product TEXT NOT NULL,
  version TEXT, start_inc TEXT, start_exc TEXT, end_inc TEXT, end_exc TEXT, origin TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS ix_vc_product ON vuln_cpes(product);
CREATE INDEX IF NOT EXISTS ix_vc_vuln ON vuln_cpes(vuln_id);
CREATE TABLE IF NOT EXISTS kev(
  cve TEXT PRIMARY KEY, name TEXT, action TEXT, due TEXT, added TEXT, ransomware TEXT, notes TEXT);
CREATE TABLE IF NOT EXISTS epss(cve TEXT PRIMARY KEY, score REAL, percentile REAL, updated REAL);
CREATE TABLE IF NOT EXISTS findings(
  id INTEGER PRIMARY KEY, component_id INTEGER NOT NULL REFERENCES components(id) ON DELETE CASCADE,
  vuln_id TEXT NOT NULL REFERENCES vulns(id), status TEXT NOT NULL DEFAULT 'open', confidence TEXT NOT NULL,
  priority TEXT NOT NULL DEFAULT 'medium', fixed_version TEXT, recommendation TEXT NOT NULL DEFAULT '{}',
  first_seen REAL NOT NULL, last_seen REAL NOT NULL, resolved_at REAL, notified_priority TEXT, note TEXT,
  UNIQUE(component_id, vuln_id));
CREATE INDEX IF NOT EXISTS ix_find_status ON findings(status);
CREATE TABLE IF NOT EXISTS news(
  id INTEGER PRIMARY KEY, link TEXT UNIQUE NOT NULL, title TEXT NOT NULL, feed TEXT NOT NULL,
  published TEXT, matched TEXT NOT NULL DEFAULT '[]', fetched REAL NOT NULL, notified INTEGER NOT NULL DEFAULT 0,
  body TEXT NOT NULL DEFAULT '');
CREATE TABLE IF NOT EXISTS events(id INTEGER PRIMARY KEY, ts REAL NOT NULL, level TEXT NOT NULL, message TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS settings(key TEXT PRIMARY KEY, value TEXT NOT NULL);
"""

# Columnas añadidas después de la primera versión del esquema
MIGRATIONS = [("news", "body", "body TEXT NOT NULL DEFAULT ''")]

DEFAULT_TEMPLATE = (
    "[$priority] $vuln_id en $component $version ($target)\n"
    "$summary\n"
    "CVSS: $cvss | Explotada activamente: $kev | EPSS: $epss\n"
    "Solución: $fix\n"
    "$link"
)

DEFAULTS = {
    "interval_minutes": 30,
    "notify_min_priority": "high",
    "notify_digest_header": "PreventiveMeasure: $count vulnerabilidades nuevas que te afectan",
    "notify_template": DEFAULT_TEMPLATE,
    "notify_news": True,
    "nvd_api_key": "",
    "feeds": [
        "https://www.cisa.gov/cybersecurity-advisories/all.xml",
        "https://feeds.feedburner.com/TheHackersNews",
        "https://www.bleepingcomputer.com/feed/",
        "https://isc.sans.edu/rssfeed_full.xml",
    ],
    "channels": {
        "email": {"enabled": False, "host": "", "port": 587, "security": "starttls", "user": "",
                  "password": "", "sender": "", "to": ""},
        "telegram": {"enabled": False, "bot_token": "", "chat_id": ""},
        "whatsapp_twilio": {"enabled": False, "account_sid": "", "auth_token": "", "from": "", "to": ""},
        "whatsapp_callmebot": {"enabled": False, "phone": "", "apikey": ""},
        "discord": {"enabled": False, "webhook_url": ""},
        "slack": {"enabled": False, "webhook_url": ""},
        "teams": {"enabled": False, "webhook_url": ""},
        "ntfy": {"enabled": False, "server": "https://ntfy.sh", "topic": "", "token": ""},
        "webhook": {"enabled": False, "url": "", "secret": ""},
    },
}

# Campos que nunca salen por la API
# url (webhook genérico) y topic (ntfy) suelen ser el propio secreto: quien los conoce puede leer o publicar
SECRET_FIELDS = {"password", "bot_token", "auth_token", "apikey", "token", "secret", "webhook_url", "nvd_api_key",
                 "url", "topic"}


def token_hash(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


@contextmanager
def conn():
    c = sqlite3.connect(DB_PATH, timeout=30)
    c.row_factory = sqlite3.Row
    c.execute("PRAGMA foreign_keys=ON")
    try:
        yield c
        c.commit()
    finally:
        c.close()


def init() -> str | None:
    """Crea/migra la BD. Devuelve el token de administración solo cuando se acaba de generar:
    en la BD únicamente queda su hash, así que no se puede volver a mostrar."""
    DATA_DIR.mkdir(parents=True, exist_ok=True, mode=0o700)
    (DATA_DIR / "uploads").mkdir(exist_ok=True, mode=0o700)
    new_token = None
    with conn() as c:
        c.execute("PRAGMA journal_mode=WAL")
        c.executescript(SCHEMA)
        for table, column, ddl in MIGRATIONS:
            if column not in {r["name"] for r in c.execute(f"PRAGMA table_info({table})")}:
                c.execute(f"ALTER TABLE {table} ADD COLUMN {ddl}")
        c.execute("INSERT OR IGNORE INTO settings VALUES('agent_token', ?)", (json.dumps(secrets.token_urlsafe(32)),))
        if old := c.execute("SELECT value FROM settings WHERE key='admin_token'").fetchone():
            # Migración: versiones anteriores guardaban el token en claro
            c.execute("INSERT OR IGNORE INTO settings VALUES('admin_token_sha256', ?)",
                      (json.dumps(token_hash(json.loads(old["value"]))),))
            c.execute("DELETE FROM settings WHERE key='admin_token'")
        if not c.execute("SELECT 1 FROM settings WHERE key='admin_token_sha256'").fetchone():
            new_token = secrets.token_urlsafe(32)
            c.execute("INSERT INTO settings VALUES('admin_token_sha256', ?)", (json.dumps(token_hash(new_token)),))
    _restrict_permissions()
    return new_token


def rotate_admin_token() -> str:
    token = secrets.token_urlsafe(32)
    set_setting("admin_token_sha256", token_hash(token))
    return token


def _restrict_permissions() -> None:
    """La BD contiene secretos de canales y hashes de tokens. En Windows chmod no restringe (usar icacls);
    en volúmenes de otro propietario puede fallar: se avisa y se sigue."""
    try:
        os.chmod(DATA_DIR, 0o700)
        os.chmod(DB_PATH, 0o600)  # SQLite crea -wal/-shm con el modo del fichero principal
    except OSError as e:
        print(f"Aviso: no se pudieron restringir permisos de {DATA_DIR}: {e}", file=sys.stderr)


def get_setting(key: str):
    with conn() as c:
        row = c.execute("SELECT value FROM settings WHERE key=?", (key,)).fetchone()
    if row:
        return json.loads(row["value"])
    return json.loads(json.dumps(DEFAULTS.get(key)))  # copia profunda


def set_setting(key: str, value) -> None:
    with conn() as c:
        c.execute("INSERT INTO settings VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                  (key, json.dumps(value)))


def channels() -> dict:
    """Canales guardados fusionados con los valores por defecto (campos nuevos incluidos)."""
    saved = get_setting("channels")
    return {name: {**default, **saved.get(name, {})} for name, default in DEFAULTS["channels"].items()}


def resolve_secret(value: str) -> str:
    """'env:NOMBRE' lee la variable de entorno; así el secreto no vive en la BD.
    Las variables PM_* (tokens del propio monitor) nunca se resuelven: no deben acabar en un canal."""
    if isinstance(value, str) and value.startswith("env:"):
        name = value[4:]
        return "" if name.upper().startswith("PM_") else os.environ.get(name, "")
    return value


def log(level: str, message: str) -> None:
    with conn() as c:
        c.execute("INSERT INTO events(ts, level, message) VALUES(?,?,?)", (time.time(), level, message[:2000]))
        c.execute("DELETE FROM events WHERE id < (SELECT MAX(id) - 5000 FROM events)")


def rows(sql: str, args=()) -> list[dict]:
    with conn() as c:
        return [dict(r) for r in c.execute(sql, args)]
