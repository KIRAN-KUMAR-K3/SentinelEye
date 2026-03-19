"""
db/schema.py — SentinelEye Database Layer
Indian Institute of Science | ISO Security Team

FIXES vs original:
  - threading.Lock serialises ALL writes → no more "database is locked"
  - busy_timeout = 60 seconds on every connection
  - expanduser() on DB_PATH so ~/siem.db resolves correctly
  - Retry wrapper (5 attempts) on every write operation
  - os.makedirs uses correct dirname handling
  - get_stats() covers all log_type variants from Sophos XG/XGS
  - Added src_ip index on alerts table
"""
import sqlite3
import json
import os
import time
import threading
from contextlib import contextmanager
import sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import config

# ── Global write lock: only ONE thread writes at a time ──────────────────────
_WRITE_LOCK = threading.Lock()

# ─────────────────────────────────────────────────────────────────────────────
# DDL
# ─────────────────────────────────────────────────────────────────────────────
SCHEMA_SQL = """
PRAGMA journal_mode = WAL;
PRAGMA synchronous   = NORMAL;
PRAGMA busy_timeout  = 60000;
PRAGMA cache_size    = -32000;

CREATE TABLE IF NOT EXISTS events (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    ts            DATETIME,
    log_source    TEXT,
    log_type      TEXT,
    log_component TEXT,
    log_subtype   TEXT,
    severity      TEXT,
    src_ip        TEXT,
    dst_ip        TEXT,
    src_port      INTEGER,
    dst_port      INTEGER,
    protocol      TEXT,
    action        TEXT,
    username      TEXT,
    url           TEXT,
    application   TEXT,
    threat_name   TEXT,
    sent_bytes    INTEGER,
    recv_bytes    INTEGER,
    fw_rule_name  TEXT,
    message       TEXT,
    raw           TEXT,
    file_source   TEXT,
    ingested_at   DATETIME DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_events_ts        ON events(ts);
CREATE INDEX IF NOT EXISTS idx_events_src_ip    ON events(src_ip);
CREATE INDEX IF NOT EXISTS idx_events_dst_ip    ON events(dst_ip);
CREATE INDEX IF NOT EXISTS idx_events_source    ON events(log_source);
CREATE INDEX IF NOT EXISTS idx_events_type      ON events(log_type);
CREATE INDEX IF NOT EXISTS idx_events_component ON events(log_component);
CREATE INDEX IF NOT EXISTS idx_events_action    ON events(action);
CREATE INDEX IF NOT EXISTS idx_events_threat    ON events(threat_name);
CREATE INDEX IF NOT EXISTS idx_events_username  ON events(username);

CREATE TABLE IF NOT EXISTS dns_queries (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    ts          DATETIME,
    client_ip   TEXT,
    client_port INTEGER,
    query_name  TEXT,
    query_type  TEXT,
    flags       TEXT,
    server_ip   TEXT,
    file_source TEXT
);
CREATE INDEX IF NOT EXISTS idx_dns_ts     ON dns_queries(ts);
CREATE INDEX IF NOT EXISTS idx_dns_client ON dns_queries(client_ip);
CREATE INDEX IF NOT EXISTS idx_dns_qname  ON dns_queries(query_name);

CREATE TABLE IF NOT EXISTS radius_auth (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    ts          DATETIME,
    username    TEXT,
    nas_ip      TEXT,
    client_ip   TEXT,
    result      TEXT,
    reason      TEXT,
    file_source TEXT
);
CREATE INDEX IF NOT EXISTS idx_radius_ts   ON radius_auth(ts);
CREATE INDEX IF NOT EXISTS idx_radius_user ON radius_auth(username);
CREATE INDEX IF NOT EXISTS idx_radius_res  ON radius_auth(result);

CREATE TABLE IF NOT EXISTS dhcp_leases (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    ts          DATETIME,
    event_type  TEXT,
    ip_address  TEXT,
    mac_address TEXT,
    hostname    TEXT,
    interface   TEXT,
    file_source TEXT
);
CREATE INDEX IF NOT EXISTS idx_dhcp_ts  ON dhcp_leases(ts);
CREATE INDEX IF NOT EXISTS idx_dhcp_ip  ON dhcp_leases(ip_address);
CREATE INDEX IF NOT EXISTS idx_dhcp_mac ON dhcp_leases(mac_address);

CREATE TABLE IF NOT EXISTS mac_ip_map (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    ts          DATETIME,
    mac_address TEXT,
    ip_address  TEXT,
    interface   TEXT,
    file_source TEXT
);
CREATE INDEX IF NOT EXISTS idx_macip_mac ON mac_ip_map(mac_address);
CREATE INDEX IF NOT EXISTS idx_macip_ip  ON mac_ip_map(ip_address);

CREATE TABLE IF NOT EXISTS alerts (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at   DATETIME DEFAULT CURRENT_TIMESTAMP,
    rule_id      TEXT,
    rule_name    TEXT,
    severity     TEXT,
    src_ip       TEXT,
    dst_ip       TEXT,
    username     TEXT,
    description  TEXT,
    event_ids    TEXT,
    acknowledged INTEGER DEFAULT 0,
    ack_at       DATETIME,
    ack_by       TEXT
);
CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts(severity);
CREATE INDEX IF NOT EXISTS idx_alerts_rule     ON alerts(rule_id);
CREATE INDEX IF NOT EXISTS idx_alerts_ack      ON alerts(acknowledged);
CREATE INDEX IF NOT EXISTS idx_alerts_src      ON alerts(src_ip);
CREATE INDEX IF NOT EXISTS idx_alerts_ts       ON alerts(created_at);

CREATE TABLE IF NOT EXISTS ingested_files (
    filepath    TEXT PRIMARY KEY,
    log_source  TEXT,
    rows_loaded INTEGER,
    loaded_at   DATETIME DEFAULT CURRENT_TIMESTAMP
);
"""

# ─────────────────────────────────────────────────────────────────────────────
# Connection helpers
# ─────────────────────────────────────────────────────────────────────────────

def _db_path() -> str:
    return os.path.expanduser(config.DB_PATH)


def get_connection() -> sqlite3.Connection:
    """Read connection — safe for multiple threads simultaneously."""
    conn = sqlite3.connect(_db_path(), timeout=60, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA busy_timeout=60000")
    return conn


@contextmanager
def _write_conn():
    """Serialised write connection — only one writer at a time via threading.Lock."""
    with _WRITE_LOCK:
        conn = sqlite3.connect(_db_path(), timeout=120, check_same_thread=False)
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA busy_timeout=60000")
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()


def _retry(fn, retries=5, delay=0.3):
    """Retry a write function on OperationalError (locked db)."""
    for attempt in range(retries):
        try:
            return fn()
        except sqlite3.OperationalError as e:
            if "locked" in str(e).lower() and attempt < retries - 1:
                time.sleep(delay * (attempt + 1))
            else:
                raise


def init_db():
    """Create / upgrade all tables and indexes."""
    db = _db_path()
    parent = os.path.dirname(os.path.abspath(db))
    if parent:
        os.makedirs(parent, exist_ok=True)
    with _write_conn() as conn:
        conn.executescript(SCHEMA_SQL)
    print(f"[+] Database ready at {db}")


# ─────────────────────────────────────────────────────────────────────────────
# File tracking
# ─────────────────────────────────────────────────────────────────────────────

def is_file_ingested(filepath: str) -> bool:
    conn = get_connection()
    try:
        row = conn.execute(
            "SELECT 1 FROM ingested_files WHERE filepath=?", (filepath,)
        ).fetchone()
        return row is not None
    finally:
        conn.close()


def mark_file_ingested(filepath: str, log_source: str, rows: int):
    def _do():
        with _write_conn() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO ingested_files(filepath,log_source,rows_loaded) VALUES(?,?,?)",
                (filepath, log_source, rows)
            )
    _retry(_do)


# ─────────────────────────────────────────────────────────────────────────────
# Bulk inserts (all serialised through write lock + retry)
# ─────────────────────────────────────────────────────────────────────────────

def bulk_insert_events(rows: list):
    if not rows:
        return
    sql = """INSERT INTO events
        (ts,log_source,log_type,log_component,log_subtype,severity,
         src_ip,dst_ip,src_port,dst_port,protocol,action,username,
         url,application,threat_name,sent_bytes,recv_bytes,fw_rule_name,
         message,raw,file_source)
        VALUES
        (:ts,:log_source,:log_type,:log_component,:log_subtype,:severity,
         :src_ip,:dst_ip,:src_port,:dst_port,:protocol,:action,:username,
         :url,:application,:threat_name,:sent_bytes,:recv_bytes,:fw_rule_name,
         :message,:raw,:file_source)"""
    def _do():
        with _write_conn() as conn:
            conn.executemany(sql, rows)
    _retry(_do)


def bulk_insert_dns(rows: list):
    if not rows:
        return
    sql = """INSERT INTO dns_queries
        (ts,client_ip,client_port,query_name,query_type,flags,server_ip,file_source)
        VALUES(:ts,:client_ip,:client_port,:query_name,:query_type,:flags,:server_ip,:file_source)"""
    def _do():
        with _write_conn() as conn:
            conn.executemany(sql, rows)
    _retry(_do)


def bulk_insert_radius(rows: list):
    if not rows:
        return
    sql = """INSERT INTO radius_auth
        (ts,username,nas_ip,client_ip,result,reason,file_source)
        VALUES(:ts,:username,:nas_ip,:client_ip,:result,:reason,:file_source)"""
    def _do():
        with _write_conn() as conn:
            conn.executemany(sql, rows)
    _retry(_do)


def bulk_insert_dhcp(rows: list):
    if not rows:
        return
    sql = """INSERT INTO dhcp_leases
        (ts,event_type,ip_address,mac_address,hostname,interface,file_source)
        VALUES(:ts,:event_type,:ip_address,:mac_address,:hostname,:interface,:file_source)"""
    def _do():
        with _write_conn() as conn:
            conn.executemany(sql, rows)
    _retry(_do)


def bulk_insert_mac_ip(rows: list):
    if not rows:
        return
    sql = """INSERT INTO mac_ip_map(ts,mac_address,ip_address,interface,file_source)
             VALUES(:ts,:mac_address,:ip_address,:interface,:file_source)"""
    def _do():
        with _write_conn() as conn:
            conn.executemany(sql, rows)
    _retry(_do)


# ─────────────────────────────────────────────────────────────────────────────
# Alerts
# ─────────────────────────────────────────────────────────────────────────────

def insert_alert(rule_id, rule_name, severity, src_ip, dst_ip,
                 username, description, event_ids=None):
    def _do():
        with _write_conn() as conn:
            conn.execute(
                """INSERT INTO alerts
                   (rule_id,rule_name,severity,src_ip,dst_ip,username,description,event_ids)
                   VALUES(?,?,?,?,?,?,?,?)""",
                (rule_id, rule_name, severity, src_ip or "", dst_ip or "",
                 username or "", description or "", json.dumps(event_ids or []))
            )
    _retry(_do)


def get_alerts(severity=None, unacked_only=False, limit=500):
    clauses, params = [], []
    if severity:
        clauses.append("severity=?"); params.append(severity)
    if unacked_only:
        clauses.append("acknowledged=0")
    where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
    conn = get_connection()
    try:
        rows = conn.execute(
            f"SELECT * FROM alerts {where} ORDER BY created_at DESC LIMIT {limit}",
            params
        ).fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()


def acknowledge_alert(alert_id: int, ack_by: str = "analyst"):
    def _do():
        with _write_conn() as conn:
            conn.execute(
                "UPDATE alerts SET acknowledged=1, ack_at=datetime('now'), ack_by=? WHERE id=?",
                (ack_by, alert_id)
            )
    _retry(_do)


# ─────────────────────────────────────────────────────────────────────────────
# Query helpers
# ─────────────────────────────────────────────────────────────────────────────

def query_events(src_ip=None, dst_ip=None, log_type=None, log_source=None,
                 action=None, since=None, until=None, limit=200):
    clauses, params = [], []
    if src_ip:     clauses.append("src_ip=?");        params.append(src_ip)
    if dst_ip:     clauses.append("dst_ip=?");        params.append(dst_ip)
    if log_type:   clauses.append("log_type LIKE ?"); params.append(f"%{log_type}%")
    if log_source: clauses.append("log_source=?");    params.append(log_source)
    if action:     clauses.append("action=?");        params.append(action)
    if since:      clauses.append("ts>=?");           params.append(since)
    if until:      clauses.append("ts<=?");           params.append(until)
    where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
    conn = get_connection()
    try:
        rows = conn.execute(
            f"SELECT * FROM events {where} ORDER BY ts DESC LIMIT {limit}",
            params
        ).fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()


def get_stats() -> dict:
    """Summary counts for the dashboard. Covers all Sophos XG/XGS log_type variants."""
    conn = get_connection()
    try:
        def count(sql, p=()):
            r = conn.execute(sql, p).fetchone()
            return r[0] if r else 0
        return {
            "total_events":    count("SELECT COUNT(*) FROM events"),
            "total_dns":       count("SELECT COUNT(*) FROM dns_queries"),
            "total_radius":    count("SELECT COUNT(*) FROM radius_auth"),
            "total_dhcp":      count("SELECT COUNT(*) FROM dhcp_leases"),
            "open_alerts":     count("SELECT COUNT(*) FROM alerts WHERE acknowledged=0"),
            "critical_alerts": count("SELECT COUNT(*) FROM alerts WHERE severity='Critical' AND acknowledged=0"),
            # Sophos logs action as 'Allow'/'Deny' — also catch 'Allowed'/'Denied'
            "denied_events":   count("SELECT COUNT(*) FROM events WHERE action IN ('Deny','Denied','Drop')"),
            "allowed_events":  count("SELECT COUNT(*) FROM events WHERE action IN ('Allow','Allowed')"),
            # ATP log_type varies: 'ATP' or 'Advanced Threat Protection'
            "atp_events":      count("SELECT COUNT(*) FROM events WHERE log_type LIKE '%ATP%' OR log_type LIKE '%Threat%'"),
            # IPS log_type varies
            "ips_events":      count("SELECT COUNT(*) FROM events WHERE log_type LIKE '%IPS%' OR log_type LIKE '%Intrusion%'"),
            "dos_events":      count("SELECT COUNT(*) FROM events WHERE log_component LIKE '%DoS%'"),
            "files_ingested":  count("SELECT COUNT(*) FROM ingested_files"),
            "radius_rejects":  count("SELECT COUNT(*) FROM radius_auth WHERE result='Reject'"),
        }
    finally:
        conn.close()
