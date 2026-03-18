"""
db/schema.py  – SQLite schema initialisation and data-access layer
"""
import sqlite3
import json
import os
from datetime import datetime
from contextlib import contextmanager
import sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import config


# ─────────────────────────────────────────────────────────────────────────────
# DDL
# ─────────────────────────────────────────────────────────────────────────────

SCHEMA_SQL = """
PRAGMA journal_mode = WAL;
PRAGMA synchronous   = NORMAL;

CREATE TABLE IF NOT EXISTS events (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    ts               DATETIME,
    log_source       TEXT,      -- firewall | dns | radius | dhcp
    log_type         TEXT,      -- Firewall | Content Filtering | ATP | IPS | Event …
    log_component    TEXT,      -- Firewall Rule | HTTP | Application | DoS Attack …
    log_subtype      TEXT,      -- Allowed | Denied | Alert | System …
    severity         TEXT,      -- Information | Notice | Warning | Critical
    src_ip           TEXT,
    dst_ip           TEXT,
    src_port         INTEGER,
    dst_port         INTEGER,
    protocol         TEXT,
    action           TEXT,      -- Allow | Deny | Alert | Drop
    username         TEXT,
    url              TEXT,
    application      TEXT,
    threat_name      TEXT,
    sent_bytes       INTEGER,
    recv_bytes        INTEGER,
    fw_rule_name     TEXT,
    message          TEXT,
    raw              TEXT,
    file_source      TEXT,
    ingested_at      DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_events_ts       ON events(ts);
CREATE INDEX IF NOT EXISTS idx_events_src_ip   ON events(src_ip);
CREATE INDEX IF NOT EXISTS idx_events_dst_ip   ON events(dst_ip);
CREATE INDEX IF NOT EXISTS idx_events_source   ON events(log_source);
CREATE INDEX IF NOT EXISTS idx_events_type     ON events(log_type);
CREATE INDEX IF NOT EXISTS idx_events_action   ON events(action);
CREATE INDEX IF NOT EXISTS idx_events_threat   ON events(threat_name);

-- ── DNS queries ──────────────────────────────────────────────────────────────
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
CREATE INDEX IF NOT EXISTS idx_dns_ts        ON dns_queries(ts);
CREATE INDEX IF NOT EXISTS idx_dns_client    ON dns_queries(client_ip);
CREATE INDEX IF NOT EXISTS idx_dns_qname     ON dns_queries(query_name);

-- ── RADIUS authentication ────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS radius_auth (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    ts          DATETIME,
    username    TEXT,
    nas_ip      TEXT,
    client_ip   TEXT,
    result      TEXT,   -- Accept | Reject
    reason      TEXT,
    file_source TEXT
);
CREATE INDEX IF NOT EXISTS idx_radius_ts   ON radius_auth(ts);
CREATE INDEX IF NOT EXISTS idx_radius_user ON radius_auth(username);
CREATE INDEX IF NOT EXISTS idx_radius_res  ON radius_auth(result);

-- ── DHCP leases ──────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS dhcp_leases (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    ts          DATETIME,
    event_type  TEXT,   -- DHCPACK | DHCPREQUEST | DHCPNAK | DHCPDISCOVER
    ip_address  TEXT,
    mac_address TEXT,
    hostname    TEXT,
    interface   TEXT,
    file_source TEXT
);
CREATE INDEX IF NOT EXISTS idx_dhcp_ts  ON dhcp_leases(ts);
CREATE INDEX IF NOT EXISTS idx_dhcp_ip  ON dhcp_leases(ip_address);
CREATE INDEX IF NOT EXISTS idx_dhcp_mac ON dhcp_leases(mac_address);

-- ── MAC→IP mapping (from Mac_IP logs) ───────────────────────────────────────
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

-- ── Alerts ───────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS alerts (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at   DATETIME DEFAULT CURRENT_TIMESTAMP,
    rule_id      TEXT,
    rule_name    TEXT,
    severity     TEXT,   -- Critical | High | Medium | Low
    src_ip       TEXT,
    dst_ip       TEXT,
    username     TEXT,
    description  TEXT,
    event_ids    TEXT,   -- JSON list of related event IDs
    acknowledged INTEGER DEFAULT 0,
    ack_at       DATETIME,
    ack_by       TEXT
);
CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts(severity);
CREATE INDEX IF NOT EXISTS idx_alerts_rule     ON alerts(rule_id);
CREATE INDEX IF NOT EXISTS idx_alerts_ack      ON alerts(acknowledged);

-- ── Ingestion tracking ───────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS ingested_files (
    filepath     TEXT PRIMARY KEY,
    log_source   TEXT,
    rows_loaded  INTEGER,
    loaded_at    DATETIME DEFAULT CURRENT_TIMESTAMP
);
"""


# ─────────────────────────────────────────────────────────────────────────────
# Connection / helpers
# ─────────────────────────────────────────────────────────────────────────────

def get_connection() -> sqlite3.Connection:
    conn = sqlite3.connect(config.DB_PATH, timeout=30)
    conn.row_factory = sqlite3.Row
    return conn


@contextmanager
def db_conn():
    conn = get_connection()
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def init_db():
    """Create all tables / indexes."""
    os.makedirs(os.path.dirname(os.path.abspath(config.DB_PATH)), exist_ok=True)
    with db_conn() as conn:
        conn.executescript(SCHEMA_SQL)
    print(f"[+] Database ready at {config.DB_PATH}")


# ─────────────────────────────────────────────────────────────────────────────
# Data-access helpers
# ─────────────────────────────────────────────────────────────────────────────

def is_file_ingested(filepath: str) -> bool:
    with db_conn() as conn:
        row = conn.execute(
            "SELECT 1 FROM ingested_files WHERE filepath=?", (filepath,)
        ).fetchone()
    return row is not None


def mark_file_ingested(filepath: str, log_source: str, rows: int):
    with db_conn() as conn:
        conn.execute(
            "INSERT OR REPLACE INTO ingested_files(filepath,log_source,rows_loaded) VALUES(?,?,?)",
            (filepath, log_source, rows)
        )


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
    with db_conn() as conn:
        conn.executemany(sql, rows)


def bulk_insert_dns(rows: list):
    if not rows:
        return
    sql = """INSERT INTO dns_queries
        (ts,client_ip,client_port,query_name,query_type,flags,server_ip,file_source)
        VALUES(:ts,:client_ip,:client_port,:query_name,:query_type,:flags,:server_ip,:file_source)"""
    with db_conn() as conn:
        conn.executemany(sql, rows)


def bulk_insert_radius(rows: list):
    if not rows:
        return
    sql = """INSERT INTO radius_auth
        (ts,username,nas_ip,client_ip,result,reason,file_source)
        VALUES(:ts,:username,:nas_ip,:client_ip,:result,:reason,:file_source)"""
    with db_conn() as conn:
        conn.executemany(sql, rows)


def bulk_insert_dhcp(rows: list):
    if not rows:
        return
    sql = """INSERT INTO dhcp_leases
        (ts,event_type,ip_address,mac_address,hostname,interface,file_source)
        VALUES(:ts,:event_type,:ip_address,:mac_address,:hostname,:interface,:file_source)"""
    with db_conn() as conn:
        conn.executemany(sql, rows)


def bulk_insert_mac_ip(rows: list):
    if not rows:
        return
    sql = """INSERT INTO mac_ip_map(ts,mac_address,ip_address,interface,file_source)
             VALUES(:ts,:mac_address,:ip_address,:interface,:file_source)"""
    with db_conn() as conn:
        conn.executemany(sql, rows)


def insert_alert(rule_id, rule_name, severity, src_ip, dst_ip,
                 username, description, event_ids=None):
    sql = """INSERT INTO alerts
        (rule_id,rule_name,severity,src_ip,dst_ip,username,description,event_ids)
        VALUES(?,?,?,?,?,?,?,?)"""
    with db_conn() as conn:
        conn.execute(sql, (
            rule_id, rule_name, severity, src_ip, dst_ip,
            username, description, json.dumps(event_ids or [])
        ))


def get_alerts(severity=None, unacked_only=False, limit=500):
    clauses, params = [], []
    if severity:
        clauses.append("severity=?"); params.append(severity)
    if unacked_only:
        clauses.append("acknowledged=0")
    where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
    sql = f"SELECT * FROM alerts {where} ORDER BY created_at DESC LIMIT {limit}"
    with db_conn() as conn:
        rows = conn.execute(sql, params).fetchall()
    return [dict(r) for r in rows]


def acknowledge_alert(alert_id: int, ack_by: str = "analyst"):
    with db_conn() as conn:
        conn.execute(
            "UPDATE alerts SET acknowledged=1, ack_at=datetime('now'), ack_by=? WHERE id=?",
            (ack_by, alert_id)
        )


def query_events(src_ip=None, dst_ip=None, log_type=None, log_source=None,
                 action=None, since=None, until=None, limit=200):
    clauses, params = [], []
    if src_ip:     clauses.append("src_ip=?");     params.append(src_ip)
    if dst_ip:     clauses.append("dst_ip=?");     params.append(dst_ip)
    if log_type:   clauses.append("log_type LIKE ?"); params.append(f"%{log_type}%")
    if log_source: clauses.append("log_source=?"); params.append(log_source)
    if action:     clauses.append("action=?");     params.append(action)
    if since:      clauses.append("ts>=?");        params.append(since)
    if until:      clauses.append("ts<=?");        params.append(until)
    where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
    sql = f"SELECT * FROM events {where} ORDER BY ts DESC LIMIT {limit}"
    with db_conn() as conn:
        rows = conn.execute(sql, params).fetchall()
    return [dict(r) for r in rows]


def get_stats() -> dict:
    """Return dashboard summary counts."""
    with db_conn() as conn:
        def count(sql, p=()):
            row = conn.execute(sql, p).fetchone()
            return row[0] if row else 0

        return {
            "total_events":     count("SELECT COUNT(*) FROM events"),
            "total_dns":        count("SELECT COUNT(*) FROM dns_queries"),
            "total_radius":     count("SELECT COUNT(*) FROM radius_auth"),
            "total_dhcp":       count("SELECT COUNT(*) FROM dhcp_leases"),
            "open_alerts":      count("SELECT COUNT(*) FROM alerts WHERE acknowledged=0"),
            "critical_alerts":  count("SELECT COUNT(*) FROM alerts WHERE severity='Critical' AND acknowledged=0"),
            "denied_events":    count("SELECT COUNT(*) FROM events WHERE action='Deny'"),
            "atp_events":       count("SELECT COUNT(*) FROM events WHERE log_type='ATP'"),
            "ips_events":       count("SELECT COUNT(*) FROM events WHERE log_type='IPS'"),
            "dos_events":       count("SELECT COUNT(*) FROM events WHERE log_component='DoS Attack'"),
            "files_ingested":   count("SELECT COUNT(*) FROM ingested_files"),
            "radius_rejects":   count("SELECT COUNT(*) FROM radius_auth WHERE result='Reject'"),
        }
