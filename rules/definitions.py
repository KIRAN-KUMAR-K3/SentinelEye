"""
rules/definitions.py
SOC detection rules tuned to the Sophos XG/DNS/RADIUS log schema.

Each rule is a dict with:
  id          – unique string
  name        – human label
  severity    – Critical | High | Medium | Low
  description – what it detects
  fn          – callable(conn) → list of alert dicts  {src_ip, dst_ip, username, description, event_ids}
"""

import sqlite3
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import config


# ─────────────────────────────────────────────────────────────────────────────
# Helper
# ─────────────────────────────────────────────────────────────────────────────

def _rows(conn: sqlite3.Connection, sql: str, params=()):
    conn.row_factory = sqlite3.Row
    return [dict(r) for r in conn.execute(sql, params).fetchall()]


# ─────────────────────────────────────────────────────────────────────────────
# Rule functions
# ─────────────────────────────────────────────────────────────────────────────

def r001_c2_communication(conn):
    """ATP Web / Network alert = C2 / malware phone-home."""
    rows = _rows(conn, """
        SELECT id, src_ip, dst_ip, url, threat_name, ts
        FROM   events
        WHERE  log_type = 'ATP'
          AND  log_subtype IN ('Alert','alert')
          AND  acknowledged_alert IS NULL
        ORDER BY ts DESC
        LIMIT 500
    """)
    alerts = []
    for r in rows:
        alerts.append({
            "src_ip":      r["src_ip"],
            "dst_ip":      r["dst_ip"],
            "username":    "",
            "description": f"C2/Malware detected: {r['threat_name']} → {r['url'] or r['dst_ip']}",
            "event_ids":   [r["id"]],
        })
    return alerts


def r002_dos_attack(conn):
    """Firewall DoS Attack component."""
    rows = _rows(conn, """
        SELECT id, src_ip, dst_ip, protocol, ts, COUNT(*) as cnt
        FROM   events
        WHERE  log_component = 'DoS Attack'
        GROUP BY src_ip
        HAVING cnt >= 5
        ORDER BY cnt DESC
        LIMIT 200
    """)
    return [{
        "src_ip":      r["src_ip"],
        "dst_ip":      r["dst_ip"],
        "username":    "",
        "description": f"DoS Attack: {r['cnt']} events from {r['src_ip']} ({r['protocol']})",
        "event_ids":   [],
    } for r in rows]


def r003_ips_signature(conn):
    """IPS signature triggered (high-risk only)."""
    rows = _rows(conn, """
        SELECT id, src_ip, dst_ip, message, severity, ts
        FROM   events
        WHERE  log_type IN ('IPS','ips')
          AND  severity IN ('Warning','Critical','Error','Notice')
        ORDER BY ts DESC
        LIMIT 300
    """)
    return [{
        "src_ip":      r["src_ip"],
        "dst_ip":      r["dst_ip"],
        "username":    "",
        "description": f"IPS Signature: {r['message']} ({r['severity']})",
        "event_ids":   [r["id"]],
    } for r in rows]


def r004_ip_spoof(conn):
    """IP Spoofing prevention triggered."""
    rows = _rows(conn, """
        SELECT id, src_ip, dst_ip, ts
        FROM   events
        WHERE  log_component LIKE '%IP Spoof%'
        ORDER BY ts DESC
        LIMIT 200
    """)
    return [{
        "src_ip":      r["src_ip"],
        "dst_ip":      r["dst_ip"],
        "username":    "",
        "description": f"IP Spoofing attempt from {r['src_ip']} → {r['dst_ip']}",
        "event_ids":   [r["id"]],
    } for r in rows]


def r005_radius_brute_force(conn):
    """Multiple RADIUS Auth-Reject within a time window → brute force."""
    window = config.BRUTE_FORCE_WINDOW_SEC
    thresh = config.BRUTE_FORCE_THRESHOLD
    rows = _rows(conn, f"""
        SELECT username, nas_ip,
               COUNT(*) as cnt,
               MIN(ts)  as first_seen,
               MAX(ts)  as last_seen
        FROM   radius_auth
        WHERE  result = 'Reject'
          AND  ts >= datetime('now', '-{window} seconds')
        GROUP BY username, nas_ip
        HAVING cnt >= {thresh}
        ORDER BY cnt DESC
    """)
    return [{
        "src_ip":      r["nas_ip"],
        "dst_ip":      "",
        "username":    r["username"],
        "description": (
            f"Brute force: {r['cnt']} RADIUS rejects for '{r['username']}' "
            f"from {r['nas_ip']} between {r['first_seen']} and {r['last_seen']}"
        ),
        "event_ids":   [],
    } for r in rows]


def r006_admin_login_unusual(conn):
    """Admin Web GUI or CLI login from non-RFC1918 / unexpected address."""
    rows = _rows(conn, """
        SELECT id, username, src_ip, log_component, ts
        FROM   events
        WHERE  log_component IN ('GUI','CLI')
          AND  log_subtype = 'Admin'
          AND  action = 'Allow'
          AND  (
            src_ip NOT LIKE '10.%'
            AND src_ip NOT LIKE '172.16.%'
            AND src_ip NOT LIKE '192.168.%'
          )
        ORDER BY ts DESC
        LIMIT 100
    """)
    return [{
        "src_ip":      r["src_ip"],
        "dst_ip":      "",
        "username":    r["username"],
        "description": (
            f"Admin {r['log_component']} login from EXTERNAL IP {r['src_ip']} "
            f"by '{r['username']}' at {r['ts']}"
        ),
        "event_ids":   [r["id"]],
    } for r in rows]


def r007_dns_tunneling(conn):
    """Single host making > DNS_TUNNEL_QUERY_THRESHOLD queries in 1 minute."""
    thresh = config.DNS_TUNNEL_QUERY_THRESHOLD
    rows = _rows(conn, f"""
        SELECT client_ip,
               strftime('%Y-%m-%d %H:%M', ts) as minute,
               COUNT(*) as cnt
        FROM   dns_queries
        GROUP BY client_ip, minute
        HAVING cnt > {thresh}
        ORDER BY cnt DESC
        LIMIT 50
    """)
    return [{
        "src_ip":      r["client_ip"],
        "dst_ip":      "",
        "username":    "",
        "description": (
            f"Possible DNS tunneling: {r['cnt']} queries from {r['client_ip']} "
            f"in 1 minute ({r['minute']})"
        ),
        "event_ids":   [],
    } for r in rows]


def r008_large_outbound_transfer(conn):
    """Single firewall-allowed session with > LARGE_TRANSFER_BYTES sent."""
    thresh = config.LARGE_TRANSFER_BYTES
    rows = _rows(conn, f"""
        SELECT id, src_ip, dst_ip, sent_bytes, application, ts
        FROM   events
        WHERE  action = 'Allow'
          AND  sent_bytes > {thresh}
        ORDER BY sent_bytes DESC
        LIMIT 100
    """)
    return [{
        "src_ip":      r["src_ip"],
        "dst_ip":      r["dst_ip"],
        "username":    "",
        "description": (
            f"Large outbound transfer: {r['sent_bytes']:,} bytes "
            f"from {r['src_ip']} → {r['dst_ip']}  app={r['application']}"
        ),
        "event_ids":   [r["id"]],
    } for r in rows]


def r009_port_scan(conn):
    """Single source hitting > PORT_SCAN_THRESHOLD distinct dst_ports in 1 minute."""
    window = config.PORT_SCAN_WINDOW_SEC
    thresh = config.PORT_SCAN_THRESHOLD
    rows = _rows(conn, f"""
        SELECT src_ip,
               strftime('%Y-%m-%d %H:%M', ts) as minute,
               COUNT(DISTINCT dst_port) as ports,
               GROUP_CONCAT(DISTINCT dst_ip) as targets
        FROM   events
        WHERE  action = 'Deny'
          AND  ts >= datetime('now', '-{window*10} seconds')
        GROUP BY src_ip, minute
        HAVING ports > {thresh}
        ORDER BY ports DESC
        LIMIT 50
    """)
    return [{
        "src_ip":      r["src_ip"],
        "dst_ip":      "",
        "username":    "",
        "description": (
            f"Port scan: {r['ports']} distinct ports scanned by {r['src_ip']} "
            f"at {r['minute']} targeting: {(r['targets'] or '')[:120]}"
        ),
        "event_ids":   [],
    } for r in rows]


def r010_p2p_torrent(conn):
    """Content filter blocked P2P/Torrent traffic."""
    rows = _rows(conn, """
        SELECT id, src_ip, dst_ip, application, ts,
               COUNT(*) as cnt
        FROM   events
        WHERE  log_component = 'Application'
          AND  action = 'Deny'
          AND  (
            application LIKE '%Torrent%'
            OR application LIKE '%P2P%'
            OR application LIKE '%BitTorrent%'
          )
        GROUP BY src_ip
        HAVING cnt >= 3
        ORDER BY cnt DESC
        LIMIT 100
    """)
    return [{
        "src_ip":      r["src_ip"],
        "dst_ip":      r["dst_ip"],
        "username":    "",
        "description": f"P2P/Torrent: {r['cnt']} blocked events from {r['src_ip']} ({r['application']})",
        "event_ids":   [r["id"]],
    } for r in rows]


def r011_antivirus_alert(conn):
    """Anti-Virus detection in HTTP/FTP/SMTP."""
    rows = _rows(conn, """
        SELECT id, src_ip, dst_ip, url, threat_name, log_component, ts
        FROM   events
        WHERE  log_type = 'Anti-Virus'
          OR  (log_type='Content Filtering' AND threat_name != '')
        ORDER BY ts DESC
        LIMIT 200
    """)
    return [{
        "src_ip":      r["src_ip"],
        "dst_ip":      r["dst_ip"],
        "username":    "",
        "description": (
            f"Virus/Malware detected via {r['log_component']}: "
            f"{r['threat_name']} from {r['src_ip']} "
            f"url={r['url'] or '-'}"
        ),
        "event_ids":   [r["id"]],
    } for r in rows]


def r012_ssl_vpn_brute_force(conn):
    """Multiple SSL-VPN or VPN Portal Auth failures."""
    rows = _rows(conn, """
        SELECT id, username, src_ip, ts, COUNT(*) as cnt
        FROM   events
        WHERE  log_component IN ('SSL_VPN','VPN_Portal_Authentication','My_Account_Authentication')
          AND  action = 'Deny'
          AND  ts >= datetime('now', '-600 seconds')
        GROUP BY src_ip
        HAVING cnt >= 5
        ORDER BY cnt DESC
        LIMIT 50
    """)
    return [{
        "src_ip":      r["src_ip"],
        "dst_ip":      "",
        "username":    r["username"],
        "description": f"VPN Brute Force: {r['cnt']} failures from {r['src_ip']}",
        "event_ids":   [r["id"]],
    } for r in rows]


def r013_external_ssh_to_firewall(conn):
    """SSH (TCP/22) attempts to firewall management interface from external."""
    rows = _rows(conn, """
        SELECT id, src_ip, dst_ip, ts
        FROM   events
        WHERE  log_component = 'Appliance Access'
          AND  dst_port = 22
          AND  src_ip NOT LIKE '10.%'
          AND  src_ip NOT LIKE '172.%'
          AND  src_ip NOT LIKE '192.168.%'
        ORDER BY ts DESC
        LIMIT 100
    """)
    return [{
        "src_ip":      r["src_ip"],
        "dst_ip":      r["dst_ip"],
        "username":    "",
        "description": f"External SSH attempt to firewall from {r['src_ip']} at {r['ts']}",
        "event_ids":   [r["id"]],
    } for r in rows]


def r014_repeated_deny_same_src(conn):
    """Single external IP generating > 500 Deny events (possible scanner/attacker)."""
    rows = _rows(conn, """
        SELECT src_ip, COUNT(*) as cnt,
               COUNT(DISTINCT dst_ip) as targets,
               MIN(ts) as first, MAX(ts) as last
        FROM   events
        WHERE  action = 'Deny'
          AND  src_ip NOT LIKE '10.%'
          AND  src_ip NOT LIKE '172.%'
          AND  src_ip NOT LIKE '192.168.%'
          AND  src_ip != ''
        GROUP BY src_ip
        HAVING cnt > 500
        ORDER BY cnt DESC
        LIMIT 50
    """)
    return [{
        "src_ip":      r["src_ip"],
        "dst_ip":      "",
        "username":    "",
        "description": (
            f"Aggressive external IP: {r['cnt']:,} denies from {r['src_ip']} "
            f"targeting {r['targets']} hosts  ({r['first']} → {r['last']})"
        ),
        "event_ids":   [],
    } for r in rows]


def r015_suspicious_dns_query(conn):
    """DNS queries to known suspicious TLDs / DGA-like long labels."""
    rows = _rows(conn, """
        SELECT client_ip, query_name, COUNT(*) as cnt
        FROM   dns_queries
        WHERE (
            length(query_name) > 50
            OR query_name LIKE '%.xyz'
            OR query_name LIKE '%.top'
            OR query_name LIKE '%.tk'
            OR query_name LIKE '%.ml'
            OR query_name LIKE '%.ga'
            OR query_name LIKE '%.cf'
            OR query_name LIKE '%.pw'
            OR query_name LIKE '%.website'
            OR query_name LIKE '%.click'
            OR query_name LIKE '%.download'
        )
        GROUP BY client_ip, query_name
        HAVING cnt >= 2
        ORDER BY cnt DESC
        LIMIT 200
    """)
    return [{
        "src_ip":      r["client_ip"],
        "dst_ip":      "",
        "username":    "",
        "description": f"Suspicious DNS query: {r['query_name']} ({r['cnt']}×) from {r['client_ip']}",
        "event_ids":   [],
    } for r in rows]


# ─────────────────────────────────────────────────────────────────────────────
# Rule registry
# ─────────────────────────────────────────────────────────────────────────────

RULES = [
    {"id": "R001", "name": "C2 Communication",            "severity": "Critical", "fn": r001_c2_communication},
    {"id": "R002", "name": "DoS Attack",                  "severity": "High",     "fn": r002_dos_attack},
    {"id": "R003", "name": "IPS Signature Triggered",     "severity": "High",     "fn": r003_ips_signature},
    {"id": "R004", "name": "IP Spoofing Attempt",         "severity": "High",     "fn": r004_ip_spoof},
    {"id": "R005", "name": "RADIUS Brute Force",          "severity": "High",     "fn": r005_radius_brute_force},
    {"id": "R006", "name": "Admin Login from External",   "severity": "Critical", "fn": r006_admin_login_unusual},
    {"id": "R007", "name": "DNS Tunneling",               "severity": "High",     "fn": r007_dns_tunneling},
    {"id": "R008", "name": "Large Outbound Transfer",     "severity": "Medium",   "fn": r008_large_outbound_transfer},
    {"id": "R009", "name": "Port Scan Detected",          "severity": "High",     "fn": r009_port_scan},
    {"id": "R010", "name": "P2P / Torrent Traffic",       "severity": "Low",      "fn": r010_p2p_torrent},
    {"id": "R011", "name": "Antivirus / Malware Alert",   "severity": "High",     "fn": r011_antivirus_alert},
    {"id": "R012", "name": "VPN Brute Force",             "severity": "High",     "fn": r012_ssl_vpn_brute_force},
    {"id": "R013", "name": "External SSH to Firewall",    "severity": "Critical", "fn": r013_external_ssh_to_firewall},
    {"id": "R014", "name": "Repeated Denies (Scanner)",   "severity": "Medium",   "fn": r014_repeated_deny_same_src},
    {"id": "R015", "name": "Suspicious DNS Query (DGA?)", "severity": "Medium",   "fn": r015_suspicious_dns_query},
]
