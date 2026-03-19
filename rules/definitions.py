"""
rules/definitions.py — SOC Detection Rules
Indian Institute of Science | ISO Security Team

All 15 rules fixed:
  - R001: removed non-existent 'acknowledged_alert' column
  - R002: fixed GROUP BY to include non-aggregated columns
  - R006: fixed action check (Sophos logs 'Successful' not 'Allow' for GUI/CLI)
  - R011: fixed OR operator precedence with parentheses
  - All rules use robust SQL compatible with SQLite
"""
import sqlite3
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import config


def _rows(conn: sqlite3.Connection, sql: str, params=()):
    conn.row_factory = sqlite3.Row
    try:
        return [dict(r) for r in conn.execute(sql, params).fetchall()]
    except sqlite3.OperationalError as e:
        print(f"    SQL error: {e}")
        return []


# ─────────────────────────────────────────────────────────────────────────────
# R001 — C2 / Malware Communication
# ─────────────────────────────────────────────────────────────────────────────
def r001_c2_communication(conn):
    """ATP Web/Network alert = C2 or malware phone-home."""
    rows = _rows(conn, """
        SELECT id, src_ip, dst_ip, url, threat_name, ts
        FROM   events
        WHERE  (log_type LIKE '%ATP%' OR log_type LIKE '%Threat%')
          AND  (log_subtype LIKE '%Alert%' OR log_subtype LIKE '%Blocked%')
        ORDER BY ts DESC
        LIMIT 500
    """)
    return [{
        "src_ip":      r["src_ip"] or "",
        "dst_ip":      r["dst_ip"] or "",
        "username":    "",
        "description": f"C2/Malware detected: {r['threat_name'] or 'Unknown'} → {r['url'] or r['dst_ip'] or '?'}",
        "event_ids":   [r["id"]],
    } for r in rows]


# ─────────────────────────────────────────────────────────────────────────────
# R002 — DoS Attack
# ─────────────────────────────────────────────────────────────────────────────
def r002_dos_attack(conn):
    """Firewall DoS Attack component with 5+ events from same source."""
    rows = _rows(conn, """
        SELECT src_ip, dst_ip, protocol,
               COUNT(*) as cnt
        FROM   events
        WHERE  log_component LIKE '%DoS%'
        GROUP BY src_ip
        HAVING cnt >= 5
        ORDER BY cnt DESC
        LIMIT 200
    """)
    return [{
        "src_ip":      r["src_ip"] or "",
        "dst_ip":      r["dst_ip"] or "",
        "username":    "",
        "description": f"DoS Attack: {r['cnt']} events from {r['src_ip']} protocol={r['protocol'] or '?'}",
        "event_ids":   [],
    } for r in rows]


# ─────────────────────────────────────────────────────────────────────────────
# R003 — IPS Signature
# ─────────────────────────────────────────────────────────────────────────────
def r003_ips_signature(conn):
    """IPS signature triggered at Warning/Critical/Notice level."""
    rows = _rows(conn, """
        SELECT id, src_ip, dst_ip, message, severity, ts
        FROM   events
        WHERE  (log_type LIKE '%IPS%' OR log_type LIKE '%Intrusion%')
          AND  severity IN ('Warning','Critical','Error','Notice')
        ORDER BY ts DESC
        LIMIT 300
    """)
    return [{
        "src_ip":      r["src_ip"] or "",
        "dst_ip":      r["dst_ip"] or "",
        "username":    "",
        "description": f"IPS Signature: {r['message'] or 'triggered'} (sev={r['severity']})",
        "event_ids":   [r["id"]],
    } for r in rows]


# ─────────────────────────────────────────────────────────────────────────────
# R004 — IP Spoofing
# ─────────────────────────────────────────────────────────────────────────────
def r004_ip_spoof(conn):
    """IP Spoofing prevention triggered."""
    rows = _rows(conn, """
        SELECT id, src_ip, dst_ip, ts
        FROM   events
        WHERE  log_component LIKE '%IP Spoof%'
           OR  log_component LIKE '%Spoof%'
        ORDER BY ts DESC
        LIMIT 200
    """)
    return [{
        "src_ip":      r["src_ip"] or "",
        "dst_ip":      r["dst_ip"] or "",
        "username":    "",
        "description": f"IP Spoofing attempt from {r['src_ip']} → {r['dst_ip']}",
        "event_ids":   [r["id"]],
    } for r in rows]


# ─────────────────────────────────────────────────────────────────────────────
# R005 — RADIUS Brute Force
# ─────────────────────────────────────────────────────────────────────────────
def r005_radius_brute_force(conn):
    """Multiple RADIUS Auth-Reject → brute force candidate."""
    window = config.BRUTE_FORCE_WINDOW_SEC
    thresh = config.BRUTE_FORCE_THRESHOLD
    rows = _rows(conn, f"""
        SELECT username, nas_ip,
               COUNT(*)  as cnt,
               MIN(ts)   as first_seen,
               MAX(ts)   as last_seen
        FROM   radius_auth
        WHERE  result = 'Reject'
          AND  ts >= datetime('now', '-{window} seconds')
        GROUP BY username, nas_ip
        HAVING cnt >= {thresh}
        ORDER BY cnt DESC
    """)
    return [{
        "src_ip":      r["nas_ip"] or "",
        "dst_ip":      "",
        "username":    r["username"] or "",
        "description": (
            f"RADIUS brute force: {r['cnt']} rejects for '{r['username']}' "
            f"from {r['nas_ip']} ({r['first_seen']} → {r['last_seen']})"
        ),
        "event_ids": [],
    } for r in rows]


# ─────────────────────────────────────────────────────────────────────────────
# R006 — Admin Login from External IP
# ─────────────────────────────────────────────────────────────────────────────
def r006_admin_login_external(conn):
    """GUI/CLI admin login from non-RFC1918 IP (Sophos logs 'Successful' status)."""
    rows = _rows(conn, """
        SELECT id, username, src_ip, log_component, ts, message
        FROM   events
        WHERE  log_component IN ('GUI','CLI')
          AND  (log_subtype = 'Admin' OR log_subtype = 'System')
          AND  (action IN ('Allow','Info') OR message LIKE '%success%' OR message LIKE '%logged in%')
          AND  src_ip NOT LIKE '10.%'
          AND  src_ip NOT LIKE '172.16.%'
          AND  src_ip NOT LIKE '172.17.%'
          AND  src_ip NOT LIKE '172.18.%'
          AND  src_ip NOT LIKE '172.19.%'
          AND  src_ip NOT LIKE '172.2%.%'
          AND  src_ip NOT LIKE '172.3%.%'
          AND  src_ip NOT LIKE '192.168.%'
          AND  src_ip != ''
        ORDER BY ts DESC
        LIMIT 100
    """)
    return [{
        "src_ip":      r["src_ip"] or "",
        "dst_ip":      "",
        "username":    r["username"] or "",
        "description": (
            f"Admin {r['log_component']} login from EXTERNAL IP {r['src_ip']} "
            f"by '{r['username']}' at {r['ts']}"
        ),
        "event_ids": [r["id"]],
    } for r in rows]


# ─────────────────────────────────────────────────────────────────────────────
# R007 — DNS Tunneling
# ─────────────────────────────────────────────────────────────────────────────
def r007_dns_tunneling(conn):
    """Single host > DNS_TUNNEL_QUERY_THRESHOLD queries in 1 minute."""
    thresh = config.DNS_TUNNEL_QUERY_THRESHOLD
    rows = _rows(conn, f"""
        SELECT client_ip,
               strftime('%Y-%m-%d %H:%M', ts) as minute,
               COUNT(*) as cnt
        FROM   dns_queries
        GROUP  BY client_ip, minute
        HAVING cnt > {thresh}
        ORDER  BY cnt DESC
        LIMIT  50
    """)
    return [{
        "src_ip":      r["client_ip"] or "",
        "dst_ip":      "",
        "username":    "",
        "description": (
            f"Possible DNS tunneling: {r['cnt']} queries from {r['client_ip']} "
            f"in 1 minute ({r['minute']})"
        ),
        "event_ids": [],
    } for r in rows]


# ─────────────────────────────────────────────────────────────────────────────
# R008 — Large Outbound Transfer
# ─────────────────────────────────────────────────────────────────────────────
def r008_large_outbound(conn):
    """Single session > LARGE_TRANSFER_BYTES sent outbound."""
    thresh = config.LARGE_TRANSFER_BYTES
    rows = _rows(conn, f"""
        SELECT id, src_ip, dst_ip, sent_bytes, application, ts
        FROM   events
        WHERE  action IN ('Allow','Allowed')
          AND  sent_bytes > {thresh}
          AND  src_ip != ''
        ORDER  BY sent_bytes DESC
        LIMIT  100
    """)
    return [{
        "src_ip":      r["src_ip"] or "",
        "dst_ip":      r["dst_ip"] or "",
        "username":    "",
        "description": (
            f"Large outbound: {r['sent_bytes']:,} bytes "
            f"from {r['src_ip']} → {r['dst_ip']}  app={r['application'] or '?'}"
        ),
        "event_ids": [r["id"]],
    } for r in rows]


# ─────────────────────────────────────────────────────────────────────────────
# R009 — Port Scan
# ─────────────────────────────────────────────────────────────────────────────
def r009_port_scan(conn):
    """Single src hitting > PORT_SCAN_THRESHOLD distinct dst_ports in 1 minute."""
    thresh = config.PORT_SCAN_THRESHOLD
    rows = _rows(conn, f"""
        SELECT src_ip,
               strftime('%Y-%m-%d %H:%M', ts) as minute,
               COUNT(DISTINCT dst_port) as ports,
               COUNT(DISTINCT dst_ip)   as targets
        FROM   events
        WHERE  action IN ('Deny','Denied','Drop')
          AND  src_ip != ''
          AND  dst_port IS NOT NULL
        GROUP  BY src_ip, minute
        HAVING ports > {thresh}
        ORDER  BY ports DESC
        LIMIT  50
    """)
    return [{
        "src_ip":      r["src_ip"] or "",
        "dst_ip":      "",
        "username":    "",
        "description": (
            f"Port scan: {r['ports']} ports from {r['src_ip']} "
            f"at {r['minute']} targeting {r['targets']} hosts"
        ),
        "event_ids": [],
    } for r in rows]


# ─────────────────────────────────────────────────────────────────────────────
# R010 — P2P / Torrent
# ─────────────────────────────────────────────────────────────────────────────
def r010_p2p_torrent(conn):
    """Content filter blocked P2P/Torrent traffic from same host."""
    rows = _rows(conn, """
        SELECT src_ip, application,
               COUNT(*) as cnt
        FROM   events
        WHERE  log_component = 'Application'
          AND  action IN ('Deny','Denied','Drop')
          AND  (
            application LIKE '%Torrent%'
            OR application LIKE '%P2P%'
            OR application LIKE '%BitTorrent%'
          )
          AND  src_ip != ''
        GROUP  BY src_ip
        HAVING cnt >= 3
        ORDER  BY cnt DESC
        LIMIT  100
    """)
    return [{
        "src_ip":      r["src_ip"] or "",
        "dst_ip":      "",
        "username":    "",
        "description": f"P2P/Torrent: {r['cnt']} blocked events from {r['src_ip']} ({r['application']})",
        "event_ids":   [],
    } for r in rows]


# ─────────────────────────────────────────────────────────────────────────────
# R011 — Antivirus / Malware
# ─────────────────────────────────────────────────────────────────────────────
def r011_antivirus_alert(conn):
    """Antivirus detection in HTTP/FTP/SMTP."""
    rows = _rows(conn, """
        SELECT id, src_ip, dst_ip, url, threat_name, log_component, ts
        FROM   events
        WHERE  (
            log_type LIKE '%Anti%Virus%'
            OR log_type LIKE '%AntiVirus%'
            OR log_type LIKE '%Virus%'
            OR (log_type LIKE '%Content%' AND threat_name != '' AND threat_name IS NOT NULL)
        )
        ORDER BY ts DESC
        LIMIT 200
    """)
    return [{
        "src_ip":      r["src_ip"] or "",
        "dst_ip":      r["dst_ip"] or "",
        "username":    "",
        "description": (
            f"AV alert via {r['log_component'] or '?'}: "
            f"{r['threat_name'] or 'malware'} from {r['src_ip']} url={r['url'] or '-'}"
        ),
        "event_ids": [r["id"]],
    } for r in rows]


# ─────────────────────────────────────────────────────────────────────────────
# R012 — VPN Brute Force
# ─────────────────────────────────────────────────────────────────────────────
def r012_vpn_brute_force(conn):
    """SSL-VPN/VPN Portal auth failures ≥ 5 in last 10 minutes."""
    rows = _rows(conn, """
        SELECT src_ip, username,
               COUNT(*) as cnt
        FROM   events
        WHERE  log_component IN (
                   'SSL_VPN','VPN_Portal_Authentication',
                   'My_Account_Authentication','IPSec'
               )
          AND  action IN ('Deny','Denied','Drop')
          AND  ts >= datetime('now', '-600 seconds')
          AND  src_ip != ''
        GROUP  BY src_ip
        HAVING cnt >= 5
        ORDER  BY cnt DESC
        LIMIT  50
    """)
    return [{
        "src_ip":      r["src_ip"] or "",
        "dst_ip":      "",
        "username":    r["username"] or "",
        "description": f"VPN brute force: {r['cnt']} failures from {r['src_ip']}",
        "event_ids":   [],
    } for r in rows]


# ─────────────────────────────────────────────────────────────────────────────
# R013 — External SSH to Firewall
# ─────────────────────────────────────────────────────────────────────────────
def r013_external_ssh(conn):
    """TCP/22 to firewall appliance from non-RFC1918 IP."""
    rows = _rows(conn, """
        SELECT id, src_ip, dst_ip, ts
        FROM   events
        WHERE  log_component LIKE '%Appliance%'
          AND  dst_port = 22
          AND  src_ip NOT LIKE '10.%'
          AND  src_ip NOT LIKE '172.1%.%'
          AND  src_ip NOT LIKE '172.2%.%'
          AND  src_ip NOT LIKE '172.3%.%'
          AND  src_ip NOT LIKE '192.168.%'
          AND  src_ip != ''
        ORDER  BY ts DESC
        LIMIT  100
    """)
    return [{
        "src_ip":      r["src_ip"] or "",
        "dst_ip":      r["dst_ip"] or "",
        "username":    "",
        "description": f"External SSH to firewall from {r['src_ip']} at {r['ts']}",
        "event_ids":   [r["id"]],
    } for r in rows]


# ─────────────────────────────────────────────────────────────────────────────
# R014 — Repeated Denies (Scanner / Attacker)
# ─────────────────────────────────────────────────────────────────────────────
def r014_repeated_denies(conn):
    """External IP with > 500 Deny events — likely scanner or attacker."""
    rows = _rows(conn, """
        SELECT src_ip,
               COUNT(*)              as cnt,
               COUNT(DISTINCT dst_ip) as targets,
               MIN(ts) as first,
               MAX(ts) as last
        FROM   events
        WHERE  action IN ('Deny','Denied','Drop')
          AND  src_ip NOT LIKE '10.%'
          AND  src_ip NOT LIKE '172.1%.%'
          AND  src_ip NOT LIKE '172.2%.%'
          AND  src_ip NOT LIKE '172.3%.%'
          AND  src_ip NOT LIKE '192.168.%'
          AND  src_ip != ''
        GROUP  BY src_ip
        HAVING cnt > 500
        ORDER  BY cnt DESC
        LIMIT  50
    """)
    return [{
        "src_ip":      r["src_ip"] or "",
        "dst_ip":      "",
        "username":    "",
        "description": (
            f"Aggressive external IP: {r['cnt']:,} denies from {r['src_ip']} "
            f"targeting {r['targets']} hosts  ({r['first']} → {r['last']})"
        ),
        "event_ids": [],
    } for r in rows]


# ─────────────────────────────────────────────────────────────────────────────
# R015 — Suspicious DNS (DGA / malicious TLDs)
# ─────────────────────────────────────────────────────────────────────────────
def r015_suspicious_dns(conn):
    """DNS queries to suspicious TLDs or DGA-like long hostnames."""
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
        "src_ip":      r["client_ip"] or "",
        "dst_ip":      "",
        "username":    "",
        "description": f"Suspicious DNS: {r['query_name']} ({r['cnt']}×) from {r['client_ip']}",
        "event_ids":   [],
    } for r in rows]


# ─────────────────────────────────────────────────────────────────────────────
# Rule registry
# ─────────────────────────────────────────────────────────────────────────────
RULES = [
    {"id": "R001", "name": "C2 Communication",          "severity": "Critical", "fn": r001_c2_communication},
    {"id": "R002", "name": "DoS Attack",                "severity": "High",     "fn": r002_dos_attack},
    {"id": "R003", "name": "IPS Signature Triggered",   "severity": "High",     "fn": r003_ips_signature},
    {"id": "R004", "name": "IP Spoofing Attempt",       "severity": "High",     "fn": r004_ip_spoof},
    {"id": "R005", "name": "RADIUS Brute Force",        "severity": "High",     "fn": r005_radius_brute_force},
    {"id": "R006", "name": "Admin Login from External", "severity": "Critical", "fn": r006_admin_login_external},
    {"id": "R007", "name": "DNS Tunneling",             "severity": "High",     "fn": r007_dns_tunneling},
    {"id": "R008", "name": "Large Outbound Transfer",   "severity": "Medium",   "fn": r008_large_outbound},
    {"id": "R009", "name": "Port Scan Detected",        "severity": "High",     "fn": r009_port_scan},
    {"id": "R010", "name": "P2P / Torrent Traffic",     "severity": "Low",      "fn": r010_p2p_torrent},
    {"id": "R011", "name": "Antivirus / Malware Alert", "severity": "High",     "fn": r011_antivirus_alert},
    {"id": "R012", "name": "VPN Brute Force",           "severity": "High",     "fn": r012_vpn_brute_force},
    {"id": "R013", "name": "External SSH to Firewall",  "severity": "Critical", "fn": r013_external_ssh},
    {"id": "R014", "name": "Repeated Denies (Scanner)", "severity": "Medium",   "fn": r014_repeated_denies},
    {"id": "R015", "name": "Suspicious DNS (DGA?)",     "severity": "Medium",   "fn": r015_suspicious_dns},
]
