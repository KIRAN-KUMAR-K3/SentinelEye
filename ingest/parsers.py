"""
ingest/parsers.py
Parsers for every log type found on the NFS mount.

Supported formats
  ─ Sophos XG/XGS firewall  (key=value syslog)
  ─ BIND9 DNS query log
  ─ FreeRADIUS auth log
  ─ ISC dhcpd log
  ─ Mac_IP mapping log (numbered day files)
"""

import re
from datetime import datetime
from typing import Optional

# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

MONTH_MAP = {
    "Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4, "May": 5, "Jun": 6,
    "Jul": 7, "Aug": 8, "Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12,
}


def _try_int(v: str) -> Optional[int]:
    try:
        return int(v)
    except (ValueError, TypeError):
        return None


# ─────────────────────────────────────────────────────────────────────────────
# Sophos XG/XGS  (key=value syslog)
# ─────────────────────────────────────────────────────────────────────────────

# Match:  key="quoted value"  OR  key=unquoted_token
_KV_RE = re.compile(r'(\w+)=("(?:[^"\\]|\\.)*"|\S+)')
# Syslog prefix:  Mon  DD HH:MM:SS  hostname
_SYSLOG_HDR = re.compile(
    r'^(\w{3})\s+(\d{1,2})\s+(\d{2}:\d{2}:\d{2})\s+(\S+)\s+(.*)', re.DOTALL
)


def parse_sophos_kv(line: str) -> dict:
    """Return a flat dict from one Sophos firewall log line."""
    kv: dict = {}
    m = _SYSLOG_HDR.match(line)
    if m:
        kv["_syslog_mon"]  = m.group(1)
        kv["_syslog_day"]  = m.group(2)
        kv["_syslog_time"] = m.group(3)
        kv["_hostname"]    = m.group(4)
        rest = m.group(5)
    else:
        rest = line

    for km in _KV_RE.finditer(rest):
        key = km.group(1)
        val = km.group(2)
        if val.startswith('"') and val.endswith('"'):
            val = val[1:-1]
        kv[key] = val

    return kv


def sophos_to_event(kv: dict, file_source: str) -> Optional[dict]:
    """Convert a parsed Sophos KV dict into a normalised events row."""
    # Build timestamp from date= + time= fields
    ts_str = None
    if kv.get("date") and kv.get("time"):
        ts_str = f"{kv['date']} {kv['time']}"
    elif kv.get("_syslog_mon"):
        # fall back to syslog header (no year — use current year heuristic)
        mon = MONTH_MAP.get(kv["_syslog_mon"], 1)
        day = kv.get("_syslog_day", "1").zfill(2)
        t   = kv.get("_syslog_time", "00:00:00")
        ts_str = f"2025-{mon:02d}-{day} {t}"

    log_type      = kv.get("log_type", "")
    log_component = kv.get("log_component", "")
    log_subtype   = kv.get("log_subtype", "")
    priority      = kv.get("priority", "Information")

    # Normalise action
    status = kv.get("status", kv.get("log_subtype", "")).strip()
    action_map = {
        "Allow": "Allow", "Allowed": "Allow",
        "Deny": "Deny",   "Denied": "Deny",
        "Drop": "Deny",   "Alert": "Alert",
        "System": "Info", "Admin": "Info",
    }
    action = action_map.get(status, status or "Unknown")

    return {
        "ts":            ts_str,
        "log_source":    "firewall",
        "log_type":      log_type,
        "log_component": log_component,
        "log_subtype":   log_subtype,
        "severity":      priority,
        "src_ip":        kv.get("src_ip") or kv.get("sourceip", ""),
        "dst_ip":        kv.get("dst_ip") or kv.get("destinationip", ""),
        "src_port":      _try_int(kv.get("src_port")),
        "dst_port":      _try_int(kv.get("dst_port")),
        "protocol":      kv.get("protocol", ""),
        "action":        action,
        "username":      kv.get("user_name", kv.get("login_user", "")),
        "url":           kv.get("url", ""),
        "application":   kv.get("application_name", kv.get("application", "")),
        "threat_name":   kv.get("threatname", ""),
        "sent_bytes":    _try_int(kv.get("sent_bytes")),
        "recv_bytes":    _try_int(kv.get("recv_bytes")),
        "fw_rule_name":  kv.get("fw_rule_name", ""),
        "message":       kv.get("message", ""),
        "raw":           None,   # don't store raw to save space; set to raw line if needed
        "file_source":   file_source,
    }


# ─────────────────────────────────────────────────────────────────────────────
# BIND9 DNS query log
# ─────────────────────────────────────────────────────────────────────────────

# 11-Apr-2025 15:45:44.391 queries: info: client @0x7f18dd2dffa8 10.61.244.157#64047 (domain): query: DOMAIN IN TYPE FLAGS (server)
_DNS_RE = re.compile(
    r'^(\d{2}-\w{3}-\d{4})\s+(\d{2}:\d{2}:\d{2})\.\d+\s+queries:\s+\S+:\s+'
    r'client\s+@\S+\s+(\d[\d.]+)#(\d+)\s+\([^)]*\):\s+query:\s+'
    r'(\S+)\s+IN\s+(\w+)\s+([+\-\w]*)\s+\((\S+)\)',
    re.IGNORECASE,
)


def parse_dns_line(line: str, file_source: str) -> Optional[dict]:
    m = _DNS_RE.match(line.strip())
    if not m:
        return None
    date_str, time_str, client_ip, client_port, qname, qtype, flags, server_ip = m.groups()
    # Parse  DD-Mon-YYYY
    parts = date_str.split("-")
    day, mon_str, year = parts[0], parts[1], parts[2]
    mon = MONTH_MAP.get(mon_str, 1)
    ts = f"{year}-{mon:02d}-{int(day):02d} {time_str}"
    return {
        "ts":          ts,
        "client_ip":   client_ip,
        "client_port": _try_int(client_port),
        "query_name":  qname.rstrip(".").lower(),
        "query_type":  qtype.upper(),
        "flags":       flags,
        "server_ip":   server_ip,
        "file_source": file_source,
    }


# ─────────────────────────────────────────────────────────────────────────────
# FreeRADIUS auth log
# ─────────────────────────────────────────────────────────────────────────────

# Two common formats:
# 1) Detail file (multi-line records separated by blank lines)
# 2) Single-line:  Mon DD HH:MM:SS 2019 : Auth: (N) Login OK: [user] (from client X port Y)

_RADIUS_LOGIN_OK  = re.compile(
    r'(\w{3})\s+(\d+)\s+(\d{2}:\d{2}:\d{2})\s+(\d{4})\s+:\s+Auth:.*Login OK:\s+\[([^\]]+)\].*from client\s+(\S+)', re.I
)
_RADIUS_LOGIN_BAD = re.compile(
    r'(\w{3})\s+(\d+)\s+(\d{2}:\d{2}:\d{2})\s+(\d{4})\s+:\s+Auth:.*Login incorrect.*\[([^\]]+)\].*from client\s+(\S+)', re.I
)
# Detail-file block parser  ─  accumulate lines until blank line, then extract
_RADIUS_ACCT_RE   = re.compile(r'^\s+(\S[\S\s]*?)\s+=\s+(.+)$')


def _parse_radius_singleline(line: str, file_source: str) -> Optional[dict]:
    for pattern, result in (
        (_RADIUS_LOGIN_OK,  "Accept"),
        (_RADIUS_LOGIN_BAD, "Reject"),
    ):
        m = pattern.match(line)
        if m:
            mon_str, day, t, year, username, nas_ip = m.groups()
            mon = MONTH_MAP.get(mon_str, 1)
            ts  = f"{year}-{mon:02d}-{int(day):02d} {t}"
            return {
                "ts":          ts,
                "username":    username,
                "nas_ip":      nas_ip,
                "client_ip":   "",
                "result":      result,
                "reason":      "",
                "file_source": file_source,
            }
    return None


def parse_radius_block(block_lines: list, file_source: str) -> Optional[dict]:
    """Parse a FreeRADIUS detail-file record block."""
    if not block_lines:
        return None
    header = block_lines[0].strip()
    # Header: "Mon DD HH:MM:SS YYYY"
    hm = re.match(r'(\w{3})\s+(\d+)\s+(\d{2}:\d{2}:\d{2})\s+(\d{4})', header)
    if not hm:
        return None
    mon_str, day, t, year = hm.groups()
    mon = MONTH_MAP.get(mon_str, 1)
    ts  = f"{year}-{mon:02d}-{int(day):02d} {t}"

    attrs: dict = {}
    for line in block_lines[1:]:
        m = _RADIUS_ACCT_RE.match(line)
        if m:
            k, v = m.group(1).strip(), m.group(2).strip().strip('"')
            attrs[k] = v

    username   = attrs.get("User-Name", "")
    nas_ip     = attrs.get("NAS-IP-Address", attrs.get("Client-IP-Address", ""))
    client_ip  = attrs.get("Framed-IP-Address", "")
    pkt_type   = attrs.get("Packet-Type", attrs.get("packet-type", ""))
    acct_status= attrs.get("Acct-Status-Type", "")

    result = "Unknown"
    if "Access-Accept" in pkt_type:   result = "Accept"
    elif "Access-Reject" in pkt_type: result = "Reject"
    elif acct_status:                 result = f"Acct-{acct_status}"

    return {
        "ts":          ts,
        "username":    username,
        "nas_ip":      nas_ip,
        "client_ip":   client_ip,
        "result":      result,
        "reason":      attrs.get("Reply-Message", ""),
        "file_source": file_source,
    }


# ─────────────────────────────────────────────────────────────────────────────
# ISC dhcpd log
# ─────────────────────────────────────────────────────────────────────────────

# Jan  1 00:00:01 host dhcpd: DHCPACK on 10.x.x.x to aa:bb:cc:dd:ee:ff (hostname) via eth0
# Jan  1 00:00:01 host dhcpd: DHCPREQUEST for 10.x.x.x from aa:bb:cc:dd:ee:ff (host) via eth0
_DHCP_RE = re.compile(
    r'^(\w{3})\s+(\d+)\s+(\d{2}:\d{2}:\d{2})\s+\S+\s+dhcpd:\s+'
    r'(DHCP\w+)(?:\s+(?:on|for|to)\s+([\d.]+))?\s+'
    r'(?:to|from)?\s*([\da-fA-F:]{17})?'
    r'(?:\s+\(([^)]*)\))?(?:\s+via\s+(\S+))?',
    re.I
)


def parse_dhcp_line(line: str, file_source: str, year_hint: str = "2025") -> Optional[dict]:
    m = _DHCP_RE.match(line.strip())
    if not m:
        return None
    mon_str, day, t, event_type, ip, mac, hostname, iface = m.groups()
    mon = MONTH_MAP.get(mon_str, 1)
    ts  = f"{year_hint}-{mon:02d}-{int(day):02d} {t}"
    return {
        "ts":          ts,
        "event_type":  event_type.upper(),
        "ip_address":  ip or "",
        "mac_address": (mac or "").lower(),
        "hostname":    hostname or "",
        "interface":   iface or "",
        "file_source": file_source,
    }


# ─────────────────────────────────────────────────────────────────────────────
# Mac_IP mapping logs  (numbered day files like 01.01.20.gz)
# Lines may look like standard syslog with MAC→IP bind events
# or custom format:  IP  MAC  hostname  interface
# ─────────────────────────────────────────────────────────────────────────────

_MACIP_RE = re.compile(
    r'(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}|\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2}).*?'
    r'([\da-fA-F]{2}(?:[:\-][\da-fA-F]{2}){5}).*?([\d.]{7,15})'
)


def parse_macip_line(line: str, file_source: str) -> Optional[dict]:
    m = _MACIP_RE.search(line)
    if not m:
        return None
    ts_raw, mac, ip = m.group(1), m.group(2), m.group(3)
    return {
        "ts":          ts_raw,
        "mac_address": mac.lower().replace("-", ":"),
        "ip_address":  ip,
        "interface":   "",
        "file_source": file_source,
    }


# ─────────────────────────────────────────────────────────────────────────────
# Router / dispatcher
# ─────────────────────────────────────────────────────────────────────────────

def classify_firewall_file(filename: str) -> str:
    """Return the log_component hint from the filename."""
    name = filename.lower()
    for token in (
        "atp", "application_filter", "http", "web_filter", "web_server",
        "dos_attack", "firewall_rules", "appliance_access", "icmp",
        "invalid_traffic", "ip_spoof", "anomaly", "signatures",
        "smtp", "ftp", "anti_virus", "anti_spam",
        "cli", "gui", "dhcp", "ipsec", "ssl_vpn", "vpn", "ha",
        "interface", "appliance", "up2date",
    ):
        if token in name:
            return token.replace("_", " ").title()
    return "Unknown"
