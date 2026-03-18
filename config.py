"""
SIEM Configuration
Edit these paths and settings to match your environment.
"""
import os

# ── Mount base ──────────────────────────────────────────────────────────────
MOUNT_BASE = "/mnt"

# ── Log source paths ─────────────────────────────────────────────────────────
LOG_SOURCES = {
    "firewall": {
        "base": "/mnt/Firewall-Logs/Firewall-Logs",
        "subdirs": [
            "Firewall", "IPS", "Content_Filtering",
            "Advanced_Threat_Protection", "Anti_Virus", "Anti_Spam",
            "Event", "System_Health", "SD-WAN",
            "Web_Server_Protection", "Mac_IP",
        ],
    },
    "dns": {
        "base": "/mnt/iDNS-Logs",
        "subdirs": ["idns1", "idns2"],
    },
    "radius": {
        "base": "/mnt/Radius-Logs",
        "subdirs": ["primary-radius", "secondary-radius"],
    },
    "dhcp": {
        "base": "/mnt/Radius-Logs",
        "subdirs": ["primary-dhcp", "secondary-dhcp"],
    },
}

# ── Database ─────────────────────────────────────────────────────────────────
DB_PATH = os.path.expanduser("~/siem.db")

# ── Ingestion ────────────────────────────────────────────────────────────────
MAX_WORKERS       = 8      # parallel gz decompressor threads
BATCH_SIZE        = 2000   # rows per DB commit
SKIP_INGESTED     = True   # skip files already recorded in db

# ── Dashboard ────────────────────────────────────────────────────────────────
DASHBOARD_HOST    = "0.0.0.0"
DASHBOARD_PORT    = 5000
SECRET_KEY        = "change-me-in-production"

# ── Alerting ─────────────────────────────────────────────────────────────────
# Set ALERT_EMAIL to enable email alerts (requires smtplib config in alerts/alerter.py)
ALERT_EMAIL       = None        # e.g. "soc@yourorg.com"
SMTP_HOST         = "localhost"
SMTP_PORT         = 25

# ── Thresholds (used by detection rules) ────────────────────────────────────
BRUTE_FORCE_WINDOW_SEC    = 300   # 5-minute window
BRUTE_FORCE_THRESHOLD     = 10    # failed logins before alert
PORT_SCAN_WINDOW_SEC      = 60
PORT_SCAN_THRESHOLD       = 20    # distinct dst ports from single src
DNS_TUNNEL_QUERY_THRESHOLD= 5000  # IISc DNS servers generate high volume — tune per investigation   # DNS queries/min from single host
LARGE_TRANSFER_BYTES      = 100_000_000  # 100 MB outbound
