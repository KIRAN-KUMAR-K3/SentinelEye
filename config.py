"""
config.py — SentinelEye SIEM Configuration
Indian Institute of Science | ISO Security Team
Edit paths and thresholds to match your environment.
"""
import os

# ── Mount base ───────────────────────────────────────────────────────────────
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
DB_PATH = os.path.expanduser("~/siem.db")   # expanduser so ~ resolves correctly

# ── Ingestion ────────────────────────────────────────────────────────────────
# IMPORTANT: Keep MAX_WORKERS at 4 or less to avoid SQLite write contention.
# The ingester uses a single-writer queue so this controls decompression parallelism.
MAX_WORKERS   = 4      # parallel gz decompressor threads
BATCH_SIZE    = 1000   # rows per DB commit (smaller = less memory, more commits)
SKIP_INGESTED = True   # skip files already recorded in ingested_files table

# ── Dashboard ─────────────────────────────────────────────────────────────────
DASHBOARD_HOST = "0.0.0.0"
DASHBOARD_PORT = 5000
SECRET_KEY     = "sentineleye-iisc-iso-2025"

# ── Alerting ──────────────────────────────────────────────────────────────────
ALERT_EMAIL = None   # set to "soc@iisc.ac.in" to enable email alerts
SMTP_HOST   = "localhost"
SMTP_PORT   = 25

# ── Detection thresholds ──────────────────────────────────────────────────────
BRUTE_FORCE_WINDOW_SEC     = 300          # 5-minute window for brute-force detection
BRUTE_FORCE_THRESHOLD      = 10           # RADIUS rejects before brute-force alert
PORT_SCAN_WINDOW_SEC       = 60           # window for port scan detection
PORT_SCAN_THRESHOLD        = 20           # distinct dst ports before port-scan alert
DNS_TUNNEL_QUERY_THRESHOLD = 5000         # queries/min — IISc DNS resolvers are high volume
LARGE_TRANSFER_BYTES       = 100_000_000  # 100 MB outbound = large transfer alert
