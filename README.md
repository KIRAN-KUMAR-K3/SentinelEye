<div align="center">

<img src="https://capsule-render.vercel.app/api?type=waving&color=0:0d1117,50:1a1f35,100:0d47a1&height=220&section=header&text=SentinelEye%20SIEM&fontSize=56&fontColor=79c0ff&fontAlignY=38&desc=SOC%20Operations%20Platform%20%7C%20Indian%20Institute%20of%20Science%2C%20Bangalore&descAlignY=58&descColor=8b949e&animation=fadeIn" />

<br/>

[![Python](https://img.shields.io/badge/Python-3.10+-FFD43B?style=flat&logo=python&logoColor=blue)](https://python.org)
[![Flask](https://img.shields.io/badge/Flask-3.0-000000?style=flat&logo=flask&logoColor=white)](https://flask.palletsprojects.com)
[![SQLite](https://img.shields.io/badge/SQLite-WAL%20Mode-07405E?style=flat&logo=sqlite&logoColor=white)](https://sqlite.org)
[![Sophos](https://img.shields.io/badge/Sophos-XG%2FXGS-0C64A4?style=flat&logo=sophos&logoColor=white)](https://sophos.com)
[![License](https://img.shields.io/badge/License-MIT-3fb950?style=flat)](LICENSE)
[![Platform](https://img.shields.io/badge/Platform-Linux-FCC624?style=flat&logo=linux&logoColor=black)](https://linux.org)
[![Status](https://img.shields.io/badge/Status-Active-brightgreen?style=flat)]()
[![Author](https://img.shields.io/badge/Author-KIRAN%20KUMAR%20K-79c0ff?style=flat&logo=github)](https://github.com/KIRAN-KUMAR-K3)
[![IISc](https://img.shields.io/badge/Built%20at-IISc%20Bangalore-003087?style=flat)](https://iisc.ac.in)
[![Team](https://img.shields.io/badge/Team-ISO%20Security-ff6b35?style=flat)]()

<br/>

> **A fully local, high-performance SIEM built for real-world SOC operations.**
> **40M+ rows · 8 SOC views · 15 detection rules · 30+ REST APIs · Dark analyst dashboard.**

<br/>

[▶️ Installation](#%EF%B8%8F-installation--setup) · [🚀 How to Run](#-how-to-run-step-by-step) · [🖥️ Dashboard](#%EF%B8%8F-dashboard-views) · [🔎 Detection Rules](#-detection-rules) · [🔧 CLI Reference](#-cli-reference) · [🧠 Architecture](#-architecture)

</div>

---

## 🛡️ What is SentinelEye?

**SentinelEye** is a lightweight, purpose-built SIEM (Security Information and Event Management) platform developed by the **ISO Security Team** at the **Indian Institute of Science, Bangalore**. It processes compressed log archives from enterprise network infrastructure and turns raw log data into actionable threat intelligence.

Built on actual IISc production logs from a Sophos XG/XGS enterprise firewall deployment — covering firewalls, DNS servers, RADIUS authenticators, and DHCP servers — ingesting **40M+ parsed rows** into a fully local SQLite database.

```
🔥 40M+ rows  ·  15 rules  ·  8 SOC views  ·  30+ REST APIs  ·  100% local
```

---

## ⚡ Key Features

| Feature | Description |
|---------|-------------|
| 🗜️ **Smart Parallel Ingestion** | Worker threads decompress/parse · single writer thread commits · eliminates DB locking |
| 🧠 **15 SOC Detection Rules** | C2/ATP, DoS, Brute Force, Port Scan, DNS Tunneling, Data Exfiltration, VPN attacks & more |
| 🖥️ **8-View Dark SOC Dashboard** | Overview · Alerts · Firewall · DNS · Users · Threats · Network · Event Hunt |
| 🔍 **IP Pivot Investigation** | Click any IP → 6-tab modal: Firewall / DNS / RADIUS / DHCP / Alerts / Threats |
| 👤 **User Investigation** | Search username/email → full firewall, RADIUS, VPN, alert cross-history |
| 📋 **Advanced Event Hunt** | 10-field search: IP, port, type, action, username, protocol, keyword, date range |
| ✅ **Full Alert Lifecycle** | Auto-generate → Filter → Bulk-ACK with analyst name → Export CSV/JSON |
| 🌐 **DNS Intelligence** | 40M+ query analysis, DGA/suspicious TLD detection, top clients and domains |
| 📅 **Global Date Filter** | Apply date range across ALL 8 dashboard views simultaneously |
| 📡 **Live Ingestion Monitor** | `monitor.py` — real-time rows/sec, ETA, per-source progress bar |
| 💾 **Idempotent Ingest** | Already-processed files are auto-skipped — safe to re-run at any time |
| 📊 **Full Export** | Alerts and events exportable as CSV or JSON from dashboard or CLI |
| 🔒 **Secure by Design** | IP/MAC/date regex validation · parameterised SQL · threading.Lock on all writes |

---

## 🗂️ Log Sources

```
/mnt/
├── Firewall-Logs/Firewall-Logs/
│   ├── Firewall/                    ← Allow/Deny rules
│   ├── IPS/                         ← Intrusion Prevention
│   ├── Advanced_Threat_Protection/  ← C2 / ATP / Malware
│   ├── Content_Filtering/           ← HTTP · App Filter · Web
│   ├── Anti_Virus/                  ← HTTP/FTP/SMTP AV hits
│   ├── Anti_Spam/                   ← SMTP spam blocks
│   ├── Event/                       ← CLI/GUI/DHCP/IPSec/VPN/HA
│   ├── SD-WAN/                      ← Profile/Route/SLA
│   ├── Web_Server_Protection/       ← WAF events
│   └── Mac_IP/                      ← MAC↔IP binding history
├── iDNS-Logs/
│   ├── idns1/                       ← BIND9 primary DNS
│   └── idns2/                       ← BIND9 secondary DNS
└── Radius-Logs/
    ├── primary-radius/              ← FreeRADIUS auth
    ├── secondary-radius/            ← FreeRADIUS auth
    ├── primary-dhcp/                ← ISC dhcpd leases
    └── secondary-dhcp/              ← ISC dhcpd leases
```

> **Storage reality:** The full dataset spans several terabytes of compressed logs across firewall, DNS, and RADIUS/DHCP sources.
> Ingesting everything requires significant disk space and runtime.
> **Use the `--since` flag (recommended) to ingest only the last 30 days** — fast, practical, and sufficient for SOC work.

---

## ▶️ Installation & Setup

### Prerequisites
```
Python 3.10+   pip   NFS mount at /mnt   sudo access (NFS paths need root)
                                        (edit config.py to change paths)
```

> **Why sudo?** The `/mnt` NFS mount paths are owned by root. Without sudo, the ingester finds 0 files.
> Fix permanently by adding your user to the mount group or setting `uid=` in `/etc/fstab`.

### Clone and install
```bash
git clone https://github.com/KIRAN-KUMAR-K3/SentinelEye.git
cd SentinelEye
python -m venv venu
source venu/bin/activate
pip install flask tabulate
```

---

## 🚀 How to Run — Step by Step

> ⚠️ **Critical rules:**
> - Run **one ingestion command at a time**. Wait for `[+] Done` before running the next.
> - Never press Ctrl+C during ingestion — it can corrupt the DB.
> - Use **`sudo`** so the ingester can read the NFS-mounted `/mnt` paths.
> - Use **`--since`** to limit ingestion to recent logs — the full dataset is very large.

---

### Step 1 — Initialise the database
```bash
sudo python siem.py init
```
Expected output:
```
[+] Database ready at /root/siem.db
```

---

### Step 2 — Ingest log sources (recommended: last 30 days only)

> 💡 **The `--since` flag is the most important option.** Without it the ingester will try to process the entire archive. With it, only files modified after that date are processed — typically completing in minutes.

**Firewall** — start here, largest source:
```bash
sudo python siem.py ingest --source firewall --since 2025-02-17 --workers 4
```

Wait for `[+] Done`, then **RADIUS**:
```bash
sudo python siem.py ingest --source radius --since 2025-02-17 --workers 4
```

Wait, then **DHCP**:
```bash
sudo python siem.py ingest --source dhcp --since 2025-02-17 --workers 4
```

**DNS (optional — slowest source):**
```bash
# Do this last. DNS adds query volume data but is not required for core SOC work.
sudo python siem.py ingest --source dns --since 2025-02-17 --workers 4
```

> 📅 **Update the `--since` date** to yesterday or the start of your investigation window.
> Example for today's logs only: `--since 2025-03-18`
> Example for last 7 days: `--since 2025-03-12`

---

### Step 3 — Watch live progress (open a second terminal)

While ingestion runs, open a second terminal:
```bash
cd SentinelEye
source venu/bin/activate
sudo python monitor.py
```

You will see:
```
╔══════════════════════════════════════════════════════╗
║      SentinelEye — Live Ingestion Monitor            ║
║      Indian Institute of Science | ISO Security      ║
╠══════════════════════════════════════════════════════╣
║  Files ingested :     420              in progress  ║
║  Progress       : [█░░░░░░░░░░░░░░░░░░░░░░░░░░░░░]  ║
╠══════════════════════════════════════════════════════╣
║  Firewall events:      812,330                       ║
║  DNS queries    :            0                       ║
║  RADIUS auth    :       14,210                       ║
║  DHCP leases    :        8,880                       ║
╠══════════════════════════════════════════════════════╣
║  Total rows     :      835,420                       ║
║  Ingest rate    :    85,000 rows/sec                 ║
╚══════════════════════════════════════════════════════╝
```

---

### Step 4 — Run detection rules

After all sources finish ingesting:
```bash
sudo python siem.py analyze
```

Expected output:
```
[+] Running detection rules …
  [R001] C2 Communication          ...  12 hits →  12 new alerts
  [R002] DoS Attack                ...   8 hits →   8 new alerts
  [R003] IPS Signature Triggered   ...  45 hits →  45 new alerts
  [R005] RADIUS Brute Force        ...   3 hits →   3 new alerts
  [R009] Port Scan Detected        ...  18 hits →  18 new alerts
  ...
[+] Total new alerts generated: 345
```

---

### Step 5 — Start the dashboard

```bash
sudo python siem.py dashboard
```

Then open your browser: **`http://localhost:5000`**

---

### Step 6 — Verify everything is working

```bash
sudo python siem.py report
```

Expected output:
```
╔══════════════════════════════════════════════════════╗
║     SentinelEye SIEM  —  Summary Report              ║
║     Indian Institute of Science, Bangalore           ║
╚══════════════════════════════════════════════════════╝
  Total events ingested  :   27,000,000+
  DNS queries            :   40,000,000+
  RADIUS auth records    :      500,000+
  DHCP events            :      300,000+
  Open alerts            :          345
  Critical alerts        :           14
  Denied connections     :   27,000,000+
```

---

### Step 7 — Incremental daily update

Run this each morning to pull in yesterday's new logs:
```bash
# Change the date to yesterday each time
sudo python siem.py ingest --source firewall --since 2025-03-18 --workers 4
sudo python siem.py ingest --source radius   --since 2025-03-18 --workers 4
sudo python siem.py ingest --source dhcp     --since 2025-03-18 --workers 4
sudo python siem.py analyze
```

Already-ingested files are automatically skipped (`SKIP_INGESTED = True` in `config.py`), so re-running is always safe.

---

## 📡 Live Ingestion Monitor

```
╔══════════════════════════════════════════════════════╗
║      SentinelEye — Live Ingestion Monitor            ║
║      Indian Institute of Science | ISO Security      ║
╠══════════════════════════════════════════════════════╣
║  Firewall events:   27,362,000  ✅                   ║
║  DNS queries    :   40,018,000  ✅                   ║
║  RADIUS auth    :      487,210                       ║
║  DHCP leases    :      219,880                       ║
║  MAC-IP maps    :    1,824,440                       ║
╠══════════════════════════════════════════════════════╣
║  Total rows     :   69,911,530                       ║
║  Ingest rate    :    85,000 rows/sec                 ║
║  Updated        :    14:21:51                        ║
╚══════════════════════════════════════════════════════╝
```

---

## 🖥️ Dashboard Views

All 8 views share a **global date range filter** in the top bar. The alert badge auto-refreshes every 60 seconds.

| # | View | Sidebar | What You Get |
|---|------|---------|-------------|
| 1 | **Overview** | 🏠 | 12 stat cards · stacked hourly event timeline · log type breakdown · DNS volume chart · top queried domains · recent open alerts |
| 2 | **Alerts** | 🚨 | Full alert table · filter by severity/rule/IP/date/status · checkbox bulk-ACK · rule summary table · CSV/JSON export |
| 3 | **Firewall** | 🔥 | Top denied/allowed source IPs · top destination IPs · top rules hit · protocols donut · port table · top applications · bandwidth chart |
| 4 | **DNS Analysis** | 🌐 | Query breakdown · top domains · query type chart · suspicious TLD/DGA table |
| 5 | **Users** | 👤 | Admin GUI/CLI login history · RADIUS user summary · brute-force failed login list · VPN sessions · username search |
| 6 | **Threats** | 🛡️ | ATP/C2 events · IPS signatures · DoS attacks · top infected hosts |
| 7 | **Network** | 🔗 | DHCP lease history · VPN/IPSec sessions · MAC↔IP lookup |
| 8 | **Event Hunt** | 🔍 | 10-field advanced search · src/dst IP · port · log type · action · username · protocol · keyword · date range · CSV/JSON export |

### 🔍 IP Pivot — Click any IP anywhere
Opens a 6-tab investigation modal instantly:
```
[ Firewall Events ] [ DNS Queries ] [ RADIUS Auth ] [ DHCP Leases ] [ Alerts ] [ Threats ]
```
Shows complete cross-source history for that IP in one place.

---

## 🔎 Detection Rules

| ID | Rule Name | Severity | Trigger Logic |
|----|-----------|----------|---------------|
| `R001` | C2 Communication | 🔴 Critical | ATP log_type events with Alert/Blocked subtype |
| `R002` | DoS Attack | 🟠 High | `log_component` contains DoS · ≥5 events same source |
| `R003` | IPS Signature Triggered | 🟠 High | IPS log_type at Warning/Critical/Notice priority |
| `R004` | IP Spoofing Attempt | 🟠 High | `log_component` contains IP Spoof |
| `R005` | RADIUS Brute Force | 🟠 High | ≥10 RADIUS Rejects for same user within 5 minutes |
| `R006` | Admin Login from External IP | 🔴 Critical | GUI/CLI login from non-RFC1918 IP address |
| `R007` | DNS Tunneling | 🟠 High | >5000 DNS queries/min from a single host |
| `R008` | Large Outbound Transfer | 🟡 Medium | Single allowed session sending >100 MB outbound |
| `R009` | Port Scan Detected | 🟠 High | >20 distinct destination ports in 60 seconds |
| `R010` | P2P / Torrent Traffic | 🟢 Low | Application filter blocking BitTorrent/P2P |
| `R011` | Antivirus / Malware Alert | 🟠 High | AV detection via HTTP/FTP/SMTP with threat name |
| `R012` | VPN Brute Force | 🟠 High | ≥5 SSL-VPN/Portal auth failures in 10 minutes |
| `R013` | External SSH to Firewall | 🔴 Critical | TCP/22 to appliance from non-RFC1918 IP |
| `R014` | Repeated Denies — Scanner | 🟡 Medium | External IP accumulating >500 deny events |
| `R015` | Suspicious DNS — DGA? | 🟡 Medium | Queries to .xyz .tk .ml .cf .pw or hostname length >50 |

---

## 🧩 Adding Custom Detection Rules

```python
# Step 1 — Add your function to rules/definitions.py

def r016_suspicious_useragent(conn):
    """Detect scanning tools by user-agent strings in firewall messages."""
    rows = _rows(conn, """
        SELECT id, src_ip, url, ts
        FROM   events
        WHERE  message LIKE '%masscan%'
           OR  message LIKE '%nmap%'
           OR  message LIKE '%python-requests%'
           OR  message LIKE '%curl%'
    """)
    return [{
        "src_ip":      r["src_ip"] or "",
        "dst_ip":      "",
        "username":    "",
        "description": f"Scanning tool detected from {r['src_ip']} → {r['url'] or '?'}",
        "event_ids":   [r["id"]],
    } for r in rows]


# Step 2 — Register it in the RULES list at the bottom of the file
{"id": "R016", "name": "Suspicious User-Agent", "severity": "Medium", "fn": r016_suspicious_useragent},
```

Then run `sudo python siem.py analyze` to execute your new rule.
Each rule must include: unique ID, descriptive name, severity level, clear docstring, and deduplication logic.

---

## 🧠 Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│               NFS Mount (/mnt) — compressed .gz log archives        │
│   Firewall .gz  DNS .gz  RADIUS .gz  DHCP .gz  Mac_IP .gz           │
└──────────────────────────────┬──────────────────────────────────────┘
                               │
              ┌────────────────▼──────────────────┐
              │         Ingestion Engine           │
              │  N parser threads (decompress)     │
              │     ↓  rows via queue  ↓           │
              │  1 writer thread (DB commits)      │  ← Zero locking
              │  ingest/ingester.py                │
              │  ingest/parsers.py (5 parsers)     │
              └────────────────┬──────────────────┘
                               │
              ┌────────────────▼──────────────────┐
              │          SQLite Database           │
              │  ~/siem.db  ·  WAL mode            │
              │  7 tables  ·  all indexed          │
              │                                    │
              │  events        dns_queries         │
              │  radius_auth   dhcp_leases         │
              │  mac_ip_map    alerts              │
              │  ingested_files                    │
              └──────────────┬──────────┬──────────┘
                             │          │
            ┌────────────────▼─┐  ┌─────▼──────────────────┐
            │  Rule Engine     │  │  Flask Dashboard        │
            │  rules/          │  │  30+ REST API endpoints │
            │  15 SQL rules    │  │  8 SOC views            │
            │  dedup + alerts  │  │  IP pivot modal         │
            └──────────────────┘  │  User investigation     │
                                  │  Global date filter     │
                                  │  CSV / JSON export      │
                                  └─────────────────────────┘
```

---

## 📁 Project Structure

```
SentinelEye/
│
├── siem.py                       ← CLI: init · ingest · analyze · dashboard · query · alerts · report
├── config.py                     ← All paths, thresholds, worker counts
├── monitor.py                    ← Live ingestion progress (rows/sec, ETA, per-source)
├── requirements.txt
│
├── db/
│   └── schema.py                 ← SQLite DDL · 7 tables · threading.Lock · retry logic
│
├── ingest/
│   ├── parsers.py                ← 5 parsers: Sophos XG KV · BIND9 · FreeRADIUS · ISC DHCP · MAC-IP
│   └── ingester.py               ← Queue-based single-writer ingestion engine
│
├── rules/
│   ├── definitions.py            ← 15 SOC detection rules (all SQL-based, deduplicated)
│   └── engine.py                 ← Rule runner · alert persistence · dedup check
│
└── dashboard/
    ├── app.py                    ← Flask · 30+ secure endpoints · input validation
    └── templates/
        └── index.html            ← Dark dashboard · Bootstrap 5 · Chart.js · 8 views
```

---

## 🔧 CLI Reference

```bash
# ── Database ─────────────────────────────────────────────────────────────────
sudo python siem.py init

# ── Ingestion — RECOMMENDED: use --since to limit to recent logs ──────────────
sudo python siem.py ingest --source firewall --since 2025-02-17 --workers 4
sudo python siem.py ingest --source radius   --since 2025-02-17 --workers 4
sudo python siem.py ingest --source dhcp     --since 2025-02-17 --workers 4
sudo python siem.py ingest --source dns      --since 2025-02-17 --workers 4  # slowest, do last

# Preview files without ingesting
sudo python siem.py ingest --source firewall --since 2025-02-17 --dry-run

# ── Live monitor (separate terminal, runs alongside ingestion) ────────────────
sudo python monitor.py

# ── Detection rules ───────────────────────────────────────────────────────────
sudo python siem.py analyze                          # run all 15 rules
sudo python siem.py analyze --rules R001 R006 R013   # run specific rules only

# ── Dashboard ─────────────────────────────────────────────────────────────────
sudo python siem.py dashboard                        # http://localhost:5000
sudo python siem.py dashboard --port 8080            # custom port
sudo python siem.py dashboard --debug                # Flask debug mode

# ── Query events (CLI) ────────────────────────────────────────────────────────
sudo python siem.py query --src-ip 10.217.51.86
sudo python siem.py query --action Deny --since 2025-03-01 --limit 500
sudo python siem.py query --type ATP --format json
sudo python siem.py query --type IPS --format csv > ips_events.csv

# ── Manage alerts (CLI) ───────────────────────────────────────────────────────
sudo python siem.py alerts                             # all open alerts
sudo python siem.py alerts --severity Critical         # critical only
sudo python siem.py alerts --unacked                   # unacknowledged only
sudo python siem.py alerts --ack 42 --ack-by kiran     # acknowledge alert #42

# ── Summary report ────────────────────────────────────────────────────────────
sudo python siem.py report

# ── Quick DB health check ─────────────────────────────────────────────────────
sudo python3 -c "
import sqlite3, os
conn = sqlite3.connect(os.path.expanduser('~/siem.db'))
for t in ['events','dns_queries','radius_auth','dhcp_leases','ingested_files','alerts']:
    n = conn.execute(f'SELECT COUNT(*) FROM {t}').fetchone()[0]
    print(f'  {t:25s}: {n:>12,}')
conn.close()
"
```

---

## ⚙️ Configuration (`config.py`)

```python
# NFS mount point where .gz files are stored
MOUNT_BASE = "/mnt"

# SQLite database path (when running with sudo, this resolves to /root/siem.db)
DB_PATH = os.path.expanduser("~/siem.db")

# Ingestion settings
MAX_WORKERS   = 4      # parallel decompression threads — keep at 4
BATCH_SIZE    = 1000   # rows per DB commit
SKIP_INGESTED = True   # skip files already in ingested_files table (safe to re-run)

# Dashboard
DASHBOARD_HOST = "0.0.0.0"
DASHBOARD_PORT = 5000

# Detection rule thresholds
BRUTE_FORCE_WINDOW_SEC     = 300          # 5 min window for R005
BRUTE_FORCE_THRESHOLD      = 10           # RADIUS rejects before alert
PORT_SCAN_THRESHOLD        = 20           # distinct dst_port count for R009
DNS_TUNNEL_QUERY_THRESHOLD = 5000         # queries/min for R007
LARGE_TRANSFER_BYTES       = 100_000_000  # 100 MB for R008
```

---

## 🗄️ Database Schema

| Table | Key Columns |
|-------|-------------|
| `events` | `ts · log_type · log_component · src_ip · dst_ip · action · threat_name · username` |
| `dns_queries` | `ts · client_ip · query_name · query_type · server_ip` |
| `radius_auth` | `ts · username · nas_ip · client_ip · result` |
| `dhcp_leases` | `ts · event_type · ip_address · mac_address · hostname` |
| `mac_ip_map` | `ts · mac_address · ip_address · interface` |
| `alerts` | `rule_id · severity · src_ip · description · acknowledged · ack_by` |
| `ingested_files` | `filepath · log_source · rows_loaded · loaded_at` |

---

## 📈 Performance

| Metric | Value |
|--------|-------|
| Firewall events (full ingest) | **27,362,000+** |
| DNS queries (full ingest) | **40,018,000+** |
| Ingestion speed | 50,000 – 100,000 rows/sec over NFS |
| Recommended ingest window | **Last 30 days** via `--since` flag |
| DB engine | SQLite WAL · tested beyond 70M rows |
| Dashboard API response | < 500ms — all queries index-backed |
| REST API endpoints | 30+ secure endpoints |

---

## 🔒 Security & Coding Standards

- All REST API inputs validated — IP regex, MAC regex, ISO date check, string length limits
- All SQL uses parameterised queries — zero SQL injection surface
- `threading.Lock()` on all write operations — zero DB write contention
- Retry logic (5 attempts with backoff) on every DB write
- All log data stays **100% local** — nothing sent to external services
- Raw `.gz` files are **read-only** — never modified

---

## ⚠️ Troubleshooting

| Problem | Cause | Fix |
|---------|-------|-----|
| `Found 0 .gz files` (without sudo) | `/mnt` NFS paths not readable by regular user | Run with `sudo` or fix NFS mount permissions |
| `database is locked` | Multiple processes writing simultaneously | `sudo pkill -9 -f python` → `sudo rm ~/siem.db-wal ~/siem.db-shm` → restart |
| `database disk image is malformed` | Ctrl+C during write corrupted the DB | `sudo rm ~/siem.db ~/siem.db-wal ~/siem.db-shm` → `sudo python siem.py init` → re-ingest |
| `DNS/RADIUS/DHCP = 0` | DB was locked when those sources ran | Re-run: `sudo python siem.py ingest --source dns --workers 4` |
| Ingestion very slow | Processing full archive without `--since` | Always use `--since YYYY-MM-DD` to limit scope |
| Dashboard shows 0 events | Ingestion not yet complete | Wait for `[+] Done` before starting dashboard |
| DB stored at `/root/siem.db` | Running with sudo expands `~` to `/root` | Expected behaviour — use `sudo python siem.py report` to query it |

---

## 🤝 Contributing

```bash
git checkout -b feature/new-rule
# → add rule function to rules/definitions.py
# → register {"id": "R016", "name": "...", "severity": "...", "fn": ...} in RULES
# → test with: sudo python siem.py analyze --rules R016
# → open a pull request
```

---

## 📜 License

```
MIT License — © 2025 KIRAN KUMAR K
Free to use, modify, and distribute with attribution.
```

---

<div align="center">

**Built with 🛡️ for the SOC by [KIRAN KUMAR K](https://github.com/KIRAN-KUMAR-K3)**

*Information Security Intern @ IISc Bangalore · Ethical Hacker · VAPT*

*Developed under the ISO Security Team — Indian Institute of Science, Bangalore*

<br/>

[![GitHub](https://img.shields.io/badge/GitHub-KIRAN--KUMAR--K3-181717?style=flat&logo=github)](https://github.com/KIRAN-KUMAR-K3)
[![LinkedIn](https://img.shields.io/badge/LinkedIn-kiran--kumar--k3-0077B5?style=flat&logo=linkedin)](https://linkedin.com/in/kiran-kumar-k3)
[![Blog](https://img.shields.io/badge/Blog-kirankumark3.blogspot.com-FF5722?style=flat&logo=blogger)](https://kirankumark3.blogspot.com)
[![BugCrowd](https://img.shields.io/badge/BugCrowd-KIRAN--KUMAR--K-F26822?style=flat&logo=bugcrowd)](https://bugcrowd.com/h/KIRAN-KUMAR-K)]

<img src="https://capsule-render.vercel.app/api?type=waving&color=0:0d47a1,50:1a1f35,100:0d1117&height=100&section=footer" />

</div>
