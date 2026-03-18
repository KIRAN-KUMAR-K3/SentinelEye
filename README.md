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
> **45,437 compressed log files · 40M+ rows · 8 SOC views · 15 detection rules · Dark analyst dashboard.**

<br/>

[▶️ Installation](#%EF%B8%8F-installation--setup) · [🚀 How to Run](#-how-to-run-step-by-step) · [🖥️ Dashboard](#%EF%B8%8F-dashboard-views) · [🔎 Detection Rules](#-detection-rules) · [🔧 CLI Reference](#-cli-reference) · [🧠 Architecture](#-architecture)

</div>

---

## 🛡️ What is SentinelEye?

**SentinelEye** is a lightweight, purpose-built SIEM (Security Information and Event Management) platform developed by the **ISO Security Team** at the **Indian Institute of Science, Bangalore**. It processes compressed log archives from enterprise network infrastructure and turns raw log data into actionable threat intelligence.

Built on actual IISc production logs from a Sophos XG/XGS enterprise firewall deployment — **45,437 `.gz` files** across firewalls, DNS servers, RADIUS authenticators, and DHCP servers — ingesting **40M+ parsed rows** into a fully local SQLite database.

```
🔥 45,437 files  ·  40M+ rows  ·  15 rules  ·  8 SOC views  ·  30+ REST APIs  ·  100% local
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
│   ├── Firewall/                    ← Allow/Deny rules            —  4,806 files
│   ├── IPS/                         ← Intrusion Prevention         —  1,600 files
│   ├── Advanced_Threat_Protection/  ← C2 / ATP / Malware           —    792 files
│   ├── Content_Filtering/           ← HTTP · App Filter · Web      —  1,676 files
│   ├── Anti_Virus/                  ← HTTP/FTP/SMTP AV hits        —  2,400 files
│   ├── Anti_Spam/                   ← SMTP spam blocks             —    800 files
│   ├── Event/                       ← CLI/GUI/DHCP/IPSec/VPN/HA    —  7,487 files
│   ├── SD-WAN/                      ← Profile/Route/SLA            —  2,253 files
│   ├── Web_Server_Protection/       ← WAF events                   —    829 files
│   └── Mac_IP/                      ← MAC↔IP binding history       —  7,299 files
├── iDNS-Logs/
│   ├── idns1/                       ← BIND9 primary DNS            —  3,401 files
│   └── idns2/                       ← BIND9 secondary DNS          —  3,167 files
└── Radius-Logs/
    ├── primary-radius/              ← FreeRADIUS auth              —  2,874 files
    ├── secondary-radius/            ← FreeRADIUS auth              —  1,277 files
    ├── primary-dhcp/                ← ISC dhcpd leases             —  2,703 files
    └── secondary-dhcp/              ← ISC dhcpd leases             —  1,273 files
                                                          ────────────────────────
                                                          Total:      45,437 files
```

---

## ▶️ Installation & Setup

### Prerequisites
```
Python 3.10+   pip   NFS mount at /mnt   (edit config.py to change paths)
```

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

> ⚠️ **Critical rule:** Run **one ingestion command at a time**. Wait for `[+] Done` before running the next. Never press Ctrl+C during ingestion.

### Step 1 — Initialise the database
```bash
python siem.py init
```
Expected output:
```
[+] Database ready at /home/iso/siem.db
```

---

### Step 2 — Ingest log sources (one at a time)

**Firewall** (largest — takes 1–3 hours depending on NFS speed):
```bash
python siem.py ingest --source firewall --workers 4
```

Wait for `[+] Done`, then **DNS** (~45–90 min):
```bash
python siem.py ingest --source dns --workers 4
```

Wait, then **RADIUS**:
```bash
python siem.py ingest --source radius --workers 4
```

Wait, then **DHCP**:
```bash
python siem.py ingest --source dhcp --workers 4
```

> 💡 Use `--workers 4` (not 8 or 16). More workers only helps decompression speed; the single writer thread is the real bottleneck. 4 workers is the sweet spot for stability.

---

### Step 3 — Watch live progress (open a second terminal)

While ingestion runs, open a second terminal and run:
```bash
cd SentinelEye
source venu/bin/activate
python monitor.py
```

You will see:
```
╔══════════════════════════════════════════════════════╗
║      SentinelEye — Live Ingestion Monitor            ║
║      Indian Institute of Science | ISO Security      ║
╠══════════════════════════════════════════════════════╣
║  Files ingested :   4,200 / 45,437           9.2%   ║
║  Progress       : [███░░░░░░░░░░░░░░░░░░░░░░░░░░░]  ║
╠══════════════════════════════════════════════════════╣
║  Firewall events:    4,812,330                       ║
║  DNS queries    :            0                       ║
║  RADIUS auth    :            0                       ║
║  DHCP leases    :            0                       ║
╠══════════════════════════════════════════════════════╣
║  Total rows     :    4,812,330                       ║
║  Ingest rate    :    85,000 rows/sec                 ║
╚══════════════════════════════════════════════════════╝
```

---

### Step 4 — Run detection rules

After all sources finish ingesting:
```bash
python siem.py analyze
```

Expected output:
```
[+] Running detection rules …
  [R001] C2 Communication          ...  12 hits →  12 new alerts
  [R002] DoS Attack                ...   8 hits →   8 new alerts
  [R003] IPS Signature Triggered   ...  45 hits →  45 new alerts
  [R004] IP Spoofing Attempt       ...   6 hits →   6 new alerts
  [R005] RADIUS Brute Force        ...   0 hits →   0 new alerts
  [R006] Admin Login from External ...   2 hits →   2 new alerts
  [R007] DNS Tunneling             ... 193 hits → 193 new alerts
  [R008] Large Outbound Transfer   ...   5 hits →   5 new alerts
  [R009] Port Scan Detected        ...  18 hits →  18 new alerts
  [R014] Repeated Denies (Scanner) ...  24 hits →  24 new alerts
  [R015] Suspicious DNS (DGA?)     ...  32 hits →  32 new alerts
  ...
[+] Total new alerts generated: 345
```

---

### Step 5 — Start the dashboard

```bash
python siem.py dashboard
```

Then open your browser and go to: **`http://localhost:5000`**

---

### Step 6 — Verify everything is working

```bash
python siem.py report
```

Expected output:
```
╔══════════════════════════════════════════════════╗
║     SentinelEye SIEM  —  Summary Report          ║
║     Indian Institute of Science, Bangalore       ║
╚══════════════════════════════════════════════════╝
  Total events ingested  :   27,000,000+
  DNS queries            :   40,000,000+
  RADIUS auth records    :      500,000+
  DHCP events            :      300,000+
  Files ingested         :       45,437
  Open alerts            :          345
  Critical alerts        :           14
  Denied connections     :   27,000,000+
```

---

## 📡 Live Ingestion Monitor

```
╔══════════════════════════════════════════════════════╗
║      SentinelEye — Live Ingestion Monitor            ║
║      Indian Institute of Science | ISO Security      ║
╠══════════════════════════════════════════════════════╣
║  Files ingested :  18,200 / 45,437          40.0%   ║
║  Progress       : [████████████░░░░░░░░░░░░░░░░░░]  ║
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

All 8 views share a **global date range filter** in the top bar. The sidebar shows IISc / ISO branding. The alert badge auto-refreshes every 60 seconds.

| # | View | Sidebar | What You Get |
|---|------|---------|-------------|
| 1 | **Overview** | 🏠 | 12 stat cards · stacked hourly event timeline · log type breakdown · DNS volume chart · top queried domains · recent open alerts |
| 2 | **Alerts** | 🚨 | Full alert table · filter by severity/rule/IP/date/status · checkbox bulk-ACK · rule summary table · CSV/JSON export |
| 3 | **Firewall** | 🔥 | Top denied/allowed source IPs · top destination IPs · top rules hit · protocols donut · port table with service names · top applications · bandwidth chart per host |
| 4 | **DNS Analysis** | 🌐 | 40M+ query breakdown · top domains with client count · query type chart · suspicious TLD/DGA highlighted table |
| 5 | **Users** | 👤 | Admin GUI/CLI login history · RADIUS user summary · brute-force failed login list · VPN/SSL sessions · username investigation search box |
| 6 | **Threats** | 🛡️ | ATP/C2 events with threat names · IPS signatures · DoS attacks · top compromised/infected hosts |
| 7 | **Network** | 🔗 | DHCP lease history · VPN/IPSec session table · MAC↔IP lookup by IP or MAC address |
| 8 | **Event Hunt** | 🔍 | 10-field advanced search · src/dst IP · port · log type/source · action · username/email · protocol · keyword · date range · CSV/JSON export |

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

Then run `python siem.py analyze` to execute your new rule.

---

## 🧠 Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│               NFS Mount (/mnt) — 45,437 .gz files                   │
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
python siem.py init

# ── Ingestion (always one source at a time) ───────────────────────────────────
python siem.py ingest --source firewall --workers 4
python siem.py ingest --source dns      --workers 4
python siem.py ingest --source radius   --workers 4
python siem.py ingest --source dhcp     --workers 4

python siem.py ingest --source firewall --since 2025-04-01   # incremental update
python siem.py ingest --source firewall --dry-run            # preview files only

# ── Live monitor (separate terminal, runs alongside ingestion) ────────────────
python monitor.py

# ── Detection rules ───────────────────────────────────────────────────────────
python siem.py analyze                          # run all 15 rules
python siem.py analyze --rules R001 R006 R013   # run specific rules only

# ── Dashboard ─────────────────────────────────────────────────────────────────
python siem.py dashboard                        # http://localhost:5000
python siem.py dashboard --port 8080            # custom port
python siem.py dashboard --debug                # Flask debug mode

# ── Query events (CLI) ────────────────────────────────────────────────────────
python siem.py query --src-ip 10.217.51.86
python siem.py query --action Deny --since 2025-03-01 --limit 500
python siem.py query --type ATP --format json
python siem.py query --type IPS --format csv > ips_events.csv

# ── Manage alerts (CLI) ───────────────────────────────────────────────────────
python siem.py alerts                             # all open alerts
python siem.py alerts --severity Critical         # critical only
python siem.py alerts --unacked                   # unacknowledged only
python siem.py alerts --ack 42 --ack-by kiran     # acknowledge alert #42

# ── Summary report ────────────────────────────────────────────────────────────
python siem.py report

# ── Quick DB health check ─────────────────────────────────────────────────────
python3 -c "
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

# SQLite database path (~/ expands to home directory)
DB_PATH = os.path.expanduser("~/siem.db")

# Ingestion settings
# Keep workers at 4 — more workers don't help (single writer bottleneck)
MAX_WORKERS   = 4      # parallel decompression threads
BATCH_SIZE    = 1000   # rows per DB commit
SKIP_INGESTED = True   # skip files already in ingested_files table

# Dashboard
DASHBOARD_HOST = "0.0.0.0"
DASHBOARD_PORT = 5000

# Detection rule thresholds — tune to your network
BRUTE_FORCE_WINDOW_SEC     = 300          # 5 min window for R005
BRUTE_FORCE_THRESHOLD      = 10           # RADIUS rejects before alert
PORT_SCAN_THRESHOLD        = 20           # distinct dst_port count for R009
DNS_TUNNEL_QUERY_THRESHOLD = 5000         # queries/min for R007 (IISc DNS is high-volume)
LARGE_TRANSFER_BYTES       = 100_000_000  # 100 MB for R008
```

---

## 🗄️ Database Schema

| Table | Verified Rows | Key Columns |
|-------|---------------|-------------|
| `events` | 27,362,000+ ✅ | `ts · log_type · log_component · src_ip · dst_ip · action · threat_name · username` |
| `dns_queries` | 40,018,000+ ✅ | `ts · client_ip · query_name · query_type · server_ip` |
| `radius_auth` | ~500,000+ | `ts · username · nas_ip · client_ip · result` |
| `dhcp_leases` | ~300,000+ | `ts · event_type · ip_address · mac_address · hostname` |
| `mac_ip_map` | ~2,000,000+ | `ts · mac_address · ip_address · interface` |
| `alerts` | 345+ ✅ | `rule_id · severity · src_ip · description · acknowledged · ack_by` |
| `ingested_files` | 45,437 | `filepath · log_source · rows_loaded · loaded_at` |

---

## 📈 Performance

| Metric | Value |
|--------|-------|
| Log files processed | **45,437** `.gz` archives |
| Firewall events (verified live) | **27,362,000+** ✅ |
| DNS queries (verified live) | **40,018,000+** ✅ |
| Alerts generated (first run) | **345+** ✅ |
| Ingestion speed | 50,000 – 100,000 rows/sec over NFS |
| Worker threads | 4 (stable) — 8–12 (faster NFS) |
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
| `database is locked` | Multiple processes writing simultaneously | `pkill -9 -f python` → `rm ~/siem.db-wal ~/siem.db-shm` → restart |
| `database disk image is malformed` | Ctrl+C during write corrupted the DB | `rm ~/siem.db ~/siem.db-wal ~/siem.db-shm` → `python siem.py init` → re-ingest |
| `DNS/RADIUS/DHCP = 0` | DB was locked when those sources ran | Re-run: `python siem.py ingest --source dns --workers 4` |
| `Files ingested = 0` | `mark_file_ingested` failed silently | Fixed in FINAL version — upgrade `db/schema.py` |
| `acknowledged_alert` column error | Phantom column in old R001 rule | Fixed in FINAL version — upgrade `rules/definitions.py` |
| Dashboard shows 0 firewall events | Still ingesting DNS (loads first alphabetically) | Wait for firewall ingest to complete |
| Ingestion very slow | NFS latency or too many workers | Reduce to `--workers 2`, check NFS mount speed |

---

## 🤝 Contributing

```bash
git checkout -b feature/new-rule
# → add rule function to rules/definitions.py
# → register {"id": "R016", "name": "...", "severity": "...", "fn": ...} in RULES
# → test with: python siem.py analyze --rules R016
# → open a pull request
```

Each rule must include: unique ID, descriptive name, severity level, clear docstring, and deduplication logic.

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
[![BugCrowd](https://img.shields.io/badge/BugCrowd-KIRAN--KUMAR--K-F26822?style=flat&logo=bugcrowd)](https://bugcrowd.com/h/KIRAN-KUMAR-K)

<img src="https://capsule-render.vercel.app/api?type=waving&color=0:0d47a1,50:1a1f35,100:0d1117&height=100&section=footer" />

</div>
