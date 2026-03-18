<div align="center">

<img src="https://capsule-render.vercel.app/api?type=waving&color=0:0d1117,50:1a1f35,100:0d47a1&height=200&section=header&text=SentinelEye%20SIEM&fontSize=52&fontColor=79c0ff&fontAlignY=38&desc=SOC%20Operations%20Platform%20for%20Enterprise%20Log%20Analysis&descAlignY=58&descColor=8b949e&animation=fadeIn" />

<br/>

[![Python](https://img.shields.io/badge/Python-3.10+-FFD43B?style=flat&logo=python&logoColor=blue)](https://python.org)
[![Flask](https://img.shields.io/badge/Flask-3.0-000000?style=flat&logo=flask&logoColor=white)](https://flask.palletsprojects.com)
[![SQLite](https://img.shields.io/badge/SQLite-WAL%20Mode-07405E?style=flat&logo=sqlite&logoColor=white)](https://sqlite.org)
[![Sophos](https://img.shields.io/badge/Sophos-XG%2FXGS-0C64A4?style=flat&logo=sophos&logoColor=white)](https://sophos.com)
[![License](https://img.shields.io/badge/License-MIT-3fb950?style=flat)](LICENSE)
[![Platform](https://img.shields.io/badge/Platform-Linux-FCC624?style=flat&logo=linux&logoColor=black)](https://linux.org)
[![Status](https://img.shields.io/badge/Status-Active-brightgreen?style=flat)]()
[![Author](https://img.shields.io/badge/Author-KIRAN%20KUMAR%20K-79c0ff?style=flat&logo=github)](https://github.com/KIRAN-KUMAR-K3)

<br/>

> **A fully local, high-performance SIEM built for SOC analysts.**
> **Ingests 45,000+ compressed log files, detects threats in real-time, and presents everything in a dark-mode analyst dashboard.**

<br/>

[🚀 Quick Start](#-quick-start) · [🧠 Architecture](#-architecture) · [🔎 Detection Rules](#-detection-rules) · [📊 Dashboard](#-dashboard) · [📁 Project Structure](#-project-structure)

</div>

---

## 🛡️ What is SentinelEye?

**SentinelEye** is a lightweight, purpose-built SIEM (Security Information and Event Management) platform designed for real-world SOC operations. It processes compressed log archives from enterprise network infrastructure — firewalls, DNS servers, RADIUS authenticators, and DHCP servers — and turns them into actionable threat intelligence.

Built during an internship at **IISc Bangalore**, this project handles actual production log data from a Sophos XG/XGS enterprise firewall deployment — over **45,437 `.gz` files** spanning multiple log sources, generating **30M+ parsed rows** in the database.

```
🔥 45,437 compressed log files  |  30M+ rows ingested  |  15 detection rules  |  7 DB tables  |  1 SOC dashboard
```

---

## ⚡ Key Features

| Feature | Description |
|---------|-------------|
| 🗜️ **Parallel Ingestion** | Multi-threaded `.gz` decompressor — processes 50k–200k rows/sec over NFS |
| 🧠 **15 Detection Rules** | C2, DoS, Brute Force, Port Scan, DNS Tunneling, Data Exfiltration & more |
| 📊 **Dark SOC Dashboard** | Flask + Chart.js dashboard with live charts, alert management, IP pivot |
| 🔍 **IP Pivot / Hunt** | Click any IP → see all firewall, DNS, RADIUS, DHCP, and alert history instantly |
| 📋 **Event Search** | Filter events by src/dst IP, action, log source, date range |
| ✅ **Alert Lifecycle** | Rule generates alerts → analyst reviews → one-click ACK with attribution |
| 💾 **Idempotent Ingest** | Already-processed files are skipped; only new files are loaded on re-run |
| 📡 **Live Monitor** | `monitor.py` — real-time ingestion dashboard showing rows/sec, ETA, progress |
| 🔧 **CLI-First** | Full `siem.py` CLI for scripting, automation, and headless server use |

---

## 🗂️ Log Sources Supported

```
/mnt/
├── Firewall-Logs/
│   ├── Firewall/                    ← Firewall rules (allowed/denied)    —  4,806 files
│   ├── IPS/                         ← Intrusion Prevention signatures    —  1,600 files
│   ├── Advanced_Threat_Protection/  ← C2 / ATP alerts                   —    792 files
│   ├── Content_Filtering/           ← HTTP, App Filter, Web Filter       —  1,676 files
│   ├── Anti_Virus/                  ← HTTP/FTP/SMTP AV hits              —  2,400 files
│   ├── Anti_Spam/                   ← SMTP spam blocks                   —    800 files
│   ├── Event/                       ← CLI, GUI, DHCP, IPSec, VPN, HA…   —  7,487 files
│   ├── SD-WAN/                      ← SD-WAN profile/route/SLA           —  2,253 files
│   ├── Web_Server_Protection/       ← WAF events                         —    829 files
│   └── Mac_IP/                      ← MAC↔IP binding history             —  7,299 files
├── iDNS-Logs/
│   ├── idns1/                       ← BIND9 query log (primary)          —  3,401 files
│   └── idns2/                       ← BIND9 query log (secondary)        —  3,167 files
└── Radius-Logs/
    ├── primary-radius/              ← FreeRADIUS auth                    —  2,874 files
    ├── secondary-radius/            ← FreeRADIUS auth                    —  1,277 files
    ├── primary-dhcp/                ← ISC dhcpd leases                   —  2,703 files
    └── secondary-dhcp/             ← ISC dhcpd leases                   —  1,273 files
                                                               ─────────────────────────
                                                               Total:       45,437 files
```

---

## 🚀 Quick Start

### Prerequisites

```bash
Python 3.10+    pip    NFS mount at /mnt (or edit config.py to change paths)
```

### Install & Run

```bash
# 1. Clone the repository
git clone https://github.com/KIRAN-KUMAR-K3/SentinelEye.git
cd SentinelEye

# 2. Create virtualenv and install dependencies
python -m venv venu && source venu/bin/activate
pip install flask tabulate

# 3. Initialise the SQLite database
python siem.py init

# 4. Ingest all log sources (parallel — tune --workers to your NFS speed)
python siem.py ingest --source all --workers 8

# 5. (Optional) Watch live ingestion progress in a second terminal
python monitor.py

# 6. Run all detection rules
python siem.py analyze

# 7. Launch the SOC dashboard
python siem.py dashboard
#  ➜  http://localhost:5000
```

> 💡 **Tip:** The dashboard works on partial data — start it while ingestion is still running to see results in real time.

---

## 📡 Live Ingestion Monitor

Run `monitor.py` in a separate terminal alongside ingestion to get a live view:

```
╔══════════════════════════════════════════════════╗
║         SentinelEye — Ingestion Monitor          ║
╠══════════════════════════════════════════════════╣
║  Files ingested :   8,200 / 45,437               ║
║  Progress       : [██████████░░░░░░░░░░░░░░░░░░]  18.0% ║
╠══════════════════════════════════════════════════╣
║  Firewall events:    4,812,330                   ║
║  DNS queries    :    8,922,000                   ║
║  RADIUS auth    :      487,210                   ║
║  DHCP leases    :      219,880                   ║
╠══════════════════════════════════════════════════╣
║  Total rows     :   14,441,420                   ║
║  Ingest rate    :    92,400 rows/sec             ║
║  Updated        :    14:21:51                    ║
╚══════════════════════════════════════════════════╝
  Refreshing every 5 seconds … (Ctrl+C to exit)
```

---

## 🖥️ Dashboard Preview

```
┌─────────────────────────────────────────────────────────────────────┐
│  ⚡ SIEM — SOC Dashboard                        ▶ Run Rules  ↻     │
├──────────┬──────────┬──────────┬──────────┬──────────┬─────────────┤
│  4.2M    │   38     │   12     │ 980,441  │  6,231   │   2,190     │
│  EVENTS  │  ALERTS  │ CRITICAL │  DENIED  │   ATP    │    DoS      │
├──────────┴──────────┴──────────┴──────────┴──────────┴─────────────┤
│  Event Timeline (24h)             │  Log Type Breakdown             │
│  ████████░░██████░░████████████  │  ◉ Firewall  ◎ Content  ◎ IPS  │
├──────────────────┬────────────────┴────────────────────────────────┤
│  Top Denied IPs  │  RADIUS Auth Results  │  Alerts by Severity     │
│  ═══════════════ │  ════════════════════ │  ══════════════════════ │
│  > 14.x.x.x 812 │  Accept  ██████  91%  │  Critical  ████  12     │
│  > 45.x.x.x 540 │  Reject  ██      9%   │  High      ████  26     │
│  > 91.x.x.x 312 │                       │  Medium    ██    8      │
├──────────────────┴───────────────────────┴────────────────────────┤
│  Open Alerts                                    [Filter ▼]         │
│  ─────────────────────────────────────────────────────────────── │
│  [12] C2 Communication     CRITICAL  10.134.x.x   [ACK]          │
│  [11] External SSH         CRITICAL  45.33.x.x    [ACK]          │
│  [9]  RADIUS Brute Force   HIGH      10.10.1.x    [ACK]          │
└────────────────────────────────────────────────────────────────────┘
```

---

## 🔎 Detection Rules

| ID | Rule Name | Severity | Logic |
|----|-----------|----------|-------|
| `R001` | C2 Communication | 🔴 Critical | ATP `log_subtype=Alert` events |
| `R002` | DoS Attack | 🟠 High | `log_component=DoS Attack` with ≥5 events per source |
| `R003` | IPS Signature Triggered | 🟠 High | IPS Warning/Critical/Notice priority |
| `R004` | IP Spoofing Attempt | 🟠 High | `IP_Spoof_Prevention` component events |
| `R005` | RADIUS Brute Force | 🟠 High | ≥10 RADIUS Rejects for same user in 5 min |
| `R006` | Admin Login from External IP | 🔴 Critical | GUI/CLI admin login from non-RFC1918 address |
| `R007` | DNS Tunneling | 🟠 High | >200 DNS queries/min from a single host |
| `R008` | Large Outbound Transfer | 🟡 Medium | Single session sending >100 MB outbound |
| `R009` | Port Scan Detected | 🟠 High | >20 distinct destination ports in 60 seconds |
| `R010` | P2P / Torrent Traffic | 🟢 Low | App filter blocking BitTorrent/P2P clients |
| `R011` | Antivirus / Malware Alert | 🟠 High | AV detection via HTTP/FTP/SMTP protocols |
| `R012` | VPN Brute Force | 🟠 High | ≥5 SSL-VPN/Portal auth failures in 10 min |
| `R013` | External SSH to Firewall | 🔴 Critical | TCP/22 to appliance from non-private IP |
| `R014` | Repeated Denies (Scanner) | 🟡 Medium | External IP with >500 deny events total |
| `R015` | Suspicious DNS (DGA?) | 🟡 Medium | Long labels / suspicious TLDs (.xyz .tk .ml…) |

---

## 🧠 Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                  NFS Mount (/mnt)  — 45,437 .gz files           │
│   Firewall .gz   DNS .gz   RADIUS .gz   DHCP .gz   Mac_IP .gz  │
└──────────────────────────┬──────────────────────────────────────┘
                           │
                  ┌────────▼────────┐
                  │   Ingester      │  ThreadPoolExecutor (8 workers)
                  │  ingest/        │  ─ Sophos KV syslog parser
                  │  parsers.py     │  ─ BIND9 query log parser
                  │  ingester.py    │  ─ FreeRADIUS detail parser
                  └────────┬────────┘  ─ ISC dhcpd log parser
                           │           ─ MAC-IP binding parser
                  ┌────────▼────────┐
                  │   SQLite DB     │  WAL mode · 7 tables · indexed
                  │   ~/siem.db     │  events · dns_queries · radius_auth
                  │   30M+ rows     │  dhcp_leases · mac_ip_map
                  │                 │  alerts · ingested_files
                  └────┬───────┬────┘
                       │       │
          ┌────────────▼─┐  ┌──▼──────────────┐
          │ Rule Engine  │  │  Flask Dashboard │
          │ rules/       │  │  dashboard/      │
          │ 15 rules     │  │  12 REST APIs    │
          │ → alerts     │  │  + IP pivot      │
          └──────────────┘  └─────────────────┘
```

---

## 📁 Project Structure

```
SentinelEye/
│
├── siem.py                  ← CLI entry point (init/ingest/analyze/dashboard/query/alerts/report)
├── config.py                ← All paths, thresholds, and settings
├── monitor.py               ← Live ingestion progress dashboard
├── requirements.txt
│
├── db/
│   └── schema.py            ← SQLite DDL + all data-access helpers
│
├── ingest/
│   ├── parsers.py           ← 5 log format parsers (Sophos KV, BIND9, RADIUS, DHCP, MAC-IP)
│   └── ingester.py          ← Parallel file discovery + ingestion engine
│
├── rules/
│   ├── definitions.py       ← 15 SOC detection rules (SQL-based)
│   └── engine.py            ← Rule runner + dedup + alert persistence
│
└── dashboard/
    ├── app.py               ← Flask app + 12 REST API endpoints
    └── templates/
        └── index.html       ← Dark SOC dashboard (Bootstrap 5 + Chart.js)
```

---

## 🔧 CLI Reference

```bash
# Database
python siem.py init

# Ingestion
python siem.py ingest --source all              # all 45k files
python siem.py ingest --source firewall         # firewall only
python siem.py ingest --source dns              # DNS only
python siem.py ingest --workers 16              # tune parallelism
python siem.py ingest --since 2025-01-01        # incremental update
python siem.py ingest --dry-run                 # preview without loading

# Live monitor (run in a separate terminal during ingestion)
python monitor.py

# Detection
python siem.py analyze                          # all 15 rules
python siem.py analyze --rules R001 R006 R013   # specific rules

# Dashboard
python siem.py dashboard --port 5000
python siem.py dashboard --debug

# Query Events
python siem.py query --src-ip 10.217.51.86
python siem.py query --action Deny --since 2025-03-01
python siem.py query --type ATP --format json
python siem.py query --type IPS --format csv > ips.csv

# Alerts
python siem.py alerts                           # all open alerts
python siem.py alerts --severity Critical       # critical only
python siem.py alerts --unacked                 # unacknowledged
python siem.py alerts --ack 42 --ack-by analyst # acknowledge

# Report
python siem.py report                           # summary stats to stdout
```

---

## ⚙️ Configuration (`config.py`)

```python
MOUNT_BASE      = "/mnt"          # NFS mount point
DB_PATH         = "~/siem.db"     # SQLite database location
MAX_WORKERS     = 8               # parallel ingestion threads
BATCH_SIZE      = 2000            # rows per DB commit
SKIP_INGESTED   = True            # skip already-processed files

# Detection thresholds
BRUTE_FORCE_THRESHOLD       = 10          # RADIUS rejects in window
PORT_SCAN_THRESHOLD         = 20          # distinct dst ports in 60s
DNS_TUNNEL_QUERY_THRESHOLD  = 200         # queries/min per host
LARGE_TRANSFER_BYTES        = 100_000_000 # 100 MB outbound threshold
```

---

## 🗄️ Database Schema

| Table | Real Rows | Key Columns |
|-------|-----------|-------------|
| `events` | ~10M+ | `ts, log_type, log_component, src_ip, dst_ip, action, threat_name` |
| `dns_queries` | **8,922,000+** ✅ | `ts, client_ip, query_name, query_type, server_ip` |
| `radius_auth` | ~500k+ | `ts, username, nas_ip, client_ip, result` |
| `dhcp_leases` | ~300k+ | `ts, event_type, ip_address, mac_address, hostname` |
| `mac_ip_map` | ~2M+ | `ts, mac_address, ip_address, interface` |
| `alerts` | varies | `rule_id, severity, src_ip, description, acknowledged` |
| `ingested_files` | 45,437 | `filepath, log_source, rows_loaded, loaded_at` |

---

## 🧩 Adding Custom Rules

```python
# 1. Add to rules/definitions.py
def r016_suspicious_useragent(conn):
    rows = _rows(conn, """
        SELECT id, src_ip, url, ts
        FROM   events
        WHERE  message LIKE '%curl%'
           OR  message LIKE '%python-requests%'
           OR  message LIKE '%masscan%'
    """)
    return [{
        "src_ip":      r["src_ip"],
        "dst_ip":      "",
        "username":    "",
        "description": f"Suspicious user-agent from {r['src_ip']} → {r['url']}",
        "event_ids":   [r["id"]],
    } for r in rows]

# 2. Register in RULES list
{"id": "R016", "name": "Suspicious User-Agent", "severity": "Medium", "fn": r016_suspicious_useragent},
```

---

## 📈 Performance

| Metric | Value |
|--------|-------|
| Log files processed | **45,437** `.gz` archives |
| DNS rows loaded (verified live) | **8,922,000+** |
| Estimated total rows | **30M+** across all sources |
| Ingestion speed | 50,000 – 200,000 rows/sec |
| Workers | 8 threads (configurable up to 16+) |
| DB engine | SQLite WAL (tested beyond 50M rows) |
| Dashboard response | < 500ms (all queries index-backed) |

---

## 🔒 Security Notes

> **This tool is intended for authorised use on your own infrastructure only.**
> All log data stays **fully local** — nothing is sent to any external service.
> The SQLite database stores parsed events; raw log files are never modified.

---

## 🤝 Contributing

Contributions, new detection rules, and parser improvements are welcome!

```bash
# Fork → Clone → Branch → PR
git checkout -b feature/new-rule
```

Please ensure any new detection rule includes: rule ID, name, severity, a clear docstring, and deduplication logic.

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

[![GitHub](https://img.shields.io/badge/GitHub-KIRAN--KUMAR--K3-181717?style=flat&logo=github)](https://github.com/KIRAN-KUMAR-K3)
[![LinkedIn](https://img.shields.io/badge/LinkedIn-kiran--kumar--k3-0077B5?style=flat&logo=linkedin)](https://linkedin.com/in/kiran-kumar-k3)
[![Blog](https://img.shields.io/badge/Blog-kirankumark3.blogspot.com-FF5722?style=flat&logo=blogger)](https://kirankumark3.blogspot.com)
[![BugCrowd](https://img.shields.io/badge/BugCrowd-KIRAN--KUMAR--K-F26822?style=flat&logo=bugcrowd)](https://bugcrowd.com/h/KIRAN-KUMAR-K)

<img src="https://capsule-render.vercel.app/api?type=waving&color=0:0d47a1,50:1a1f35,100:0d1117&height=100&section=footer" />

</div>
