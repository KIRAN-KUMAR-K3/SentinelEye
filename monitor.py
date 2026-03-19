#!/usr/bin/env python3
"""
monitor.py — Live Ingestion Progress Monitor
Indian Institute of Science | ISO Security Team

Run in a second terminal while ingestion is running:
    python monitor.py
"""
import sqlite3, time, os, sys

DB = os.path.expanduser("~/siem.db")

def bar(pct, width=28):
    f = int(width * pct / 100)
    return "█" * f + "░" * (width - f)

def get(conn, sql):
    try:
        r = conn.execute(sql).fetchone()
        return r[0] if r else 0
    except Exception:
        return 0

print(f"\n  Watching: {DB}")
print("  Press Ctrl+C to stop\n")

prev_rows = 0
prev_time = time.time()

while True:
    try:
        conn = sqlite3.connect(DB, timeout=5)
        conn.execute("PRAGMA query_only=ON")

        events   = get(conn, "SELECT COUNT(*) FROM events")
        dns      = get(conn, "SELECT COUNT(*) FROM dns_queries")
        radius   = get(conn, "SELECT COUNT(*) FROM radius_auth")
        dhcp     = get(conn, "SELECT COUNT(*) FROM dhcp_leases")
        mac_ip   = get(conn, "SELECT COUNT(*) FROM mac_ip_map")
        files_in = get(conn, "SELECT COUNT(*) FROM ingested_files")
        conn.close()

        now        = time.time()
        total_rows = events + dns + radius + dhcp + mac_ip
        delta      = total_rows - prev_rows
        delta_t    = now - prev_time
        rate       = int(delta / delta_t) if delta_t > 0 else 0
        prev_rows  = total_rows
        prev_time  = now

        # Estimate total from known file counts
        total_files_est = 45437
        pct_files = min(files_in / total_files_est * 100, 100)

        os.system("clear")
        print("╔══════════════════════════════════════════════════════╗")
        print("║      SentinelEye — Live Ingestion Monitor            ║")
        print("║      Indian Institute of Science | ISO Security      ║")
        print("╠══════════════════════════════════════════════════════╣")
        print(f"║  Files ingested : {files_in:>7,} / {total_files_est:,}                   ║")
        print(f"║  Progress       : [{bar(pct_files)}]  {pct_files:5.1f}%  ║")
        print("╠══════════════════════════════════════════════════════╣")
        print(f"║  Firewall events: {events:>14,}                      ║")
        print(f"║  DNS queries    : {dns:>14,}                      ║")
        print(f"║  RADIUS auth    : {radius:>14,}                      ║")
        print(f"║  DHCP leases    : {dhcp:>14,}                      ║")
        print(f"║  MAC-IP maps    : {mac_ip:>14,}                      ║")
        print("╠══════════════════════════════════════════════════════╣")
        print(f"║  Total rows     : {total_rows:>14,}                      ║")
        print(f"║  Ingest rate    : {rate:>11,} rows/sec                  ║")
        print(f"║  Updated        : {time.strftime('%H:%M:%S'):>8}                         ║")
        print("╚══════════════════════════════════════════════════════╝")
        print("\n  Refreshes every 5 seconds … (Ctrl+C to stop)")

    except KeyboardInterrupt:
        print("\n  Stopped."); sys.exit(0)
    except Exception as e:
        os.system("clear")
        print(f"  DB not ready yet: {e}\n  Retrying in 5 seconds …")

    time.sleep(5)
