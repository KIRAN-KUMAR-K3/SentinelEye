#!/usr/bin/env python3
"""
monitor.py — run this in a second terminal to watch ingestion progress live.
Usage:  python monitor.py
"""
import sqlite3, time, os, sys

DB = os.path.expanduser("~/siem.db")

def get(conn, sql):
    try:
        r = conn.execute(sql).fetchone()
        return r[0] if r else 0
    except:
        return 0

def bar(pct, width=30):
    filled = int(width * pct / 100)
    return "█" * filled + "░" * (width - filled)

print(f"\n  Watching: {DB}")
print("  Press Ctrl+C to stop\n")

prev_events = 0
prev_time   = time.time()

while True:
    try:
        conn = sqlite3.connect(DB, timeout=5)
        events   = get(conn, "SELECT COUNT(*) FROM events")
        dns      = get(conn, "SELECT COUNT(*) FROM dns_queries")
        radius   = get(conn, "SELECT COUNT(*) FROM radius_auth")
        dhcp     = get(conn, "SELECT COUNT(*) FROM dhcp_leases")
        files_in = get(conn, "SELECT COUNT(*) FROM ingested_files")
        conn.close()

        now       = time.time()
        delta_rows= events - prev_events
        delta_sec = now - prev_time
        rate      = int(delta_rows / delta_sec) if delta_sec > 0 else 0
        prev_events = events
        prev_time   = now

        total_est = 45437
        pct_files = files_in / total_est * 100

        os.system("clear")
        print("╔══════════════════════════════════════════════════╗")
        print("║         SentinelEye — Ingestion Monitor          ║")
        print("╠══════════════════════════════════════════════════╣")
        print(f"║  Files ingested : {files_in:>7,} / {total_est:,}                ║")
        print(f"║  Progress       : [{bar(pct_files)}] {pct_files:5.1f}% ║")
        print("╠══════════════════════════════════════════════════╣")
        print(f"║  Firewall events: {events:>12,}                      ║")
        print(f"║  DNS queries    : {dns:>12,}                      ║")
        print(f"║  RADIUS auth    : {radius:>12,}                      ║")
        print(f"║  DHCP leases    : {dhcp:>12,}                      ║")
        print("╠══════════════════════════════════════════════════╣")
        total_rows = events + dns + radius + dhcp
        print(f"║  Total rows     : {total_rows:>12,}                      ║")
        print(f"║  Ingest rate    : {rate:>9,} rows/sec                  ║")
        print(f"║  Updated        : {time.strftime('%H:%M:%S'):>8}                         ║")
        print("╚══════════════════════════════════════════════════╝")
        print("\n  Refreshing every 5 seconds … (Ctrl+C to exit)")

    except Exception as e:
        print(f"  DB not ready yet or ingestion not started: {e}")

    time.sleep(5)
