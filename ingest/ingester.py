"""
ingest/ingester.py
Discovers all .gz files under the NFS mount, decompresses them in parallel,
and inserts normalised rows into the SQLite database.

Usage:
    python siem.py ingest --source all --workers 8
"""

import gzip
import os
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path
from typing import Optional

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import config
from db import schema as db
from ingest.parsers import (
    parse_sophos_kv, sophos_to_event,
    parse_dns_line,
    parse_radius_block, _parse_radius_singleline,
    parse_dhcp_line,
    parse_macip_line,
)


# ─────────────────────────────────────────────────────────────────────────────
# File discovery
# ─────────────────────────────────────────────────────────────────────────────

def discover_files(source: str = "all", since: Optional[str] = None):
    """Yield (filepath, log_source) tuples for all matching .gz files."""
    since_ts = datetime.fromisoformat(since) if since else None

    sources = (
        list(config.LOG_SOURCES.keys())
        if source == "all"
        else [source]
    )

    for src_name in sources:
        src_cfg = config.LOG_SOURCES.get(src_name)
        if not src_cfg:
            print(f"[!] Unknown source: {src_name}")
            continue
        base = src_cfg["base"]
        for subdir in src_cfg["subdirs"]:
            folder = Path(base) / subdir
            if not folder.exists():
                print(f"[~] Skipping missing folder: {folder}")
                continue
            for gz_file in sorted(folder.glob("*.gz")):
                if since_ts:
                    mtime = datetime.fromtimestamp(gz_file.stat().st_mtime)
                    if mtime < since_ts:
                        continue
                yield str(gz_file), src_name


# ─────────────────────────────────────────────────────────────────────────────
# Per-file processing
# ─────────────────────────────────────────────────────────────────────────────

def _ingest_firewall_file(filepath: str) -> int:
    """Parse a Sophos XG/XGS gz log file. Returns row count."""
    rows  = []
    count = 0
    fname = os.path.basename(filepath)

    try:
        with gzip.open(filepath, "rt", encoding="utf-8", errors="replace") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                kv  = parse_sophos_kv(line)
                row = sophos_to_event(kv, filepath)
                if row:
                    rows.append(row)
                    count += 1
                    if len(rows) >= config.BATCH_SIZE:
                        db.bulk_insert_events(rows)
                        rows.clear()
    except (gzip.BadGzipFile, EOFError, OSError) as e:
        print(f"[!] Bad file {fname}: {e}")
        return 0

    if rows:
        db.bulk_insert_events(rows)
    return count


def _ingest_dns_file(filepath: str) -> int:
    rows  = []
    count = 0
    try:
        with gzip.open(filepath, "rt", encoding="utf-8", errors="replace") as f:
            for line in f:
                row = parse_dns_line(line, filepath)
                if row:
                    rows.append(row)
                    count += 1
                    if len(rows) >= config.BATCH_SIZE:
                        db.bulk_insert_dns(rows)
                        rows.clear()
    except (gzip.BadGzipFile, EOFError, OSError) as e:
        print(f"[!] Bad file {os.path.basename(filepath)}: {e}")
        return 0
    if rows:
        db.bulk_insert_dns(rows)
    return count


def _ingest_radius_file(filepath: str) -> int:
    """Handle both single-line and detail-file RADIUS formats."""
    rows  = []
    count = 0
    block = []

    def flush_block():
        nonlocal count
        if block:
            row = parse_radius_block(block, filepath)
            if row:
                rows.append(row)
                count += 1
            block.clear()

    try:
        with gzip.open(filepath, "rt", encoding="utf-8", errors="replace") as f:
            for line in f:
                stripped = line.rstrip("\n")
                if stripped == "":                 # blank line = end of block
                    flush_block()
                elif stripped[0] not in ("\t", " ") and block:
                    # New block starts
                    flush_block()
                    block.append(stripped)
                else:
                    row = _parse_radius_singleline(stripped, filepath)
                    if row:
                        rows.append(row)
                        count += 1
                    else:
                        block.append(stripped)

                if len(rows) >= config.BATCH_SIZE:
                    db.bulk_insert_radius(rows)
                    rows.clear()

        flush_block()
    except (gzip.BadGzipFile, EOFError, OSError) as e:
        print(f"[!] Bad file {os.path.basename(filepath)}: {e}")
        return 0

    if rows:
        db.bulk_insert_radius(rows)
    return count


def _ingest_dhcp_file(filepath: str) -> int:
    """Try to extract year from filename (e.g. dhcpd.log.01.01.22.gz → 2022)."""
    year_hint = "2025"
    fname     = os.path.basename(filepath)
    # Look for 2-digit year at end, e.g. ".22.gz"
    ym = __import__("re").search(r'\.(\d{2})\.gz$', fname, __import__("re").I)
    if ym:
        yr = int(ym.group(1))
        year_hint = str(2000 + yr)

    rows  = []
    count = 0
    try:
        with gzip.open(filepath, "rt", encoding="utf-8", errors="replace") as f:
            for line in f:
                row = parse_dhcp_line(line, filepath, year_hint=year_hint)
                if row:
                    rows.append(row)
                    count += 1
                    if len(rows) >= config.BATCH_SIZE:
                        db.bulk_insert_dhcp(rows)
                        rows.clear()
    except (gzip.BadGzipFile, EOFError, OSError) as e:
        print(f"[!] Bad file {os.path.basename(filepath)}: {e}")
        return 0
    if rows:
        db.bulk_insert_dhcp(rows)
    return count


def _ingest_macip_file(filepath: str) -> int:
    rows  = []
    count = 0
    try:
        with gzip.open(filepath, "rt", encoding="utf-8", errors="replace") as f:
            for line in f:
                row = parse_macip_line(line, filepath)
                if row:
                    rows.append(row)
                    count += 1
                    if len(rows) >= config.BATCH_SIZE:
                        db.bulk_insert_mac_ip(rows)
                        rows.clear()
    except (gzip.BadGzipFile, EOFError, OSError) as e:
        print(f"[!] Bad macip file: {e}")
        return 0
    if rows:
        db.bulk_insert_mac_ip(rows)
    return count


# ─────────────────────────────────────────────────────────────────────────────
# Dispatcher
# ─────────────────────────────────────────────────────────────────────────────

def _ingest_file(filepath: str, log_source: str) -> tuple:
    """Route a file to the right parser. Returns (filepath, rows_loaded)."""
    if config.SKIP_INGESTED and db.is_file_ingested(filepath):
        return filepath, -1   # -1 = skipped

    fname = os.path.basename(filepath).lower()

    # Mac_IP files: numeric day prefix like  01.01.20.gz
    if log_source == "firewall" and __import__("re").match(r'^\d{2}\.\d{2}', fname):
        rows = _ingest_macip_file(filepath)
    elif log_source == "firewall":
        rows = _ingest_firewall_file(filepath)
    elif log_source == "dns":
        rows = _ingest_dns_file(filepath)
    elif log_source == "radius":
        rows = _ingest_radius_file(filepath)
    elif log_source == "dhcp":
        rows = _ingest_dhcp_file(filepath)
    else:
        rows = 0

    if rows > 0:
        db.mark_file_ingested(filepath, log_source, rows)

    return filepath, rows


# ─────────────────────────────────────────────────────────────────────────────
# Ingester class
# ─────────────────────────────────────────────────────────────────────────────

class Ingester:
    def __init__(self, workers: int = None):
        self.workers = workers or config.MAX_WORKERS

    def run(self, source: str = "all", since: str = None, dry_run: bool = False):
        files = list(discover_files(source, since))
        total = len(files)
        print(f"[+] Found {total:,} .gz files  (source={source})")

        if dry_run:
            for fp, src in files[:50]:
                print(f"    {src:10s}  {fp}")
            if total > 50:
                print(f"    … and {total-50} more")
            return

        if total == 0:
            print("[!] No files to ingest.")
            return

        t0      = time.time()
        done    = 0
        skipped = 0
        errors  = 0
        total_rows = 0

        print(f"[+] Starting ingestion with {self.workers} workers …", flush=True)
        print(f"    Progress updates every 10 files.\n", flush=True)

        with ThreadPoolExecutor(max_workers=self.workers) as pool:
            futures = {
                pool.submit(_ingest_file, fp, src): (fp, src)
                for fp, src in files
            }
            for future in as_completed(futures):
                try:
                    fp, rows = future.result()
                    fname = os.path.basename(fp)
                    if rows == -1:
                        skipped += 1
                    elif rows == 0:
                        errors += 1
                        print(f"  [!] Empty/bad: {fname}", flush=True)
                    else:
                        total_rows += rows
                    done += 1

                    # Progress every 10 files
                    if done % 10 == 0 or done == total:
                        elapsed = time.time() - t0
                        pct     = done / total * 100
                        rate    = done / elapsed if elapsed else 0
                        eta     = (total - done) / rate if rate else 0
                        rows_rate = total_rows / elapsed if elapsed else 0
                        print(
                            f"  [{done:>5}/{total}]  {pct:5.1f}%  |  "
                            f"rows: {total_rows:>10,}  ({rows_rate:>8,.0f} rows/s)  |  "
                            f"ETA: {eta/60:5.1f} min  |  last: {fname[:40]}",
                            flush=True,
                        )
                except Exception as exc:
                    print(f"\n[!] Worker error: {exc}", flush=True)
                    errors += 1

        elapsed = time.time() - t0
        print(f"\n[+] Done in {elapsed:.1f}s")
        print(f"    Files processed : {done - skipped:,}")
        print(f"    Files skipped   : {skipped:,}  (already ingested)")
        print(f"    Files errored   : {errors:,}")
        print(f"    Rows inserted   : {total_rows:,}")
        print(f"    Rate            : {total_rows/elapsed if elapsed else 0:,.0f} rows/sec")
