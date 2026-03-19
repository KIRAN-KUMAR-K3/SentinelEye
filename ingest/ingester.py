"""
ingest/ingester.py — Log File Ingestion Engine
Indian Institute of Science | ISO Security Team

Architecture fix (eliminates "database is locked"):
  - Worker threads ONLY decompress + parse files → put rows in a queue
  - A SINGLE writer thread drains the queue and commits to SQLite
  - This means only one thread ever writes to the DB at any time
  - --workers controls decompression parallelism, not write parallelism
"""
import gzip
import os
import sys
import re
import time
import queue
import threading
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

# Sentinel value to signal the writer thread to stop
_DONE = object()


# ─────────────────────────────────────────────────────────────────────────────
# File discovery
# ─────────────────────────────────────────────────────────────────────────────

def discover_files(source: str = "all", since: Optional[str] = None):
    """Yield (filepath, log_source) for all matching .gz files."""
    since_ts = datetime.fromisoformat(since) if since else None
    sources  = list(config.LOG_SOURCES.keys()) if source == "all" else [source]

    for src_name in sources:
        src_cfg = config.LOG_SOURCES.get(src_name)
        if not src_cfg:
            print(f"[!] Unknown source: {src_name}"); continue
        for subdir in src_cfg["subdirs"]:
            folder = Path(src_cfg["base"]) / subdir
            if not folder.exists():
                print(f"[~] Skipping missing: {folder}"); continue
            for gz_file in sorted(folder.glob("*.gz")):
                if since_ts:
                    if datetime.fromtimestamp(gz_file.stat().st_mtime) < since_ts:
                        continue
                yield str(gz_file), src_name


# ─────────────────────────────────────────────────────────────────────────────
# Per-file parsers  (decompress + parse only, NO DB writes)
# ─────────────────────────────────────────────────────────────────────────────

def _parse_firewall_file(filepath: str):
    rows = []
    try:
        with gzip.open(filepath, "rt", encoding="utf-8", errors="replace") as f:
            for line in f:
                line = line.strip()
                if not line: continue
                kv  = parse_sophos_kv(line)
                row = sophos_to_event(kv, filepath)
                if row: rows.append(row)
    except Exception:
        pass
    return rows, "events"


def _parse_dns_file(filepath: str):
    rows = []
    try:
        with gzip.open(filepath, "rt", encoding="utf-8", errors="replace") as f:
            for line in f:
                row = parse_dns_line(line, filepath)
                if row: rows.append(row)
    except Exception:
        pass
    return rows, "dns"


def _parse_radius_file(filepath: str):
    rows, block = [], []

    def flush(block):
        if block:
            row = parse_radius_block(block, filepath)
            if row: rows.append(row)

    try:
        with gzip.open(filepath, "rt", encoding="utf-8", errors="replace") as f:
            for line in f:
                stripped = line.rstrip("\n")
                if stripped == "":
                    flush(block); block = []
                elif stripped[0] not in ("\t", " ") and block:
                    flush(block); block = [stripped]
                else:
                    r = _parse_radius_singleline(stripped, filepath)
                    if r: rows.append(r)
                    else: block.append(stripped)
        flush(block)
    except Exception:
        pass
    return rows, "radius"


def _parse_dhcp_file(filepath: str):
    fname = os.path.basename(filepath)
    year_hint = "2025"
    ym = re.search(r'\.(\d{2})\.gz$', fname, re.I)
    if ym:
        year_hint = str(2000 + int(ym.group(1)))
    rows = []
    try:
        with gzip.open(filepath, "rt", encoding="utf-8", errors="replace") as f:
            for line in f:
                row = parse_dhcp_line(line, filepath, year_hint=year_hint)
                if row: rows.append(row)
    except Exception:
        pass
    return rows, "dhcp"


def _parse_macip_file(filepath: str):
    rows = []
    try:
        with gzip.open(filepath, "rt", encoding="utf-8", errors="replace") as f:
            for line in f:
                row = parse_macip_line(line, filepath)
                if row: rows.append(row)
    except Exception:
        pass
    return rows, "mac_ip"


def _parse_file(filepath: str, log_source: str):
    """Route to the right parser. Returns (rows, table_type, filepath)."""
    if config.SKIP_INGESTED and db.is_file_ingested(filepath):
        return None, None, filepath   # None = skip

    fname = os.path.basename(filepath).lower()
    if log_source == "firewall" and re.match(r'^\d{2}\.\d{2}', fname):
        rows, ttype = _parse_macip_file(filepath)
    elif log_source == "firewall":
        rows, ttype = _parse_firewall_file(filepath)
    elif log_source == "dns":
        rows, ttype = _parse_dns_file(filepath)
    elif log_source == "radius":
        rows, ttype = _parse_radius_file(filepath)
    elif log_source == "dhcp":
        rows, ttype = _parse_dhcp_file(filepath)
    else:
        rows, ttype = [], "events"

    return rows, ttype, filepath


# ─────────────────────────────────────────────────────────────────────────────
# Single writer thread  — drains the write queue
# ─────────────────────────────────────────────────────────────────────────────

_write_fn = {
    "events": db.bulk_insert_events,
    "dns":    db.bulk_insert_dns,
    "radius": db.bulk_insert_radius,
    "dhcp":   db.bulk_insert_dhcp,
    "mac_ip": db.bulk_insert_mac_ip,
}

def _writer_thread(write_q: queue.Queue, stats: dict):
    """Runs in a single thread. Reads (rows, ttype, filepath) from queue."""
    while True:
        item = write_q.get()
        if item is _DONE:
            break
        rows, ttype, filepath = item
        if rows:
            # Write in batches of BATCH_SIZE
            for i in range(0, len(rows), config.BATCH_SIZE):
                batch = rows[i:i + config.BATCH_SIZE]
                try:
                    _write_fn[ttype](batch)
                except Exception as e:
                    print(f"\n  [!] Write error for {os.path.basename(filepath)}: {e}")
            db.mark_file_ingested(filepath, ttype, len(rows))
            stats["rows"] += len(rows)
        stats["written"] += 1
        write_q.task_done()


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
            for fp, src in files[:30]:
                print(f"    {src:10s}  {fp}")
            if total > 30:
                print(f"    … and {total-30} more")
            return

        if total == 0:
            print("[!] No files to ingest."); return

        t0 = time.time()
        print(f"[+] Ingesting with {self.workers} parser threads + 1 writer thread …\n", flush=True)

        # Shared stats dict (writer thread updates it)
        stats = {"rows": 0, "written": 0}

        # Start the single writer thread
        write_q = queue.Queue(maxsize=self.workers * 4)
        writer  = threading.Thread(target=_writer_thread, args=(write_q, stats), daemon=True)
        writer.start()

        done = skipped = errors = 0

        with ThreadPoolExecutor(max_workers=self.workers) as pool:
            futures = {
                pool.submit(_parse_file, fp, src): (fp, src)
                for fp, src in files
            }
            for future in as_completed(futures):
                fp, src = futures[future]
                fname   = os.path.basename(fp)
                try:
                    rows, ttype, _ = future.result()
                    if rows is None:
                        skipped += 1
                    elif len(rows) == 0:
                        errors += 1
                    else:
                        write_q.put((rows, ttype, fp))  # hand to writer
                    done += 1

                except Exception as exc:
                    print(f"\n  [!] Parse error {fname}: {exc}", flush=True)
                    errors += 1
                    done += 1

                # Progress every 10 files
                if done % 10 == 0 or done == total:
                    elapsed  = time.time() - t0
                    pct      = done / total * 100
                    rate     = done / elapsed if elapsed else 0
                    eta      = (total - done) / rate if rate else 0
                    row_rate = stats["rows"] / elapsed if elapsed else 0
                    print(
                        f"  [{done:>5}/{total}]  {pct:5.1f}%  |  "
                        f"rows: {stats['rows']:>10,}  ({row_rate:>8,.0f} r/s)  |  "
                        f"ETA: {eta/60:4.1f}m  |  {fname[:35]}",
                        flush=True,
                    )

        # Signal writer to finish and wait
        write_q.put(_DONE)
        writer.join()

        elapsed = time.time() - t0
        print(f"\n[+] Done in {elapsed:.1f}s")
        print(f"    Files parsed  : {done - skipped:,}")
        print(f"    Files skipped : {skipped:,}  (already ingested)")
        print(f"    Files empty   : {errors:,}")
        print(f"    Rows inserted : {stats['rows']:,}")
        print(f"    Rate          : {stats['rows']/elapsed if elapsed else 0:,.0f} rows/sec")
