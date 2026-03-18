#!/usr/bin/env python3
"""
siem.py  –  SIEM CLI entry point

Commands:
  init        Create/upgrade the SQLite database
  ingest      Parse .gz log files from the NFS mount into the DB
  analyze     Run SOC detection rules and generate alerts
  dashboard   Start the web dashboard  (http://localhost:5000)
  query       Query events from the CLI
  alerts      View / acknowledge alerts
  report      Print summary report to stdout

Examples:
  python siem.py init
  python siem.py ingest --source all --workers 8
  python siem.py ingest --source firewall --since 2025-01-01
  python siem.py analyze
  python siem.py analyze --rules R001 R005 R013
  python siem.py dashboard --port 5000
  python siem.py query --src-ip 10.217.51.86 --limit 50
  python siem.py alerts --severity Critical --unacked
  python siem.py alerts --ack 12
  python siem.py report
"""

import argparse
import sys
import os


def main():
    parser = argparse.ArgumentParser(
        prog="siem",
        description="SIEM — Log Analysis & SOC Operations",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    sub = parser.add_subparsers(dest="cmd")

    # init
    sub.add_parser("init", help="Initialise the SQLite database")

    # ingest
    p = sub.add_parser("ingest", help="Ingest .gz log files")
    p.add_argument("--source", default="all",
                   choices=["all","firewall","dns","radius","dhcp"],
                   help="Which log source to ingest (default: all)")
    p.add_argument("--workers", type=int, default=8,
                   help="Parallel worker threads (default: 8)")
    p.add_argument("--since", metavar="YYYY-MM-DD",
                   help="Only process files modified after this date")
    p.add_argument("--dry-run", action="store_true",
                   help="List files that would be ingested without loading them")

    # analyze
    p = sub.add_parser("analyze", help="Run detection rules")
    p.add_argument("--rules", nargs="+", metavar="R001",
                   help="Run only these rule IDs (default: all)")
    p.add_argument("--since", metavar="YYYY-MM-DD",
                   help="(Informational – filter hint for future use)")

    # dashboard
    p = sub.add_parser("dashboard", help="Start web dashboard")
    p.add_argument("--host", default="0.0.0.0")
    p.add_argument("--port", type=int, default=5000)
    p.add_argument("--debug", action="store_true")

    # query
    p = sub.add_parser("query", help="Query events from the DB")
    p.add_argument("--src-ip")
    p.add_argument("--dst-ip")
    p.add_argument("--type", dest="log_type")
    p.add_argument("--source", dest="log_source")
    p.add_argument("--action")
    p.add_argument("--since", metavar="YYYY-MM-DD")
    p.add_argument("--limit", type=int, default=100)
    p.add_argument("--format", choices=["table","json","csv"], default="table")

    # alerts
    p = sub.add_parser("alerts", help="View / manage alerts")
    p.add_argument("--severity", choices=["Critical","High","Medium","Low"])
    p.add_argument("--unacked", action="store_true", help="Show only unacknowledged")
    p.add_argument("--ack", type=int, metavar="ID", help="Acknowledge alert by ID")
    p.add_argument("--ack-by", default="analyst")

    # report
    sub.add_parser("report", help="Print summary stats report")

    # ── dispatch ──────────────────────────────────────────────────────────────
    args = parser.parse_args()

    if not args.cmd:
        parser.print_help()
        sys.exit(0)

    if args.cmd == "init":
        from db.schema import init_db
        init_db()

    elif args.cmd == "ingest":
        from db.schema import init_db
        init_db()          # ensure schema exists
        from ingest.ingester import Ingester
        ing = Ingester(workers=args.workers)
        ing.run(source=args.source, since=args.since, dry_run=args.dry_run)

    elif args.cmd == "analyze":
        from rules.engine import RuleEngine
        print("[+] Running detection rules …")
        engine = RuleEngine()
        engine.run(rule_ids=args.rules)

    elif args.cmd == "dashboard":
        from dashboard.app import create_app
        app = create_app()
        print(f"[+] Dashboard → http://{args.host}:{args.port}")
        app.run(host=args.host, port=args.port, debug=args.debug)

    elif args.cmd == "query":
        from db.schema import query_events
        rows = query_events(
            src_ip=args.src_ip, dst_ip=args.dst_ip,
            log_type=args.log_type, log_source=args.log_source,
            action=args.action, since=args.since, limit=args.limit,
        )
        _print_rows(rows, fmt=args.format)

    elif args.cmd == "alerts":
        from db.schema import get_alerts, acknowledge_alert
        if args.ack:
            acknowledge_alert(args.ack, ack_by=args.ack_by)
            print(f"[+] Alert {args.ack} acknowledged by {args.ack_by}")
        else:
            rows = get_alerts(severity=args.severity, unacked_only=args.unacked)
            _print_rows(rows, fmt="table",
                        cols=["id","severity","rule_name","src_ip","description","created_at"])

    elif args.cmd == "report":
        _print_report()


# ─── helpers ──────────────────────────────────────────────────────────────────

def _print_rows(rows, fmt="table", cols=None):
    if not rows:
        print("(no results)")
        return
    if fmt == "json":
        import json
        print(json.dumps(rows, default=str, indent=2))
    elif fmt == "csv":
        import csv
        keys = cols or list(rows[0].keys())
        w = csv.DictWriter(sys.stdout, fieldnames=keys, extrasaction="ignore")
        w.writeheader()
        w.writerows(rows)
    else:
        # simple table
        keys = cols or list(rows[0].keys())
        widths = {k: max(len(str(k)), max(len(str(r.get(k,"") or "")) for r in rows))
                  for k in keys}
        widths = {k: min(v, 60) for k, v in widths.items()}
        header = "  ".join(str(k).ljust(widths[k]) for k in keys)
        sep    = "  ".join("-" * widths[k] for k in keys)
        print(header)
        print(sep)
        for r in rows:
            print("  ".join(str(r.get(k,"") or "")[:widths[k]].ljust(widths[k]) for k in keys))
        print(f"\n({len(rows)} rows)")


def _print_report():
    from db.schema import get_stats, get_alerts
    s = get_stats()
    print("\n╔══════════════════════════════════════╗")
    print("║         SIEM  –  Summary Report       ║")
    print("╚══════════════════════════════════════╝")
    print(f"  Total events ingested : {s['total_events']:>12,}")
    print(f"  DNS queries           : {s['total_dns']:>12,}")
    print(f"  RADIUS auth records   : {s['total_radius']:>12,}")
    print(f"  DHCP events           : {s['total_dhcp']:>12,}")
    print(f"  Files ingested        : {s['files_ingested']:>12,}")
    print()
    print(f"  Open alerts           : {s['open_alerts']:>12,}")
    print(f"  Critical alerts       : {s['critical_alerts']:>12,}")
    print(f"  Denied connections    : {s['denied_events']:>12,}")
    print(f"  ATP/Threat events     : {s['atp_events']:>12,}")
    print(f"  IPS events            : {s['ips_events']:>12,}")
    print(f"  DoS attacks           : {s['dos_events']:>12,}")
    print(f"  RADIUS rejects        : {s['radius_rejects']:>12,}")
    print()
    alerts = get_alerts(unacked_only=True, limit=10)
    if alerts:
        print("  Top open alerts:")
        for a in alerts[:10]:
            print(f"    [{a['severity']:8s}] {a['rule_name']:30s}  {a['src_ip']:15s}  {a['description'][:60]}")
    print()


if __name__ == "__main__":
    main()
