"""
rules/engine.py — Detection Rule Runner
Indian Institute of Science | ISO Security Team

Fix: uses read-only connection for rule queries, write lock only for insert_alert.
"""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from db.schema import insert_alert, get_connection
from rules.definitions import RULES


class RuleEngine:
    def __init__(self):
        # Use a read-only connection for rule SQL queries
        self.conn = get_connection()

    def run(self, rule_ids: list = None, verbose: bool = True) -> int:
        rules_to_run = (
            [r for r in RULES if r["id"] in rule_ids]
            if rule_ids else RULES
        )

        total_alerts = 0
        for rule in rules_to_run:
            if verbose:
                print(f"  [{rule['id']}] {rule['name']} ...", end=" ", flush=True)
            try:
                hits = rule["fn"](self.conn)
            except Exception as exc:
                print(f"ERROR: {exc}")
                continue

            new_alerts = 0
            for hit in hits:
                # Deduplicate: skip if same rule+src_ip already has an open alert
                existing = self.conn.execute(
                    "SELECT 1 FROM alerts WHERE rule_id=? AND src_ip=? AND acknowledged=0 LIMIT 1",
                    (rule["id"], hit.get("src_ip", ""))
                ).fetchone()
                if existing:
                    continue
                insert_alert(
                    rule_id=rule["id"],
                    rule_name=rule["name"],
                    severity=rule["severity"],
                    src_ip=hit.get("src_ip", ""),
                    dst_ip=hit.get("dst_ip", ""),
                    username=hit.get("username", ""),
                    description=hit.get("description", ""),
                    event_ids=hit.get("event_ids", []),
                )
                new_alerts += 1
                total_alerts += 1

            if verbose:
                print(f"{len(hits)} hits → {new_alerts} new alerts")

        if verbose:
            print(f"\n[+] Total new alerts generated: {total_alerts}")
        return total_alerts
