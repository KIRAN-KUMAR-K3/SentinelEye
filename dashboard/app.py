"""
dashboard/app.py
Flask-based SOC dashboard.

Run:  python siem.py dashboard
Then: http://localhost:5000
"""
import os, sys, json
from datetime import datetime, timedelta
from flask import Flask, render_template, request, jsonify, redirect, url_for

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import config
from db.schema import (
    get_connection, get_stats, get_alerts,
    acknowledge_alert, query_events,
)


def create_app():
    app = Flask(__name__, template_folder="templates")
    app.secret_key = config.SECRET_KEY

    # ── helpers ──────────────────────────────────────────────────────────────

    def _conn():
        return get_connection()

    def _rows(sql, params=()):
        conn = _conn()
        conn.row_factory = __import__("sqlite3").Row
        return [dict(r) for r in conn.execute(sql, params).fetchall()]

    # ── routes ───────────────────────────────────────────────────────────────

    @app.route("/")
    def index():
        stats  = get_stats()
        alerts = get_alerts(unacked_only=True, limit=20)
        return render_template("index.html", stats=stats, alerts=alerts)

    @app.route("/api/stats")
    def api_stats():
        return jsonify(get_stats())

    @app.route("/api/alerts")
    def api_alerts():
        severity   = request.args.get("severity")
        unacked    = request.args.get("unacked", "0") == "1"
        limit      = int(request.args.get("limit", 200))
        return jsonify(get_alerts(severity=severity, unacked_only=unacked, limit=limit))

    @app.route("/api/alerts/<int:alert_id>/ack", methods=["POST"])
    def ack_alert(alert_id):
        analyst = request.json.get("analyst", "dashboard")
        acknowledge_alert(alert_id, ack_by=analyst)
        return jsonify({"ok": True})

    @app.route("/api/events")
    def api_events():
        params = {k: request.args.get(k) for k in
                  ("src_ip","dst_ip","log_type","log_source","action","since","until")}
        limit = int(request.args.get("limit", 100))
        events = query_events(limit=limit, **params)
        return jsonify(events)

    @app.route("/api/chart/actions")
    def chart_actions():
        rows = _rows("""
            SELECT action, COUNT(*) as cnt
            FROM   events
            GROUP BY action
            ORDER BY cnt DESC
        """)
        return jsonify(rows)

    @app.route("/api/chart/hourly")
    def chart_hourly():
        hours = int(request.args.get("hours", 24))
        since = (datetime.utcnow() - timedelta(hours=hours)).strftime("%Y-%m-%d %H:%M:%S")
        rows = _rows(f"""
            SELECT strftime('%Y-%m-%d %H:00', ts) as hour,
                   COUNT(*) as total,
                   SUM(CASE WHEN action='Deny' THEN 1 ELSE 0 END) as denied
            FROM   events
            WHERE  ts >= ?
            GROUP BY hour
            ORDER BY hour
        """, (since,))
        return jsonify(rows)

    @app.route("/api/chart/top_src")
    def chart_top_src():
        action = request.args.get("action", "Deny")
        rows = _rows("""
            SELECT src_ip, COUNT(*) as cnt
            FROM   events
            WHERE  action = ?
              AND  src_ip != ''
            GROUP BY src_ip
            ORDER BY cnt DESC
            LIMIT 15
        """, (action,))
        return jsonify(rows)

    @app.route("/api/chart/top_dst")
    def chart_top_dst():
        rows = _rows("""
            SELECT dst_ip, COUNT(*) as cnt
            FROM   events
            WHERE  dst_ip != ''
            GROUP BY dst_ip
            ORDER BY cnt DESC
            LIMIT 15
        """)
        return jsonify(rows)

    @app.route("/api/chart/log_types")
    def chart_log_types():
        rows = _rows("""
            SELECT log_type, COUNT(*) as cnt
            FROM   events
            GROUP BY log_type
            ORDER BY cnt DESC
            LIMIT 12
        """)
        return jsonify(rows)

    @app.route("/api/chart/top_dns_clients")
    def chart_top_dns_clients():
        rows = _rows("""
            SELECT client_ip, COUNT(*) as cnt
            FROM   dns_queries
            GROUP BY client_ip
            ORDER BY cnt DESC
            LIMIT 15
        """)
        return jsonify(rows)

    @app.route("/api/chart/top_dns_domains")
    def chart_top_dns_domains():
        rows = _rows("""
            SELECT query_name, COUNT(*) as cnt
            FROM   dns_queries
            GROUP BY query_name
            ORDER BY cnt DESC
            LIMIT 20
        """)
        return jsonify(rows)

    @app.route("/api/chart/radius_results")
    def chart_radius():
        rows = _rows("""
            SELECT result, COUNT(*) as cnt
            FROM   radius_auth
            GROUP BY result
            ORDER BY cnt DESC
        """)
        return jsonify(rows)

    @app.route("/api/chart/alerts_severity")
    def chart_alerts_sev():
        rows = _rows("""
            SELECT severity, COUNT(*) as cnt
            FROM   alerts
            GROUP BY severity
            ORDER BY CASE severity
                WHEN 'Critical' THEN 1
                WHEN 'High'     THEN 2
                WHEN 'Medium'   THEN 3
                ELSE 4 END
        """)
        return jsonify(rows)

    @app.route("/api/ip_lookup/<ip>")
    def ip_lookup(ip):
        """Return all activity for a given IP across all tables."""
        fw = _rows(
            "SELECT ts,log_type,log_component,action,dst_ip,dst_port,protocol,message "
            "FROM events WHERE src_ip=? ORDER BY ts DESC LIMIT 100", (ip,)
        )
        dns = _rows(
            "SELECT ts,query_name,query_type FROM dns_queries WHERE client_ip=? ORDER BY ts DESC LIMIT 100",
            (ip,)
        )
        radius = _rows(
            "SELECT ts,username,result,nas_ip FROM radius_auth WHERE client_ip=? OR nas_ip=? ORDER BY ts DESC LIMIT 50",
            (ip, ip)
        )
        dhcp = _rows(
            "SELECT ts,event_type,mac_address,hostname FROM dhcp_leases WHERE ip_address=? ORDER BY ts DESC LIMIT 50",
            (ip,)
        )
        alerts_for_ip = _rows(
            "SELECT id,rule_name,severity,description,created_at FROM alerts WHERE src_ip=? ORDER BY created_at DESC",
            (ip,)
        )
        return jsonify({
            "ip":        ip,
            "firewall":  fw,
            "dns":       dns,
            "radius":    radius,
            "dhcp":      dhcp,
            "alerts":    alerts_for_ip,
        })

    @app.route("/api/run_rules", methods=["POST"])
    def run_rules():
        from rules.engine import RuleEngine
        engine = RuleEngine()
        count = engine.run(verbose=False)
        return jsonify({"new_alerts": count})

    return app
