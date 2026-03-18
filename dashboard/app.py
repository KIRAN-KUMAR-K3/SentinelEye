"""
dashboard/app.py  –  SentinelEye SOC Platform
Indian Institute of Science  |  ISO Security Team
Secure Flask backend with 30+ REST endpoints.
"""
import os, sys, json, csv, io, re
from datetime import datetime, timedelta
from flask import Flask, render_template, request, jsonify, Response

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import config
from db.schema import get_connection, get_stats, get_alerts, acknowledge_alert

# ─── Input validators ─────────────────────────────────────────────────────────
_IP_RE  = re.compile(r'^\d{1,3}(\.\d{1,3}){3}$')
_MAC_RE = re.compile(r'^[0-9a-f:]{17}$')

def _safe_ip(v):
    v = (v or "").strip()
    return v if _IP_RE.match(v) else None

def _safe_int(v, default=100, lo=1, hi=5000):
    try:   return max(lo, min(hi, int(v)))
    except: return default

def _safe_date(v):
    try:   datetime.fromisoformat(str(v)); return str(v)
    except: return None

def _safe_str(v, maxlen=100):
    return str(v or "").strip()[:maxlen]


def create_app():
    app = Flask(__name__, template_folder="templates")
    app.secret_key = config.SECRET_KEY

    # ── DB helpers ─────────────────────────────────────────────────────────────
    def _rows(sql, params=()):
        import sqlite3
        conn = get_connection()
        conn.row_factory = sqlite3.Row
        try:   return [dict(r) for r in conn.execute(sql, params).fetchall()]
        finally: conn.close()

    def _scalar(sql, params=()):
        conn = get_connection()
        try:
            r = conn.execute(sql, params).fetchone()
            return r[0] if r else 0
        finally: conn.close()

    def _date_clause(col="ts"):
        c, p = [], []
        s = _safe_date(request.args.get("since"))
        u = _safe_date(request.args.get("until"))
        if s: c.append(f"{col} >= ?"); p.append(s)
        if u: c.append(f"{col} <= ?"); p.append(u + " 23:59:59")
        return c, p

    # ══════════════════════════════════════════════
    # PAGES
    # ══════════════════════════════════════════════

    @app.route("/")
    def index():
        return render_template("index.html")

    # ══════════════════════════════════════════════
    # OVERVIEW
    # ══════════════════════════════════════════════

    @app.route("/api/stats")
    def api_stats():
        s = get_stats()
        s["unique_src_ips"]  = _scalar("SELECT COUNT(DISTINCT src_ip) FROM events WHERE src_ip!=''")
        s["total_users"]     = _scalar("SELECT COUNT(DISTINCT username) FROM radius_auth WHERE username!=''")
        s["atp_threat_types"]= _scalar("SELECT COUNT(DISTINCT threat_name) FROM events WHERE threat_name!=''")
        s["vpn_sessions"]    = _scalar("SELECT COUNT(*) FROM events WHERE log_component LIKE '%VPN%' OR log_component LIKE '%SSL%'")
        s["mac_bindings"]    = _scalar("SELECT COUNT(DISTINCT mac_address) FROM mac_ip_map WHERE mac_address!=''")
        s["dhcp_leases"]     = _scalar("SELECT COUNT(*) FROM dhcp_leases")
        s["unique_domains"]  = _scalar("SELECT COUNT(DISTINCT query_name) FROM dns_queries")
        return jsonify(s)

    @app.route("/api/chart/hourly")
    def chart_hourly():
        hours = _safe_int(request.args.get("hours", 24), 24, 1, 168)
        since = (datetime.utcnow() - timedelta(hours=hours)).strftime("%Y-%m-%d %H:%M:%S")
        return jsonify(_rows("""
            SELECT strftime('%Y-%m-%d %H:00', ts) as hour,
                   COUNT(*) as total,
                   SUM(CASE WHEN action='Deny'  THEN 1 ELSE 0 END) as denied,
                   SUM(CASE WHEN action='Allow' THEN 1 ELSE 0 END) as allowed,
                   SUM(CASE WHEN action='Alert' THEN 1 ELSE 0 END) as alerted
            FROM events WHERE ts >= ?
            GROUP BY hour ORDER BY hour
        """, (since,)))

    @app.route("/api/chart/log_types")
    def chart_log_types():
        return jsonify(_rows("""
            SELECT COALESCE(NULLIF(log_type,''),'Unknown') as log_type, COUNT(*) as cnt
            FROM events GROUP BY log_type ORDER BY cnt DESC LIMIT 12
        """))

    @app.route("/api/chart/alerts_severity")
    def chart_alerts_sev():
        return jsonify(_rows("""
            SELECT severity, COUNT(*) as total,
                   SUM(CASE WHEN acknowledged=0 THEN 1 ELSE 0 END) as open
            FROM alerts GROUP BY severity
            ORDER BY CASE severity WHEN 'Critical' THEN 1 WHEN 'High' THEN 2
                                   WHEN 'Medium' THEN 3 ELSE 4 END
        """))

    # ══════════════════════════════════════════════
    # ALERTS
    # ══════════════════════════════════════════════

    @app.route("/api/alerts")
    def api_alerts():
        severity = _safe_str(request.args.get("severity",""))
        rule_id  = _safe_str(request.args.get("rule_id",""))
        unacked  = request.args.get("unacked","0") == "1"
        src_ip   = _safe_ip(request.args.get("src_ip","") or "")
        limit    = _safe_int(request.args.get("limit",500),500,1,2000)
        c, p     = _date_clause("created_at")
        if severity: c.append("severity=?");  p.append(severity)
        if rule_id:  c.append("rule_id=?");   p.append(rule_id)
        if unacked:  c.append("acknowledged=0")
        if src_ip:   c.append("src_ip=?");    p.append(src_ip)
        where = ("WHERE " + " AND ".join(c)) if c else ""
        return jsonify(_rows(f"SELECT * FROM alerts {where} ORDER BY created_at DESC LIMIT {limit}", p))

    @app.route("/api/alerts/<int:alert_id>/ack", methods=["POST"])
    def ack_alert(alert_id):
        d = request.get_json(silent=True) or {}
        analyst = _safe_str(d.get("analyst","soc-analyst"))
        acknowledge_alert(alert_id, ack_by=analyst)
        return jsonify({"ok": True})

    @app.route("/api/alerts/bulk_ack", methods=["POST"])
    def bulk_ack():
        d       = request.get_json(silent=True) or {}
        ids     = [int(i) for i in d.get("ids",[]) if str(i).isdigit()][:500]
        analyst = _safe_str(d.get("analyst","soc-analyst"))
        if not ids: return jsonify({"ok":False,"error":"no ids"}), 400
        conn = get_connection()
        try:
            conn.executemany(
                "UPDATE alerts SET acknowledged=1,ack_at=datetime('now'),ack_by=? WHERE id=?",
                [(analyst, i) for i in ids])
            conn.commit()
        finally: conn.close()
        return jsonify({"ok":True,"acked":len(ids)})

    @app.route("/api/alerts/export")
    def export_alerts():
        rows = _rows("SELECT * FROM alerts ORDER BY created_at DESC LIMIT 10000")
        fmt  = _safe_str(request.args.get("format","csv"))
        if fmt == "json":
            return Response(json.dumps(rows, default=str), mimetype="application/json",
                            headers={"Content-Disposition":"attachment; filename=alerts.json"})
        buf = io.StringIO()
        if rows:
            w = csv.DictWriter(buf, fieldnames=rows[0].keys())
            w.writeheader(); w.writerows(rows)
        return Response(buf.getvalue(), mimetype="text/csv",
                        headers={"Content-Disposition":"attachment; filename=alerts.csv"})

    @app.route("/api/alerts/rule_summary")
    def alerts_rule_summary():
        return jsonify(_rows("""
            SELECT rule_id, rule_name, severity,
                   COUNT(*) as total,
                   SUM(CASE WHEN acknowledged=0 THEN 1 ELSE 0 END) as open
            FROM alerts GROUP BY rule_id ORDER BY total DESC
        """))

    # ══════════════════════════════════════════════
    # FIREWALL
    # ══════════════════════════════════════════════

    @app.route("/api/firewall/top_src")
    def fw_top_src():
        action = _safe_str(request.args.get("action","Deny"))
        c, p = _date_clause(); c += ["action=?","src_ip!='"+"'"]
        p.append(action)
        where = "WHERE " + " AND ".join(c)
        return jsonify(_rows(f"""
            SELECT src_ip, COUNT(*) as cnt,
                   COUNT(DISTINCT dst_ip) as targets,
                   COUNT(DISTINCT dst_port) as ports
            FROM events {where}
            GROUP BY src_ip ORDER BY cnt DESC LIMIT 20
        """, p))

    @app.route("/api/firewall/top_dst")
    def fw_top_dst():
        c, p = _date_clause(); c.append("dst_ip!=''")
        where = "WHERE " + " AND ".join(c)
        return jsonify(_rows(f"""
            SELECT dst_ip, COUNT(*) as cnt,
                   SUM(CASE WHEN action='Deny' THEN 1 ELSE 0 END) as denied
            FROM events {where}
            GROUP BY dst_ip ORDER BY cnt DESC LIMIT 20
        """, p))

    @app.route("/api/firewall/top_rules")
    def fw_top_rules():
        c, p = _date_clause(); c.append("fw_rule_name!=''")
        where = "WHERE " + " AND ".join(c)
        return jsonify(_rows(f"""
            SELECT fw_rule_name, COUNT(*) as cnt,
                   SUM(CASE WHEN action='Allow' THEN 1 ELSE 0 END) as allowed,
                   SUM(CASE WHEN action='Deny'  THEN 1 ELSE 0 END) as denied
            FROM events {where}
            GROUP BY fw_rule_name ORDER BY cnt DESC LIMIT 15
        """, p))

    @app.route("/api/firewall/protocols")
    def fw_protocols():
        c, p = _date_clause(); c.append("protocol!=''")
        where = "WHERE " + " AND ".join(c)
        return jsonify(_rows(f"""
            SELECT protocol, COUNT(*) as cnt,
                   SUM(CASE WHEN action='Allow' THEN 1 ELSE 0 END) as allowed,
                   SUM(CASE WHEN action='Deny'  THEN 1 ELSE 0 END) as denied
            FROM events {where}
            GROUP BY protocol ORDER BY cnt DESC LIMIT 12
        """, p))

    @app.route("/api/firewall/top_ports")
    def fw_top_ports():
        c, p = _date_clause(); c += ["dst_port IS NOT NULL","dst_port > 0"]
        where = "WHERE " + " AND ".join(c)
        return jsonify(_rows(f"""
            SELECT dst_port as port, COUNT(*) as cnt,
                   SUM(CASE WHEN action='Deny' THEN 1 ELSE 0 END) as denied
            FROM events {where}
            GROUP BY dst_port ORDER BY cnt DESC LIMIT 15
        """, p))

    @app.route("/api/firewall/applications")
    def fw_applications():
        c, p = _date_clause(); c.append("application!=''")
        where = "WHERE " + " AND ".join(c)
        return jsonify(_rows(f"""
            SELECT application, COUNT(*) as cnt,
                   SUM(COALESCE(sent_bytes,0)) as total_bytes,
                   SUM(CASE WHEN action='Deny' THEN 1 ELSE 0 END) as denied
            FROM events {where}
            GROUP BY application ORDER BY cnt DESC LIMIT 20
        """, p))

    @app.route("/api/firewall/bandwidth")
    def fw_bandwidth():
        c, p = _date_clause()
        where = ("WHERE " + " AND ".join(c)) if c else ""
        return jsonify(_rows(f"""
            SELECT src_ip,
                   SUM(COALESCE(sent_bytes,0)) as sent,
                   SUM(COALESCE(recv_bytes,0)) as recv,
                   SUM(COALESCE(sent_bytes,0)+COALESCE(recv_bytes,0)) as total
            FROM events {where}
            GROUP BY src_ip ORDER BY total DESC LIMIT 20
        """, p))

    @app.route("/api/firewall/timeline")
    def fw_timeline():
        c, p = _date_clause()
        where = ("WHERE " + " AND ".join(c)) if c else ""
        return jsonify(_rows(f"""
            SELECT date(ts) as day, COUNT(*) as total,
                   SUM(CASE WHEN action='Allow' THEN 1 ELSE 0 END) as allowed,
                   SUM(CASE WHEN action='Deny'  THEN 1 ELSE 0 END) as denied
            FROM events {where}
            GROUP BY day ORDER BY day DESC LIMIT 90
        """, p))

    # ══════════════════════════════════════════════
    # DNS
    # ══════════════════════════════════════════════

    @app.route("/api/dns/summary")
    def dns_summary():
        c, p = _date_clause()
        where = ("WHERE " + " AND ".join(c)) if c else ""
        return jsonify({
            "total":          _scalar(f"SELECT COUNT(*) FROM dns_queries {where}", p),
            "unique_clients": _scalar(f"SELECT COUNT(DISTINCT client_ip) FROM dns_queries {where}", p),
            "unique_domains": _scalar(f"SELECT COUNT(DISTINCT query_name) FROM dns_queries {where}", p),
        })

    @app.route("/api/dns/top_domains")
    def dns_top_domains():
        c, p = _date_clause()
        where = ("WHERE " + " AND ".join(c)) if c else ""
        return jsonify(_rows(f"""
            SELECT query_name, COUNT(*) as cnt, COUNT(DISTINCT client_ip) as clients
            FROM dns_queries {where}
            GROUP BY query_name ORDER BY cnt DESC LIMIT 30
        """, p))

    @app.route("/api/dns/top_clients")
    def dns_top_clients():
        c, p = _date_clause()
        where = ("WHERE " + " AND ".join(c)) if c else ""
        return jsonify(_rows(f"""
            SELECT client_ip, COUNT(*) as cnt, COUNT(DISTINCT query_name) as unique_domains
            FROM dns_queries {where}
            GROUP BY client_ip ORDER BY cnt DESC LIMIT 20
        """, p))

    @app.route("/api/dns/query_types")
    def dns_query_types():
        return jsonify(_rows("""
            SELECT COALESCE(NULLIF(query_type,''),'Unknown') as query_type, COUNT(*) as cnt
            FROM dns_queries GROUP BY query_type ORDER BY cnt DESC LIMIT 12
        """))

    @app.route("/api/dns/suspicious")
    def dns_suspicious():
        c, p = _date_clause()
        c.append("""(length(query_name)>50
            OR query_name LIKE '%.xyz' OR query_name LIKE '%.top'
            OR query_name LIKE '%.tk'  OR query_name LIKE '%.ml'
            OR query_name LIKE '%.ga'  OR query_name LIKE '%.cf'
            OR query_name LIKE '%.pw'  OR query_name LIKE '%.website'
            OR query_name LIKE '%.click' OR query_name LIKE '%.download')""")
        where = "WHERE " + " AND ".join(c)
        return jsonify(_rows(f"""
            SELECT query_name, client_ip, COUNT(*) as cnt,
                   MIN(ts) as first_seen, MAX(ts) as last_seen
            FROM dns_queries {where}
            GROUP BY query_name, client_ip ORDER BY cnt DESC LIMIT 100
        """, p))

    @app.route("/api/dns/hourly")
    def dns_hourly():
        return jsonify(_rows("""
            SELECT strftime('%Y-%m-%d %H:00', ts) as hour, COUNT(*) as cnt
            FROM dns_queries WHERE ts >= datetime('now','-48 hours')
            GROUP BY hour ORDER BY hour
        """))

    # ══════════════════════════════════════════════
    # USERS
    # ══════════════════════════════════════════════

    @app.route("/api/users/logins")
    def users_logins():
        c, p = _date_clause()
        c += ["log_component IN ('GUI','CLI')", "username!=''"]
        where = "WHERE " + " AND ".join(c)
        return jsonify(_rows(f"""
            SELECT ts, username, src_ip, log_component, action, message
            FROM events {where} ORDER BY ts DESC LIMIT 300
        """, p))

    @app.route("/api/users/top")
    def users_top():
        c, p = _date_clause(); c.append("username!=''")
        where = "WHERE " + " AND ".join(c)
        return jsonify(_rows(f"""
            SELECT username, COUNT(*) as events, COUNT(DISTINCT src_ip) as ips,
                   SUM(CASE WHEN action='Deny' THEN 1 ELSE 0 END) as denied,
                   MIN(ts) as first_seen, MAX(ts) as last_seen
            FROM events {where}
            GROUP BY username ORDER BY events DESC LIMIT 30
        """, p))

    @app.route("/api/users/radius")
    def users_radius():
        c, p = _date_clause(); c.append("username!=''")
        where = "WHERE " + " AND ".join(c)
        return jsonify(_rows(f"""
            SELECT username, COUNT(*) as total,
                   SUM(CASE WHEN result='Accept' THEN 1 ELSE 0 END) as accepted,
                   SUM(CASE WHEN result='Reject' THEN 1 ELSE 0 END) as rejected,
                   MIN(ts) as first_seen, MAX(ts) as last_seen,
                   GROUP_CONCAT(DISTINCT nas_ip) as nas_ips
            FROM radius_auth {where}
            GROUP BY username ORDER BY total DESC LIMIT 50
        """, p))

    @app.route("/api/users/failed_logins")
    def users_failed():
        c, p = _date_clause(); c += ["result='Reject'","username!=''"]
        where = "WHERE " + " AND ".join(c)
        return jsonify(_rows(f"""
            SELECT username, nas_ip, COUNT(*) as failures,
                   MIN(ts) as first, MAX(ts) as last
            FROM radius_auth {where}
            GROUP BY username, nas_ip HAVING failures >= 3
            ORDER BY failures DESC LIMIT 50
        """, p))

    @app.route("/api/users/vpn")
    def users_vpn():
        c, p = _date_clause()
        c += ["(log_component LIKE '%VPN%' OR log_component LIKE '%SSL%')","username!=''"]
        where = "WHERE " + " AND ".join(c)
        return jsonify(_rows(f"""
            SELECT ts, username, src_ip, action, log_component, message
            FROM events {where} ORDER BY ts DESC LIMIT 200
        """, p))

    @app.route("/api/users/admin_actions")
    def users_admin():
        c, p = _date_clause(); c.append("log_component IN ('CLI','GUI')")
        where = "WHERE " + " AND ".join(c)
        return jsonify(_rows(f"""
            SELECT ts, username, src_ip, log_component, action, message
            FROM events {where} ORDER BY ts DESC LIMIT 300
        """, p))

    # ══════════════════════════════════════════════
    # THREATS
    # ══════════════════════════════════════════════

    @app.route("/api/threats/atp")
    def threats_atp():
        c, p = _date_clause(); c.append("log_type='ATP'")
        where = "WHERE " + " AND ".join(c)
        return jsonify(_rows(f"""
            SELECT ts, src_ip, dst_ip, url, threat_name, log_subtype, message
            FROM events {where} ORDER BY ts DESC LIMIT 200
        """, p))

    @app.route("/api/threats/atp_summary")
    def threats_atp_summary():
        return jsonify(_rows("""
            SELECT threat_name, COUNT(*) as hits,
                   COUNT(DISTINCT src_ip) as infected_hosts,
                   MIN(ts) as first_seen, MAX(ts) as last_seen
            FROM events WHERE log_type='ATP' AND threat_name!=''
            GROUP BY threat_name ORDER BY hits DESC LIMIT 30
        """))

    @app.route("/api/threats/ips")
    def threats_ips():
        c, p = _date_clause(); c.append("log_type='IPS'")
        where = "WHERE " + " AND ".join(c)
        return jsonify(_rows(f"""
            SELECT ts, src_ip, dst_ip, message, severity, protocol
            FROM events {where} ORDER BY ts DESC LIMIT 200
        """, p))

    @app.route("/api/threats/dos")
    def threats_dos():
        c, p = _date_clause(); c.append("log_component='DoS Attack'")
        where = "WHERE " + " AND ".join(c)
        return jsonify(_rows(f"""
            SELECT ts, src_ip, dst_ip, protocol, message
            FROM events {where} ORDER BY ts DESC LIMIT 200
        """, p))

    @app.route("/api/threats/top_hosts")
    def threats_top_hosts():
        return jsonify(_rows("""
            SELECT src_ip, COUNT(*) as incidents,
                   COUNT(DISTINCT threat_name) as threat_types,
                   MAX(ts) as last_seen
            FROM events WHERE log_type='ATP' AND src_ip!=''
            GROUP BY src_ip ORDER BY incidents DESC LIMIT 20
        """))

    # ══════════════════════════════════════════════
    # NETWORK
    # ══════════════════════════════════════════════

    @app.route("/api/network/dhcp_recent")
    def dhcp_recent():
        c, p = _date_clause()
        where = ("WHERE " + " AND ".join(c)) if c else ""
        return jsonify(_rows(f"""
            SELECT ts, event_type, ip_address, mac_address, hostname, interface
            FROM dhcp_leases {where} ORDER BY ts DESC LIMIT 200
        """, p))

    @app.route("/api/network/mac_ip")
    def mac_ip():
        ip  = _safe_ip(request.args.get("ip","") or "")
        mac = _safe_str(request.args.get("mac","")).lower()
        if mac and not _MAC_RE.match(mac): mac = None
        c, p = [], []
        if ip:  c.append("ip_address=?");  p.append(ip)
        if mac: c.append("mac_address=?"); p.append(mac)
        where = ("WHERE " + " AND ".join(c)) if c else ""
        return jsonify(_rows(f"""
            SELECT ts, mac_address, ip_address, interface
            FROM mac_ip_map {where} ORDER BY ts DESC LIMIT 200
        """, p))

    @app.route("/api/network/vpn_sessions")
    def vpn_sessions():
        c, p = _date_clause()
        c.append("log_component IN ('SSL_VPN','VPN_Portal_Authentication','IPSec','My_Account_Authentication')")
        where = "WHERE " + " AND ".join(c)
        return jsonify(_rows(f"""
            SELECT ts, username, src_ip, log_component, action, message
            FROM events {where} ORDER BY ts DESC LIMIT 200
        """, p))

    # ══════════════════════════════════════════════
    # PIVOT
    # ══════════════════════════════════════════════

    @app.route("/api/ip_lookup/<path:ip>")
    def ip_lookup(ip):
        ip = _safe_ip(ip)
        if not ip: return jsonify({"error":"Invalid IP"}), 400
        return jsonify({
            "ip":       ip,
            "firewall": _rows("SELECT ts,log_type,log_component,action,dst_ip,dst_port,protocol,username,message FROM events WHERE src_ip=? ORDER BY ts DESC LIMIT 150",(ip,)),
            "dns":      _rows("SELECT ts,query_name,query_type FROM dns_queries WHERE client_ip=? ORDER BY ts DESC LIMIT 150",(ip,)),
            "radius":   _rows("SELECT ts,username,result,nas_ip FROM radius_auth WHERE client_ip=? OR nas_ip=? ORDER BY ts DESC LIMIT 50",(ip,ip)),
            "dhcp":     _rows("SELECT ts,event_type,mac_address,hostname FROM dhcp_leases WHERE ip_address=? ORDER BY ts DESC LIMIT 50",(ip,)),
            "mac_map":  _rows("SELECT ts,mac_address,interface FROM mac_ip_map WHERE ip_address=? ORDER BY ts DESC LIMIT 20",(ip,)),
            "alerts":   _rows("SELECT id,rule_name,severity,description,created_at,acknowledged FROM alerts WHERE src_ip=? ORDER BY created_at DESC",(ip,)),
            "threats":  _rows("SELECT ts,threat_name,url,dst_ip FROM events WHERE src_ip=? AND log_type='ATP' ORDER BY ts DESC LIMIT 50",(ip,)),
            "bandwidth":_rows("SELECT SUM(COALESCE(sent_bytes,0)) as sent,SUM(COALESCE(recv_bytes,0)) as recv FROM events WHERE src_ip=?",(ip,)),
        })

    @app.route("/api/user_lookup/<path:username>")
    def user_lookup(username):
        un = _safe_str(username)
        return jsonify({
            "username": un,
            "fw_events":_rows("SELECT ts,log_component,src_ip,action,message FROM events WHERE username=? ORDER BY ts DESC LIMIT 100",(un,)),
            "radius":   _rows("SELECT ts,result,nas_ip,client_ip FROM radius_auth WHERE username=? ORDER BY ts DESC LIMIT 100",(un,)),
            "vpn":      _rows("SELECT ts,src_ip,action,log_component,message FROM events WHERE username=? AND log_component LIKE '%VPN%' ORDER BY ts DESC LIMIT 50",(un,)),
            "alerts":   _rows("SELECT id,rule_name,severity,description,created_at FROM alerts WHERE username=? ORDER BY created_at DESC",(un,)),
        })

    # ══════════════════════════════════════════════
    # EVENTS SEARCH + EXPORT
    # ══════════════════════════════════════════════

    @app.route("/api/events")
    def api_events():
        limit = _safe_int(request.args.get("limit",200),200,1,2000)
        c, p  = _date_clause()
        for f in ("log_source","log_type","log_component","action","protocol"):
            v = _safe_str(request.args.get(f,""))
            if v: c.append(f"{f}=?"); p.append(v)
        src = _safe_ip(request.args.get("src_ip","") or "")
        dst = _safe_ip(request.args.get("dst_ip","") or "")
        if src: c.append("src_ip=?"); p.append(src)
        if dst: c.append("dst_ip=?"); p.append(dst)
        port = _safe_str(request.args.get("port",""))
        if port.isdigit(): c.append("dst_port=?"); p.append(int(port))
        un = _safe_str(request.args.get("username",""))
        if un: c.append("username LIKE ?"); p.append(f"%{un}%")
        kw = _safe_str(request.args.get("keyword",""))
        if kw:
            c.append("(message LIKE ? OR url LIKE ? OR threat_name LIKE ? OR application LIKE ?)")
            k = f"%{kw}%"; p += [k,k,k,k]
        where = ("WHERE " + " AND ".join(c)) if c else ""
        return jsonify(_rows(f"""
            SELECT id,ts,log_source,log_type,log_component,log_subtype,severity,action,
                   src_ip,dst_ip,src_port,dst_port,protocol,username,application,
                   threat_name,sent_bytes,recv_bytes,fw_rule_name,url,message
            FROM events {where} ORDER BY ts DESC LIMIT {limit}
        """, p))

    @app.route("/api/events/export")
    def events_export():
        limit = _safe_int(request.args.get("limit",5000),5000,1,50000)
        fmt   = _safe_str(request.args.get("format","csv"))
        rows  = _rows(f"SELECT * FROM events ORDER BY ts DESC LIMIT {limit}")
        if fmt == "json":
            return Response(json.dumps(rows,default=str), mimetype="application/json",
                            headers={"Content-Disposition":"attachment; filename=events.json"})
        buf = io.StringIO()
        if rows:
            w = csv.DictWriter(buf, fieldnames=rows[0].keys())
            w.writeheader(); w.writerows(rows)
        return Response(buf.getvalue(), mimetype="text/csv",
                        headers={"Content-Disposition":"attachment; filename=events.csv"})

    # ══════════════════════════════════════════════
    # REPORT
    # ══════════════════════════════════════════════

    @app.route("/api/report/executive")
    def report_exec():
        return jsonify({
            "generated_at":   datetime.now().isoformat(),
            "stats":          get_stats(),
            "top_threats":    _rows("SELECT threat_name,COUNT(*) as cnt FROM events WHERE threat_name!='' GROUP BY threat_name ORDER BY cnt DESC LIMIT 10"),
            "top_denied_ips": _rows("SELECT src_ip,COUNT(*) as cnt FROM events WHERE action='Deny' AND src_ip!='' GROUP BY src_ip ORDER BY cnt DESC LIMIT 10"),
            "alert_summary":  _rows("SELECT severity,COUNT(*) as total,SUM(CASE WHEN acknowledged=0 THEN 1 ELSE 0 END) as open FROM alerts GROUP BY severity"),
            "daily_events":   _rows("SELECT date(ts) as day,COUNT(*) as cnt FROM events WHERE ts>=date('now','-7 days') GROUP BY day ORDER BY day"),
        })

    # ══════════════════════════════════════════════
    # RUN RULES
    # ══════════════════════════════════════════════

    @app.route("/api/run_rules", methods=["POST"])
    def run_rules():
        from rules.engine import RuleEngine
        count = RuleEngine().run(verbose=False)
        return jsonify({"new_alerts":count,"ts":datetime.now().isoformat()})

    return app
