import sqlite3
import re
import os
from datetime import datetime
from flask import Flask, request, jsonify, Response, send_from_directory

app = Flask(__name__, static_folder='dashboard')

# Ensure DB connects to database/waf.db
DB_PATH = os.path.join(os.path.dirname(__file__), 'database', 'waf.db')

def get_db():
    return sqlite3.connect(DB_PATH)

def init_db():
    conn = get_db()
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS security_events (
        id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp TEXT, client_ip TEXT, path TEXT, rule_id TEXT, reason TEXT, action TEXT, blocked INTEGER
    )''')
    c.execute('''CREATE TABLE IF NOT EXISTS waf_rules (
        rule_id TEXT PRIMARY KEY, rule_name TEXT, category TEXT, pattern TEXT, enabled INTEGER
    )''')
    c.execute('''CREATE TABLE IF NOT EXISTS protected_sites (
        id INTEGER PRIMARY KEY AUTOINCREMENT, domain TEXT, upstream TEXT, ssl_status TEXT, defense_mode INTEGER
    )''')

    default_rules = [
        ('942100', 'SQL Injection Shield', 'SQLi', r"('|\"|;|\bOR\b|\bAND\b|\bUNION\b|\bSELECT\b|\bDROP\b|--)", 1),
        ('941100', 'XSS Filter', 'XSS', r"(<script.*?>|javascript:|onload=|onerror=|<iframe|<img.*?>)", 1),
        ('930100', 'RCE Engine', 'RCE', r"(\.\./|\.\.\\|/etc/passwd|c:\\windows|system\(|exec\()", 1)
    ]
    for r in default_rules:
        c.execute("INSERT OR IGNORE INTO waf_rules VALUES (?, ?, ?, ?, ?)", r)

    c.execute("SELECT COUNT(*) FROM protected_sites")
    if c.fetchone()[0] == 0:
        c.execute("INSERT INTO protected_sites VALUES (1, '127.0.0.1:8000', '127.0.0.1:9000', 'Active', 1)")

    conn.commit()
    conn.close()

init_db()

# Middleware Engine
@app.before_request
def waf_middleware():
    if request.path == '/' or request.path.startswith('/api/') or '.' in request.path:
        return None

    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT defense_mode FROM protected_sites WHERE id = 1")
    site = c.fetchone()
    defense_active = site[0] if site else 1

    if not defense_active:
        conn.close()
        return None

    c.execute("SELECT rule_id, rule_name, category, pattern FROM waf_rules WHERE enabled = 1")
    active_rules = c.fetchall()
    conn.close()

    full_payload = f"{request.path} {request.query_string.decode('utf-8')} " + \
                   " ".join([f"{k}={v}" for k, v in request.args.items()]) + " " + \
                   " ".join([f"{k}={v}" for k, v in request.form.items()])

    for rule_id, rule_name, category, pattern in active_rules:
        if re.search(pattern, full_payload, re.IGNORECASE):
            conn = get_db()
            c = conn.cursor()
            c.execute('''INSERT INTO security_events (timestamp, client_ip, path, rule_id, reason, action, blocked)
                         VALUES (?, ?, ?, ?, ?, ?, 1)''', 
                      (datetime.now().strftime('%Y-%m-%d %H:%M:%S'), request.remote_addr, request.full_path, rule_id, category, "403 Blocked"))
            conn.commit()
            conn.close()

            return Response(f"<h1>403 Forbidden</h1><p>WAF Intercept - Rule {rule_id} ({rule_name})</p>", status=403)

# Serve Dashboard UI directly at root '/'
@app.route('/')
def index():
    return send_from_directory('dashboard', 'index.html')

@app.route('/<path:filename>')
def serve_static(filename):
    return send_from_directory('dashboard', filename)

# APIs
@app.route('/api/stats')
def api_stats():
    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT COUNT(*) FROM security_events")
    total = c.fetchone()[0]
    c.execute("SELECT COUNT(*) FROM security_events WHERE blocked = 1")
    blocked = c.fetchone()[0]
    c.execute("SELECT COUNT(*) FROM protected_sites")
    sites = c.fetchone()[0]
    conn.close()
    return jsonify({'total_requests': total, 'blocked_attacks': blocked, 'protected_domains': sites, 'latency_ms': 0.42})

@app.route('/api/rules', methods=['GET', 'POST'])
def api_rules():
    conn = get_db()
    c = conn.cursor()
    if request.method == 'POST':
        data = request.json
        c.execute("UPDATE waf_rules SET enabled = ? WHERE rule_id = ?", (1 if data['enabled'] else 0, data['rule_id']))
        conn.commit()
        conn.close()
        return jsonify({'status': 'success'})
    c.execute("SELECT rule_id, rule_name, category, enabled FROM waf_rules")
    rules = [{'rule_id': r[0], 'rule_name': r[1], 'category': r[2], 'enabled': bool(r[3])} for r in c.fetchall()]
    conn.close()
    return jsonify(rules)

@app.route('/api/sites', methods=['GET', 'POST'])
def api_sites():
    conn = get_db()
    c = conn.cursor()
    if request.method == 'POST':
        data = request.json
        if 'defense_mode' in data:
            c.execute("UPDATE protected_sites SET defense_mode = ? WHERE id = ?", (1 if data['defense_mode'] else 0, data['site_id']))
        conn.commit()
        conn.close()
        return jsonify({'status': 'success'})
    c.execute("SELECT id, domain, upstream, ssl_status, defense_mode FROM protected_sites")
    sites = [{'id': r[0], 'domain': r[1], 'upstream': r[2], 'ssl_status': r[3], 'defense_mode': bool(r[4])} for r in c.fetchall()]
    conn.close()
    return jsonify(sites)

@app.route('/api/logs')
def api_logs():
    query = request.args.get('q', '')
    threat = request.args.get('threat', 'All Threat Types')
    conn = get_db()
    c = conn.cursor()
    sql = "SELECT timestamp, client_ip, path, rule_id, action, blocked FROM security_events WHERE (client_ip LIKE ? OR path LIKE ?)"
    params = [f'%{query}%', f'%{query}%']
    if threat != 'All Threat Types':
        sql += " AND reason = ?"
        params.append(threat)
    sql += " ORDER BY id DESC LIMIT 50"
    c.execute(sql, params)
    rows = c.fetchall()
    conn.close()
    return jsonify([{'timestamp': r[0], 'client_ip': r[1], 'path': r[2], 'rule_id': r[3], 'action': r[4], 'blocked': bool(r[5])} for r in rows])

if __name__ == '__main__':
    app.run(host='127.0.0.1', port=8000, debug=True)