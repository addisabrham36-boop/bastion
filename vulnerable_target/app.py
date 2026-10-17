"""
Apex Global Bank — Comprehensive Vulnerable Target Web Application
Designed for WAF Interception Demos, Penetration Testing & Presentations.
"""

from datetime import datetime
import html
import os
from pathlib import Path
import sqlite3
import subprocess
import urllib.request
from urllib.parse import urlparse
from flask import Flask, redirect, render_template, render_template_string, request, url_for

app = Flask(__name__, template_folder=str(Path(__file__).resolve().parent / "templates"))

DB_PATH = Path(__file__).resolve().parent / "bank.db"

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    with get_db() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS accounts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                account_number TEXT UNIQUE,
                holder_name TEXT,
                account_type TEXT,
                balance REAL,
                status TEXT
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS transactions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                account_number TEXT,
                description TEXT,
                amount REAL,
                transaction_type TEXT,
                timestamp TEXT
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS tickets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_name TEXT,
                subject TEXT,
                message TEXT,
                status TEXT,
                created_at TEXT
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS security_toggles (
                key TEXT PRIMARY KEY,
                name TEXT,
                category TEXT,
                is_vulnerable INTEGER,
                description TEXT
            )
        """)

        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM accounts")
        if cursor.fetchone()[0] == 0:
            accounts_data = [
                ("4892-1092-3841", "Valued Account Holder (You)", "Primary Business Checking", 142580.40, "Active"),
                ("9104-5820-1948", "Valued Account Holder (You)", "Reserve High-Yield Savings", 520100.00, "Active"),
                ("7721-3940-1029", "Alexander Hamilton (VIP Client)", "Corporate Treasury Vault", 12500000.00, "Active"),
                ("3391-4820-5921", "Sarah Jenkins (Staff Admin)", "Executive Payroll Holding", 89400.00, "Active"),
                ("6619-2049-1182", "CipherTech Global Ltd", "Escrow Settlement Account", 3450000.00, "Active"),
            ]
            conn.executemany("INSERT INTO accounts (account_number, holder_name, account_type, balance, status) VALUES (?, ?, ?, ?, ?)", accounts_data)

        cursor.execute("SELECT COUNT(*) FROM transactions")
        if cursor.fetchone()[0] == 0:
            tx_data = [
                ("4892-1092-3841", "Apex Cloud Infrastructure", -1450.00, "DEBIT", "2026-09-16 14:15:00"),
                ("4892-1092-3841", "Wire Transfer from ACME Corp", 28500.00, "CREDIT", "2026-09-16 11:30:00"),
                ("9104-5820-1948", "Monthly APY Interest Deposit", 2104.50, "CREDIT", "2026-09-15 00:00:00"),
                ("7721-3940-1029", "Offshore Liquidity Allocation", -500000.00, "DEBIT", "2026-09-14 18:20:00"),
            ]
            conn.executemany("INSERT INTO transactions (account_number, description, amount, transaction_type, timestamp) VALUES (?, ?, ?, ?, ?)", tx_data)

        cursor.execute("SELECT COUNT(*) FROM tickets")
        if cursor.fetchone()[0] == 0:
            tickets_data = [
                ("Alice Morgan", "Inquiry regarding wire fee", "Hello, please confirm international wire processing hours.", "Open", "2026-09-16 15:00:00"),
                ("Bob Davis", "API Webhook Integration", "Can we configure real-time webhook callback notifications for new deposits?", "Resolved", "2026-09-15 10:20:00"),
            ]
            conn.executemany("INSERT INTO tickets (user_name, subject, message, status, created_at) VALUES (?, ?, ?, ?, ?)", tickets_data)

        default_toggles = [
            ("sqli_enabled", "SQL Injection (SQLi)", "SQLi", 1, "Direct string interpolation in SQL queries without parameterized binding."),
            ("xss_enabled", "Cross-Site Scripting (XSS)", "XSS", 1, "Unescaped reflection of user input directly in the HTML DOM."),
            ("rce_enabled", "Command Injection (RCE)", "RCE", 1, "Arbitrary system shell command execution via subprocess.getoutput."),
            ("lfi_enabled", "Path Traversal / LFI", "LFI", 1, "Arbitrary filesystem document reading without path traversal sanitation."),
            ("ssrf_enabled", "Server-Side Request Forgery (SSRF)", "SSRF", 1, "Unrestricted outbound HTTP requests allowing localhost and cloud metadata queries."),
            ("idor_enabled", "IDOR / Broken Access Control", "IDOR", 1, "Direct database ID lookups without checking user identity or authorization."),
        ]
        for t in default_toggles:
            conn.execute("INSERT OR IGNORE INTO security_toggles (key, name, category, is_vulnerable, description) VALUES (?, ?, ?, ?, ?)", t)
        conn.commit()

init_db()

def get_toggle(key: str) -> bool:
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT is_vulnerable FROM security_toggles WHERE key = ?", (key,))
        row = cursor.fetchone()
        return bool(row[0]) if row else True

def get_all_toggles():
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT key, name, category, is_vulnerable, description FROM security_toggles")
        return [dict(r) for r in cursor.fetchall()]

def set_toggle(key: str, is_vulnerable: bool):
    with get_db() as conn:
        conn.execute("UPDATE security_toggles SET is_vulnerable = ? WHERE key = ?", (1 if is_vulnerable else 0, key))
        conn.commit()


@app.before_request
def route_via_waf_proxy():
    # Allow if already proxied through Bastion WAF (Port 8080)
    if request.headers.get("X-Bastion-Proxy") == "1" or "8080" in request.headers.get("X-Forwarded-Host", ""):
        return None
    if request.path.startswith("/static"):
        return None
    # Allow direct unproxied mode if explicitly requested with ?direct=1
    if request.args.get("direct") == "1":
        return None
    # Automatically route browser requests from Port 5000 to WAF Reverse Proxy (Port 8080)
    if ":5000" in request.host:
        qs = f"?{request.query_string.decode('utf-8')}" if request.query_string else ""
        return redirect(f"http://127.0.0.1:8080{request.path}{qs}", code=307)


@app.route("/")
def index():
    return render_template("index.html", current_page="index", output_title=None, output_content=None)


# 1. SQL Injection
@app.route("/search")
def search():
    query = request.args.get("q", "")
    is_vulnerable = get_toggle("sqli_enabled")
    conn = get_db()
    cursor = conn.cursor()

    if is_vulnerable:
        sql = f"SELECT account_number, description, amount, transaction_type, timestamp FROM transactions WHERE description LIKE '%{query}%' OR account_number = '{query}'"
        try:
            cursor.execute(sql)
            results = cursor.fetchall()
            output = f"Executed Raw Query: {sql}\n\nMatching Ledger Entries Found ({len(results)}):\n"
            for r in results:
                output += f"• [{r[4]}] {r[1]} | Account: {r[0]} | Amount: ${r[2]:,.2f} ({r[3]})\n"
        except Exception as e:
            output = f"SQL Syntax / Database Execution Error:\n{str(e)}\n\nQuery: {sql}"
    else:
        sql = "SELECT account_number, description, amount, transaction_type, timestamp FROM transactions WHERE description LIKE ? OR account_number = ?"
        try:
            cursor.execute(sql, (f"%{query}%", query))
            results = cursor.fetchall()
            output = f"[SECURE MODE] Parameterized Query Executed:\n{sql}\nParameters: ['%{query}%', '{query}']\n\nResults ({len(results)}):\n"
            for r in results:
                output += f"• [{r[4]}] {r[1]} | Account: {r[0]} | Amount: ${r[2]:,.2f} ({r[3]})\n"
        except Exception as e:
            output = f"Error: {str(e)}"
    conn.close()

    return render_template(
        "index.html",
        current_page="index",
        output_title="1. Transaction Search Query Output (SQLi Lab)",
        output_content=output,
        is_safe_rendered=False,
    )


# 2. Reflected XSS
@app.route("/comment")
def comment():
    msg = request.args.get("msg", "")
    is_vulnerable = get_toggle("xss_enabled")

    if is_vulnerable:
        rendered_output = f"<div style='font-size: 1rem; color: #0284c7;'><strong>Inquiry Received:</strong> {msg}</div>"
        return render_template(
            "index.html",
            current_page="index",
            output_title="2. Customer Support Response (Reflected XSS Lab)",
            output_content=rendered_output,
            is_safe_rendered=True,
        )
    else:
        escaped_msg = html.escape(msg)
        rendered_output = f"<div style='font-size: 1rem; color: #15803d;'><strong>[SECURE MODE] Sanitized Inquiry:</strong> {escaped_msg}</div>"
        return render_template(
            "index.html",
            current_page="index",
            output_title="2. Customer Support Response (Reflected XSS Remediated)",
            output_content=rendered_output,
            is_safe_rendered=True,
        )


# 3. Remote Code Execution
@app.route("/exec")
def exec_cmd():
    cmd = request.args.get("cmd", "")
    if not cmd:
        return redirect("/")

    is_vulnerable = get_toggle("rce_enabled")

    if is_vulnerable:
        output = subprocess.getoutput(cmd)
        title = "3. Host Diagnostic Terminal (RCE Vulnerable Lab)"
    else:
        allowed_cmds = {"whoami", "id", "uptime", "date", "uname -a"}
        cleaned_cmd = cmd.strip()
        if cleaned_cmd in allowed_cmds:
            output = f"[SECURE MODE] Permitted Command: {cleaned_cmd}\n\n" + subprocess.getoutput(cleaned_cmd)
        else:
            output = f"[SECURE MODE REJECTED] Command '{cmd}' is not in the authorized server diagnostic whitelist: {list(allowed_cmds)}"
        title = "3. Host Diagnostic Terminal (RCE Remediated)"

    return render_template(
        "index.html",
        current_page="index",
        output_title=title,
        output_content=output,
        is_safe_rendered=False,
    )


# 4. Path Traversal / LFI
@app.route("/file")
def read_file():
    filename = request.args.get("name", "")
    if not filename:
        return redirect("/")

    is_vulnerable = get_toggle("lfi_enabled")

    if is_vulnerable:
        try:
            with open(filename, "r", encoding="utf-8", errors="replace") as f:
                content = f.read()
            output = f"File Contents ({filename}):\n\n{content}"
        except Exception as e:
            output = f"File Read Error for '{filename}':\n{str(e)}"
        title = f"4. Document & Statement Reader (LFI Lab - {filename})"
    else:
        safe_name = Path(filename).name
        sample_statements = {
            "statement_aug.txt": "Apex Global Bank - Statement of Account (August 2026)\nHolder: Valued Account Holder\nEnding Balance: $142,580.40\nStatus: Verified",
            "audit_report.txt": "Apex Global Bank - Internal Security Audit\nStatus: Bastion WAF Reverse Proxy Active.",
        }
        if safe_name in sample_statements:
            output = f"[SECURE MODE] Serving authorized statement: {safe_name}\n\n{sample_statements[safe_name]}"
        else:
            output = f"[SECURE MODE BLOCKED] Access to path '{filename}' denied. Only authorized statements in sandboxed directory are accessible."
        title = f"4. Document Reader (Path Traversal Remediated)"

    return render_template(
        "index.html",
        current_page="index",
        output_title=title,
        output_content=output,
        is_safe_rendered=False,
    )


# 5. SSRF
@app.route("/webhook")
def webhook_query():
    target_url = request.args.get("url", "")
    if not target_url:
        return redirect("/")

    is_vulnerable = get_toggle("ssrf_enabled")

    if is_vulnerable:
        try:
            req = urllib.request.Request(target_url, headers={"User-Agent": "ApexBank-WebhookClient/1.0"})
            with urllib.request.urlopen(req, timeout=3.0) as resp:
                data = resp.read().decode("utf-8", errors="replace")
            output = f"HTTP Response from [{target_url}]:\n\n{data[:2000]}"
        except Exception as e:
            output = f"SSRF Outbound Query to [{target_url}] failed:\n{str(e)}"
        title = "5. FX Webhook & Rate Query (SSRF Lab)"
    else:
        parsed = urlparse(target_url)
        hostname = (parsed.hostname or "").lower()
        blocked_hosts = {"localhost", "127.0.0.1", "0.0.0.0", "169.254.169.254", "metadata.google.internal"}

        if (
            not hostname
            or hostname in blocked_hosts
            or hostname.startswith("10.")
            or hostname.startswith("192.168.")
            or parsed.scheme not in ("http", "https")
        ):
            output = f"[SECURE MODE BLOCKED] Outbound request to '{target_url}' rejected. Private subnets, loopbacks, and cloud metadata endpoints are strictly restricted."
        else:
            try:
                req = urllib.request.Request(target_url, headers={"User-Agent": "ApexBank-WebhookClient/1.0"})
                with urllib.request.urlopen(req, timeout=3.0) as resp:
                    data = resp.read().decode("utf-8", errors="replace")
                output = f"[SECURE MODE] Validated Public Webhook [{target_url}]:\n\n{data[:2000]}"
            except Exception as e:
                output = f"Public Webhook query error: {str(e)}"
        title = "5. FX Webhook Query (SSRF Remediated)"

    return render_template(
        "index.html",
        current_page="index",
        output_title=title,
        output_content=output,
        is_safe_rendered=False,
    )


# 6. IDOR
@app.route("/account/view")
def view_account():
    account_id = request.args.get("id", "1")
    is_vulnerable = get_toggle("idor_enabled")
    conn = get_db()
    cursor = conn.cursor()

    if is_vulnerable:
        cursor.execute("SELECT id, account_number, holder_name, account_type, balance, status FROM accounts WHERE id = ?", (account_id,))
        acc = cursor.fetchone()
        if acc:
            output = (
                f"Account Record #{acc[0]}:\n"
                f"• Account Number: {acc[1]}\n"
                f"• Account Holder: {acc[2]}\n"
                f"• Account Classification: {acc[3]}\n"
                f"• Available Liquidity: ${acc[4]:,.2f}\n"
                f"• Standing Status: {acc[5]}\n"
            )
        else:
            output = f"Account ID #{account_id} not found."
        title = f"6. Customer Account Record #{account_id} (IDOR Lab)"
    else:
        if str(account_id) in ("1", "2"):
            cursor.execute("SELECT id, account_number, holder_name, account_type, balance, status FROM accounts WHERE id = ?", (account_id,))
            acc = cursor.fetchone()
            output = (
                f"[SECURE MODE AUTHORIZED] Your Account Record #{acc[0]}:\n"
                f"• Account Number: {acc[1]}\n"
                f"• Account Holder: {acc[2]}\n"
                f"• Type: {acc[3]}\n"
                f"• Balance: ${acc[4]:,.2f}\n"
            )
        else:
            output = f"[SECURE MODE 403 ACCESS DENIED] You do not have authorization to view Account ID #{account_id} (Belongs to another customer)."
        title = f"6. Customer Account Record (IDOR Remediated)"
    conn.close()

    return render_template(
        "index.html",
        current_page="index",
        output_title=title,
        output_content=output,
        is_safe_rendered=False,
    )


# 7. CSRF Fund Transfer
@app.route("/transfer")
def transfer_funds():
    to_account = request.args.get("to_account", "")
    amount_str = request.args.get("amount", "0")
    try:
        amount = float(amount_str)
    except ValueError:
        amount = 0.0

    if to_account and amount > 0:
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO transactions (account_number, description, amount, transaction_type, timestamp) VALUES (?, ?, ?, ?, ?)",
            ("4892-1092-3841", f"Wire Transfer to {to_account}", -amount, "DEBIT", datetime.now().strftime("%Y-%m-%d %H:%M:%S")),
        )
        conn.commit()
        conn.close()
        output = f"Wire Transfer of ${amount:,.2f} initiated to Account [{to_account}] successfully!"
    else:
        output = "Invalid transfer parameters provided."

    return render_template(
        "index.html",
        current_page="index",
        output_title="7. Wire Transfer Result (CSRF Lab)",
        output_content=output,
        is_safe_rendered=False,
    )


# 8. SSTI
@app.route("/receipt")
def receipt():
    name = request.args.get("name", "Valued Customer")
    template = f"""
    <div style='background: #fff; padding: 20px; border-radius: 8px; border: 1px solid #cbd5e1;'>
        <h4 style='color: #0f172a; margin-bottom: 10px;'>Official Apex Global Transaction Receipt</h4>
        <p><strong>Customer:</strong> {name}</p>
        <p><strong>Date:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
        <p><strong>Confirmation Code:</strong> APX-98421-CONF</p>
    </div>
    """
    rendered = render_template_string(template)
    return render_template(
        "index.html",
        current_page="index",
        output_title="8. Branded Receipt Generator (SSTI Lab)",
        output_content=rendered,
        is_safe_rendered=True,
    )


# Staff Management Portal
@app.route("/staff")
def staff_portal():
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT id, account_number, holder_name, account_type, balance, status FROM accounts")
    accounts = [dict(r) for r in cursor.fetchall()]
    cursor.execute("SELECT id, user_name, subject, message, status, created_at FROM tickets ORDER BY id DESC")
    tickets = [dict(r) for r in cursor.fetchall()]
    conn.close()

    toggles = get_all_toggles()
    xss_vulnerable = get_toggle("xss_enabled")

    return render_template(
        "staff.html",
        current_page="staff",
        accounts=accounts,
        tickets=tickets,
        toggles=toggles,
        xss_vulnerable=xss_vulnerable,
    )


@app.route("/staff/toggle", methods=["POST"])
def staff_toggle():
    key = request.form.get("key")
    is_vulnerable = request.form.get("is_vulnerable") == "1"
    if key:
        set_toggle(key, is_vulnerable)
    return redirect("/staff")


@app.route("/staff/toggle-all", methods=["POST"])
def staff_toggle_all():
    vulnerable = request.form.get("vulnerable") == "1"
    toggles = get_all_toggles()
    for t in toggles:
        set_toggle(t["key"], vulnerable)
    return redirect("/staff")


@app.route("/ticket/new", methods=["POST"])
def new_ticket():
    user_name = request.form.get("user_name", "Anonymous")
    subject = request.form.get("subject", "General Inquiry")
    message = request.form.get("message", "")

    conn = get_db()
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO tickets (user_name, subject, message, status, created_at) VALUES (?, ?, ?, ?, ?)",
        (user_name, subject, message, "Open", datetime.now().strftime("%Y-%m-%d %H:%M:%S")),
    )
    conn.commit()
    conn.close()
    return redirect("/staff")


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=True)
