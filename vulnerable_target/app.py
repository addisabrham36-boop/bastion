"""
Apex Global Bank — Vulnerable Target Application with Staff Security Toggles.
Provides 8 distinct vulnerability testing modules.
"""

from datetime import datetime
import html
import os
from pathlib import Path
import re
import sqlite3
import subprocess
import urllib.request
from urllib.parse import urlparse

from flask import Flask, redirect, render_template, render_template_string, request, url_for

from .database import get_all_toggles, get_db, get_toggle, init_bank_db, set_toggle

app = Flask(__name__)
init_bank_db()


@app.route("/")
def index():
    return render_template("index.html")


# 1. SQL Injection (SQLi)
@app.route("/search")
def search():
    query = request.args.get("q", "")
    is_vulnerable = get_toggle("sqli_enabled")

    conn = get_db()
    cursor = conn.cursor()

    if is_vulnerable:
        # Vulnerable direct SQL concatenation
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
        # Secure parameterized query
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
        output_title="1. Transaction Search Query Output (SQLi Lab)",
        output_content=output,
        is_safe_rendered=False,
    )


# 2. Reflected Cross-Site Scripting (XSS)
@app.route("/comment")
def comment():
    msg = request.args.get("msg", "")
    is_vulnerable = get_toggle("xss_enabled")

    if is_vulnerable:
        # Vulnerable unescaped reflection
        rendered_output = f"<div style='font-size: 1rem; color: #0284c7;'><strong>Inquiry Received:</strong> {msg}</div>"
        return render_template(
            "index.html",
            output_title="2. Customer Support Response (Reflected XSS Lab)",
            output_content=rendered_output,
            is_safe_rendered=True,
        )
    else:
        # Secure HTML-escaped output
        escaped_msg = html.escape(msg)
        rendered_output = f"<div style='font-size: 1rem; color: #15803d;'><strong>[SECURE MODE] Sanitized Inquiry:</strong> {escaped_msg}</div>"
        return render_template(
            "index.html",
            output_title="2. Customer Support Response (Reflected XSS Remediated)",
            output_content=rendered_output,
            is_safe_rendered=True,
        )


# 3. Remote Code Execution (RCE) / Command Injection
@app.route("/exec")
def exec_cmd():
    cmd = request.args.get("cmd", "")
    if not cmd:
        return redirect("/")

    is_vulnerable = get_toggle("rce_enabled")

    if is_vulnerable:
        # Vulnerable arbitrary shell execution
        output = subprocess.getoutput(cmd)
        title = "3. Host Diagnostic Terminal (RCE Vulnerable Lab)"
    else:
        # Secure sanitized whitelist
        allowed_cmds = {"whoami", "id", "uptime", "date", "uname -a"}
        cleaned_cmd = cmd.strip()
        if cleaned_cmd in allowed_cmds:
            output = f"[SECURE MODE] Permitted Command: {cleaned_cmd}\n\n" + subprocess.getoutput(cleaned_cmd)
        else:
            output = f"[SECURE MODE REJECTED] Command '{cmd}' is not in the authorized server diagnostic whitelist: {list(allowed_cmds)}"
        title = "3. Host Diagnostic Terminal (RCE Remediated)"

    return render_template(
        "index.html",
        output_title=title,
        output_content=output,
        is_safe_rendered=False,
    )


# 4. Path Traversal / Local File Inclusion (LFI)
@app.route("/file")
def read_file():
    filename = request.args.get("name", "")
    if not filename:
        return redirect("/")

    is_vulnerable = get_toggle("lfi_enabled")

    if is_vulnerable:
        # Vulnerable direct file opening
        try:
            with open(filename, "r", encoding="utf-8", errors="replace") as f:
                content = f.read()
            output = f"File Contents ({filename}):\n\n{content}"
        except Exception as e:
            output = f"File Read Error for '{filename}':\n{str(e)}"
        title = f"4. Document & Statement Reader (LFI Lab - {filename})"
    else:
        # Secure strict basename sandboxing
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
        output_title=title,
        output_content=output,
        is_safe_rendered=False,
    )


# 5. Server-Side Request Forgery (SSRF)
@app.route("/webhook")
def webhook_query():
    target_url = request.args.get("url", "")
    if not target_url:
        return redirect("/")

    is_vulnerable = get_toggle("ssrf_enabled")

    if is_vulnerable:
        # Vulnerable unrestricted outbound fetch
        try:
            req = urllib.request.Request(
                target_url,
                headers={"User-Agent": "ApexBank-WebhookClient/1.0"},
            )
            with urllib.request.urlopen(req, timeout=3.0) as resp:
                data = resp.read().decode("utf-8", errors="replace")
            output = f"HTTP Response from [{target_url}]:\n\n{data[:2000]}"
        except Exception as e:
            output = f"SSRF Outbound Query to [{target_url}] failed:\n{str(e)}"
        title = "5. FX Webhook & Rate Query (SSRF Lab)"
    else:
        # Secure URL validation: block localhost, private IPs, cloud metadata
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
        output_title=title,
        output_content=output,
        is_safe_rendered=False,
    )


# 6. Insecure Direct Object Reference (IDOR)
@app.route("/account/view")
def view_account():
    account_id = request.args.get("id", "1")
    is_vulnerable = get_toggle("idor_enabled")

    conn = get_db()
    cursor = conn.cursor()

    if is_vulnerable:
        # Vulnerable: directly returns any account ID
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
        # Secure: enforces ownership (only allows accessing account 1 or 2 belonging to current session)
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
        output_title=title,
        output_content=output,
        is_safe_rendered=False,
    )


# 7. CSRF / Insecure Fund Wire
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
        output_title="7. Wire Transfer Result (CSRF Lab)",
        output_content=output,
        is_safe_rendered=False,
    )


# 8. Server-Side Template Injection (SSTI)
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
        output_title="8. Branded Receipt Generator (SSTI Lab)",
        output_content=rendered,
        is_safe_rendered=True,
    )


# STAFF & ADMIN MANAGEMENT PORTAL
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
