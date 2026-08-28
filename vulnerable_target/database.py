"""
SQLite database for Apex Global Bank: accounts, transactions, support tickets, and security toggles.
"""

from pathlib import Path
import sqlite3
from typing import Any, Dict, List

DB_PATH = Path(__file__).resolve().parent / "bank.db"


def get_db() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_bank_db():
    with get_db() as conn:
        # Accounts
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS accounts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                account_number TEXT UNIQUE,
                holder_name TEXT,
                account_type TEXT,
                balance REAL,
                status TEXT
            )
            """
        )

        # Transactions
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS transactions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                account_number TEXT,
                description TEXT,
                amount REAL,
                transaction_type TEXT,
                timestamp TEXT
            )
            """
        )

        # Support Tickets (Stored XSS Lab)
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS tickets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_name TEXT,
                subject TEXT,
                message TEXT,
                status TEXT,
                created_at TEXT
            )
            """
        )

        # Security & Vulnerability Toggles
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS security_toggles (
                key TEXT PRIMARY KEY,
                name TEXT,
                category TEXT,
                is_vulnerable INTEGER,
                description TEXT
            )
            """
        )

        # Populate Seed Data
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
            conn.executemany(
                "INSERT INTO accounts (account_number, holder_name, account_type, balance, status) VALUES (?, ?, ?, ?, ?)",
                accounts_data,
            )

        cursor.execute("SELECT COUNT(*) FROM transactions")
        if cursor.fetchone()[0] == 0:
            tx_data = [
                ("4892-1092-3841", "Apex Cloud Hosting Infrastructure", -1450.00, "DEBIT", "2026-08-24 14:15:00"),
                ("4892-1092-3841", "Wire Transfer Settlement from ACME Corp", 28500.00, "CREDIT", "2026-08-24 11:30:00"),
                ("9104-5820-1948", "Monthly APY Interest Deposit", 2104.50, "CREDIT", "2026-08-23 00:00:00"),
                ("7721-3940-1029", "Offshore Liquidity Allocation", -500000.00, "DEBIT", "2026-08-22 18:20:00"),
                ("4892-1092-3841", "Executive Security Retainer Fee", -3200.00, "DEBIT", "2026-08-21 09:45:00"),
            ]
            conn.executemany(
                "INSERT INTO transactions (account_number, description, amount, transaction_type, timestamp) VALUES (?, ?, ?, ?, ?)",
                tx_data,
            )

        cursor.execute("SELECT COUNT(*) FROM tickets")
        if cursor.fetchone()[0] == 0:
            tickets_data = [
                ("Alice Morgan", "Inquiry regarding wire fee", "Hello, please confirm international wire processing hours.", "Open", "2026-08-24 15:00:00"),
                ("Bob Davis", "API Webhook Integration", "Can we configure real-time webhook callback notifications for new deposits?", "Resolved", "2026-08-23 10:20:00"),
            ]
            conn.executemany(
                "INSERT INTO tickets (user_name, subject, message, status, created_at) VALUES (?, ?, ?, ?, ?)",
                tickets_data,
            )

        # Initialize Default Security Toggles (All Vulnerable by default for lab testing)
        default_toggles = [
            ("sqli_enabled", "SQL Injection Vulnerability", "SQLi", 1, "Direct string interpolation in SQL queries without parameterized binding."),
            ("xss_enabled", "Cross-Site Scripting Vulnerability", "XSS", 1, "Unescaped reflection of user input and ticket messages directly in HTML DOM."),
            ("rce_enabled", "Command Injection Vulnerability", "RCE", 1, "Arbitrary system shell command execution via subprocess.getoutput."),
            ("lfi_enabled", "Path Traversal / LFI Vulnerability", "LFI", 1, "Arbitrary filesystem document reading without path traversal sanitation."),
            ("ssrf_enabled", "Server-Side Request Forgery Vulnerability", "SSRF", 1, "Unrestricted outbound HTTP requests allowing localhost and cloud metadata queries."),
            ("idor_enabled", "IDOR / Broken Access Control", "IDOR", 1, "Direct database ID lookups without checking user identity or authorization."),
        ]
        for t in default_toggles:
            conn.execute(
                "INSERT OR IGNORE INTO security_toggles (key, name, category, is_vulnerable, description) VALUES (?, ?, ?, ?, ?)",
                t,
            )
        conn.commit()


def get_toggle(key: str) -> bool:
    """Returns True if the vulnerability is currently active (vulnerable mode)."""
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT is_vulnerable FROM security_toggles WHERE key = ?", (key,))
        row = cursor.fetchone()
        return bool(row[0]) if row else True


def get_all_toggles() -> List[Dict[str, Any]]:
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT key, name, category, is_vulnerable, description FROM security_toggles")
        return [dict(r) for r in cursor.fetchall()]


def set_toggle(key: str, is_vulnerable: bool):
    with get_db() as conn:
        conn.execute("UPDATE security_toggles SET is_vulnerable = ? WHERE key = ?", (1 if is_vulnerable else 0, key))
        conn.commit()
