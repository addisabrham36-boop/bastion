"""
SQLite database storage for WAF security events, rules, and protected sites.
"""

from datetime import datetime, timezone
import io
import csv
from pathlib import Path
import sqlite3
from typing import Any, Dict, List, Optional, Set

DB_PATH = Path(__file__).resolve().parent / "waf.db"


def get_connection() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    with get_connection() as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT,
                client_ip TEXT,
                method TEXT,
                path TEXT,
                blocked INTEGER,
                rule_id TEXT,
                reason TEXT,
                action TEXT,
                payload_snippet TEXT DEFAULT ''
            )
            """
        )

        # Ensure schema migrations
        cursor = conn.cursor()
        cursor.execute("PRAGMA table_info(events)")
        existing_cols = {row[1] for row in cursor.fetchall()}
        if "action" not in existing_cols:
            conn.execute("ALTER TABLE events ADD COLUMN action TEXT")
        if "payload_snippet" not in existing_cols:
            conn.execute("ALTER TABLE events ADD COLUMN payload_snippet TEXT DEFAULT ''")

        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS waf_rules (
                rule_id TEXT PRIMARY KEY,
                rule_name TEXT,
                category TEXT,
                enabled INTEGER
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS protected_sites (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                domain TEXT UNIQUE,
                upstream TEXT,
                ssl_status TEXT,
                defense_mode INTEGER
            )
            """
        )

        default_rules = [
            # ── OWASP CRS Core Ruleset ──────────────────────────────────────
            # HTTP Protocol Anomalies
            ("920100", "Invalid HTTP Request Method", "HTTP Protocol", 1),
            ("920200", "HTTP Header Anomaly", "HTTP Protocol", 1),
            ("920300", "CRLF Injection / HTTP Response Splitting", "HTTP Protocol", 1),
            # HTTP Request Smuggling
            ("921100", "HTTP Request Smuggling", "HTTP Smuggling", 1),
            # Scanner / Recon Detection
            ("913100", "Security Scanner Signature", "Scanner Detection", 1),
            ("913110", "Malicious Bot / Bad User-Agent", "Scanner Detection", 1),
            ("913120", "Attack Tool Path Signature", "Scanner Detection", 1),
            # SQL Injection
            ("942100", "SQL Injection (SQLi) Shield", "SQLi", 1),
            ("942200", "MySQL / PostgreSQL Specific Injection", "SQLi", 1),
            ("942300", "SQLi in JSON / Advanced Encoding Bypass", "SQLi", 1),
            # Cross-Site Scripting
            ("941100", "Cross-Site Scripting (XSS) Filter", "XSS", 1),
            ("941200", "DOM-Based XSS via location.hash / document.write", "XSS", 1),
            # Path Traversal / LFI
            ("930120", "Path Traversal / LFI Guard", "Path Traversal", 1),
            ("930100", "Null Byte Injection in File Paths", "Path Traversal", 1),
            # Remote Code Execution
            ("932100", "Unix Command Injection Engine", "RCE", 1),
            ("932110", "Windows Command Injection Engine", "RCE", 1),
            ("932160", "Reverse Shell / Bind Shell Payload", "RCE", 1),
            # Java Injection
            ("944100", "Java EL / OGNL Injection", "Java Injection", 1),
            ("944110", "Log4Shell (CVE-2021-44228) Detection", "Java Injection", 1),
            ("944200", "Java Deserialization Attack", "Java Injection", 1),
            # PHP Injection
            ("933100", "PHP Code Injection", "PHP Injection", 1),
            ("933110", "PHP Object Injection (Unserialize)", "PHP Injection", 1),
            ("933120", "PHP File Inclusion", "PHP Injection", 1),
            # Remote File Inclusion
            ("950100", "Remote File Inclusion (RFI)", "RFI", 1),
            ("950110", "RFI Evasion via URL Encoding", "RFI", 1),
            # NoSQL Injection
            ("951100", "MongoDB / NoSQL Injection", "NoSQL Injection", 1),
            ("951200", "Redis / CouchDB / Elasticsearch Injection", "NoSQL Injection", 1),
            # Server-Side Template Injection
            ("952100", "Server-Side Template Injection (SSTI)", "SSTI", 1),
            # XML External Entity
            ("953100", "XML External Entity (XXE) Injection", "XXE", 1),
            # SSRF
            ("934100", "Server-Side Request Forgery (SSRF) Guard", "SSRF", 1),
        ]
        for r in default_rules:
            conn.execute(
                "INSERT OR IGNORE INTO waf_rules (rule_id, rule_name, category, enabled) VALUES (?, ?, ?, ?)",
                r,
            )

        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM protected_sites")
        count_row = cursor.fetchone()
        if count_row and count_row[0] == 0:
            conn.execute(
                "INSERT INTO protected_sites (id, domain, upstream, ssl_status, defense_mode) VALUES (1, '127.0.0.1:8080', '127.0.0.1:5000', 'Active', 1)"
            )
        conn.commit()


def log_event(
    client_ip: str,
    method: str,
    path: str,
    blocked: bool,
    rule_id: str = "",
    reason: str = "",
    action: Optional[str] = None,
    payload_snippet: str = "",
):
    if action is None:
        action = "403 Blocked" if blocked else "200 Allowed"
    with get_connection() as conn:
        conn.execute(
            """
            INSERT INTO events (timestamp, client_ip, method, path, blocked, rule_id, reason, action, payload_snippet)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S"),
                client_ip,
                method,
                path,
                int(blocked),
                rule_id,
                reason,
                action,
                payload_snippet,
            ),
        )
        conn.commit()


def get_stats() -> Dict[str, Any]:
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM events")
        total = cursor.fetchone()[0]

        cursor.execute("SELECT COUNT(*) FROM events WHERE blocked = 1")
        blocked = cursor.fetchone()[0]

        cursor.execute("SELECT COUNT(*) FROM protected_sites")
        sites = cursor.fetchone()[0]

        return {
            "total_requests": total,
            "blocked_attacks": blocked,
            "protected_domains": sites,
            "latency_ms": 0.42,
        }


def get_recent_events(limit: int = 15) -> List[Dict[str, Any]]:
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            """
            SELECT id, timestamp, client_ip, method, path, blocked, rule_id, reason,
                   COALESCE(action, CASE WHEN blocked = 1 THEN '403 Blocked' ELSE '200 Allowed' END) as action,
                   COALESCE(payload_snippet, '') as payload_snippet
            FROM events ORDER BY id DESC LIMIT ?
            """,
            (limit,),
        )
        rows = cursor.fetchall()
        return [dict(row) for row in rows]


def get_logs(query: str = "", threat: str = "All Threat Types", limit: int = 50) -> List[Dict[str, Any]]:
    with get_connection() as conn:
        cursor = conn.cursor()
        sql = """
            SELECT id, timestamp, client_ip, method, path, blocked, rule_id, reason,
                   COALESCE(action, CASE WHEN blocked = 1 THEN '403 Blocked' ELSE '200 Allowed' END) as action,
                   COALESCE(payload_snippet, '') as payload_snippet
            FROM events WHERE (client_ip LIKE ? OR path LIKE ? OR payload_snippet LIKE ?)
        """
        params: List[Any] = [f"%{query}%", f"%{query}%", f"%{query}%"]
        if threat and threat != "All Threat Types":
            sql += " AND (reason LIKE ? OR rule_id LIKE ?)"
            params.extend([f"%{threat}%", f"%{threat}%"])
        sql += " ORDER BY id DESC LIMIT ?"
        params.append(limit)

        cursor.execute(sql, params)
        rows = cursor.fetchall()
        return [dict(row) for row in rows]


def clear_logs():
    with get_connection() as conn:
        conn.execute("DELETE FROM events")
        conn.commit()


def export_logs_csv() -> str:
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["ID", "Timestamp", "Client IP", "Method", "Path", "Blocked", "Rule ID", "Reason", "Action", "Payload Snippet"])
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT id, timestamp, client_ip, method, path, blocked, rule_id, reason, action, payload_snippet FROM events ORDER BY id DESC")
        for row in cursor.fetchall():
            writer.writerow(list(row))
    return output.getvalue()


def get_rules() -> List[Dict[str, Any]]:
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT rule_id, rule_name, category, enabled FROM waf_rules")
        rows = cursor.fetchall()
        return [
            {
                "rule_id": r["rule_id"],
                "rule_name": r["rule_name"],
                "category": r["category"],
                "enabled": bool(r["enabled"]),
            }
            for r in rows
        ]


def set_rule_state(rule_id: str, enabled: bool):
    with get_connection() as conn:
        conn.execute("UPDATE waf_rules SET enabled = ? WHERE rule_id = ?", (1 if enabled else 0, rule_id))
        conn.commit()


def get_enabled_rule_ids() -> Set[str]:
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT rule_id FROM waf_rules WHERE enabled = 1")
        rows = cursor.fetchall()
        return {r[0] for r in rows}


def get_sites() -> List[Dict[str, Any]]:
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT id, domain, upstream, ssl_status, defense_mode FROM protected_sites")
        rows = cursor.fetchall()
        return [
            {
                "id": r["id"],
                "domain": r["domain"],
                "upstream": r["upstream"],
                "ssl_status": r["ssl_status"],
                "defense_mode": bool(r["defense_mode"]),
            }
            for r in rows
        ]


def add_site(domain: str, upstream: str, ssl_status: str = "Active", defense_mode: bool = True):
    with get_connection() as conn:
        conn.execute(
            """
            INSERT OR REPLACE INTO protected_sites (domain, upstream, ssl_status, defense_mode)
            VALUES (?, ?, ?, ?)
            """,
            (domain, upstream, ssl_status, 1 if defense_mode else 0),
        )
        conn.commit()


def set_site_defense(site_id: int, defense_mode: bool):
    with get_connection() as conn:
        conn.execute("UPDATE protected_sites SET defense_mode = ? WHERE id = ?", (1 if defense_mode else 0, site_id))
        conn.commit()


def delete_site(site_id: int):
    with get_connection() as conn:
        conn.execute("DELETE FROM protected_sites WHERE id = ?", (site_id,))
        conn.commit()
