"""
SQLite database storage for WAF security events, rules, and protected sites.
"""

import os
from datetime import datetime, timezone
import io
import csv
from pathlib import Path
import sqlite3
from typing import Any, Dict, List, Optional, Set

DEFAULT_DB_PATH = Path(__file__).resolve().parent / "waf.db"


def get_db_path() -> Path:
    env_path = os.environ.get("BASTION_DB_PATH")
    if env_path:
        return Path(env_path)
    return DEFAULT_DB_PATH


def get_connection() -> sqlite3.Connection:
    db_path = get_db_path()
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
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

        # Auto-seed all discovered rules
        try:
            from bastion.core.engine import discover_rules
            discovered = discover_rules()
            cat_map = {
                "913": "Scanner Detection",
                "920": "HTTP Protocol",
                "921": "HTTP Smuggling",
                "930": "Path Traversal",
                "932": "Remote Code Execution",
                "933": "PHP Injection",
                "934": "SSRF",
                "941": "Cross-Site Scripting",
                "942": "SQL Injection",
                "944": "Java & Log4Shell",
                "950": "Remote File Inclusion",
                "951": "NoSQL Injection",
                "952": "Template Injection (SSTI)",
                "953": "XML External Entity (XXE)",
                "960": "Client-Side & Logic",
            }
            for rule in discovered:
                cat = cat_map.get(rule.RULE_ID[:3], "General Security")
                conn.execute(
                    "INSERT OR IGNORE INTO waf_rules (rule_id, rule_name, category, enabled) VALUES (?, ?, ?, 1)",
                    (rule.RULE_ID, rule.NAME, cat),
                )
        except Exception as e:
            pass

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
