"""
SQLite database storage for WAF security events, rules, and protected sites.
100% truthful telemetry, real-time statistics, and audit logging.
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
                payload_snippet TEXT DEFAULT '',
                duration_ms REAL DEFAULT NULL
            )
            """
        )

        cursor = conn.cursor()
        cursor.execute("PRAGMA table_info(events)")
        existing_cols = {row[1] for row in cursor.fetchall()}
        if "action" not in existing_cols:
            conn.execute("ALTER TABLE events ADD COLUMN action TEXT")
        if "payload_snippet" not in existing_cols:
            conn.execute("ALTER TABLE events ADD COLUMN payload_snippet TEXT DEFAULT ''")
        if "duration_ms" not in existing_cols:
            conn.execute("ALTER TABLE events ADD COLUMN duration_ms REAL DEFAULT NULL")

        # Add indexes for control API query performance
        conn.execute("CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_events_blocked ON events(blocked)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_events_rule_id ON events(rule_id)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_events_action ON events(action)")

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

        # Seed protected sites if none exist
        cursor.execute("SELECT COUNT(*) FROM protected_sites")
        if cursor.fetchone()[0] == 0:
            default_sites = [
                ("127.0.0.1:8080", "https://abrham-addis-portfolio.netlify.app", "Active", 0),
                ("localhost:8080", "https://abrham-addis-portfolio.netlify.app", "Active", 0),
                ("127.0.0.1", "https://abrham-addis-portfolio.netlify.app", "Active", 0),
                ("localhost", "https://abrham-addis-portfolio.netlify.app", "Active", 0),
                ("abrham-addis-portfolio.netlify.app", "https://abrham-addis-portfolio.netlify.app", "Active", 0),
            ]
            for domain, upstream, ssl_status, defense_mode in default_sites:
                conn.execute(
                    "INSERT OR REPLACE INTO protected_sites (domain, upstream, ssl_status, defense_mode) VALUES (?, ?, ?, ?)",
                    (domain, upstream, ssl_status, defense_mode),
                )

        # Remove obsolete orphan rule 942300 if present
        conn.execute("DELETE FROM waf_rules WHERE rule_id = '942300'")

        # Auto-seed all discovered rules and native registry rules
        try:
            from bastion.core.engine import discover_rules
            from bastion.rules.registry import RuleRegistry

            reg = RuleRegistry.create_default()
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
                "973": "API Policy",
                "975": "Resource Exhaustion",
                "976": "Multipart Upload",
                "977": "Authentication Abuse",
                "978": "Parameter Pollution",
                "979": "Security Headers",
                "980": "Host Header Injection",
            }

            for rule_obj in reg.list_rules():
                rid = rule_obj.id
                rname = getattr(rule_obj, "name", "")
                cat_val = getattr(getattr(rule_obj, "category", None), "value", "General Security")
                if rid.isdigit() and len(rid) >= 3:
                    cat_val = cat_map.get(rid[:3], cat_val.capitalize())
                elif rid.startswith("PAYLOAD_"):
                    rname = rname or f"Native Scored Rule {rid}"
                    cat_val = "Native Scored Rules"
                elif rid.startswith("BLOCKLIST_"):
                    rname = rname or f"Reputation Blocklist {rid}"
                    cat_val = "Reputation"

                conn.execute(
                    "INSERT OR IGNORE INTO waf_rules (rule_id, rule_name, category, enabled) VALUES (?, ?, ?, 1)",
                    (rid, rname or rid, cat_val),
                )

            # Register Threat Intelligence IOC Rules
            ioc_rules = [
                ("IOC_IP_THREAT", "Threat Intelligence IP Indicator Match", "Threat Intelligence"),
                ("IOC_DOMAIN_THREAT", "Threat Intelligence Domain Indicator Match", "Threat Intelligence"),
                ("IOC_PATH_THREAT", "Threat Intelligence URI / Path Indicator Match", "Threat Intelligence"),
            ]
            for rid, rname, rcat in ioc_rules:
                conn.execute(
                    "INSERT OR IGNORE INTO waf_rules (rule_id, rule_name, category, enabled) VALUES (?, ?, ?, 1)",
                    (rid, rname, rcat),
                )

            # Register Rate Limit Rule
            conn.execute(
                "INSERT OR IGNORE INTO waf_rules (rule_id, rule_name, category, enabled) VALUES (?, ?, ?, 1)",
                ("RATE_LIMIT_EXCEEDED", "Rate Limit Exceeded", "Rate Limiting"),
            )
        except Exception:
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
    duration_ms: Optional[float] = None,
):
    if action is None:
        action = "403 Blocked" if blocked else "200 Allowed"
    with get_connection() as conn:
        conn.execute(
            """
            INSERT INTO events (timestamp, client_ip, method, path, blocked, rule_id, reason, action, payload_snippet, duration_ms)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
                duration_ms,
            ),
        )
        conn.commit()


def get_stats() -> Dict[str, Any]:
    """Calculate truthful aggregate statistics directly from database records."""
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM events")
        total = cursor.fetchone()[0]

        cursor.execute("SELECT COUNT(*) FROM events WHERE blocked = 1")
        blocked = cursor.fetchone()[0]

        cursor.execute("SELECT COUNT(*) FROM protected_sites")
        sites = cursor.fetchone()[0]

        clean = max(0, total - blocked)

        # Real average latency from measured requests (last 500)
        cursor.execute(
            "SELECT AVG(duration_ms) FROM (SELECT duration_ms FROM events WHERE duration_ms IS NOT NULL ORDER BY id DESC LIMIT 500)"
        )
        avg_lat_row = cursor.fetchone()
        avg_latency = round(avg_lat_row[0], 2) if avg_lat_row and avg_lat_row[0] is not None else None

        # Real threat category breakdown from all blocked events
        cursor.execute("""
            SELECT 
                SUM(CASE WHEN rule_id LIKE '942%' OR lower(reason) LIKE '%sql%' THEN 1 ELSE 0 END),
                SUM(CASE WHEN rule_id LIKE '941%' OR lower(reason) LIKE '%xss%' OR lower(reason) LIKE '%script%' THEN 1 ELSE 0 END),
                SUM(CASE WHEN rule_id LIKE '930%' OR lower(reason) LIKE '%traversal%' OR lower(reason) LIKE '%passwd%' THEN 1 ELSE 0 END),
                SUM(CASE WHEN rule_id LIKE '932%' OR lower(reason) LIKE '%rce%' OR lower(reason) LIKE '%command%' OR lower(reason) LIKE '%shell%' THEN 1 ELSE 0 END),
                SUM(CASE WHEN rule_id LIKE '934%' OR lower(reason) LIKE '%ssrf%' OR lower(reason) LIKE '%metadata%' THEN 1 ELSE 0 END),
                SUM(CASE WHEN rule_id LIKE '944%' OR lower(reason) LIKE '%log4j%' OR lower(reason) LIKE '%jndi%' THEN 1 ELSE 0 END),
                SUM(CASE WHEN rule_id LIKE '913%' OR lower(reason) LIKE '%bot%' OR lower(reason) LIKE '%scanner%' THEN 1 ELSE 0 END)
            FROM events WHERE blocked = 1
        """)
        row = cursor.fetchone()
        sqli = row[0] or 0
        xss = row[1] or 0
        traversal = row[2] or 0
        rce = row[3] or 0
        ssrf = row[4] or 0
        log4j = row[5] or 0
        scanners = row[6] or 0
        categorized_total = sqli + xss + traversal + rce + ssrf + log4j + scanners
        other = max(0, blocked - categorized_total)

        threat_breakdown = {
            "SQLi": sqli,
            "XSS": xss,
            "Traversal": traversal,
            "RCE": rce,
            "SSRF": ssrf,
            "Log4Shell": log4j,
            "Scanners": scanners,
            "Other": other,
        }

        return {
            "total_requests": total,
            "blocked_attacks": blocked,
            "clean_requests": clean,
            "protected_domains": sites,
            "threat_breakdown": threat_breakdown,
            "latency_ms": avg_latency,
        }


def get_control_overview_stats(time_range: str = "all") -> Dict[str, Any]:
    """
    Return truthful metrics for the control API /api/v1/overview endpoint.
    All counts are derived from the SQLite events table.
    time_range: "24h", "7d", or "all".
    """
    with get_connection() as conn:
        cursor = conn.cursor()

        # Build time filter clause
        time_clause = ""
        time_params: list = []
        if time_range == "24h":
            time_clause = "WHERE timestamp >= datetime('now', '-1 day')"
        elif time_range == "7d":
            time_clause = "WHERE timestamp >= datetime('now', '-7 days')"
        # "all" has no filter

        # Total proxy-inspected HTTP requests
        cursor.execute(f"SELECT COUNT(*) FROM events {time_clause}", time_params)
        total_requests = cursor.fetchone()[0]

        # Requests blocked by WAF or Rate Limiting
        where_prefix = "AND" if time_clause else "WHERE"
        cursor.execute(
            f"SELECT COUNT(*) FROM events {time_clause} {where_prefix} blocked = 1",
            time_params,
        )
        blocked_attacks = cursor.fetchone()[0]

        # Requests allowed through
        allowed_requests = max(0, total_requests - blocked_attacks)

        # Detection mode events (would have blocked)
        cursor.execute(
            f"SELECT COUNT(*) FROM events {time_clause} {where_prefix} blocked = 0 AND action LIKE '%Detection Mode%'",
            time_params,
        )
        would_block_events = cursor.fetchone()[0]

        # Rate-limit events
        cursor.execute(
            f"SELECT COUNT(*) FROM events {time_clause} {where_prefix} (rule_id = 'RATE_LIMIT_EXCEEDED' OR action LIKE '%429%')",
            time_params,
        )
        rate_limited_events = cursor.fetchone()[0]

        # Real average latency from measured requests (last 500 within time range)
        cursor.execute(
            f"SELECT AVG(duration_ms) FROM (SELECT duration_ms FROM events {time_clause} {'AND' if time_clause else 'WHERE'} duration_ms IS NOT NULL ORDER BY id DESC LIMIT 500)",
            time_params,
        )
        avg_lat_row = cursor.fetchone()
        avg_latency_ms = round(avg_lat_row[0], 2) if avg_lat_row and avg_lat_row[0] is not None else None

        return {
            "total_requests": total_requests,
            "blocked_attacks": blocked_attacks,
            "allowed_requests": allowed_requests,
            "would_block_events": would_block_events,
            "rate_limited_events": rate_limited_events,
            "avg_latency_ms": avg_latency_ms,
        }


def get_recent_events(limit: int = 25) -> List[Dict[str, Any]]:
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


def get_logs(query: str = "", threat: str = "All Threat Types", limit: int = 100) -> List[Dict[str, Any]]:
    with get_connection() as conn:
        cursor = conn.cursor()
        sql = """
            SELECT id, timestamp, client_ip, method, path, blocked, rule_id, reason,
                   COALESCE(action, CASE WHEN blocked = 1 THEN '403 Blocked' ELSE '200 Allowed' END) as action,
                   COALESCE(payload_snippet, '') as payload_snippet
            FROM events WHERE (client_ip LIKE ? OR path LIKE ? OR payload_snippet LIKE ? OR reason LIKE ?)
        """
        params: List[Any] = [f"%{query}%", f"%{query}%", f"%{query}%", f"%{query}%"]
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
        cursor.execute("SELECT rule_id, rule_name, category, enabled FROM waf_rules ORDER BY category, rule_id")
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


def set_all_rules_state(enabled: bool, category: Optional[str] = None):
    with get_connection() as conn:
        if category and category != "ALL":
            conn.execute("UPDATE waf_rules SET enabled = ? WHERE category = ?", (1 if enabled else 0, category))
        else:
            conn.execute("UPDATE waf_rules SET enabled = ?", (1 if enabled else 0,))
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
