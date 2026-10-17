#!/usr/bin/env python3
"""
CVE — Bastion CVE Search Tool.

Search for known vulnerabilities by service name, version, or severity.

Usage:
    CVE <service>                   Search CVEs for a service
    CVE <service> <version>         Filter by version
    CVE --severity critical         Filter by severity
    CVE --list-services             List all indexed services
    CVE --stats                     Show database statistics
"""

import argparse
import json
import os
import sys
from pathlib import Path

# ── Paths ──────────────────────────────────────────────────────────────────
SCRIPT_DIR = Path(__file__).resolve().parent
CVE_DB_PATH = SCRIPT_DIR / "cve_data" / "cve_database.json"

# ── ANSI colours ───────────────────────────────────────────────────────────
BOLD = "\033[1m"
RESET = "\033[0m"
RED = "\033[91m"
ORANGE = "\033[38;5;208m"
YELLOW = "\033[93m"
GREEN = "\033[92m"
CYAN = "\033[96m"
GRAY = "\033[90m"
WHITE = "\033[97m"
UNDERLINE = "\033[4m"

SEVERITY_COLOURS = {
    "CRITICAL": RED,
    "HIGH": ORANGE,
    "MEDIUM": YELLOW,
    "LOW": GREEN,
}


def load_database() -> list:
    """Load the CVE database from disk."""
    if not CVE_DB_PATH.exists():
        print(f"{RED}✗ CVE database not found at {CVE_DB_PATH}{RESET}")
        print(f"  Run the Bastion dashboard to auto-build, or check your installation.")
        sys.exit(1)
    with open(CVE_DB_PATH, "r", encoding="utf-8") as f:
        return json.load(f)


def severity_badge(sev: str) -> str:
    """Return a coloured severity string."""
    colour = SEVERITY_COLOURS.get(sev.upper(), WHITE)
    return f"{colour}{BOLD}[{sev.upper()}]{RESET}"


def print_cve(entry: dict, compact: bool = False):
    """Pretty-print a single CVE entry."""
    sev = entry.get("severity", "UNKNOWN").upper()
    badge = severity_badge(sev)
    cvss = entry.get("cvss", "N/A")

    print(f"\n  {CYAN}{BOLD}{entry['id']}{RESET}  {badge}  CVSS: {BOLD}{cvss}{RESET}")
    print(f"  {GRAY}Service:{RESET} {WHITE}{entry.get('service', 'N/A')}{RESET}  "
          f"{GRAY}Vendor:{RESET} {WHITE}{entry.get('vendor', 'N/A')}{RESET}")
    print(f"  {GRAY}Affected:{RESET} {WHITE}{entry.get('versions_affected', 'N/A')}{RESET}")
    if not compact:
        print(f"  {entry.get('description', 'No description.')}")
        ref = entry.get("reference", "")
        if ref:
            print(f"  {GRAY}{UNDERLINE}{ref}{RESET}")
        tags = entry.get("tags", [])
        if tags:
            tag_str = " ".join(f"#{t}" for t in tags)
            print(f"  {GRAY}{tag_str}{RESET}")
    print(f"  {GRAY}{'─' * 64}{RESET}")


def search_cves(db: list, service: str = "", version: str = "", severity: str = "") -> list:
    """Filter the database by service, version, and severity."""
    results = db

    if service:
        s = service.lower()
        results = [
            e for e in results
            if s in e.get("service", "").lower()
            or s in e.get("vendor", "").lower()
            or s in " ".join(e.get("tags", [])).lower()
        ]

    if version:
        v = version.lower()
        results = [
            e for e in results
            if v in e.get("versions_affected", "").lower()
        ]

    if severity:
        sev = severity.upper()
        results = [e for e in results if e.get("severity", "").upper() == sev]

    # Sort: CRITICAL first, then by CVSS descending
    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    results.sort(key=lambda e: (severity_order.get(e.get("severity", "").upper(), 9), -(e.get("cvss", 0) or 0)))

    return results


def list_services(db: list):
    """Print all unique services in the database."""
    services = {}
    for e in db:
        svc = e.get("service", "unknown").lower()
        if svc not in services:
            services[svc] = {"vendor": e.get("vendor", ""), "count": 0}
        services[svc]["count"] += 1

    print(f"\n{BOLD}{WHITE}  ╔══════════════════════════════════════════════════════════╗{RESET}")
    print(f"{BOLD}{WHITE}  ║           BASTION — Indexed Services ({len(services)})              ║{RESET}")
    print(f"{BOLD}{WHITE}  ╚══════════════════════════════════════════════════════════╝{RESET}\n")

    for svc in sorted(services.keys()):
        info = services[svc]
        print(f"  {CYAN}●{RESET} {WHITE}{BOLD}{svc:<25}{RESET} {GRAY}{info['vendor']:<20}{RESET} {YELLOW}{info['count']} CVEs{RESET}")

    print(f"\n  {GRAY}Total: {len(db)} CVEs across {len(services)} services{RESET}\n")


def show_stats(db: list):
    """Show database statistics."""
    total = len(db)
    sev_counts = {}
    svc_counts = {}
    for e in db:
        sev = e.get("severity", "UNKNOWN").upper()
        sev_counts[sev] = sev_counts.get(sev, 0) + 1
        svc = e.get("service", "unknown").lower()
        svc_counts[svc] = svc_counts.get(svc, 0) + 1

    print(f"\n{BOLD}{WHITE}  ╔══════════════════════════════════════════════════════════╗{RESET}")
    print(f"{BOLD}{WHITE}  ║             BASTION — CVE Database Stats                 ║{RESET}")
    print(f"{BOLD}{WHITE}  ╚══════════════════════════════════════════════════════════╝{RESET}\n")

    print(f"  {GRAY}Total CVEs:{RESET}   {BOLD}{WHITE}{total}{RESET}")
    print(f"  {GRAY}Services:{RESET}     {BOLD}{WHITE}{len(svc_counts)}{RESET}")
    print()

    print(f"  {BOLD}Severity Breakdown:{RESET}")
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
        count = sev_counts.get(sev, 0)
        bar_len = int((count / max(total, 1)) * 40)
        colour = SEVERITY_COLOURS.get(sev, WHITE)
        bar = f"{colour}{'█' * bar_len}{GRAY}{'░' * (40 - bar_len)}{RESET}"
        print(f"  {severity_badge(sev):>30s}  {bar}  {WHITE}{count}{RESET}")

    print(f"\n  {BOLD}Top 10 Services:{RESET}")
    top = sorted(svc_counts.items(), key=lambda x: -x[1])[:10]
    for svc, count in top:
        bar_len = int((count / max(top[0][1], 1)) * 30)
        print(f"  {CYAN}{svc:<20}{RESET}  {CYAN}{'█' * bar_len}{RESET}  {WHITE}{count}{RESET}")

    print()


def banner():
    print(f"""
{RED}   ██████╗██╗   ██╗███████╗{RESET}
{RED}  ██╔════╝██║   ██║██╔════╝{RESET}   {BOLD}{WHITE}Bastion CVE Search Tool{RESET}
{RED}  ██║     ██║   ██║█████╗  {RESET}   {GRAY}Vulnerability Lookup Engine{RESET}
{RED}  ██║     ╚██╗ ██╔╝██╔══╝  {RESET}   {GRAY}──────────────────────────{RESET}
{RED}  ╚██████╗ ╚████╔╝ ███████╗{RESET}   {GRAY}Type a service name to search.{RESET}
{RED}   ╚═════╝  ╚═══╝  ╚══════╝{RESET}
""")


def main():
    parser = argparse.ArgumentParser(
        prog="CVE",
        description="Bastion CVE Search — find vulnerabilities by service name, version, or severity.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""Examples:
  CVE apache              Search all Apache CVEs
  CVE openssh 7.6         Search OpenSSH CVEs matching version 7.6
  CVE --severity critical Show only CRITICAL severity CVEs
  CVE samba --severity high
  CVE --list-services     List all indexed services
  CVE --stats             Show database statistics""",
    )
    parser.add_argument("service", nargs="?", default="", help="Service name to search (e.g. apache, openssh, samba)")
    parser.add_argument("version", nargs="?", default="", help="Version string to filter (e.g. 7.6, 2.4)")
    parser.add_argument("--severity", "-s", default="", help="Filter by severity: CRITICAL, HIGH, MEDIUM, LOW")
    parser.add_argument("--list-services", "-l", action="store_true", help="List all indexed services")
    parser.add_argument("--stats", action="store_true", help="Show CVE database statistics")
    parser.add_argument("--compact", "-c", action="store_true", help="Compact output (no descriptions)")
    parser.add_argument("--limit", "-n", type=int, default=0, help="Max results to show (0 = all)")

    args = parser.parse_args()

    db = load_database()

    if args.list_services:
        banner()
        list_services(db)
        return

    if args.stats:
        banner()
        show_stats(db)
        return

    if not args.service and not args.severity:
        banner()
        parser.print_help()
        return

    results = search_cves(db, service=args.service, version=args.version, severity=args.severity)

    if args.limit > 0:
        results = results[: args.limit]

    banner()

    if not results:
        print(f"  {YELLOW}No CVEs found for '{args.service}'{' version ' + args.version if args.version else ''}.{RESET}")
        print(f"  {GRAY}Try: CVE --list-services{RESET}\n")
        return

    query_desc = args.service or "all"
    if args.version:
        query_desc += f" {args.version}"
    if args.severity:
        query_desc += f" [{args.severity.upper()}]"

    print(f"  {BOLD}{WHITE}Found {len(results)} CVEs for '{query_desc}'{RESET}\n")

    for entry in results:
        print_cve(entry, compact=args.compact)

    print(f"\n  {GRAY}Showing {len(results)} result(s). Data sourced from NVD.{RESET}\n")


if __name__ == "__main__":
    main()
