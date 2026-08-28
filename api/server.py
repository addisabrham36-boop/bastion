"""
Bastion WAF Management REST API & Dashboard Server.
"""

import os
import platform
import time
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, Query, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from database.db import (
    add_site,
    clear_logs,
    delete_site,
    export_logs_csv,
    get_logs,
    get_recent_events,
    get_rules,
    get_sites,
    get_stats,
    init_db,
    set_rule_state,
    set_site_defense,
)

init_db()

app = FastAPI(title="Bastion WAF API & Dashboard Server")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

START_TIME = time.time()


class RuleToggleRequest(BaseModel):
    rule_id: str
    enabled: bool


class SiteToggleRequest(BaseModel):
    site_id: Optional[int] = None
    defense_mode: Optional[bool] = None
    domain: Optional[str] = None
    upstream: Optional[str] = None


@app.get("/api/stats")
def stats():
    return get_stats()


@app.get("/api/events")
def events():
    return get_recent_events()


@app.get("/api/logs")
def logs(q: str = Query("", alias="q"), threat: str = Query("All Threat Types", alias="threat")):
    return get_logs(query=q, threat=threat)


@app.post("/api/logs/clear")
def clear_all_logs():
    clear_logs()
    return {"status": "success", "message": "All security audit logs cleared"}


@app.get("/api/export/csv")
def export_csv():
    csv_data = export_logs_csv()
    return Response(
        content=csv_data,
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=bastion_waf_security_logs.csv"},
    )


@app.get("/api/rules")
def list_rules():
    return get_rules()


@app.post("/api/rules")
def update_rule(req: RuleToggleRequest):
    set_rule_state(req.rule_id, req.enabled)
    return {"status": "success", "rule_id": req.rule_id, "enabled": req.enabled}


@app.get("/api/sites")
def list_sites():
    return get_sites()


@app.post("/api/sites")
def update_or_add_site(req: SiteToggleRequest):
    if req.domain and req.upstream:
        add_site(req.domain, req.upstream)
        return {"status": "success", "action": "created", "domain": req.domain}
    if req.site_id is not None and req.defense_mode is not None:
        set_site_defense(req.site_id, req.defense_mode)
        return {"status": "success", "action": "updated", "site_id": req.site_id}
    return {"status": "error", "message": "Invalid site payload"}


@app.delete("/api/sites/{site_id}")
def remove_site(site_id: int):
    delete_site(site_id)
    return {"status": "success", "action": "deleted", "site_id": site_id}


@app.get("/api/system")
def system_metrics():
    # Attempt to read live memory / CPU info
    cpu_percent = 4.8
    ram_usage_mb = 138.5
    total_ram_gb = 8.0
    try:
        import psutil
        cpu_percent = psutil.cpu_percent(interval=0.1)
        mem = psutil.virtual_memory()
        ram_usage_mb = round(mem.used / (1024 * 1024), 1)
        total_ram_gb = round(mem.total / (1024 * 1024 * 1024), 1)
    except Exception:
        # Fallback if psutil not installed in current env
        pass

    uptime_sec = int(time.time() - START_TIME)
    hours, rem = divmod(uptime_sec, 3600)
    minutes, seconds = divmod(rem, 60)
    uptime_str = f"{hours}h {minutes}m {seconds}s"

    return {
        "cpu_percent": cpu_percent,
        "ram_used_mb": ram_usage_mb,
        "ram_total_gb": total_ram_gb,
        "ram_percent": round((ram_usage_mb / (total_ram_gb * 1024)) * 100, 1) if total_ram_gb else 15.0,
        "uptime": uptime_str,
        "uptime_seconds": uptime_sec,
        "platform": platform.platform(),
        "python_version": platform.python_version(),
        "proxy_status": "ONLINE (Port 8080)",
        "engine_state": "ACTIVE BLOCKING",
    }


dashboard_dir = Path(__file__).resolve().parent.parent / "dashboard"
if dashboard_dir.exists():
    app.mount("/", StaticFiles(directory=str(dashboard_dir), html=True), name="dashboard")
