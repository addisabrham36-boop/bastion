import os
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, Query, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from database.db import (
    add_site,
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


dashboard_dir = Path(__file__).resolve().parent.parent / "dashboard"
if dashboard_dir.exists():
    app.mount("/", StaticFiles(directory=str(dashboard_dir), html=True), name="dashboard")