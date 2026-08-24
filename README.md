# Bastion

A self-hosted Web Application Firewall — reverse proxy + signature-based
detection engine, with a roadmap toward anomaly detection, an ML payload
classifier, and LLM-assisted rule triage.

## Structure

```
bastion/
├── bastion/                 # core package
│   ├── core/
│   │   ├── proxy.py         # reverse proxy — Phase 2
│   │   ├── inspector.py     # request field extraction — Phase 2
│   │   ├── normalizer.py    # decode/canonicalize before rule matching — Phase 1
│   │   └── engine.py        # runs all rules, returns a verdict — Phase 1
│   ├── rules/
│   │   ├── base.py          # Rule ABC + Verdict — done (Phase 0)
│   │   ├── sqli.py          # Phase 1
│   │   ├── xss.py           # Phase 1
│   │   ├── traversal.py     # Phase 1
│   │   ├── command_injection.py  # Phase 1
│   │   └── ssrf.py          # Phase 1
│   └── detection/           # anomaly baselining, ML classifier — Phase 6
├── api/
│   └── server.py            # REST API backing the dashboard — Phase 3
├── dashboard/
│   └── index.html           # dashboard UI — built, currently mocked data
├── database/
│   ├── waf.db                # created at runtime, not committed
│   └── migrations/
├── config/
│   ├── config.json          # engine/proxy/api settings
│   └── blocklist.json       # IP/UA blocklists — editable without a redeploy
├── tests/                   # per-rule regression tests — Phase 1
└── logs/                    # runtime logs, not committed
```

## Build phases

0. **Repo skeleton** — done.
1. **Detection core** — done. `normalizer.py` (repeated URL-decode, null-byte stripping, full path/key/body extraction), `engine.py` (auto-discovers rules, blocklists, dynamic rule toggling), all OWASP CRS detection engines: `sqli.py`, `xss.py`, `traversal.py`, `command_injection.py`, `ssrf.py`.
2. **Proxy** — done. `proxy.py` + `inspector.py` with persistent connection pooling, dynamic upstream routing, and hop-by-hop header management.
3. **Persistence + API** — done. `waf.db` schema (events, waf_rules, protected_sites) in `database/db.py`, exposed by `api/server.py` with `/api/stats`, `/api/events`, `/api/logs`, `/api/rules`, `/api/sites`.
4. **Dashboard** — done. Real-time telemetry, live stream intercept, protected site management, and dynamic rule toggling in `dashboard/index.html`.
5. **Hardening** — rate limiting, malformed-request handling, load testing.
6. **AI roadmap** — `detection/anomaly.py`, `detection/classifier.py`, LLM-assisted triage.

## Setup & Running

```bash
# 1. Activate environment and install dependencies
source venv/bin/activate
pip install -r requirements.txt

# 2. Run test suite (61 tests)
pytest -v

# 3. Start WAF Proxy (Listens on port 8080 or 8000)
uvicorn bastion.core.proxy:app --host 127.0.0.1 --port 8080 --reload

# 4. Start Management API & Dashboard UI (Listens on port 8000)
uvicorn api.server:app --host 127.0.0.1 --port 8000 --reload
```

