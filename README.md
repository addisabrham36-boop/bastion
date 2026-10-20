# Bastion WAF — INSA Educational Web Application Firewall

Bastion is a reverse-proxy Web Application Firewall (WAF) and Threat Intelligence Platform built as an educational project at the Institute of Software and Advanced Technology (INSA). It is designed to demonstrate real-world WAF architecture including rule-based traffic inspection, scored threat detection, IOC enrichment, rate limiting, and live telemetry.

All traffic flows through the proxy on port `8080`. Clean requests are forwarded to the configured upstream. Detected attacks are blocked (prevention mode) or logged (detection mode) before the request reaches the backend.

---

## Components

| Component | Port | Purpose |
|---|---|---|
| WAF Reverse Proxy | `8080` | Inspects and forwards HTTP traffic |
| Security Dashboard | `8000` | Live telemetry, rule management, site configuration |
| OpenSearch (Docker) | `9200` / `5601` | Log storage and Discover UI |
| Redis (Docker) | `6379` | Rate limiting, IOC cache, telemetry stream |

---

## Detection Coverage

152 rules are registered across three layers:

**Adapted legacy rules (142)** — OWASP CRS-aligned, grouped by attack category:

| Category | Rule IDs | Threats Covered |
|---|---|---|
| SQL Injection | `942xxx` | UNION select, tautologies, time-based blind, stacked queries, schema extraction |
| Cross-Site Scripting | `941xxx` | Script tags, event handlers, `javascript:` URIs, SVG/iframe injection, DOM sinks |
| Path Traversal / LFI | `930xxx` | `../` sequences, encoded slashes, `/etc/passwd`, `/proc/self`, Windows paths |
| Remote Code Execution | `932xxx` | Shell chaining (`|`, `;`, `&&`), reverse shells, common system binaries |
| SSRF | `934xxx` | Cloud metadata endpoints, RFC 1918 subnets, dangerous protocol schemes |
| Java / Log4Shell | `944xxx` | `${jndi:ldap://}`, Java EL and OGNL expressions, deserialization payloads |
| PHP Injection | `933xxx` | `eval(base64_decode())`, `php://filter`, `data://` wrappers |
| Remote File Inclusion | `950xxx` | Remote URL inclusion, parameter-based path traversal |
| NoSQL Injection | `951xxx` | MongoDB operators (`$where`, `$ne`, `$regex`), Redis/CouchDB probing |
| Template Injection (SSTI) | `952xxx` | Jinja2, Twig, FreeMarker, Smarty, Velocity, Handlebars expressions |
| XXE | `953xxx` | `<!DOCTYPE>` external entities, `SYSTEM file://` and `http://` disclosures |
| HTTP Protocol | `920xxx` | Disallowed methods, header anomalies, oversized values, CRLF injection |
| Request Smuggling | `921xxx` | Conflicting `Transfer-Encoding`/`Content-Length`, chunked transfer obfuscation |
| Scanner Detection | `913xxx` | Nikto, SQLMap, Nuclei, Acunetix, Burp, path-probing user agents |
| Client-Side / Logic | `960xxx` | Prototype pollution, open redirects, dangerous upload extensions |

**Native scored rules (4)** — PAYLOAD_CMDI_001, PAYLOAD_SQLI_001, PAYLOAD_TRAVERSAL_001, PAYLOAD_XSS_001

**Blocklist rules (2)** — BLOCKLIST_IP, BLOCKLIST_UA

**IOC rules (3)** — IOC_IP_THREAT, IOC_DOMAIN_THREAT, IOC_PATH_THREAT

**Rate limit rule (1)** — RATE_LIMIT_EXCEEDED

---

## Requirements

- Python 3.13
- Docker and Docker Compose (for Redis and OpenSearch)
- Packages listed in `requirements.txt`

For Brotli decompression support:

```bash
venv/bin/pip install 'brotli>=1.1.0'
```

---

## Setup

```bash
git clone <repo-url>
cd bastion
python -m venv venv
venv/bin/pip install -r requirements.txt
```

Initialise the database (creates `bastion.db` with all 152 rules):

```bash
venv/bin/python -c "from database.db import init_db; init_db()"
```

---

## Running

### Without Docker (proxy only)

```bash
venv/bin/python -m uvicorn bastion.core.proxy:app --host 0.0.0.0 --port 8080
```

### With Docker Compose (full stack)

```bash
docker compose up -d --build
```

This starts the WAF proxy, Redis, OpenSearch, and the security dashboard together.

### CLI

```bash
# Start the full stack
bastion start

# Stop the full stack
bastion stop

# Show status
bastion status
```

---

## Vulnerable Banking Lab

A deliberately vulnerable Flask banking application is included for testing. It runs on port `5000` and is accessed through the WAF proxy at `http://127.0.0.1:8080`.

```bash
# Start the WAF stack + vulnerable lab
bastion lab start

# Stop
bastion lab stop

# Check status
bastion lab status
```

The lab target is only started when the `lab` Docker Compose profile is active. It is not included in the default `docker compose up` command.

---

## Configuration

Settings are read from environment variables (or a `.env` file). Key variables:

| Variable | Default | Description |
|---|---|---|
| `UPSTREAM_URL` | — | Backend URL to forward clean traffic to |
| `BASTION_RATE_LIMIT_ENABLED` | `true` | Set to `false` to disable rate limiting at runtime |
| `BASTION_RATE_LIMIT_TIMEOUT_SECONDS` | `0.1` | Redis timeout for rate limit checks |
| `BASTION_IOC_TIMEOUT_SECONDS` | `0.1` | Redis timeout for IOC lookups |
| `REDIS_URL` | `redis://redis:6379/0` | Redis connection string |
| `OPENSEARCH_URL` | `http://opensearch:9200` | OpenSearch endpoint |

Rate limiting uses a Redis sliding window. If Redis is unavailable, the limiter fails open (requests proceed). The kill switch (`BASTION_RATE_LIMIT_ENABLED=false`) disables rate limiting without affecting WAF rule inspection or IOC checks.

---

## Defense Modes

Each protected site can be set independently per domain:

- **Prevention mode** — Requests matching a rule threshold are blocked and return `403`.
- **Detection mode** — Attacks are logged but not blocked. The request is forwarded to the upstream.

The mode is changed through the dashboard or directly in the database.

---

## Running Tests

```bash
venv/bin/pytest tests/ -v
```

Expected result: 394 passed, 1 skipped (live Redis test), 0 failed.

The skipped test (`test_rate_limiter_real_redis_sliding_window`) requires a running Redis instance and is skipped automatically when Redis is not reachable.

---

## OpenSearch Integration

The WAF publishes security events to Redis as a stream. A telemetry worker consumes the stream and bulk-indexes events into OpenSearch under the `bastion-waf-events` index.

Fields indexed include `timestamp`, `client.ip`, `decision.enforced_action`, `decision.threat_score`, `detections` (nested array of matched rules), and request/timing metadata. Two saved searches are registered on startup: "All Security Detections" and "Blocked Attack Events".

To bootstrap the index template and saved searches manually:

```bash
venv/bin/python -c "from bastion.opensearch_bootstrap import bootstrap; import asyncio; asyncio.run(bootstrap())"
```

---

## Project Structure

```
bastion/
  api/          Control API (rule toggles, site management, status)
  core/         Proxy, rule engine, decision engine, request context
  rules/        Rule definitions (142 legacy + native + blocklist)
  storage/      Redis IOC repository, rate limiter
  threat_intel/ IOC ingestion and evaluation service
  telemetry/    Redis stream consumer, OpenSearch bulk indexer
  opensearch_bootstrap.py  Index template and saved search setup
database/
  db.py         SQLite schema, rule seeding, site and event storage
vulnerable_target/
  app.py        Deliberately vulnerable Flask banking application (lab)
tests/
  integration/  Live proxy integration tests
  unit/         Isolated component tests
```

---

## License

MIT License. Copyright (c) 2026 Addis Abraham. See [LICENSE](LICENSE).
