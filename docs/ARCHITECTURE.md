# Bastion-TIP System Architecture

Bastion-TIP is a modular Web Application Firewall (WAF) and Threat Intelligence Platform built in Python 3. It decouples the real-time request proxy path (Data Plane) from the security telemetry and management operations (Control Plane).

```
                         Public Internet / Browser
                                    |
                              DNS -> HTTPS
                                    |
                           +------------------+
                           | Caddy Edge Proxy |
                           | TLS / size limit |
                           +------------------+
                                    |
                            private Docker net
                                    |
                      +---------------------------+
                      | Bastion Gateway (Python)  |
                      | configured site routing   |
                      +---------------------------+
                         |        |          |
             decision ALLOW       |          +------> local policy / rules
                         |        |
                         v        v
                  Authorized     Redis
                  Upstream       - IOC keys (per-indicator TTL)
                  Website        - atomic rate limits (Lua sliding window)
                                 - event stream (bastion:events:v1)
                                      |
                               ingestion worker
                                      |
                                  OpenSearch
                                 (bulk index)

         Admin Browser -> /api/v1/ -> authenticated control API
                                   |
                         auth / RBAC / audit records
```

## Data Plane Components
- **SiteRouter (`bastion/proxy/router.py`):** Resolves incoming `Host` headers strictly against validated `sites.yaml` configs. Rejects unknown hosts (`421 Misdirected Request`) and prevents open-proxy/SSRF abuse.
- **PreflightValidator (`bastion/core/preflight.py`):** Rejects oversized URIs, unauthorized HTTP methods, and excessive headers prior to expensive inspection.
- **Normalization Engine (`bastion/core/normalization.py`):** Generates canonical inspection views (multi-pass URL decode, path resolution, bounded JSON/form parsing) without mutating the forwarded request.
- **Rule Engine & Registry (`bastion/rules/`):** Evaluates deterministic signature packs (SQLi, XSS, Path Traversal, OS Command Injection) within bounded regex time.
- **Decision Engine (`bastion/core/decision.py`):** Enforces Prevention Mode vs. Detection Mode policies using scored thresholds.
- **Upstream Client (`bastion/proxy/service.py`):** Handles upstream connection pooling, hop-by-hop header removal, and streaming responses with `X-Bastion-Request-ID`.

## Control & Observability Plane
- **Redis IOC & Rate Limiter (`bastion/storage/`):** Per-IOC keys with individual TTLs; atomic sliding-window token bucket using Redis Lua.
- **Telemetry Worker (`bastion/telemetry/worker.py`):** Consumer group worker pulling from Redis Streams, batching bulk inserts into OpenSearch, with dead-letter protection.
- **Control API (`bastion/api/routes/control.py`):** Role-based access control (`admin`, `viewer`), audit logging, site mode toggles, and health endpoints.
