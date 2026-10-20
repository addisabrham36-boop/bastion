# Architecture & Technical Decisions Record (ADR)

## ADR-001: Preservation of Existing Working Code and Tests
- **Context:** The repository at `/home/abrham/bastion` contained working proxy logic, a SQLite event store, and 175 passing tests covering various threat vectors (SQLi, XSS, SSRF, Command Injection, etc.), as well as a custom SOC dashboard in `dashboard/index.html`.
- **Decision:** Do not discard existing code. Incrementally refactor and build the enhanced architectural layers prescribed in the Master Spec (Pydantic Settings, RequestContext, BaseRule/Registry, Redis IOC/RateLimiting, OpenSearch telemetry worker, typed API endpoints) while maintaining full compatibility with the existing dashboard and test suite.
- **Consequences:** Existing tests continue to run and verify rule efficacy; new modular components are added in parallel and integrated cleanly.

## ADR-002: Dual Virtual Environment Management on Arch Linux
- **Context:** Arch Linux enforces PEP 668 (externally managed environment). The system Python is 3.14.7. The repository already has a functioning `venv` with Python 3.13.7 runtime with pytest and dependencies installed.
- **Decision:** Use the existing project virtual environment (`venv`) which has pre-built wheels and tested dependencies. Any missing packages (e.g. `opensearch-py`, `redis`) will be installed strictly within this virtual environment.

## ADR-003: Redis IOC Expiry & Atomic Rate Limiter
- **Context:** The blueprint previously added IOCs to a shared set with a single set-wide TTL, causing indicator refresh collision or early expiration. Rate limiting also lacked atomic synchronization.
- **Decision:** Use individual Redis keys per IOC (`bastion:ioc:v1:ip:<canonical_ip>`) with individual TTLs. Implement rate limiting using atomic Lua scripts operating on Redis sorted sets (sliding window) with explicit TTLs on keys.
