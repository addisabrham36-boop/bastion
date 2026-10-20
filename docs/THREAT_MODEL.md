# Bastion-TIP Threat Model & Security Architecture

**Document Version:** 1.0.0  
**Context:** INSA Graduation Demonstration — Educational WAF & Threat Intelligence Platform  
**Target:** Bastion-TIP (Python 3.13+, FastAPI, Redis 7, OpenSearch 3.9.0)

---

## 1. System Overview & Current-State Architecture

Bastion-TIP decouples real-time request inspection and proxying (Data Plane) from threat intelligence processing, log storage, and system management (Control Plane).

```
                      +-----------------------------+
                      |   Untrusted Public Client   |
                      +-----------------------------+
                                     |
                                     | [HTTP/1.1 Request]
                                     v
                       +============================+
                       |   TRUST BOUNDARY 1: EDGE   |
                       +============================+
                                     |
                                     v
                      +-----------------------------+
                      |   Bastion WAF Data Plane    |
                      |   - Host & Preflight Gate   |
                      |   - Normalization Pipeline  |
                      |   - Rule Engine (15+ packs) |
                      |   - Decision Engine         |
                      |   - Redis Rate Limiter      |
                      |   - Redis IOC Lookup Cache  |
                      +-----------------------------+
                        /          |             \
      [ALLOW / DETECTION]          |              [BLOCK / 403 / 421 / 429]
              /                    |                           \
             v                     v                            v
  +=====================+   +=====================+     +-------------------+
  | TRUST BOUNDARY 2:   |   | TRUST BOUNDARY 3:   |     | Error Response /  |
  | UPSTREAM BACKEND    |   | STORAGE & TELEMETRY |     | Block Page        |
  +=====================+   +=====================+     +-------------------+
             |                         |
             v                         v
+------------------------+   +-------------------+
| Authorized Upstream    |   | Redis (Stream &   |
| (e.g. Netlify Portf.)  |   | IOCs / Rate Limit)|
+------------------------+   +-------------------+
                                       |
                                       v
                             +-------------------+
                             | Telemetry Worker  |
                             +-------------------+
                                       |
                                       v
                             +-------------------+
                             | OpenSearch &      |
                             | Dashboards (SOC)  |
                             +-------------------+

                      +=============================+
                      |   TRUST BOUNDARY 4: ADMIN   |
                      +=============================+
                                     |
                                     v
                      +-----------------------------+
                      | Control API (/api/v1/)      |
                      | RBAC (admin/viewer)         |
                      | Audit Log & TIP Management  |
                      +-----------------------------+
```

---

## 2. Trust Boundaries

| Boundary | Components Involved | Description | Enforcement Mechanisms |
|---|---|---|---|
| **TB-1: Client Ingress** | External Client -> Bastion WAF | Untrusted internet or local client sending arbitrary HTTP traffic. | Port binding, Preflight checks, Max body/URI bounds, Host header validation, WAF inspection. |
| **TB-2: Upstream Forwarding** | Bastion WAF -> Protected Target | Trusted egress to authorized origin backend. | Strict `sites.yaml` destination routing, TLS SNI & certificate verification, Hop-by-hop header stripping. |
| **TB-3: Telemetry & Broker** | Bastion WAF -> Redis / OpenSearch | Private internal data plane and log aggregation. | Docker internal network (`bastion_internal`), TLS on OpenSearch, basic authentication, isolated Redis key namespaces. |
| **TB-4: Management Plane** | Operator -> Control API (`:9000`) | Administrative configuration and threat intelligence management. | HTTP Bearer token / session authentication, RBAC (`admin`, `viewer`), audit logging, origin validation. |
| **TB-5: Threat Feed Ingestion** | TIP Engine -> External Threat Feeds | Ingestion of raw indicator lists (IPs, domains, hashes). | Source allowlisting, syntax validation, canonicalization, confidence thresholds, dry-run evaluation. |

---

## 3. Assets & Security Objectives

1. **Target Web Application Availability & Integrity**: Protect upstream servers against application-layer exploits (OWASP Top 10), denial of service, and parameter pollution.
2. **Upstream Confidentiality**: Prevent SSRF, unauthorized path traversal, and header leakage to unapproved origins.
3. **Telemetry Truthfulness & Auditability**: Ensure all security events, detections, and administrative modifications are immutably and accurately logged without data fabrication.
4. **Threat Intelligence Quality**: Ensure only validated, non-stale, high-confidence indicators are evaluated, preventing self-denial of service.
5. **Operational Resiliency**: Prevent WAF failures, Redis outages, or OpenSearch latency from crashing or stalling the proxy data path.

---

## 4. Threat & Abuse Cases

| ID | Threat / Abuse Case | STRIDE Category | Mitigation Strategy in Bastion-TIP |
|---|---|---|---|
| **T-01** | **Evasion via Multi-Encoding & Path Obfuscation** | Tampering | Multi-pass recursive URL decoding, path canonicalization (`..` stripping, normalization), case folding, null byte rejection before evaluation. |
| **T-02** | **ReDoS (Regular Expression Denial of Service)** | Denial of Service | Pre-compiled deterministic regexes, length-bounded input evaluation, regex complexity audits, rule execution timeouts. |
| **T-03** | **Open Proxy / SSRF Abuse via Host Header** | Elevation of Privilege | Strict `Host` allowlisting from `sites.yaml`. Rejection of unmapped hosts with `421 Misdirected Request`. Fixed upstream mapping. |
| **T-04** | **HTTP Request Smuggling / Protocol Desync** | Tampering / Repudiation | Enforce RFC 9112 rules: reject requests with both `Content-Length` and `Transfer-Encoding`, reject malformed chunking, strip hop-by-hop headers. |
| **T-05** | **Threat Intelligence Poisoning** | Tampering | Feeds must be explicitly configured; incoming indicators undergo IP/domain format validation; confidence thresholds prevent untrusted automated blocking. |
| **T-06** | **Credential & Secret Exposure** | Information Disclosure | Secrets kept strictly in `.env` (gitignored), masked in logs, sanitized API responses, no credentials in URL parameters. |
| **T-07** | **Redis / OpenSearch Outage Degradation** | Denial of Service | Documented fallback policies: fail-open for ordinary traffic with local logging, strict fail-closed for designated sensitive paths, non-blocking telemetry queuing with memory bounds. |
| **T-08** | **Parameter Pollution & Body Inconsistencies** | Tampering | Inspection views parse repeated query parameters into arrays; strict checks for ambiguous parameter injection. |

---

## 5. Assumptions and Operational Environment

- **Detection Mode by Default**: In educational and demonstration modes, Bastion detects threats and logs them with `would_action="BLOCK"` while allowing legitimate and test traffic through (`enforced_action="ALLOW"`), unless explicit Prevention Mode is activated for a site.
- **Edge Proxy Termination**: Volumetric DDoS (Layer 3/4) and HTTP/2/3 termination are assumed to be handled by an edge proxy (e.g. Caddy/Cloudflare) when exposed publicly.
- **Local Isolated Deployment**: For INSA graduation demonstration, all components run in an isolated Docker Compose network on loopback interfaces (`127.0.0.1`), with no public DNS exposure or production impact.

---

## 6. Gap Analysis & Roadmap Alignment

| Component | Current State | Target Graduation State | Priority |
|---|---|---|---|
| **Rule Engine** | Dual engine (`Engine` vs `BaseRule/RuleRegistry`) | Single unified OOP rule engine, structured `Detection` objects, ReDoS bounds, explicit exclusions. | **Phase 1** |
| **Rule Families** | ~11 active families | 15+ comprehensive, unit-tested families with negative tests, encoding variants, OWASP 2025 mapping. | **Phase 2** |
| **Proxy Correctness** | Basic proxy with compression fix | Bounded streaming, client IP CIDR derivation, framing desync rejection, local mock upstream integration tests. | **Phase 3** |
| **Rate Limiter** | Standalone Lua script in storage | Integrated into proxy data path, IPv4/IPv6 normalization, route policies, outage fallback tests. | **Phase 4** |
| **Threat Intelligence** | Basic Redis IP set | Full canonical IOC model (IP, Domain, URL, Hash), feed import pipeline, SQLite/Redis/OpenSearch sync, authenticated management API. | **Phase 5** |
| **Management Security** | In-memory token sessions | Authenticated REST API with role enforcement (`admin`, `viewer`), audit trail, secure health checks, outage resiliency. | **Phase 6** |
| **Evaluation Harness** | Ad-hoc pytest | Reproducible test harness, positive/negative corpora, latency (p50/p95/p99) benchmarks, graduation evaluation report. | **Phase 7** |
| **Documentation** | Partial docs | Complete rule catalogue, OWASP matrix, architecture, and INSA graduation guide. | **Phase 8** |
