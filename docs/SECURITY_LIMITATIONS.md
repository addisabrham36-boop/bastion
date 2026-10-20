# Bastion-TIP Security Boundaries and Known Limitations

## 1. Validated Security Boundaries
- **Strict Upstream Routing:** Upstream origins are sourced solely from trusted site configurations (`sites.yaml`). Inbound requests cannot specify or override the destination host.
- **Header Forwarding Trust:** Forwarding headers (`X-Forwarded-For`, `Forwarded`) are only respected if the immediate TCP/ASGI peer is inside a configured trusted CIDR (`BASTION_TRUSTED_PROXY_CIDRS`). Direct public requests cannot spoof their identity.
- **Resource Limits:** Request URIs, header blocks, and bodies are strictly limited and bounded during reading (not solely relying on declared `Content-Length`).
- **Private Backend Exposure:** Redis and OpenSearch are configured for private internal network access only.
- **Redis IOC Isolation:** Indicators use individual keys (`bastion:ioc:v1:ip:<ip>`) with independent TTLs, avoiding shared set expiration collisions.

## 2. Explicit System Limitations
- **Not an Enterprise CDN/DDoS Shield:** A custom Python reverse proxy is not designed to absorb multi-gigabit volumetric DDoS attacks. An upstream CDN or edge firewall (e.g. Caddy, Cloudflare) must front the gateway.
- **HTTP/2 and HTTP/3 Parsing:** HTTP/2 and HTTP/3 termination must be handled by the edge reverse proxy (e.g., Caddy). Bastion operates on HTTP/1.1 ASGI primitives.
- **Payload Inspection Depth:** Large file uploads and streaming media bodies are bounded by `max_body_bytes`. Content exceeding limits is evaluated according to `unsupported_body_policy`.
- **Evasion Resilience:** While repeated URL decoding and path normalization mitigate standard obfuscation techniques, zero-day evasion vectors and complex multi-layer encoding variations require ongoing signature updates and testing in Detection Mode.
