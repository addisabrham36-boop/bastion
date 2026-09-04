# 🛡️ Bastion Enterprise WAF

A high-performance, standalone Web Application Firewall (WAF) and Reverse Proxy engine with 100+ OWASP CRS-aligned detection rules, fine-grained category controls, real-time telemetry security dashboard, and multi-domain routing.

[![License: MIT](https://img.shields.io/badge/License-MIT-white.svg)](LICENSE)
[![Python: 3.13](https://img.shields.io/badge/Python-3.13-white.svg)](https://python.org)

---

## 🚀 Key Features

- **⚡ High-Throughput Reverse Proxy**: Inspects all inbound HTTP traffic on port `8080` with sub-millisecond latency.
- **🛡️ 100+ Fine-Grained Detection Rules**: Covers 15 attack categories with individual rule toggling support.
- **📊 Real-Time Security SOC Dashboard**: Live traffic stream, colored threat visualization charts, and telemetry on port `8000`.
- **🌐 Multi-Domain Upstream Routing**: Protect multiple real websites and backend microservices dynamically from the dashboard.
- **🛡️ Bypass / Defense Mode per Site**: Toggle active blocking vs passive inspection per protected domain.
- **🐳 Docker Ready**: Deploy anywhere with standard containerization.

---

## 🗂️ Detection Rule Categories (100+ Rules)

| Category | OWASP ID Range | Threats Blocked |
|---|---|---|
| **SQL Injection (SQLi)** | `942xxx` | UNION select, tautologies (`1=1`), time-based sleep, boolean blind, stacked queries, schema extraction |
| **Cross-Site Scripting (XSS)** | `941xxx` | `<script>` tags, event handlers (`onerror`, `onload`), `javascript:` URIs, SVG/iframe injection, DOM sinks |
| **Path Traversal & LFI** | `930xxx` | Dot-dot sequences (`../`), encoded slashes, `/etc/passwd`, `/proc/self`, Windows `win.ini` & `web.config` |
| **Remote Code Execution (RCE)** | `932xxx` | Chained shell commands (`|`, `;`, `&&`), reverse shells, unix/windows binaries (`whoami`, `powershell`) |
| **Server-Side Request Forgery (SSRF)** | `934xxx` | Cloud metadata endpoints (AWS, GCP, Azure, K8s), private RFC 1918 subnets, dangerous protocol schemes |
| **Java & Log4Shell** | `944xxx` | Log4Shell (`${jndi:ldap://}`), Java EL & OGNL expressions, Java deserialization payloads |
| **PHP Injection & Wrappers** | `933xxx` | `eval(base64_decode())`, `php://filter`, `php://input`, `data://` wrapper inclusion |
| **Remote File Inclusion (RFI)** | `950xxx` | Remote script URL inclusion, parameter wrapper evasion, directory traversal combinations |
| **NoSQL & Database Injection** | `951xxx` | MongoDB operator injection (`$where`, `$ne`, `$regex`), Redis/CouchDB/Elasticsearch probing |
| **Template Injection (SSTI)** | `952xxx` | Jinja2, Twig, FreeMarker, Smarty, Velocity, Pebble, Handlebars template expressions |
| **XML External Entity (XXE)** | `953xxx` | `<!DOCTYPE>` external entities, SYSTEM `file://` & `http://` file disclosures |
| **HTTP Protocol Enforcement** | `920xxx` | Disallowed HTTP methods (TRACE, DEBUG), header anomalies, oversized values, CRLF splitting |
| **HTTP Request Smuggling** | `921xxx` | Conflicting `Transfer-Encoding` / `Content-Length`, obfuscated chunked transfer headers |
| **Scanner & Bot Detection** | `913xxx` | Automated vulnerability scanners (Nikto, SQLMap, Nuclei, Acunetix, Burp), sensitive path probing |
| **Client-Side & Logic** | `960xxx` | Prototype pollution (`__proto__`), unvalidated open redirects, dangerous file upload extensions |

---

## ⚡ Quick Start

### 1. Launch Bastion
Run from anywhere in your terminal:
```bash
bastion
```
Or start with a default upstream website:
```bash
bastion --upstream http://127.0.0.1:3000
```

### 2. Access Interfaces
| Service | URL | Description |
|---|---|---|
| ⚡ **WAF Reverse Proxy** | `http://127.0.0.1:8080` | Forward web traffic through this port to protect your website |
| 📊 **Security Dashboard** | `http://127.0.0.1:8000` | Real-time threat telemetry, rule toggles, and domain management |

---

## 🌐 Connecting Real Websites

1. Open the Security Dashboard at **`http://127.0.0.1:8000`**.
2. Click **"Protect a New Website"** in the top header.
3. Enter your domain (e.g. `example.com` or `myapp.internal`) and your backend upstream address (e.g. `127.0.0.1:3000` or `192.168.1.50:80`).
4. Point your reverse proxy / DNS (Nginx, Cloudflare, or Load Balancer) to Bastion's proxy port (`8080`).

---

## 🐳 Docker Deployment

```bash
# Start Bastion services
docker-compose up -d --build
```

---

## 🧪 Running Tests

```bash
pytest -v
```

---

## 📄 License

Distributed under the [MIT License](LICENSE). Copyright (c) 2026 Addis Abraham.
