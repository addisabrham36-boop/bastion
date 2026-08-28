# 🛡️ Bastion WAF

A production-grade, self-hosted Web Application Firewall — reverse proxy + 30-rule OWASP CRS-aligned detection engine, real-time black & white security dashboard, and Docker support.

[![License: MIT](https://img.shields.io/badge/License-MIT-white.svg)](LICENSE)
[![Python: 3.13](https://img.shields.io/badge/Python-3.13-white.svg)](https://python.org)

---

## 🗂️ Detection Rules (30 Rules)

| Rule ID | Name | Category |
|---|---|---|
| `920100` | Invalid HTTP Request Method | HTTP Protocol |
| `920200` | HTTP Header Anomaly | HTTP Protocol |
| `920300` | CRLF Injection / HTTP Response Splitting | HTTP Protocol |
| `921100` | HTTP Request Smuggling | HTTP Smuggling |
| `913100` | Security Scanner Signature (Nikto, SQLMap, etc.) | Scanner Detection |
| `913110` | Malicious Bot / Bad User-Agent | Scanner Detection |
| `913120` | Attack Tool Path Signature | Scanner Detection |
| `942100` | SQL Injection (SQLi) Shield | SQLi |
| `942200` | MySQL / PostgreSQL Specific Injection | SQLi |
| `942300` | SQLi in JSON / Advanced Encoding Bypass | SQLi |
| `941100` | Cross-Site Scripting (XSS) Filter | XSS |
| `941200` | DOM-Based XSS | XSS |
| `930120` | Path Traversal / LFI Guard | Path Traversal |
| `930100` | Null Byte Injection in File Paths | Path Traversal |
| `932100` | Unix Command Injection Engine | RCE |
| `932110` | Windows Command Injection Engine | RCE |
| `932160` | Reverse Shell / Bind Shell Payload | RCE |
| `944100` | Java EL / OGNL Injection | Java Injection |
| `944110` | Log4Shell (CVE-2021-44228) | Java Injection |
| `944200` | Java Deserialization Attack | Java Injection |
| `933100` | PHP Code Injection | PHP Injection |
| `933110` | PHP Object Injection | PHP Injection |
| `933120` | PHP File Inclusion | PHP Injection |
| `950100` | Remote File Inclusion (RFI) | RFI |
| `950110` | RFI Evasion | RFI |
| `951100` | MongoDB / NoSQL Injection | NoSQL Injection |
| `951200` | Redis / CouchDB / Elasticsearch Injection | NoSQL Injection |
| `952100` | Server-Side Template Injection (SSTI) | SSTI |
| `953100` | XML External Entity (XXE) Injection | XXE |
| `934100` | Server-Side Request Forgery (SSRF) Guard | SSRF |

---

## ⚡ Quick Start

### Global Command (Any Terminal)
```bash
bastion
```

### Or from project directory
```bash
./start.sh
```

### URLs
| Service | URL | Description |
|---|---|---|
| 🏦 Protected Bank Portal | http://127.0.0.1:8080 | Via WAF proxy |
| 📊 Security Dashboard | http://127.0.0.1:8000 | Live telemetry & rule toggles |
| 🎯 Direct Target | http://127.0.0.1:5000 | Unprotected upstream |

---

## 🐳 Docker

```bash
# Start all services
docker-compose up --build

# Run in background
docker-compose up -d --build
```

---

## 🧪 Testing

```bash
venv/bin/pytest -v
```

---

## 📄 License

[MIT License](LICENSE) — Copyright (c) 2026 Abrham Addis
