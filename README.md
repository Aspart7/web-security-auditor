# Web Security & OWASP Headers Auditor

Zero-dependency Python CLI security posture auditor for inspecting **OWASP HTTP Security Headers**, **Session Cookie Flags**, **CORS Misconfigurations**, **Server Version Disclosure**, and **TLS/X.509 Posture**.

Includes an interactive local demo web server (`/vulnerable` vs. `/hardened`) for side-by-side before/after verification and **Burp Suite Proxy / Repeater** analysis.

> **Ethical Use Disclaimer:** Run this tool only against systems you own, local test labs, or targets where you hold explicit written authorization.

---

## Features

- **Zero External Dependencies:** Built strictly on Python's standard library (`urllib`, `ssl`, `socket`, `http.cookies`, `json`, `html`, `argparse`).
- **OWASP Security Header Checks:**
  - `Content-Security-Policy` (presence + detection of `'unsafe-inline'`, `'unsafe-eval'`, wildcard `*`)
  - `Strict-Transport-Security` (HTTPS enforcement, `max-age >= 31536000`, `includeSubDomains`)
  - `X-Content-Type-Options` (`nosniff`)
  - `X-Frame-Options` / CSP `frame-ancestors` (clickjacking protection)
  - `Referrer-Policy`, `Permissions-Policy`, `Cross-Origin-Opener-Policy` & `Cross-Origin-Resource-Policy`
- **Cookie Security Audit:** Parses every `Set-Cookie` header for `HttpOnly`, `Secure`, and `SameSite` (`Strict` / `Lax`) attributes.
- **CORS Probe:** Sends a benign external `Origin` check to detect arbitrary origin reflection and unsafe `Access-Control-Allow-Credentials: true` combinations.
- **Fingerprinting / Disclosure:** Flags exposed version numbers in `Server`, `X-Powered-By`, and `X-AspNet-Version`.
- **TLS Posture (HTTPS targets):** Inspects negotiated protocol version (`TLSv1.2`/`TLSv1.3`), cipher suite, and certificate expiration window.
- **Automated Risk Scoring & Reporting:** Weighted `0–100` score (`A+` to `F`), terminal summary, machine-readable JSON, and self-contained executive HTML reports.

---

## Architecture

```text
web-security-auditor/
├── auditor/
│   ├── __init__.py       # Package metadata
│   ├── checks.py         # Header, cookie, CORS, disclosure, TLS & scoring engine
│   └── report.py         # CLI, JSON, and HTML report formatters
├── tests/
│   └── test_auditor.py   # Integration & unit tests on ephemeral local HTTPServer
├── examples/             # Real generated reports from /vulnerable & /hardened
├── demo_app.py           # Local lab server (/vulnerable and /hardened routes)
└── web_auditor.py        # CLI entry point
```

---

## Quick Start

### 1. Run the local lab server
```bash
python demo_app.py --port 8080
```

### 2. Audit both endpoints (Before vs. After Hardening)
```bash
python web_auditor.py http://127.0.0.1:8080/vulnerable --html examples/vulnerable_report.html --json examples/vulnerable_report.json
python web_auditor.py http://127.0.0.1:8080/hardened --html examples/hardened_report.html
```

### Before vs. After Comparison (Local Demo)

| Control | `/vulnerable` | `/hardened` |
|---|---|---|
| **Score / Grade** | `0 / 100` (**Grade F**) | `96 / 100` (**Grade A+**) |
| `Content-Security-Policy` | Missing (`FAIL`, High) | Restrictive `'self'` policy (`PASS`) |
| `X-Content-Type-Options` | Missing (`FAIL`, Medium) | `nosniff` (`PASS`) |
| `X-Frame-Options` | Missing (`FAIL`, Medium) | `DENY` (`PASS`) |
| `Set-Cookie` (`sessionid`) | Missing `HttpOnly`, `Secure`, `SameSite` (`FAIL`) | `HttpOnly; Secure; SameSite=Strict` (`PASS`) |
| `CORS` Reflection | Reflects arbitrary `Origin` + Credentials (`Critical`) | Not reflected (`PASS`) |
| Server Banner | Exposes `Apache/2.4.49` & `PHP/7.4.3` (`WARN`) | Suppressed (`PASS`) |

---

## Burp Suite Workflow Integration

1. Start `demo_app.py` locally (`http://127.0.0.1:8080`).
2. Route browser traffic through **Burp Suite Proxy** (`127.0.0.1:8081` or default `8080` if demo runs on `8085`).
3. Send requests for `/vulnerable` and `/hardened` to **Burp Repeater**, inject an untrusted `Origin: https://attacker.example` header, and compare server responses alongside the automated HTML report from `web_auditor.py`.

---

## Running Tests

```bash
python -m unittest discover -s tests -v
```
