"""Core HTTP security header, cookie, CORS, disclosure, and TLS audit checks."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from http.cookies import SimpleCookie
import re
import socket
import ssl
from typing import Any
import urllib.error
import urllib.parse
import urllib.request

SEVERITY_PENALTY: dict[str, int] = {
    "Critical": 25,
    "High": 15,
    "Medium": 8,
    "Low": 4,
    "Info": 0,
}

SENSITIVE_COOKIE_RE = re.compile(
    r"(sess|sid|auth|token|jwt|csrf|xsrf|id|account|user)", re.IGNORECASE
)
VERSION_IN_HEADER_RE = re.compile(r"\d+(?:\.\d+)+")


@dataclass
class Finding:
    """Single security control check outcome."""

    id: str
    title: str
    category: str
    severity: str
    status: str
    owasp_ref: str
    evidence: str
    remediation: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class AuditResult:
    """Aggregated security posture report for an audited URL."""

    target_url: str
    final_url: str
    status_code: int
    scanned_at: str
    score: int
    grade: str
    findings: list[Finding] = field(default_factory=list)
    headers: dict[str, str] = field(default_factory=dict)
    tls_info: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "target_url": self.target_url,
            "final_url": self.final_url,
            "status_code": self.status_code,
            "scanned_at": self.scanned_at,
            "score": self.score,
            "grade": self.grade,
            "findings": [f.to_dict() for f in self.findings],
            "headers": dict(self.headers),
            "tls_info": dict(self.tls_info),
        }


def _normalize_headers(headers: dict[str, str]) -> dict[str, str]:
    return {k.lower(): v for k, v in headers.items()}


def _parse_csp_directives(csp_value: str) -> dict[str, list[str]]:
    directives: dict[str, list[str]] = {}
    for raw_part in csp_value.split(";"):
        part = raw_part.strip()
        if not part:
            continue
        tokens = part.split()
        name = tokens[0].lower()
        directives[name] = [t.lower() for t in tokens[1:]]
    return directives


def audit_headers(headers: dict[str, str], is_https: bool) -> list[Finding]:
    """Audit OWASP-recommended HTTP security response headers."""
    h = _normalize_headers(headers)
    findings: list[Finding] = []

    # 1. Content-Security-Policy
    csp = h.get("content-security-policy", "").strip()
    csp_directives = _parse_csp_directives(csp) if csp else {}
    if not csp:
        findings.append(
            Finding(
                id="HDR-CSP",
                title="Content-Security-Policy (CSP)",
                category="Security Headers",
                severity="High",
                status="FAIL",
                owasp_ref="OWASP A05:2021 - Security Misconfiguration",
                evidence="Content-Security-Policy header is missing.",
                remediation=(
                    "Set a restrictive CSP such as: "
                    "Content-Security-Policy: default-src 'self'; script-src 'self'; "
                    "object-src 'none'; frame-ancestors 'none'; base-uri 'self'"
                ),
            )
        )
    else:
        weak_tokens: list[str] = []
        for directive in ("default-src", "script-src"):
            values = csp_directives.get(directive, [])
            if "'unsafe-inline'" in values:
                weak_tokens.append(f"{directive} allows 'unsafe-inline'")
            if "'unsafe-eval'" in values:
                weak_tokens.append(f"{directive} allows 'unsafe-eval'")
            if "*" in values:
                weak_tokens.append(f"{directive} allows wildcard '*'")
        if weak_tokens:
            findings.append(
                Finding(
                    id="HDR-CSP",
                    title="Content-Security-Policy (CSP)",
                    category="Security Headers",
                    severity="Medium",
                    status="WARN",
                    owasp_ref="OWASP A03:2021 - Injection / XSS Defense",
                    evidence=f"CSP present but weakened ({'; '.join(weak_tokens)}): {csp}",
                    remediation=(
                        "Remove 'unsafe-inline', 'unsafe-eval', and '*' from "
                        "default-src and script-src; use nonces or hashes instead."
                    ),
                )
            )
        else:
            findings.append(
                Finding(
                    id="HDR-CSP",
                    title="Content-Security-Policy (CSP)",
                    category="Security Headers",
                    severity="Info",
                    status="PASS",
                    owasp_ref="OWASP A05:2021 - Security Misconfiguration",
                    evidence=f"Strict CSP configured: {csp}",
                    remediation="Maintain least-privilege CSP directives.",
                )
            )

    # 2. Strict-Transport-Security
    hsts = h.get("strict-transport-security", "").strip()
    if not is_https:
        findings.append(
            Finding(
                id="HDR-HSTS",
                title="Strict-Transport-Security (HSTS)",
                category="Transport Security",
                severity="Low",
                status="WARN",
                owasp_ref="OWASP A02:2021 - Cryptographic Failures",
                evidence="Target responded over HTTP; HSTS is only honored over HTTPS.",
                remediation=(
                    "Serve production traffic exclusively over HTTPS and set: "
                    "Strict-Transport-Security: max-age=31536000; includeSubDomains"
                ),
            )
        )
    elif not hsts:
        findings.append(
            Finding(
                id="HDR-HSTS",
                title="Strict-Transport-Security (HSTS)",
                category="Transport Security",
                severity="High",
                status="FAIL",
                owasp_ref="OWASP A02:2021 - Cryptographic Failures",
                evidence="Strict-Transport-Security header is missing on HTTPS response.",
                remediation=(
                    "Enable HSTS with at least 1 year duration: "
                    "Strict-Transport-Security: max-age=31536000; includeSubDomains"
                ),
            )
        )
    else:
        max_age_match = re.search(r"max-age\s*=\s*(\d+)", hsts, re.IGNORECASE)
        max_age = int(max_age_match.group(1)) if max_age_match else 0
        has_subdomains = "includesubdomains" in hsts.lower()
        if max_age < 31536000 or not has_subdomains:
            findings.append(
                Finding(
                    id="HDR-HSTS",
                    title="Strict-Transport-Security (HSTS)",
                    category="Transport Security",
                    severity="Medium",
                    status="WARN",
                    owasp_ref="OWASP A02:2021 - Cryptographic Failures",
                    evidence=(
                        f"HSTS policy could be stronger (max-age={max_age}, "
                        f"includeSubDomains={has_subdomains}): {hsts}"
                    ),
                    remediation="Set max-age>=31536000 and add includeSubDomains.",
                )
            )
        else:
            findings.append(
                Finding(
                    id="HDR-HSTS",
                    title="Strict-Transport-Security (HSTS)",
                    category="Transport Security",
                    severity="Info",
                    status="PASS",
                    owasp_ref="OWASP A02:2021 - Cryptographic Failures",
                    evidence=f"HSTS properly enforced: {hsts}",
                    remediation="Keep HSTS enabled across all subdomains.",
                )
            )

    # 3. X-Content-Type-Options
    xcto = h.get("x-content-type-options", "").strip()
    if xcto.lower() != "nosniff":
        findings.append(
            Finding(
                id="HDR-XCTO",
                title="X-Content-Type-Options",
                category="Security Headers",
                severity="Medium",
                status="FAIL",
                owasp_ref="OWASP A05:2021 - Security Misconfiguration",
                evidence=(
                    f"Expected 'nosniff', got: {xcto!r}"
                    if xcto
                    else "X-Content-Type-Options header is missing."
                ),
                remediation="Add header: X-Content-Type-Options: nosniff",
            )
        )
    else:
        findings.append(
            Finding(
                id="HDR-XCTO",
                title="X-Content-Type-Options",
                category="Security Headers",
                severity="Info",
                status="PASS",
                owasp_ref="OWASP A05:2021 - Security Misconfiguration",
                evidence="X-Content-Type-Options: nosniff is set.",
                remediation="No action required.",
            )
        )

    # 4. X-Frame-Options / CSP frame-ancestors
    xfo = h.get("x-frame-options", "").strip()
    frame_ancestors = csp_directives.get("frame-ancestors", [])
    xfo_valid = xfo.upper() in ("DENY", "SAMEORIGIN")
    fa_valid = any(v in ("'none'", "'self'") for v in frame_ancestors)
    if xfo_valid or fa_valid:
        evidence_parts = []
        if xfo:
            evidence_parts.append(f"X-Frame-Options={xfo}")
        if frame_ancestors:
            evidence_parts.append(f"CSP frame-ancestors={' '.join(frame_ancestors)}")
        findings.append(
            Finding(
                id="HDR-XFO",
                title="Clickjacking Protection (X-Frame-Options / frame-ancestors)",
                category="Security Headers",
                severity="Info",
                status="PASS",
                owasp_ref="OWASP A05:2021 - Clickjacking Defense",
                evidence="; ".join(evidence_parts),
                remediation="No action required.",
            )
        )
    else:
        findings.append(
            Finding(
                id="HDR-XFO",
                title="Clickjacking Protection (X-Frame-Options / frame-ancestors)",
                category="Security Headers",
                severity="Medium",
                status="FAIL",
                owasp_ref="OWASP A05:2021 - Clickjacking Defense",
                evidence=(
                    f"Weak or missing clickjacking protection (X-Frame-Options={xfo!r})."
                ),
                remediation=(
                    "Set X-Frame-Options: DENY (or SAMEORIGIN) and CSP "
                    "frame-ancestors 'none'."
                ),
            )
        )

    # 5. Referrer-Policy
    ref_policy = h.get("referrer-policy", "").strip().lower()
    safe_referrers = {
        "no-referrer",
        "same-origin",
        "strict-origin",
        "strict-origin-when-cross-origin",
        "no-referrer-when-downgrade",
    }
    if ref_policy in safe_referrers:
        findings.append(
            Finding(
                id="HDR-REFERRER",
                title="Referrer-Policy",
                category="Privacy & Headers",
                severity="Info",
                status="PASS",
                owasp_ref="OWASP A05:2021 - Information Exposure",
                evidence=f"Referrer-Policy set to {ref_policy}.",
                remediation="No action required.",
            )
        )
    else:
        findings.append(
            Finding(
                id="HDR-REFERRER",
                title="Referrer-Policy",
                category="Privacy & Headers",
                severity="Low",
                status="FAIL",
                owasp_ref="OWASP A05:2021 - Information Exposure",
                evidence=(
                    f"Unsafe Referrer-Policy: {ref_policy!r}"
                    if ref_policy
                    else "Referrer-Policy header is missing."
                ),
                remediation="Set Referrer-Policy: strict-origin-when-cross-origin",
            )
        )

    # 6. Permissions-Policy
    perm_policy = h.get("permissions-policy", "").strip()
    if perm_policy:
        findings.append(
            Finding(
                id="HDR-PERMISSIONS",
                title="Permissions-Policy",
                category="Security Headers",
                severity="Info",
                status="PASS",
                owasp_ref="OWASP A05:2021 - Browser Feature Hardening",
                evidence=f"Permissions-Policy configured: {perm_policy}",
                remediation="No action required.",
            )
        )
    else:
        findings.append(
            Finding(
                id="HDR-PERMISSIONS",
                title="Permissions-Policy",
                category="Security Headers",
                severity="Low",
                status="FAIL",
                owasp_ref="OWASP A05:2021 - Browser Feature Hardening",
                evidence="Permissions-Policy header is missing.",
                remediation=(
                    "Disable unused browser APIs: "
                    "Permissions-Policy: geolocation=(), microphone=(), camera=()"
                ),
            )
        )

    # 7. Cross-Origin Isolation (COOP / CORP)
    coop = h.get("cross-origin-opener-policy", "").strip()
    corp = h.get("cross-origin-resource-policy", "").strip()
    if coop or corp:
        evidence_list = []
        if coop:
            evidence_list.append(f"COOP={coop}")
        if corp:
            evidence_list.append(f"CORP={corp}")
        findings.append(
            Finding(
                id="HDR-COOP-CORP",
                title="Cross-Origin Isolation (COOP / CORP)",
                category="Security Headers",
                severity="Info",
                status="PASS",
                owasp_ref="OWASP A05:2021 - Cross-Origin Isolation",
                evidence=", ".join(evidence_list),
                remediation="No action required.",
            )
        )
    else:
        findings.append(
            Finding(
                id="HDR-COOP-CORP",
                title="Cross-Origin Isolation (COOP / CORP)",
                category="Security Headers",
                severity="Low",
                status="WARN",
                owasp_ref="OWASP A05:2021 - Cross-Origin Isolation",
                evidence="Neither Cross-Origin-Opener-Policy nor Cross-Origin-Resource-Policy is set.",
                remediation=(
                    "Add Cross-Origin-Opener-Policy: same-origin and "
                    "Cross-Origin-Resource-Policy: same-origin."
                ),
            )
        )

    return findings


def _parse_cookie_flags(raw_cookie: str) -> tuple[str, dict[str, str | bool]]:
    parts = [p.strip() for p in raw_cookie.split(";") if p.strip()]
    name = "unknown"
    if parts and "=" in parts[0]:
        name = parts[0].split("=", 1)[0].strip()
    else:
        sc = SimpleCookie()
        try:
            sc.load(raw_cookie)
            if sc:
                name = next(iter(sc.keys()))
        except Exception:
            pass

    attrs: dict[str, str | bool] = {
        "httponly": False,
        "secure": False,
        "samesite": "",
    }
    for attr in parts[1:]:
        low = attr.lower()
        if low == "httponly":
            attrs["httponly"] = True
        elif low == "secure":
            attrs["secure"] = True
        elif low.startswith("samesite="):
            attrs["samesite"] = attr.split("=", 1)[1].strip().lower()
    return name, attrs


def audit_cookies(set_cookie_headers: list[str], is_https: bool) -> list[Finding]:
    """Audit Set-Cookie headers for HttpOnly, Secure, and SameSite flags."""
    if not set_cookie_headers:
        return [
            Finding(
                id="COOKIE-NONE",
                title="Session Cookie Security",
                category="Session Management",
                severity="Info",
                status="PASS",
                owasp_ref="OWASP A07:2021 - Identification & Authentication",
                evidence="No Set-Cookie headers issued in response.",
                remediation="Verify authenticated endpoints also enforce HttpOnly, Secure, and SameSite.",
            )
        ]

    findings: list[Finding] = []
    for idx, raw_cookie in enumerate(set_cookie_headers, start=1):
        name, flags = _parse_cookie_flags(raw_cookie)
        is_sensitive = bool(SENSITIVE_COOKIE_RE.search(name))

        # HttpOnly
        if not flags["httponly"]:
            findings.append(
                Finding(
                    id=f"COOKIE-{idx}-HTTPONLY",
                    title=f"Cookie '{name}' HttpOnly Flag",
                    category="Session Management",
                    severity="High" if is_sensitive else "Medium",
                    status="FAIL",
                    owasp_ref="OWASP A07:2021 - Session Hijacking Protection",
                    evidence=f"Cookie '{name}' is missing the HttpOnly attribute.",
                    remediation=f"Add 'HttpOnly' to Set-Cookie for '{name}' to block JavaScript access.",
                )
            )
        else:
            findings.append(
                Finding(
                    id=f"COOKIE-{idx}-HTTPONLY",
                    title=f"Cookie '{name}' HttpOnly Flag",
                    category="Session Management",
                    severity="Info",
                    status="PASS",
                    owasp_ref="OWASP A07:2021 - Session Hijacking Protection",
                    evidence=f"Cookie '{name}' sets HttpOnly.",
                    remediation="No action required.",
                )
            )

        # Secure
        if not flags["secure"]:
            if is_https or is_sensitive:
                findings.append(
                    Finding(
                        id=f"COOKIE-{idx}-SECURE",
                        title=f"Cookie '{name}' Secure Flag",
                        category="Session Management",
                        severity="High",
                        status="FAIL",
                        owasp_ref="OWASP A02:2021 - Cleartext Transmission of Sensitive Data",
                        evidence=f"Cookie '{name}' is missing the Secure attribute.",
                        remediation=f"Add 'Secure' to Set-Cookie for '{name}' and enforce HTTPS.",
                    )
                )
            else:
                findings.append(
                    Finding(
                        id=f"COOKIE-{idx}-SECURE",
                        title=f"Cookie '{name}' Secure Flag",
                        category="Session Management",
                        severity="Low",
                        status="WARN",
                        owasp_ref="OWASP A02:2021 - Cleartext Transmission of Sensitive Data",
                        evidence=f"Cookie '{name}' lacks the Secure attribute on HTTP.",
                        remediation=f"Serve over HTTPS and add 'Secure' to '{name}'.",
                    )
                )
        else:
            findings.append(
                Finding(
                    id=f"COOKIE-{idx}-SECURE",
                    title=f"Cookie '{name}' Secure Flag",
                    category="Session Management",
                    severity="Info",
                    status="PASS",
                    owasp_ref="OWASP A02:2021 - Cleartext Transmission of Sensitive Data",
                    evidence=f"Cookie '{name}' sets Secure.",
                    remediation="No action required.",
                )
            )

        # SameSite
        samesite = str(flags["samesite"])
        if samesite in ("lax", "strict"):
            findings.append(
                Finding(
                    id=f"COOKIE-{idx}-SAMESITE",
                    title=f"Cookie '{name}' SameSite Attribute",
                    category="Session Management",
                    severity="Info",
                    status="PASS",
                    owasp_ref="OWASP A01:2021 - CSRF Defense",
                    evidence=f"Cookie '{name}' sets SameSite={samesite.capitalize()}.",
                    remediation="No action required.",
                )
            )
        elif samesite == "none" and not flags["secure"]:
            findings.append(
                Finding(
                    id=f"COOKIE-{idx}-SAMESITE",
                    title=f"Cookie '{name}' SameSite Attribute",
                    category="Session Management",
                    severity="High",
                    status="FAIL",
                    owasp_ref="OWASP A01:2021 - CSRF Defense",
                    evidence=f"Cookie '{name}' sets SameSite=None without Secure.",
                    remediation="Use SameSite=Lax or SameSite=Strict (or pair SameSite=None with Secure).",
                )
            )
        else:
            findings.append(
                Finding(
                    id=f"COOKIE-{idx}-SAMESITE",
                    title=f"Cookie '{name}' SameSite Attribute",
                    category="Session Management",
                    severity="Medium",
                    status="FAIL",
                    owasp_ref="OWASP A01:2021 - CSRF Defense",
                    evidence=(
                        f"Cookie '{name}' sets weak SameSite={samesite!r}."
                        if samesite
                        else f"Cookie '{name}' is missing the SameSite attribute."
                    ),
                    remediation=f"Set SameSite=Strict or SameSite=Lax on cookie '{name}'.",
                )
            )

    return findings


def audit_server_disclosure(headers: dict[str, str]) -> list[Finding]:
    """Detect server/framework version disclosure headers."""
    h = _normalize_headers(headers)
    findings: list[Finding] = []
    leaks: list[str] = []

    server_val = h.get("server", "").strip()
    if server_val and VERSION_IN_HEADER_RE.search(server_val):
        leaks.append(f"Server: {server_val}")

    for hdr in ("x-powered-by", "x-aspnet-version", "x-aspnetmvc-version"):
        val = h.get(hdr, "").strip()
        if val:
            leaks.append(f"{hdr}: {val}")

    if leaks:
        findings.append(
            Finding(
                id="INFO-DISCLOSURE",
                title="Server & Technology Version Disclosure",
                category="Information Disclosure",
                severity="Low",
                status="WARN",
                owasp_ref="OWASP A05:2021 - Fingerprinting Exposure",
                evidence=f"Response headers expose technology details: {', '.join(leaks)}",
                remediation=(
                    "Strip X-Powered-By / X-AspNet-Version headers and minimize Server banner version tokens."
                ),
            )
        )
    else:
        findings.append(
            Finding(
                id="INFO-DISCLOSURE",
                title="Server & Technology Version Disclosure",
                category="Information Disclosure",
                severity="Info",
                status="PASS",
                owasp_ref="OWASP A05:2021 - Fingerprinting Exposure",
                evidence="No explicit server or framework version banners detected.",
                remediation="Continue suppressing version banners.",
            )
        )

    return findings


def audit_cors(cors_headers: dict[str, str], test_origin: str) -> list[Finding]:
    """Evaluate CORS policy against an untrusted Origin probe."""
    h = _normalize_headers(cors_headers)
    acao = h.get("access-control-allow-origin", "").strip()
    acac = h.get("access-control-allow-credentials", "").strip().lower()

    if not acao:
        return [
            Finding(
                id="CORS-POLICY",
                title="Cross-Origin Resource Sharing (CORS)",
                category="Access Control",
                severity="Info",
                status="PASS",
                owasp_ref="OWASP A01:2021 - Broken Access Control",
                evidence=f"No permissive Access-Control-Allow-Origin returned for Origin {test_origin}.",
                remediation="Maintain explicit origin allowlisting if CORS is later needed.",
            )
        ]

    if acao == test_origin and acac == "true":
        return [
            Finding(
                id="CORS-POLICY",
                title="Cross-Origin Resource Sharing (CORS)",
                category="Access Control",
                severity="Critical",
                status="FAIL",
                owasp_ref="OWASP A01:2021 - Broken Access Control",
                evidence=(
                    f"Arbitrary Origin '{test_origin}' is reflected in Access-Control-Allow-Origin "
                    "with Access-Control-Allow-Credentials: true."
                ),
                remediation=(
                    "Validate Origin against a strict static allowlist and never combine "
                    "untrusted reflection with Access-Control-Allow-Credentials: true."
                ),
            )
        ]

    if acao == "*" and acac == "true":
        return [
            Finding(
                id="CORS-POLICY",
                title="Cross-Origin Resource Sharing (CORS)",
                category="Access Control",
                severity="High",
                status="FAIL",
                owasp_ref="OWASP A01:2021 - Broken Access Control",
                evidence="Wildcard Access-Control-Allow-Origin: * paired with Allow-Credentials: true.",
                remediation="Replace wildcard '*' with an explicit trusted origin allowlist.",
            )
        ]

    if acao == test_origin or acao == "*":
        return [
            Finding(
                id="CORS-POLICY",
                title="Cross-Origin Resource Sharing (CORS)",
                category="Access Control",
                severity="Medium",
                status="WARN",
                owasp_ref="OWASP A01:2021 - Broken Access Control",
                evidence=f"Permissive Access-Control-Allow-Origin: {acao} returned for probe Origin.",
                remediation="Restrict Access-Control-Allow-Origin to explicit trusted domains.",
            )
        ]

    return [
        Finding(
            id="CORS-POLICY",
            title="Cross-Origin Resource Sharing (CORS)",
            category="Access Control",
            severity="Info",
            status="PASS",
            owasp_ref="OWASP A01:2021 - Broken Access Control",
            evidence=f"Access-Control-Allow-Origin restricted to {acao}.",
            remediation="No action required.",
        )
    ]


def audit_tls(
    hostname: str, port: int = 443, timeout: float = 5.0
) -> tuple[dict[str, Any], list[Finding]]:
    """Inspect TLS protocol version, cipher suite, and X.509 certificate validity."""
    tls_info: dict[str, Any] = {"hostname": hostname, "port": port}
    findings: list[Finding] = []
    ctx = ssl.create_default_context()

    try:
        with socket.create_connection((hostname, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                proto = ssock.version() or "Unknown"
                cipher = ssock.cipher()
                cert = ssock.getpeercert() or {}

                tls_info["protocol"] = proto
                tls_info["cipher"] = cipher[0] if cipher else "Unknown"
                tls_info["subject"] = _flatten_cert_name(cert.get("subject", ()))
                tls_info["issuer"] = _flatten_cert_name(cert.get("issuer", ()))
                not_after = cert.get("notAfter", "")
                tls_info["not_after"] = not_after

                if proto in ("SSLv2", "SSLv3", "TLSv1", "TLSv1.1"):
                    findings.append(
                        Finding(
                            id="TLS-PROTO",
                            title="TLS Protocol Version",
                            category="Transport Security",
                            severity="High",
                            status="FAIL",
                            owasp_ref="OWASP A02:2021 - Cryptographic Failures",
                            evidence=f"Deprecated protocol negotiated: {proto}.",
                            remediation="Disable TLS 1.0/1.1 and enforce TLS 1.2 or TLS 1.3.",
                        )
                    )
                else:
                    findings.append(
                        Finding(
                            id="TLS-PROTO",
                            title="TLS Protocol Version",
                            category="Transport Security",
                            severity="Info",
                            status="PASS",
                            owasp_ref="OWASP A02:2021 - Cryptographic Failures",
                            evidence=f"Strong protocol negotiated: {proto} ({tls_info['cipher']}).",
                            remediation="Maintain TLS 1.2+ configuration.",
                        )
                    )

                if not_after:
                    exp_dt = datetime.strptime(
                        not_after, "%b %d %H:%M:%S %Y %Z"
                    ).replace(tzinfo=timezone.utc)
                    days_left = (exp_dt - datetime.now(timezone.utc)).days
                    tls_info["days_until_expiry"] = days_left
                    if days_left < 0:
                        findings.append(
                            Finding(
                                id="TLS-CERT",
                                title="TLS Certificate Validity",
                                category="Transport Security",
                                severity="Critical",
                                status="FAIL",
                                owasp_ref="OWASP A02:2021 - Cryptographic Failures",
                                evidence=f"Certificate expired {-days_left} days ago ({not_after}).",
                                remediation="Renew and deploy a valid X.509 certificate immediately.",
                            )
                        )
                    elif days_left < 30:
                        findings.append(
                            Finding(
                                id="TLS-CERT",
                                title="TLS Certificate Validity",
                                category="Transport Security",
                                severity="Medium",
                                status="WARN",
                                owasp_ref="OWASP A02:2021 - Cryptographic Failures",
                                evidence=f"Certificate expires soon: {days_left} days left ({not_after}).",
                                remediation="Schedule certificate renewal or enable ACME auto-renewal.",
                            )
                        )
                    else:
                        findings.append(
                            Finding(
                                id="TLS-CERT",
                                title="TLS Certificate Validity",
                                category="Transport Security",
                                severity="Info",
                                status="PASS",
                                owasp_ref="OWASP A02:2021 - Cryptographic Failures",
                                evidence=f"Certificate valid for {days_left} days (expires {not_after}).",
                                remediation="No action required.",
                            )
                        )
    except ssl.SSLCertVerificationError as exc:
        tls_info["error"] = str(exc)
        findings.append(
            Finding(
                id="TLS-VERIFY",
                title="TLS Certificate Verification",
                category="Transport Security",
                severity="High",
                status="FAIL",
                owasp_ref="OWASP A02:2021 - Cryptographic Failures",
                evidence=f"TLS certificate validation failed: {exc}",
                remediation="Install a valid certificate chain signed by a trusted CA.",
            )
        )
    except OSError as exc:
        tls_info["error"] = str(exc)
        findings.append(
            Finding(
                id="TLS-CONN",
                title="TLS Handshake Inspection",
                category="Transport Security",
                severity="Medium",
                status="WARN",
                owasp_ref="OWASP A02:2021 - Cryptographic Failures",
                evidence=f"Unable to complete TLS inspection: {exc}",
                remediation="Verify port 443 connectivity and certificate configuration.",
            )
        )

    return tls_info, findings


def _flatten_cert_name(rdns: tuple[Any, ...]) -> str:
    parts: list[str] = []
    for rdn in rdns:
        for key, val in rdn:
            parts.append(f"{key}={val}")
    return ", ".join(parts)


def calculate_score(findings: list[Finding]) -> tuple[int, str]:
    """Compute 0-100 posture score and letter grade from audit findings."""
    score = 100
    for f in findings:
        if f.status in ("FAIL", "WARN"):
            score -= SEVERITY_PENALTY.get(f.severity, 0)
    score = max(0, min(100, score))

    if score >= 95:
        grade = "A+"
    elif score >= 88:
        grade = "A"
    elif score >= 75:
        grade = "B"
    elif score >= 60:
        grade = "C"
    elif score >= 45:
        grade = "D"
    else:
        grade = "F"
    return score, grade


def _fetch_http(
    url: str,
    timeout: float,
    insecure: bool,
    extra_headers: dict[str, str] | None = None,
) -> tuple[str, int, dict[str, str], list[str]]:
    req_headers = {"User-Agent": "WebSecurityAuditor/1.0"}
    if extra_headers:
        req_headers.update(extra_headers)
    req = urllib.request.Request(url, headers=req_headers, method="GET")

    ssl_ctx: ssl.SSLContext | None = None
    if url.lower().startswith("https://") and insecure:
        ssl_ctx = ssl._create_unverified_context()

    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ssl_ctx) as resp:
            final_url = resp.geturl()
            status_code = resp.status
            headers_dict = dict(resp.headers.items())
            set_cookies = resp.headers.get_all("Set-Cookie", []) or []
            return final_url, status_code, headers_dict, set_cookies
    except urllib.error.HTTPError as err:
        final_url = err.geturl() or url
        status_code = err.code
        headers_dict = dict(err.headers.items()) if err.headers else {}
        set_cookies = (
            err.headers.get_all("Set-Cookie", []) if err.headers else []
        ) or []
        return final_url, status_code, headers_dict, set_cookies


def scan_url(url: str, timeout: float = 8.0, insecure: bool = False) -> AuditResult:
    """Scan a target HTTP/HTTPS URL and return an AuditResult."""
    normalized_url = url.strip()
    if not normalized_url.startswith(("http://", "https://")):
        normalized_url = f"https://{normalized_url}"

    final_url, status_code, headers, set_cookies = _fetch_http(
        normalized_url, timeout=timeout, insecure=insecure
    )
    parsed = urllib.parse.urlparse(final_url)
    is_https = parsed.scheme.lower() == "https"

    findings: list[Finding] = []
    findings.extend(audit_headers(headers, is_https=is_https))
    findings.extend(audit_cookies(set_cookies, is_https=is_https))
    findings.extend(audit_server_disclosure(headers))

    # CORS reflection check using a harmless synthetic external origin
    probe_origin = "https://auditor-cors-check.example"
    try:
        _, _, cors_headers, _ = _fetch_http(
            final_url,
            timeout=timeout,
            insecure=insecure,
            extra_headers={"Origin": probe_origin},
        )
    except urllib.error.URLError:
        cors_headers = headers
    findings.extend(audit_cors(cors_headers, test_origin=probe_origin))

    tls_info: dict[str, Any] = {}
    if is_https and parsed.hostname:
        port = parsed.port or 443
        tls_info, tls_findings = audit_tls(
            parsed.hostname, port=port, timeout=min(timeout, 5.0)
        )
        findings.extend(tls_findings)

    score, grade = calculate_score(findings)
    return AuditResult(
        target_url=normalized_url,
        final_url=final_url,
        status_code=status_code,
        scanned_at=datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
        score=score,
        grade=grade,
        findings=findings,
        headers=headers,
        tls_info=tls_info,
    )
