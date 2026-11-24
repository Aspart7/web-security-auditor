"""Unit and integration tests for Web Security & OWASP Headers Auditor."""

from __future__ import annotations

from http.server import HTTPServer
import json
import threading
import unittest

from auditor.checks import (
    audit_cookies,
    audit_cors,
    audit_headers,
    scan_url,
)
from auditor.report import format_cli_summary, to_html, to_json
from demo_app import make_handler


class TestWebSecurityAuditor(unittest.TestCase):
    server: HTTPServer
    thread: threading.Thread
    base_url: str

    @classmethod
    def setUpClass(cls) -> None:
        cls.server = HTTPServer(("127.0.0.1", 0), make_handler("mixed"))
        port = cls.server.server_address[1]
        cls.base_url = f"http://127.0.0.1:{port}"
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls) -> None:
        cls.server.shutdown()
        cls.server.server_close()

    def test_vulnerable_endpoint_low_score_and_findings(self) -> None:
        result = scan_url(f"{self.base_url}/vulnerable")
        self.assertEqual(result.status_code, 200)
        self.assertLessEqual(result.score, 40)
        self.assertIn(result.grade, ("F", "D"))

        by_id = {f.id: f for f in result.findings}
        self.assertEqual(by_id["HDR-CSP"].status, "FAIL")
        self.assertEqual(by_id["HDR-XCTO"].status, "FAIL")
        self.assertEqual(by_id["HDR-XFO"].status, "FAIL")
        self.assertEqual(by_id["COOKIE-1-HTTPONLY"].status, "FAIL")
        self.assertEqual(by_id["COOKIE-1-SECURE"].status, "FAIL")
        self.assertEqual(by_id["COOKIE-1-SAMESITE"].status, "FAIL")
        self.assertEqual(by_id["INFO-DISCLOSURE"].status, "WARN")
        self.assertEqual(by_id["CORS-POLICY"].status, "FAIL")
        self.assertEqual(by_id["CORS-POLICY"].severity, "Critical")

    def test_hardened_endpoint_high_score_and_passes(self) -> None:
        result = scan_url(f"{self.base_url}/hardened")
        self.assertEqual(result.status_code, 200)
        self.assertGreaterEqual(result.score, 90)
        self.assertIn(result.grade, ("A+", "A"))

        by_id = {f.id: f for f in result.findings}
        self.assertEqual(by_id["HDR-CSP"].status, "PASS")
        self.assertEqual(by_id["HDR-XCTO"].status, "PASS")
        self.assertEqual(by_id["HDR-XFO"].status, "PASS")
        self.assertEqual(by_id["HDR-REFERRER"].status, "PASS")
        self.assertEqual(by_id["HDR-PERMISSIONS"].status, "PASS")
        self.assertEqual(by_id["HDR-COOP-CORP"].status, "PASS")
        self.assertEqual(by_id["COOKIE-1-HTTPONLY"].status, "PASS")
        self.assertEqual(by_id["COOKIE-1-SECURE"].status, "PASS")
        self.assertEqual(by_id["COOKIE-1-SAMESITE"].status, "PASS")
        self.assertEqual(by_id["INFO-DISCLOSURE"].status, "PASS")
        self.assertEqual(by_id["CORS-POLICY"].status, "PASS")

    def test_reports_json_html_and_escaping(self) -> None:
        result = scan_url(f"{self.base_url}/vulnerable")
        # Inject an XSS payload into synthetic headers to verify HTML escaping
        result.headers["X-Test-Header"] = "<script>alert(1)</script>"

        raw_json = to_json(result)
        parsed = json.loads(raw_json)
        self.assertEqual(parsed["score"], result.score)
        self.assertEqual(parsed["target_url"], f"{self.base_url}/vulnerable")
        self.assertTrue(len(parsed["findings"]) >= 10)

        rendered_html = to_html(result)
        self.assertIn("<!DOCTYPE html>", rendered_html)
        self.assertIn(f"{self.base_url}/vulnerable", rendered_html)
        self.assertIn(f"{result.score} / 100", rendered_html)
        self.assertNotIn("<script>alert(1)</script>", rendered_html)
        self.assertIn("&lt;script&gt;alert(1)&lt;/script&gt;", rendered_html)

        summary = format_cli_summary(result)
        self.assertIn("HDR-CSP", summary)
        self.assertIn(f"{result.score}/100", summary)

    def test_unit_edge_cases(self) -> None:
        # Weak CSP + missing HSTS on HTTPS
        hdr_findings = audit_headers(
            {"Content-Security-Policy": "default-src 'self' 'unsafe-inline'"},
            is_https=True,
        )
        by_id = {f.id: f for f in hdr_findings}
        self.assertEqual(by_id["HDR-CSP"].status, "WARN")
        self.assertEqual(by_id["HDR-HSTS"].status, "FAIL")

        # SameSite=None without Secure
        cookie_findings = audit_cookies(
            ["pref=dark; HttpOnly; SameSite=None; Path=/"], is_https=True
        )
        c_by_id = {f.id: f for f in cookie_findings}
        self.assertEqual(c_by_id["COOKIE-1-SAMESITE"].status, "FAIL")

        # Wildcard CORS with credentials
        cors_findings = audit_cors(
            {
                "Access-Control-Allow-Origin": "*",
                "Access-Control-Allow-Credentials": "true",
            },
            test_origin="https://auditor-cors-check.example",
        )
        self.assertEqual(cors_findings[0].status, "FAIL")
        self.assertEqual(cors_findings[0].severity, "High")


if __name__ == "__main__":
    unittest.main()
