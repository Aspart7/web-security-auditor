"""Local demo web server exposing /vulnerable and /hardened routes for Burp Suite & auditor labs."""

from __future__ import annotations

import argparse
from http.server import BaseHTTPRequestHandler, HTTPServer


class DemoSecurityHandler(BaseHTTPRequestHandler):
    """Serves vulnerable vs. hardened HTTP responses for before-and-after testing."""

    default_mode = "mixed"

    def do_GET(self) -> None:
        path = self.path.split("?", 1)[0]
        if path == "/hardened" or (path == "/" and self.default_mode == "hardened"):
            self._serve_hardened()
        else:
            self._serve_vulnerable()

    def _serve_vulnerable(self) -> None:
        self.send_response_only(200, "OK")
        self.send_header("Date", self.date_time_string())
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Server", "Apache/2.4.49 (Demo)")
        self.send_header("X-Powered-By", "PHP/7.4.3")
        self.send_header("Set-Cookie", "sessionid=demo123; Path=/")

        origin = self.headers.get("Origin")
        if origin:
            self.send_header("Access-Control-Allow-Origin", origin)
            self.send_header("Access-Control-Allow-Credentials", "true")

        self.end_headers()
        self.wfile.write(
            b"<html><body><h1>Vulnerable Demo Endpoint</h1>"
            b"<p>Missing OWASP security headers, insecure cookie, reflected CORS.</p>"
            b"<p>Compare with <a href='/hardened'>/hardened</a>.</p></body></html>"
        )

    def _serve_hardened(self) -> None:
        self.send_response_only(200, "OK")
        self.send_header("Date", self.date_time_string())
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header(
            "Content-Security-Policy",
            "default-src 'self'; script-src 'self'; object-src 'none'; frame-ancestors 'none'; base-uri 'self'",
        )
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "strict-origin-when-cross-origin")
        self.send_header("Permissions-Policy", "geolocation=(), microphone=(), camera=()")
        self.send_header("Cross-Origin-Opener-Policy", "same-origin")
        self.send_header("Cross-Origin-Resource-Policy", "same-origin")
        self.send_header(
            "Set-Cookie", "sessionid=demo123; HttpOnly; Secure; SameSite=Strict; Path=/"
        )
        self.end_headers()
        self.wfile.write(
            b"<html><body><h1>Hardened Demo Endpoint</h1>"
            b"<p>OWASP security headers, strict cookie attributes, no CORS reflection.</p>"
            b"<p>Compare with <a href='/vulnerable'>/vulnerable</a>.</p></body></html>"
        )

    def log_message(self, format: str, *args: object) -> None:
        pass


def make_handler(default_mode: str) -> type[DemoSecurityHandler]:
    class BoundHandler(DemoSecurityHandler):
        pass

    BoundHandler.default_mode = default_mode
    return BoundHandler


def main() -> None:
    parser = argparse.ArgumentParser(description="Run local vulnerable/hardened demo web server.")
    parser.add_argument("--host", default="127.0.0.1", help="Bind address (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=8080, help="Port to listen on (default: 8080)")
    parser.add_argument(
        "--mode",
        choices=["mixed", "vulnerable", "hardened"],
        default="mixed",
        help="Behavior for '/' route; '/vulnerable' and '/hardened' are always available",
    )
    args = parser.parse_args()

    server = HTTPServer((args.host, args.port), make_handler(args.mode))
    print(f"Demo server listening on http://{args.host}:{args.port} (mode={args.mode})")
    print(f"  Vulnerable route: http://{args.host}:{args.port}/vulnerable")
    print(f"  Hardened route  : http://{args.host}:{args.port}/hardened")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down demo server.")
        server.server_close()


if __name__ == "__main__":
    main()
