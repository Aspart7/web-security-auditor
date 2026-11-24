"""CLI entry point for Web Security & OWASP Headers Auditor."""

from __future__ import annotations

import argparse
from pathlib import Path
import sys
import urllib.error

from auditor import __version__
from auditor.checks import scan_url
from auditor.report import format_cli_summary, to_html, to_json

ETHICAL_BANNER = (
    "[!] Authorized Security Assessment Only: Scan only targets you own or "
    "have explicit permission to test."
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="web_auditor.py",
        description="Audit HTTP security headers, cookies, CORS, server leaks, and TLS posture.",
    )
    parser.add_argument("url", help="Target HTTP or HTTPS URL (e.g., http://127.0.0.1:8080/vulnerable)")
    parser.add_argument("--json", dest="json_path", help="Write JSON audit report to file")
    parser.add_argument("--html", dest="html_path", help="Write self-contained HTML report to file")
    parser.add_argument("--timeout", type=float, default=8.0, help="HTTP/TLS timeout in seconds (default: 8)")
    parser.add_argument(
        "--insecure",
        action="store_true",
        help="Skip TLS certificate verification during HTTP fetch (for self-signed labs)",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    print(ETHICAL_BANNER, file=sys.stderr)
    try:
        result = scan_url(args.url, timeout=args.timeout, insecure=args.insecure)
    except urllib.error.URLError as exc:
        print(f"Error connecting to target {args.url}: {exc}", file=sys.stderr)
        return 2
    except Exception as exc:
        print(f"Unexpected error auditing {args.url}: {exc}", file=sys.stderr)
        return 1

    print(format_cli_summary(result))

    if args.json_path:
        out_json = Path(args.json_path)
        out_json.parent.mkdir(parents=True, exist_ok=True)
        out_json.write_text(to_json(result), encoding="utf-8")
        print(f"Saved JSON report: {out_json}")

    if args.html_path:
        out_html = Path(args.html_path)
        out_html.parent.mkdir(parents=True, exist_ok=True)
        out_html.write_text(to_html(result), encoding="utf-8")
        print(f"Saved HTML report: {out_html}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
