"""CLI, JSON, and self-contained HTML report generators."""

from __future__ import annotations

from collections import Counter
import html
import json

from auditor.checks import AuditResult


def format_cli_summary(result: AuditResult) -> str:
    """Format an AuditResult as a readable terminal summary table."""
    sev_counts = Counter(
        f.severity for f in result.findings if f.status in ("FAIL", "WARN")
    )
    pass_count = sum(1 for f in result.findings if f.status == "PASS")

    lines = [
        "=" * 78,
        "Web Security & OWASP Headers Auditor Report",
        "=" * 78,
        f"Target URL : {result.final_url}",
        f"HTTP Status: {result.status_code}",
        f"Scanned At : {result.scanned_at}",
        f"Score/Grade: {result.score}/100 (Grade {result.grade})",
        (
            f"Summary    : {pass_count} PASS | "
            f"Critical={sev_counts['Critical']} High={sev_counts['High']} "
            f"Medium={sev_counts['Medium']} Low={sev_counts['Low']}"
        ),
        "-" * 78,
        f"{'STATUS':<7} {'SEVERITY':<9} {'ID':<18} {'CONTROL'}",
        "-" * 78,
    ]

    for f in result.findings:
        lines.append(f"{f.status:<7} {f.severity:<9} {f.id:<18} {f.title}")
        if f.status != "PASS":
            lines.append(f"        Evidence   : {f.evidence}")
            lines.append(f"        Remediation: {f.remediation}")

    lines.append("=" * 78)
    return "\n".join(lines)


def to_json(result: AuditResult) -> str:
    """Serialize an AuditResult to pretty-printed JSON."""
    return json.dumps(result.to_dict(), indent=2, ensure_ascii=False)


def _badge_color(grade: str) -> str:
    if grade in ("A+", "A"):
        return "#16a34a"
    if grade == "B":
        return "#2563eb"
    if grade == "C":
        return "#d97706"
    return "#dc2626"


def _status_pill(status: str) -> str:
    colors = {
        "PASS": ("#dcfce7", "#166534"),
        "WARN": ("#fef3c7", "#92400e"),
        "FAIL": ("#fee2e2", "#991b1b"),
    }
    bg, fg = colors.get(status, ("#e5e7eb", "#374151"))
    safe = html.escape(status)
    return (
        f'<span class="pill" style="background:{bg};color:{fg};">{safe}</span>'
    )


def _severity_pill(severity: str) -> str:
    colors = {
        "Critical": ("#7f1d1d", "#ffffff"),
        "High": ("#dc2626", "#ffffff"),
        "Medium": ("#f59e0b", "#111827"),
        "Low": ("#0ea5e9", "#ffffff"),
        "Info": ("#e2e8f0", "#334155"),
    }
    bg, fg = colors.get(severity, ("#e2e8f0", "#334155"))
    safe = html.escape(severity)
    return (
        f'<span class="pill" style="background:{bg};color:{fg};">{safe}</span>'
    )


def to_html(result: AuditResult) -> str:
    """Render a self-contained executive HTML security report."""
    sev_counts = Counter(
        f.severity for f in result.findings if f.status in ("FAIL", "WARN")
    )
    pass_count = sum(1 for f in result.findings if f.status == "PASS")
    grade_color = _badge_color(result.grade)

    rows_html = []
    for f in result.findings:
        rows_html.append(
            "<tr>"
            f"<td>{_status_pill(f.status)}</td>"
            f"<td>{_severity_pill(f.severity)}</td>"
            f"<td><strong>{html.escape(f.title)}</strong>"
            f"<div class=\"meta\">{html.escape(f.id)} &middot; {html.escape(f.owasp_ref)}</div></td>"
            f"<td><code>{html.escape(f.evidence)}</code></td>"
            f"<td>{html.escape(f.remediation)}</td>"
            "</tr>"
        )

    headers_rows = "\n".join(
        f"<tr><td class=\"hdr-key\">{html.escape(k)}</td><td><code>{html.escape(v)}</code></td></tr>"
        for k, v in sorted(result.headers.items(), key=lambda item: item[0].lower())
    )

    tls_block = ""
    if result.tls_info:
        tls_items = "".join(
            f"<li><strong>{html.escape(str(k))}:</strong> <code>{html.escape(str(v))}</code></li>"
            for k, v in result.tls_info.items()
        )
        tls_block = f"""
        <section class="card">
            <h2>TLS / Certificate Posture</h2>
            <ul class="tls-list">{tls_items}</ul>
        </section>
        """

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Security Audit Report - {html.escape(result.final_url)}</title>
<style>
  :root {{
    --bg: #f8fafc;
    --card: #ffffff;
    --text: #0f172a;
    --muted: #475569;
    --border: #e2e8f0;
  }}
  * {{ box-sizing: border-box; }}
  body {{
    margin: 0;
    padding: 32px 20px;
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
    background: var(--bg);
    color: var(--text);
    line-height: 1.5;
  }}
  .container {{ max-width: 1120px; margin: 0 auto; }}
  .header-card {{
    background: #0f172a;
    color: #f8fafc;
    border-radius: 12px;
    padding: 24px 28px;
    display: flex;
    justify-content: space-between;
    align-items: center;
    gap: 20px;
    margin-bottom: 20px;
  }}
  .header-card h1 {{ margin: 0 0 6px 0; font-size: 22px; }}
  .header-meta {{ font-size: 13px; color: #cbd5e1; }}
  .score-box {{
    text-align: center;
    min-width: 130px;
    background: rgba(255,255,255,0.08);
    border: 2px solid {grade_color};
    border-radius: 12px;
    padding: 12px 18px;
  }}
  .grade {{ font-size: 32px; font-weight: 800; color: {grade_color}; line-height: 1.1; }}
  .score-num {{ font-size: 14px; color: #e2e8f0; margin-top: 4px; }}
  .stats-grid {{
    display: grid;
    grid-template-columns: repeat(5, 1fr);
    gap: 12px;
    margin-bottom: 20px;
  }}
  .stat {{
    background: var(--card);
    border: 1px solid var(--border);
    border-radius: 10px;
    padding: 14px;
    text-align: center;
  }}
  .stat .num {{ font-size: 24px; font-weight: 700; }}
  .stat .lbl {{ font-size: 12px; color: var(--muted); text-transform: uppercase; letter-spacing: .04em; }}
  .card {{
    background: var(--card);
    border: 1px solid var(--border);
    border-radius: 10px;
    padding: 20px;
    margin-bottom: 20px;
    overflow-x: auto;
  }}
  h2 {{ margin: 0 0 14px 0; font-size: 17px; }}
  table {{ width: 100%; border-collapse: collapse; font-size: 13px; }}
  th, td {{ text-align: left; padding: 10px 12px; border-bottom: 1px solid var(--border); vertical-align: top; }}
  th {{ background: #f1f5f9; font-weight: 600; color: #334155; }}
  .pill {{
    display: inline-block;
    padding: 2px 8px;
    border-radius: 999px;
    font-size: 11px;
    font-weight: 700;
  }}
  .meta {{ font-size: 11px; color: var(--muted); margin-top: 2px; }}
  code {{
    font-family: ui-monospace, SFMono-Regular, Consolas, monospace;
    font-size: 12px;
    background: #f1f5f9;
    padding: 1px 4px;
    border-radius: 4px;
    word-break: break-word;
  }}
  .hdr-key {{ font-weight: 600; width: 240px; }}
  .tls-list {{ margin: 0; padding-left: 18px; font-size: 13px; }}
  footer {{ text-align: center; font-size: 12px; color: var(--muted); margin-top: 12px; }}
</style>
</head>
<body>
<div class="container">
  <div class="header-card">
    <div>
      <h1>Web Security &amp; OWASP Headers Audit</h1>
      <div class="header-meta">
        Target: <strong>{html.escape(result.final_url)}</strong> &middot;
        HTTP {result.status_code} &middot;
        Scanned {html.escape(result.scanned_at)}
      </div>
    </div>
    <div class="score-box">
      <div class="grade">{html.escape(result.grade)}</div>
      <div class="score-num">{result.score} / 100</div>
    </div>
  </div>

  <div class="stats-grid">
    <div class="stat"><div class="num" style="color:#7f1d1d">{sev_counts['Critical']}</div><div class="lbl">Critical</div></div>
    <div class="stat"><div class="num" style="color:#dc2626">{sev_counts['High']}</div><div class="lbl">High</div></div>
    <div class="stat"><div class="num" style="color:#d97706">{sev_counts['Medium']}</div><div class="lbl">Medium</div></div>
    <div class="stat"><div class="num" style="color:#0284c7">{sev_counts['Low']}</div><div class="lbl">Low</div></div>
    <div class="stat"><div class="num" style="color:#16a34a">{pass_count}</div><div class="lbl">Passed</div></div>
  </div>

  <section class="card">
    <h2>Security Control Findings</h2>
    <table>
      <thead>
        <tr>
          <th style="width:76px;">Status</th>
          <th style="width:92px;">Severity</th>
          <th style="width:240px;">Control &amp; OWASP Ref</th>
          <th>Observed Evidence</th>
          <th>Remediation</th>
        </tr>
      </thead>
      <tbody>
        {''.join(rows_html)}
      </tbody>
    </table>
  </section>

  {tls_block}

  <section class="card">
    <h2>Raw HTTP Response Headers</h2>
    <table>
      <thead>
        <tr><th>Header</th><th>Value</th></tr>
      </thead>
      <tbody>
        {headers_rows}
      </tbody>
    </table>
  </section>

  <footer>Generated by Web Security &amp; OWASP Headers Auditor &middot; Authorized Testing Only</footer>
</div>
</body>
</html>
"""
