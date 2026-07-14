#!/usr/bin/env python3
"""Generate human-readable SonarQube reports from the issues JSON.

Reads ``sonar-issues.json`` (downloaded by the CI step that calls
``/api/issues/search``) and writes two artifacts next to it:

* ``sonar-report.md``  - deterministic Markdown consumed by the
                         auto-remediation agent.
* ``sonar-report.html`` - simple HTML view for humans browsing the
                          workflow run.

The script is intentionally self-contained: only the Python standard
library is used, and it is safe to run on any Python 3.8+ runner.

Exit code is always 0: this is a reporting step in an intentionally
vulnerable learning lab, so a malformed upstream payload must not
gate the pipeline.
"""

from __future__ import annotations

import html
import json
import sys
from collections import Counter
from pathlib import Path
from typing import Any, Iterable

# Severity order used throughout the Markdown report.  SonarQube's
# `severity` field uses these values verbatim.
SEVERITY_ORDER = ["BLOCKER", "CRITICAL", "MAJOR", "MINOR", "INFO"]


def load_issues(path: Path) -> list[dict[str, Any]]:
    """Return the list of issues from a SonarQube /api/issues/search payload.

    The API returns ``{"issues": [...], "paging": {...}}``; some older
    SonarQube versions return a bare list.  Both shapes are handled.
    A missing or unreadable file yields an empty list rather than an
    exception so the CI step never fails.
    """
    if not path.is_file():
        print(f"::warning::{path} not found; emitting an empty report.", file=sys.stderr)
        return []
    try:
        with path.open("r", encoding="utf-8") as fh:
            data = json.load(fh)
    except json.JSONDecodeError as exc:
        print(f"::warning::{path} is not valid JSON ({exc}); emitting an empty report.", file=sys.stderr)
        return []
    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        issues = data.get("issues", [])
        return issues if isinstance(issues, list) else []
    return []


def severity_counts(issues: Iterable[dict[str, Any]]) -> Counter:
    counts: Counter = Counter()
    for issue in issues:
        sev = str(issue.get("severity", "INFO")).upper()
        counts[sev] += 1
    return counts


def rule_counts(issues: Iterable[dict[str, Any]]) -> Counter:
    counts: Counter = Counter()
    for issue in issues:
        rule = str(issue.get("rule", "unknown"))
        counts[rule] += 1
    return counts


def file_counts(issues: Iterable[dict[str, Any]]) -> Counter:
    counts: Counter = Counter()
    for issue in issues:
        path = str(issue.get("component", "")).split(":")[-1] or "(unknown)"
        counts[path] += 1
    return counts


def type_counts(issues: Iterable[dict[str, Any]]) -> Counter:
    counts: Counter = Counter()
    for issue in issues:
        t = str(issue.get("type", "OTHER")).upper()
        counts[t] += 1
    return counts


def format_issue(issue: dict[str, Any]) -> str:
    """Render a single issue as a Markdown bullet list entry."""
    rule = issue.get("rule", "unknown")
    severity = str(issue.get("severity", "INFO")).upper()
    message = (issue.get("message") or "(no message)").strip().replace("\n", " ")
    component = str(issue.get("component", "")).split(":")[-1] or "(unknown)"
    line = issue.get("line", "")
    location = f"{component}:{line}" if line else component
    issue_type = str(issue.get("type", "")).upper()
    debt = issue.get("debt", "")
    effort = f" — effort: {debt}" if debt else ""
    type_tag = f" [{issue_type}]" if issue_type else ""
    return (
        f"- **{severity}**{type_tag} `{rule}` at `{location}` — {message}{effort}"
    )


def render_markdown(issues: list[dict[str, Any]]) -> str:
    """Build the deterministic Markdown report consumed by auto-remediate."""
    sev_counts = severity_counts(issues)
    type_counts_ = type_counts(issues)
    rule_top = rule_counts(issues).most_common(10)
    file_top = file_counts(issues).most_common(10)

    # Sort by severity (BLOCKER first) then by file then by line.
    sev_rank = {s: i for i, s in enumerate(SEVERITY_ORDER)}
    def sort_key(issue: dict[str, Any]) -> tuple[int, str, int]:
        sev = sev_rank.get(str(issue.get("severity", "INFO")).upper(), len(SEVERITY_ORDER))
        component = str(issue.get("component", ""))
        line = int(issue.get("line") or 0)
        return (sev, component, line)

    sorted_issues = sorted(issues, key=sort_key)

    lines: list[str] = []
    lines.append("# SonarQube Security Analysis Report")
    lines.append("")

    # --- Executive Summary --------------------------------------------------
    total = len(issues)
    lines.append("## Executive Summary")
    lines.append("")
    lines.append(f"- Total issues: **{total}**")
    if total:
        lines.append(f"- Highest severity: **{sorted_issues[0].get('severity', 'INFO')}**")
    else:
        lines.append("- Highest severity: _(none — no issues reported)_")
    lines.append("")

    # --- Dashboard Summary --------------------------------------------------
    lines.append("## Dashboard Summary")
    lines.append("")
    lines.append("| Metric | Value |")
    lines.append("| --- | --- |")
    lines.append(f"| Bugs | {type_counts_.get('BUG', 0)} |")
    lines.append(f"| Vulnerabilities | {type_counts_.get('VULNERABILITY', 0)} |")
    lines.append(f"| Code Smells | {type_counts_.get('CODE_SMELL', 0)} |")
    lines.append(f"| Security Hotspots | {type_counts_.get('SECURITY_HOTSPOT', 0)} |")
    lines.append("")

    # --- Severity Summary ---------------------------------------------------
    lines.append("## Severity Summary")
    lines.append("")
    lines.append("| Severity | Count |")
    lines.append("| --- | --- |")
    for sev in SEVERITY_ORDER:
        lines.append(f"| {sev} | {sev_counts.get(sev, 0)} |")
    lines.append("")

    # --- Detailed Findings --------------------------------------------------
    lines.append("## Detailed Findings")
    lines.append("")
    if not sorted_issues:
        lines.append("_No issues to report._")
        lines.append("")
    else:
        for issue in sorted_issues:
            lines.append(format_issue(issue))
        lines.append("")

    # --- Files With Highest Issues -----------------------------------------
    lines.append("## Files With Highest Issues")
    lines.append("")
    if file_top:
        lines.append("| File | Issue Count |")
        lines.append("| --- | --- |")
        for path, count in file_top:
            lines.append(f"| `{path}` | {count} |")
    else:
        lines.append("_No files._")
    lines.append("")

    # --- Rule Frequency -----------------------------------------------------
    lines.append("## Rule Frequency")
    lines.append("")
    if rule_top:
        lines.append("| Rule | Count |")
        lines.append("| --- | --- |")
        for rule, count in rule_top:
            lines.append(f"| `{rule}` | {count} |")
    else:
        lines.append("_No rules triggered._")
    lines.append("")

    # --- Report Footer ------------------------------------------------------
    lines.append("## Report Footer")
    lines.append("")
    lines.append("Generated by `scripts/generate_sonar_report.py` from `sonar-issues.json`.")
    lines.append("")

    return "\n".join(lines)


def render_html(md_text: str, issues: list[dict[str, Any]]) -> str:
    """Render a minimal HTML view of the same data.

    A full Markdown-to-HTML converter would be a needless dependency.
    Instead, we render a basic table-of-issues page; the Markdown file
    is the canonical artifact for the agent.
    """
    sev_counts = severity_counts(issues)
    body: list[str] = []
    body.append("<!doctype html>")
    body.append('<html lang="en"><head>')
    body.append('<meta charset="utf-8">')
    body.append("<title>SonarQube Report</title>")
    body.append("<style>")
    body.append("body{font-family:system-ui,Arial,sans-serif;margin:2rem;}"
                "table{border-collapse:collapse;margin:1rem 0;}"
                "th,td{border:1px solid #ccc;padding:.4rem .8rem;text-align:left;}"
                "th{background:#f4f4f4;}"
                ".sev-BLOCKER{color:#7a0019;font-weight:bold;}"
                ".sev-CRITICAL{color:#b30000;font-weight:bold;}"
                ".sev-MAJOR{color:#b36b00;}"
                ".sev-MINOR{color:#005fb3;}"
                ".sev-INFO{color:#555;}"
                "</style></head><body>")
    body.append("<h1>SonarQube Security Analysis Report</h1>")
    body.append(f"<p>Total issues: <strong>{len(issues)}</strong></p>")
    body.append("<h2>Severity Summary</h2>")
    body.append("<table><tr><th>Severity</th><th>Count</th></tr>")
    for sev in SEVERITY_ORDER:
        body.append(f'<tr><td class="sev-{sev}">{sev}</td><td>{sev_counts.get(sev, 0)}</td></tr>')
    body.append("</table>")
    body.append("<h2>Issues</h2>")
    if issues:
        body.append("<table><tr><th>Severity</th><th>Rule</th><th>File</th><th>Line</th><th>Message</th></tr>")
        for issue in issues:
            sev = html.escape(str(issue.get("severity", "INFO")))
            rule = html.escape(str(issue.get("rule", "")))
            component = html.escape(str(issue.get("component", "")).split(":")[-1])
            line = html.escape(str(issue.get("line", "")))
            message = html.escape(str(issue.get("message", "")).strip())
            body.append(
                f'<tr><td class="sev-{sev}">{sev}</td><td><code>{rule}</code></td>'
                f'<td><code>{component}</code></td><td>{line}</td><td>{message}</td></tr>'
            )
        body.append("</table>")
    else:
        body.append("<p><em>No issues to report.</em></p>")
    body.append("</body></html>")
    return "\n".join(body)


def main() -> int:
    here = Path(".")
    issues_path = here / "sonar-issues.json"
    md_path = here / "sonar-report.md"
    html_path = here / "sonar-report.html"

    issues = load_issues(issues_path)
    md_text = render_markdown(issues)
    html_text = render_html(md_text, issues)

    md_path.write_text(md_text, encoding="utf-8")
    html_path.write_text(html_text, encoding="utf-8")

    print(f"Wrote {md_path} ({len(md_text)} bytes, {len(issues)} issues)")
    print(f"Wrote {html_path} ({len(html_text)} bytes)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
