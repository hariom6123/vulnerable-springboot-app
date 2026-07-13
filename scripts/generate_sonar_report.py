#!/usr/bin/env python3
"""
Generate human-readable SonarQube reports from API response.
Outputs: sonar-report.html and sonar-report.md
"""

import json
import sys
from datetime import datetime
from pathlib import Path


def load_sonar_issues(filepath='sonar-issues.json'):
    """Load SonarQube issues from JSON file."""
    try:
        with open(filepath, 'r') as f:
            data = json.load(f)
        return data.get('issues', [])
    except FileNotFoundError:
        print(f"⚠️ {filepath} not found, creating empty report")
        return []
    except json.JSONDecodeError:
        print(f"⚠️ Invalid JSON in {filepath}, creating empty report")
        return []


def generate_html_report(issues):
    """Generate HTML report."""
    severity_counts = {}
    for issue in issues:
        severity = issue.get('severity', 'INFO')
        severity_counts[severity] = severity_counts.get(severity, 0) + 1

    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>SonarQube Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; }}
        .container {{ max-width: 1000px; margin: 0 auto; background: white; padding: 30px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
        h1 {{ color: #333; border-bottom: 3px solid #667eea; padding-bottom: 10px; }}
        h2 {{ color: #555; margin-top: 30px; }}
        .summary {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 15px; margin: 20px 0; }}
        .card {{ background: #f9f9f9; padding: 15px; border-left: 4px solid #667eea; border-radius: 4px; }}
        .card.critical {{ border-left-color: #f44747; }}
        .card.major {{ border-left-color: #ff9500; }}
        .card h3 {{ margin: 0 0 10px 0; color: #666; font-size: 12px; text-transform: uppercase; }}
        .card .count {{ font-size: 28px; font-weight: bold; }}
        .issue {{ background: #f9f9f9; padding: 15px; margin: 10px 0; border-left: 4px solid #ddd; border-radius: 4px; }}
        .issue.critical {{ background: #fff3f3; border-left-color: #f44747; }}
        .issue.major {{ background: #fff8f3; border-left-color: #ff9500; }}
        .issue.minor {{ background: #fffbf3; border-left-color: #ffc107; }}
        .severity {{ display: inline-block; padding: 4px 8px; border-radius: 3px; font-weight: bold; color: white; font-size: 11px; }}
        .severity.critical {{ background: #f44747; }}
        .severity.major {{ background: #ff9500; }}
        .severity.minor {{ background: #ffc107; color: #333; }}
        .severity.info {{ background: #667eea; }}
        .message {{ font-weight: 500; margin: 5px 0; color: #333; }}
        .detail {{ font-size: 13px; color: #666; margin: 5px 0; }}
        .success {{ color: green; font-weight: bold; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>🔒 SonarQube Report</h1>
        <p>Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>

        <div class="summary">
"""

    for severity in ['CRITICAL', 'MAJOR', 'MINOR', 'INFO']:
        count = severity_counts.get(severity, 0)
        color = 'critical' if severity == 'CRITICAL' else 'major' if severity == 'MAJOR' else ''
        html_content += f'            <div class="card {color}"><h3>{severity}</h3><div class="count">{count}</div></div>\n'

    html_content += f'            <div class="card"><h3>Total</h3><div class="count">{len(issues)}</div></div>\n        </div>\n'

    if len(issues) > 0:
        html_content += '        <h2>Issues</h2>\n'
        issues_sorted = sorted(
            issues,
            key=lambda x: {'CRITICAL': 0, 'MAJOR': 1, 'MINOR': 2, 'INFO': 3}.get(x.get('severity'), 4)
        )
        for issue in issues_sorted:
            severity_lower = issue.get('severity', 'INFO').lower()
            html_content += f"""        <div class="issue {severity_lower}">
            <span class="severity {severity_lower}">{issue.get('severity')}</span>
            <span style="margin-left: 10px; font-weight: bold;">({issue.get('type', 'BUG')})</span>
            <div class="message">{issue.get('message')}</div>
            <div class="detail"><strong>File:</strong> {issue.get('component', 'Unknown')}</div>
            <div class="detail"><strong>Line:</strong> {issue.get('line', 'N/A')}</div>
            <div class="detail"><strong>Rule:</strong> {issue.get('rule', 'Unknown')}</div>
            <div class="detail"><strong>Effort:</strong> {issue.get('effort', 'N/A')}</div>
        </div>
"""
    else:
        html_content += '        <p class="success">✅ No issues found!</p>\n'

    html_content += """    </div>
</body>
</html>
"""

    with open('sonar-report.html', 'w') as f:
        f.write(html_content)
    print("✅ HTML report generated: sonar-report.html")


def generate_markdown_report(issues):
    """Generate Markdown report."""
    severity_counts = {}
    for issue in issues:
        severity = issue.get('severity', 'INFO')
        severity_counts[severity] = severity_counts.get(severity, 0) + 1

    md_content = f"# SonarQube Report\n\n**Date:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n"
    md_content += "## Summary\n\n"
    for severity in ['CRITICAL', 'MAJOR', 'MINOR', 'INFO']:
        count = severity_counts.get(severity, 0)
        md_content += f"- **{severity}:** {count} issues\n"
    md_content += f"\n**Total:** {len(issues)} issues\n\n"

    if len(issues) > 0:
        md_content += "## Issues\n\n"
        issues_sorted = sorted(
            issues,
            key=lambda x: {'CRITICAL': 0, 'MAJOR': 1, 'MINOR': 2, 'INFO': 3}.get(x.get('severity'), 4)
        )
        for idx, issue in enumerate(issues_sorted, 1):
            md_content += f"""### {idx}. [{issue.get('severity')}] {issue.get('message')}

- **File:** `{issue.get('component')}`
- **Line:** {issue.get('line')}
- **Type:** {issue.get('type')}
- **Rule:** `{issue.get('rule')}`
- **Effort:** {issue.get('effort')}

"""
    else:
        md_content += "✅ No issues found!\n"

    with open('sonar-report.md', 'w') as f:
        f.write(md_content)
    print("✅ Markdown report generated: sonar-report.md")


def main():
    """Main entry point."""
    try:
        issues = load_sonar_issues()
        generate_html_report(issues)
        generate_markdown_report(issues)
        print("\n✅ Report generation completed successfully!")
        return 0
    except Exception as e:
        print(f"❌ Error generating reports: {e}", file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())
