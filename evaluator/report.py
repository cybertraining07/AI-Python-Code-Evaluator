
from pathlib import Path
from datetime import datetime, timezone
from html import escape


def generate_report(
    test_results,
    analysis_results,
    score_results,
    output_path="reports/evaluation_report.html",
    static_results=None,
):
    """Generate a professional HTML code evaluation report."""

    output = Path(output_path)
    output.parent.mkdir(parents=True, exist_ok=True)

    static_results = static_results or {}

    def safe(value):
        return escape(str(value if value is not None else "N/A"))

    def finding_rows(findings, category):
        if not findings:
            return (
                '<tr><td colspan="4">No findings detected.</td></tr>'
            )

        rows = []

        for finding in findings:
            severity = finding.get(
                "severity",
                finding.get("code", "INFO")
            )

            rows.append(
                "<tr>"
                f"<td>{safe(category)}</td>"
                f"<td>{safe(severity)}</td>"
                f"<td>{safe(finding.get('line', 'N/A'))}</td>"
                f"<td>{safe(finding.get('message', 'No description'))}</td>"
                "</tr>"
            )

        return "\n".join(rows)

    score = score_results.get("overall_score", 0)
    grade = score_results.get("grade", "Unknown")

    breakdown = score_results.get("breakdown", {})

    test_rows = ""

    for name, details in breakdown.items():
        test_rows += (
            "<tr>"
            f"<td>{safe(name.title())}</td>"
            f"<td>{safe(details.get('score'))}</td>"
            f"<td>{safe(details.get('maximum'))}</td>"
            f"<td>{safe(details.get('status'))}</td>"
            "</tr>"
        )

    findings = []

    # Bandit security findings
    findings.extend(
        analysis_results.get("security", {}).get("findings", [])
    )

    # AST analyzer findings
    findings.extend(static_results.get("findings", []))

    # Flake8 style findings
    findings.extend(
        analysis_results.get("style", {}).get("findings", [])
    )

    findings_html = finding_rows(findings, "Code Analysis")

    complexity_blocks = (
        analysis_results.get("complexity", {}).get("blocks", [])
    )

    complexity_html = ""

    if complexity_blocks:
        for block in complexity_blocks:
            complexity_html += (
                "<tr>"
                f"<td>{safe(block.get('name'))}</td>"
                f"<td>{safe(block.get('complexity'))}</td>"
                f"<td>{safe(block.get('rank'))}</td>"
                f"<td>{safe(block.get('lineno'))}</td>"
                "</tr>"
            )
    else:
        complexity_html = (
            '<tr><td colspan="4">No complexity data available.</td></tr>'
        )

    status = test_results.get("status", "UNKNOWN")

    complete = score_results.get(
        "assessment_complete", False
    )

    report_html = f"""
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">

<title>AI Python Code Evaluation Report</title>

<style>
* {{
    box-sizing: border-box;
}}

body {{
    margin: 0;
    padding: 30px;
    font-family: Arial, sans-serif;
    background: #f1f5f9;
    color: #1e293b;
}}

.container {{
    max-width: 1100px;
    margin: auto;
}}

header {{
    background: #172554;
    color: white;
    padding: 30px;
    border-radius: 12px;
}}

header h1 {{
    margin-top: 0;
}}

.card {{
    background: white;
    padding: 22px;
    margin-top: 20px;
    border-radius: 12px;
    box-shadow: 0 2px 8px rgba(0,0,0,.05);
}}

.score {{
    font-size: 48px;
    font-weight: bold;
    color: #15803d;
}}

table {{
    width: 100%;
    border-collapse: collapse;
    margin-top: 15px;
}}

th, td {{
    padding: 12px;
    border-bottom: 1px solid #e2e8f0;
    text-align: left;
}}

th {{
    background: #e2e8f0;
}}

.badge {{
    display: inline-block;
    padding: 6px 12px;
    border-radius: 20px;
    background: #dcfce7;
    color: #166534;
}}

footer {{
    text-align: center;
    margin-top: 30px;
    color: #64748b;
}}

@media print {{
    body {{
        background: white;
        padding: 10px;
    }}

    .card {{
        box-shadow: none;
        border: 1px solid #ddd;
    }}
}}
</style>
</head>

<body>
<div class="container">

<header>
    <h1>AI Python Code Evaluation</h1>
    <p>Automated Software Quality Assessment</p>
    <p>Generated: {safe(datetime.now(timezone.utc).isoformat())}</p>
</header>

<section class="card">
    <h2>Overall Evaluation</h2>

    <div class="score">
        {safe(score) if complete else "Not finalized"}
        {"/100" if complete else ""}
    </div>

    <h3>{safe(grade)}</h3>
    <table>
        <tr>
            <th>Category</th>
            <th>Score</th>
            <th>Maximum</th>
            <th>Status</th>
        </tr>
        {test_rows}
    </table>
</section>

<section class="card">
    <h2>Automated Testing Results</h2>
    <p>Status: <strong>{safe(status)}</strong></p>
    <p>Passed: {safe(test_results.get('passed', 0))}</p>
    <p>Failed: {safe(test_results.get('failed', 0))}</p>
    <p>Errors: {safe(test_results.get('errors', 0))}</p>
    <p>Skipped: {safe(test_results.get('skipped', 0))}</p>
    <p>Pass rate: {safe(test_results.get('pass_rate', 0))}%</p>
</section>

<section class="card">
    <h2>Security and Code Findings</h2>

    <table>
        <tr>
            <th>Category</th>
            <th>Severity / Code</th>
            <th>Line</th>
            <th>Finding</th>
        </tr>
        {findings_html}
    </table>
</section>

<section class="card">
    <h2>Code Complexity Analysis</h2>

    <table>
        <tr>
            <th>Function</th>
            <th>Complexity</th>
            <th>Rank</th>
            <th>Line</th>
        </tr>
        {complexity_html}
    </table>
</section>

<section class="card">
    <h2>Evaluation Recommendations</h2>
    <ul>
        <li>Review all detected security findings.</li>
        <li>Investigate failed and skipped tests.</li>
        <li>Reduce high-complexity functions.</li>
        <li>Address code style violations.</li>
        <li>Perform additional edge-case testing.</li>
    </ul>
</section>

<footer>
    <p>AI Python Code Evaluator | Automated Evaluation Report</p>
    <p>Generated by the Python Code Evaluation Engine.</p>
</footer>

</div>
</body>
</html>
"""

    output.write_text(report_html, encoding="utf-8")

    return str(output)
