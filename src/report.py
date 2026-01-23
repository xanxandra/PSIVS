from pathlib import Path
import html

def generate_html_report(findings, output_file="report.html"):

    html_content = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Vulnerability Scan Report</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            margin: 40px;
            background-color: #f5f5f5;
        }
        h1 {
            border-bottom: 2px solid #333;
            padding-bottom: 10px;
        }
        .finding {
            background: #ffffff;
            border-left: 5px solid #c0392b;
            padding: 16px;
            margin-bottom: 20px;
        }
        .label {
            font-weight: bold;
        }
    </style>
</head>
<body>

<h1>Findings</h1>
"""

    for f in findings:
        vuln_type = html.escape(str(f["type"]))
        url = html.escape(str(f["url"]))
        param = html.escape(str(f["param"]))
        suggestion = str(f["suggestion"])

        html_content += f"""
    <div class="finding">
        <p><span class="label">Type:</span> {vuln_type}</p>
        <p><span class="label">Vulnerable URL:</span> {url}</p>
        <p><span class="label">Vulnerable Parameter:</span> {param}</p>
        <p><span class="label">Suggestion:</span>
        <a href="{suggestion}" target="_blank">View remediation guide</a>
        </p>
    </div>
    """

    html_content += """
</body>
</html>
"""

    output_path = Path(output_file).resolve()
    output_path.parent.mkdir(parents=True, exist_ok=True)
    
    with open(output_file, "w", encoding="utf-8") as f:
        f.write(html_content)
    return output_path

