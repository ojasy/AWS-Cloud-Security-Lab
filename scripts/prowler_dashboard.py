import json
import glob
import sys
from datetime import datetime

def load_findings(directory):
    findings = []
    for f in glob.glob(f"{directory}/*.ocsf.json"):
        with open(f, encoding="utf-8") as fh:
            data = json.load(fh)
            if isinstance(data, list):
                findings.extend(data)
    return findings

def generate_dashboard(findings, output="prowler_dashboard.html"):
    total  = len(findings)
    passed = sum(1 for f in findings if f.get("status") == "Success")
    failed = total - passed
    score  = round((passed / total) * 100, 1) if total else 0

    sev = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for f in findings:
        s = f.get("severity", "").lower()
        if s in sev:
            sev[s] += 1

    color = ("#22c55e" if score >= 75
             else "#f59e0b" if score >= 50
             else "#ef4444")

    sev_order = ["critical", "high", "medium", "low"]

    def sev_rank(f):
        s = f.get("severity", "low").lower()
        return sev_order.index(s) if s in sev_order else 99

    failed_findings = sorted(
        [f for f in findings if f.get("status") == "Failure"],
        key=sev_rank
    )

    failed_rows = "".join(
        f'<tr>'
        f'<td class="{f.get("severity", "").upper()}">'
        f'{f.get("severity", "").upper()}</td>'
        f'<td>{f.get("finding", {}).get("title", "N/A")}</td>'
        f'<td style="font-size:0.75rem">'
        f'{f.get("resources", [{}])[0].get("uid", "N/A")[:80]}</td>'
        f'<td style="font-size:0.75rem;color:#94a3b8">'
        f'{f.get("finding", {}).get("remediation", {}).get("desc", "")[:100]}</td>'
        f'</tr>'
        for f in failed_findings
    )

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>AWS Security Posture Dashboard</title>
  <style>
    * {{
      box-sizing: border-box;
      margin: 0;
      padding: 0;
    }}
    body {{
      font-family: 'Segoe UI', Arial, sans-serif;
      background: #0f172a;
      color: #e2e8f0;
      padding: 40px 30px;
    }}
    h1 {{
      color: #38bdf8;
      text-align: center;
      font-size: 2rem;
      margin-bottom: 6px;
    }}
    .sub {{
      text-align: center;
      color: #94a3b8;
      font-size: 0.9rem;
      margin-bottom: 30px;
    }}
    .score {{
      font-size: 6rem;
      font-weight: bold;
      color: {color};
      text-align: center;
      margin: 20px 0;
      letter-spacing: -2px;
    }}
    .score-label {{
      text-align: center;
      color: #94a3b8;
      font-size: 0.95rem;
      margin-top: -16px;
      margin-bottom: 30px;
    }}
    .cards {{
      display: flex;
      gap: 16px;
      justify-content: center;
      flex-wrap: wrap;
      margin: 20px 0 40px;
    }}
    .card {{
      background: #1e293b;
      border-radius: 14px;
      padding: 20px 30px;
      text-align: center;
      min-width: 120px;
      border: 1px solid #334155;
    }}
    .card .num {{
      font-size: 2.4rem;
      font-weight: bold;
    }}
    .card .lbl {{
      font-size: 0.8rem;
      color: #94a3b8;
      margin-top: 6px;
      text-transform: uppercase;
      letter-spacing: 0.05em;
    }}
    .section-title {{
      color: #38bdf8;
      font-size: 1.1rem;
      margin: 30px 0 14px;
      padding-bottom: 8px;
      border-bottom: 1px solid #1e293b;
    }}
    table {{
      width: 100%;
      border-collapse: collapse;
    }}
    th {{
      background: #1e293b;
      padding: 12px 14px;
      text-align: left;
      font-size: 0.82rem;
      color: #94a3b8;
      text-transform: uppercase;
      letter-spacing: 0.05em;
      border-bottom: 2px solid #334155;
    }}
    td {{
      padding: 10px 14px;
      border-bottom: 1px solid #1e293b;
      font-size: 0.83rem;
      vertical-align: top;
    }}
    tr:hover td {{
      background: #1e293b;
    }}
    .CRITICAL {{
      color: #ef4444;
      font-weight: bold;
    }}
    .HIGH {{
      color: #f97316;
      font-weight: bold;
    }}
    .MEDIUM {{
      color: #f59e0b;
      font-weight: 500;
    }}
    .LOW {{
      color: #6ee7b7;
    }}
    .footer {{
      text-align: center;
      color: #475569;
      font-size: 0.8rem;
      margin-top: 50px;
      padding-top: 20px;
      border-top: 1px solid #1e293b;
    }}
  </style>
</head>
<body>

  <h1>🛡️ AWS Security Posture Dashboard</h1>
  <p class="sub">
    Generated: {datetime.now().strftime('%Y-%m-%d %H:%M')} &nbsp;|&nbsp;
    Region: ca-central-1 &nbsp;|&nbsp;
    CIS AWS Foundations Benchmark v1.4
  </p>

  <div class="score">{score}%</div>
  <p class="score-label">Compliance Score</p>

  <div class="cards">
    <div class="card">
      <div class="num" style="color:#22c55e">{passed}</div>
      <div class="lbl">Passed</div>
    </div>
    <div class="card">
      <div class="num" style="color:#ef4444">{failed}</div>
      <div class="lbl">Failed</div>
    </div>
    <div class="card">
      <div class="num" style="color:#64748b">{total}</div>
      <div class="lbl">Total</div>
    </div>
    <div class="card">
      <div class="num" style="color:#ef4444">{sev['critical']}</div>
      <div class="lbl">Critical</div>
    </div>
    <div class="card">
      <div class="num" style="color:#f97316">{sev['high']}</div>
      <div class="lbl">High</div>
    </div>
    <div class="card">
      <div class="num" style="color:#f59e0b">{sev['medium']}</div>
      <div class="lbl">Medium</div>
    </div>
    <div class="card">
      <div class="num" style="color:#6ee7b7">{sev['low']}</div>
      <div class="lbl">Low</div>
    </div>
  </div>

  <h2 class="section-title">❌ Failed Findings — sorted by severity</h2>
  <table>
    <thead>
      <tr>
        <th style="width:90px">Severity</th>
        <th>Check</th>
        <th>Resource</th>
        <th>Remediation</th>
      </tr>
    </thead>
    <tbody>
      {failed_rows}
    </tbody>
  </table>

  <div class="footer">
    AWS Security Lab &nbsp;|&nbsp; Prowler v3.11.3 &nbsp;|&nbsp;
    {datetime.now().strftime('%B %Y')}
  </div>

</body>
</html>"""

    with open(output, "w", encoding="utf-8") as fh:
        fh.write(html)

    print(f"[+] Dashboard saved   -> {output}")
    print(f"[+] Compliance score  -> {score}%")
    print(f"[+] Passed: {passed} | Failed: {failed} | Total: {total}")
    print(f"[+] Critical: {sev['critical']} | High: {sev['high']} | "
          f"Medium: {sev['medium']} | Low: {sev['low']}")


if __name__ == "__main__":
    directory = sys.argv[1] if len(sys.argv) > 1 else "."
    findings  = load_findings(directory)

    if not findings:
        print("[!] No .ocsf.json files found in the directory.")
        print("    Usage: python prowler_dashboard.py <path_to_scan_results>")
        print("    Example: python prowler_dashboard.py .")
    else:
        print(f"[+] Loaded {len(findings)} findings from {directory}")
        generate_dashboard(findings)