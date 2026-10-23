from flask import Flask, render_template_string, jsonify, make_response
import csv, io

app = Flask(__name__)

# Fictional sample events for defensive training only.
LOGS = [
 {"timestamp":"2026-10-20 09:10:11","event_id":"4769","account":"svc_backup","service":"backup-svc","ticket_count":2,"encryption":"AES256"},
 {"timestamp":"2026-10-20 09:14:02","event_id":"4769","account":"svc_reports","service":"reporting-svc","ticket_count":12,"encryption":"RC4"},
 {"timestamp":"2026-10-20 09:18:45","event_id":"4769","account":"j.smith","service":"fileserver","ticket_count":1,"encryption":"AES128"},
 {"timestamp":"2026-10-20 09:25:31","event_id":"4769","account":"svc_legacy","service":"legacy-app","ticket_count":7,"encryption":"RC4-HMAC"},
 {"timestamp":"2026-10-20 09:42:50","event_id":"4769","account":"svc_inventory","service":"inventory-svc","ticket_count":10,"encryption":"AES128"},
]
GPO = {
 "Password minimum length": (12, "Set to 14 or more characters."),
 "Account lockout threshold": (5, "Use a reasonable threshold and monitor lockouts."),
 "Windows Firewall enabled": (True, "Enable Windows Firewall for applicable profiles."),
 "MFA for administrators": (False, "Require MFA for privileged accounts."),
 "Legacy protocols disabled": (False, "Disable legacy protocols where practical."),
 "Guest account disabled": (True, "Disable the local Guest account unless an exception is documented."),
}

def detect(logs):
    results = []
    for row in logs:
        count, enc = int(row["ticket_count"]), row["encryption"].upper()
        reasons, severity = [], "Low"
        if count >= 10:
            reasons.append(f"Unusually high service-ticket count ({count})")
            severity = "High"
        elif count >= 5:
            reasons.append(f"Elevated service-ticket count ({count})")
            severity = "Medium"
        if enc in ("RC4", "RC4-HMAC"):
            reasons.append(f"Legacy encryption observed ({enc})")
            severity = "Critical" if severity == "High" else "Medium"
        if not reasons:
            reasons.append("No configured training rule triggered")
        results.append({**row, "severity": severity, "reason": "; ".join(reasons),
          "recommendation": "Validate activity, account purpose, privileges and password strength; prefer AES where supported."
          if severity != "Low" else "Continue routine monitoring and correlate with other events."})
    rank = {"Critical":0,"High":1,"Medium":2,"Low":3}
    return sorted(results, key=lambda r: rank[r["severity"]])

def audit_gpo():
    output = []
    for name, (value, fix) in GPO.items():
        if name == "Password minimum length": passed = int(value) >= 14
        elif name == "Account lockout threshold": passed = 1 <= int(value) <= 10
        else: passed = str(value).lower() == "true"
        output.append({"name":name,"value":value,"status":"Pass" if passed else "Review",
                       "recommendation":"Setting meets this basic check." if passed else fix})
    return output

HTML = """
<!doctype html><html><head><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Active Directory Security Lab</title>
<style>
body{margin:0;background:#0b1020;color:#edf2ff;font:14px Arial;line-height:1.5}header{padding:22px 5%;background:#121a2e;border-bottom:1px solid #30405c}
header small{color:#6ee7e0;letter-spacing:2px}main{max-width:1150px;margin:auto;padding:25px 18px}h1,h2,h3{margin:5px 0 12px}
.muted{color:#a1aec9}.cards{display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin:20px 0}
.card,.panel{background:#121a2e;border:1px solid #283653;border-radius:12px;padding:17px}.card strong{display:block;font-size:28px;margin:8px 0}
.warn{color:#ff858c}.good{color:#75e0a0}.panel{margin:16px 0}.scroll{overflow-x:auto}
table{width:100%;min-width:780px;border-collapse:collapse}th,td{text-align:left;padding:10px;border-bottom:1px solid #283653;vertical-align:top;font-size:12px}
th{color:#8fa1c1;font-size:10px}.badge{padding:4px 7px;border-radius:5px;background:#49351f;color:#ffcc80}
a{display:inline-block;background:#6ee7e0;color:#0b1020;padding:10px 13px;border-radius:7px;text-decoration:none;font-weight:bold}
.grid{display:grid;grid-template-columns:repeat(2,1fr);gap:10px}.item{border:1px solid #283653;border-radius:9px;padding:13px}.item p{color:#a1aec9;font-size:12px}
@media(max-width:700px){.cards,.grid{grid-template-columns:repeat(2,1fr)}}@media(max-width:480px){.grid{grid-template-columns:1fr}}
</style></head><body><header><small>CYBERSECURITY BOOTCAMP</small><h1>Active Directory Security Lab</h1><span>SIMULATED DATA ONLY</span></header>
<main><h2>Kerberos Detection &amp; GPO Hardening</h2><p class="muted">A safe local dashboard using fictional Windows security records and sample policy settings.</p>
<a href="/export/findings.csv">Export findings CSV</a>
<div class="cards"><div class="card">Events reviewed<strong>{{logs|length}}</strong></div>
<div class="card">High / critical flags<strong class="warn">{{flags}}</strong></div>
<div class="card">GPO checks<strong>{{gpo|length}}</strong></div><div class="card">Checks passed<strong class="good">{{passed}}</strong></div></div>
<section class="panel"><h3>Kerberos Activity Review</h3><p class="muted">Training indicators are not proof of compromise; investigate context.</p><div class="scroll"><table><tr><th>Timestamp</th><th>Account</th><th>Service</th><th>Severity</th><th>Reason</th><th>Recommendation</th></tr>
{% for x in findings %}<tr><td>{{x.timestamp}}</td><td>{{x.account}}</td><td>{{x.service}}</td><td><span class="badge">{{x.severity}}</span></td><td>{{x.reason}}</td><td>{{x.recommendation}}</td></tr>{% endfor %}</table></div></section>
<section class="panel"><h3>Group Policy Hardening Audit</h3><div class="grid">{% for x in gpo %}<div class="item"><b>{{x.name}} — {{x.status}}</b><p>Sample value: {{x.value}}</p><p>{{x.recommendation}}</p></div>{% endfor %}</div></section>
<p class="muted">Educational prototype only. Do not test or modify systems without authorization.</p></main></body></html>
"""

@app.route("/")
def home():
    findings = detect(LOGS); gpo = audit_gpo()
    return render_template_string(HTML, logs=LOGS, findings=findings, gpo=gpo,
        flags=sum(x["severity"] in ("High","Critical") for x in findings),
        passed=sum(x["status"]=="Pass" for x in gpo))

@app.route("/api/findings")
def api_findings():
    return jsonify(detect(LOGS))

@app.route("/export/findings.csv")
def export_csv():
    rows = detect(LOGS); output = io.StringIO()
    fields = ["timestamp","event_id","account","service","ticket_count","encryption","severity","reason","recommendation"]
    writer = csv.DictWriter(output, fieldnames=fields); writer.writeheader(); writer.writerows(rows)
    response = make_response(output.getvalue())
    response.headers["Content-Disposition"] = "attachment; filename=security_findings.csv"
    response.headers["Content-Type"] = "text/csv; charset=utf-8"
    return response

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)
