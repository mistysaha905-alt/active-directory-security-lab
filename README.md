# Active Directory Security Lab
**Topic:** Kerberoasting Detection & Group Policy Object (GPO) Hardening

## Overview
A beginner-friendly defensive cybersecurity dashboard built with Python and Flask. It uses fictional sample data only and does not connect to a real Active Directory domain.

## Features
- Sample Kerberos activity review with severity indicators
- Six basic Group Policy security checks
- Remediation recommendations
- CSV export of findings
- JSON endpoint at `/api/findings`

## Requirements
Python 3.10+ and pip.

## Run on Windows
Save `Code_File_app.py` as `app.py`, keep `Requirements.txt` in the same folder and rename it to `requirements.txt`. Then run:
```bat
py -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
python app.py
```
Open `http://127.0.0.1:5000`.

## Run on macOS/Linux
```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python app.py
```

## Demo
1. Explain the dashboard summary cards.
2. Show the `svc_reports` sample flagged for high ticket volume and RC4 encryption.
3. Review GPO settings marked Review.
4. Export the CSV findings.
5. Optional: open `/api/findings` to view JSON.

## Limitations and safety
The rules are simplified learning heuristics and may produce false positives. This is not a production detection system or full compliance audit. Use only for authorized defensive education.
