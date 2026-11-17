# CyberSOC — Enterprise SIEM & Security Operations Dashboard

CyberSOC is an advanced defensive security monitoring portfolio project. It ingests structured security events, normalizes records, runs detection rules, presents an analyst queue, and exports findings.

> Educational SIEM prototype. Alerts are investigation leads—not proof of compromise. It is not a replacement for a production SIEM.

## Features
- Streamlit security operations dashboard.
- CSV schema validation and timestamp normalization.
- `AUTH-001`: repeated failed authentication in a configurable time window.
- `NET-001`: possible port scanning using distinct destination ports.
- `VOL-001`: high event volume from one source.
- Severity classification, triage recommendations, filters and CSV exports.
- Synthetic sample dataset and unit tests.

## Stack
Python 3.10+, Streamlit, Pandas, Pytest.

## Run locally
```bash
python -m venv .venv
# Windows PowerShell: .venv\\Scripts\\Activate.ps1
# macOS/Linux: source .venv/bin/activate
pip install -r requirements.txt
streamlit run app.py
```

## CSV schema
Required: `timestamp`, `source_ip`, `event_type`, `status`.
Optional: `destination_port` (integer).

Example:
```csv
timestamp,source_ip,event_type,status,destination_port
2026-11-01T09:00:00Z,198.51.100.20,login,failed,22
```
Supported event types include `login`, `authentication`, `connection_attempt`, `port_scan`; failed statuses include `failed`, `failure`, `denied`, `invalid`.

## Tests
```bash
pytest -q
```

## Deploy on Streamlit Community Cloud
1. Push this project to GitHub (suggested repository: `cybersoc-enterprise-siem`).
2. Visit https://share.streamlit.io/ and sign in with GitHub.
3. Create app, select your repository, branch `main`, main file `app.py`.
4. Deploy. Streamlit installs dependencies from `requirements.txt`.

## GitHub upload
Create an empty repository named `cybersoc-enterprise-siem`, then run in this folder:
```bash
git init
git add .
git commit -m "Initial CyberSOC SIEM platform"
git branch -M main
git remote add origin https://github.com/YOUR-USERNAME/cybersoc-enterprise-siem.git
git push -u origin main
```
Replace `YOUR-USERNAME` with your GitHub username.

## Safety and privacy
Use only logs you own or are authorized to analyze. Redact usernames, hostnames, internal IPs, tokens and personal data before sharing. Never commit `.env`, credentials, API keys or Streamlit secrets. The sample dataset uses documentation-only IP ranges.
