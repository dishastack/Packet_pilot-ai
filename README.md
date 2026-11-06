# PacketPilot AI

A starter Streamlit application for authorized PCAP/PCAPNG inspection.

## Features
- Protocol counts and packet table
- Source/destination IP summaries
- TCP/UDP port and TCP flag inspection
- Visible DNS query extraction
- Basic heuristic triage alerts
- CSV export
- A simple single-user password gate

## Important limitations
- This is a learning/demo project, not a production SOC platform.
- Alerts are heuristics and are not proof of malicious activity.
- It analyzes uploaded files; it does not capture live network traffic.
- The login gate is a basic single-user demo. For production or multiple users, use an identity provider (OIDC/SSO), server-side authorization, secure session controls, logging, and a security review.
- Only upload captures you are authorized to inspect.

## Deploy on Streamlit Community Cloud
1. Push `app.py`, `requirements.txt`, and this README to a GitHub repository.
2. Create an app at https://share.streamlit.io/ and select the repository, branch, and `app.py`.
3. In the app's settings, configure Secrets:
   ```toml
   APP_USERNAME = "choose-a-username"
   APP_PASSWORD = "use-a-long-unique-random-password"
   ```
4. Never commit real secrets to GitHub. If secrets were ever committed, rotate them.

## Local run
Install a supported Python version (Python 3.11 or 3.12 recommended), then run:
```bash
python -m venv .venv
```
Activate the environment, then:
```bash
python -m pip install -r requirements.txt
streamlit run app.py
```

## Suggested `.gitignore`
See the provided `.gitignore`. Do not commit `.env`, secrets, private packet captures, or local databases.
