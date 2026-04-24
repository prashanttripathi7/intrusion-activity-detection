# Intrusion Activity Detection & Attack Trace System

A beginner friendly real-time intrusion detection system (IDS) built with FastAPI, WebSockets, rule-based OWASP detection, dataset-informed pattern matching, attack correlation, timeline generation, and PDF reporting.

This project supports two main use cases:

- Real host monitoring on Windows and Linux
- Safe local demos using bundled samples and helper scripts

## Features

- Live log ingestion with FastAPI and WebSockets
- OWASP rule-based detection for:
  - `A01: Broken Access Control`
  - `A02: Cryptographic Failures`
  - `A03: Injection`
  - `A07: Identification & Authentication Failures`
- Dataset-enhanced detection using suspicious IPs, attack signatures, and abnormal request-frequency patterns
- Attack-chain correlation and timeline building
- Dark-theme browser dashboard
- PDF report generation when monitoring stops
- Windows and Linux demo scripts for safe alert generation

## Project Structure

```text
realtime IDS/
├── backend/
│   ├── api/
│   ├── correlation/
│   ├── detector/
│   ├── parser/
│   ├── realtime/
│   ├── reports/
│   ├── timeline/
│   ├── main.py
│   ├── models.py
│   ├── state.py
│   └── utils.py
├── datasets/
├── demo/
├── frontend/
├── sample_logs/
├── .gitignore
├── README.md
└── requirements.txt
```

## Requirements

- Python `3.11+`
- Windows or Linux
- Optional: Administrator or `sudo` privileges for protected log sources

## Clone The Repository

```bash
git clone https://github.com/your-username/your-repo-name.git
cd "your-repo-name"
```

Replace the URL above with your actual GitHub repository URL after pushing.

## Installation

### Windows

```powershell
python -m venv .venv
.venv\Scripts\activate
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

If `python` points to the wrong interpreter, use your full Python path.

### Linux

```bash
python3 -m venv .venv
source .venv/bin/activate
python3 -m pip install --upgrade pip
python3 -m pip install -r requirements.txt
```

## Run The Project

Start the server from the project root:

### Windows

```powershell
python -m uvicorn backend.main:app --reload
```

### Linux

```bash
python3 -m uvicorn backend.main:app --reload
```

Open the dashboard at [http://127.0.0.1:8000](http://127.0.0.1:8000).

## How Monitoring Works

When you click `Start Monitoring`, the frontend sends `auto` mode:

- On Windows, the backend reads real Event Viewer logs from `Security`, `System`, and `Application`
- On Linux, the backend tries common files such as:
  - `/var/log/auth.log`
  - `/var/log/syslog`
  - `/var/log/nginx/access.log`
  - `/var/log/apache2/access.log`
  - `/var/log/httpd/access_log`
- If no real host log source is available, the backend falls back to the bundled demo logs

When you click `Stop Monitoring`:

- monitoring stops
- a PDF report is generated
- the report becomes downloadable from the dashboard

## Step-By-Step Usage

1. Clone the repository.
2. Create and activate a virtual environment.
3. Install dependencies with `pip install -r requirements.txt`.
4. Start the backend with `uvicorn backend.main:app --reload`.
5. Open `http://127.0.0.1:8000`.
6. Click `Start Monitoring`.
7. Generate safe demo events with one of the scripts in [`demo/`](./demo).
8. Watch the logs, alerts, timeline, and attack chains update live.
9. Click `Stop Monitoring`.
10. Click `Download Report`.

## Demo Scripts

The repository includes safe demo helpers for both Windows and Linux. (For Windows, copy the demo file content and run it in PowerShell as an administrator)

### Windows Demo

File:
- [`demo/windows_event_demo.ps1`](./demo/windows_event_demo.ps1)

What it does:
- writes safe demo entries to the Windows Application event log
- triggers patterns such as:
  - weak cryptographic protocol usage
  - SQL injection text patterns
  - suspicious command execution
  - access-control denial patterns

How to run:

1. Start the IDS backend.
2. Open the dashboard.
3. Click `Start Monitoring`.
4. Open a new PowerShell window.
5. Run:

```powershell
powershell -ExecutionPolicy Bypass -File .\demo\windows_event_demo.ps1
```

6. Return to the dashboard and watch:
- alerts
- timeline entries
- suspicious IP matches
- possible attack chains

### Linux Demo

File:
- [`demo/linux_log_demo.sh`](./demo/linux_log_demo.sh)

What it does:
- appends safe demo entries to Linux auth and web logs
- simulates:
  - repeated failed logins
  - suspicious successful login after failures
  - SQL injection request patterns
  - path traversal and access-control probing

How to run:

1. Start the IDS backend.
2. Open the dashboard.
3. Click `Start Monitoring`.
4. Open a second terminal.
5. Make the script executable:

```bash
chmod +x demo/linux_log_demo.sh
```

6. Run:

```bash
./demo/linux_log_demo.sh
```

Optional custom log paths:

```bash
./demo/linux_log_demo.sh /var/log/auth.log /var/log/nginx/access.log
```

Notes:
- some Linux systems require `sudo`
- if your distro uses different log paths, pass them as arguments

## Bundled Demo Data

The following files are included for testing and fallback demo mode:

- [`datasets/pattern_signatures.json`](./datasets/pattern_signatures.json)
- [`datasets/cicids_sample.csv`](./datasets/cicids_sample.csv)
- [`sample_logs/auth.log`](./sample_logs/auth.log)
- [`sample_logs/apache_access.log`](./sample_logs/apache_access.log)
- [`sample_logs/windows_security.txt`](./sample_logs/windows_security.txt)

## API Endpoints

- `GET /health`
- `GET /logs`
- `GET /alerts`
- `GET /timeline`
- `GET /attack-chains`
- `POST /monitoring/start`
- `POST /monitoring/stop`
- `GET /report/download`
- `GET /status`
- `WS /ws/live`

## Detection Coverage

### OWASP Rule-Based Detection

- `A01: Broken Access Control`
- `A02: Cryptographic Failures`
- `A03: Injection`
- `A07: Identification & Authentication Failures`

### Dataset-Enhanced Detection

- known suspicious IP addresses
- known attack signatures
- abnormal request-frequency thresholds

## Report Output

When monitoring stops, the backend generates:

- `reports_output/ids_final_report.pdf`

The report includes:

- total alerts
- OWASP category counts
- suspicious IPs
- timeline events
- correlated attack chains

## Real Host Monitoring Notes

### Windows

- The project polls Event Viewer by calling PowerShell.
- Running PowerShell as Administrator may improve visibility into protected logs.
- The Windows demo script is the easiest way to trigger safe alerts.

### Linux

- Protected files in `/var/log/` may require elevated permissions.
- If no host logs appear, run the backend with sufficient access or use the bundled demo mode.

## GitHub Readiness

This repository already ignores local-only files such as:

- `.venv/`
- `__pycache__/`
- `.codex/`
- `reports_output/`
- generated PDF files
- common IDE settings

## Before You Push

Recommended checklist:

1. Make sure `.venv/`, `.codex/`, `reports_output/`, and `__pycache__/` are not tracked.
2. Confirm the app runs from the project root.
3. Verify the dashboard loads at `http://127.0.0.1:8000`.
4. Run at least one demo script and confirm alerts appear.
5. Stop monitoring and confirm the PDF report is generated.
6. Review `README.md` in GitHub preview after pushing.

Useful Git commands:

```bash
git status
git add .
git commit -m "Prepare IDS project for GitHub"
git branch -M main
git remote add origin https://github.com/your-username/your-repo-name.git
git push -u origin main
```

If `origin` already exists:

```bash
git remote set-url origin https://github.com/your-username/your-repo-name.git
git push -u origin main
```

## Troubleshooting

### `ModuleNotFoundError: No module named 'fastapi'`

Install dependencies from the project root:

```bash
pip install -r requirements.txt
```

### `requirements.txt` not found

Run commands from the project root, not from inside `backend/`.

### Dashboard opens but shows no logs

- click `Start Monitoring`
- run a demo script
- check whether your OS log source needs elevated permissions

### Report download does not work

- click `Stop Monitoring` first
- confirm `reports_output/ids_final_report.pdf` was generated
