# CampusFix V2 Advanced — Campus Fault Reporting System

A Flask + SQLite campus maintenance reporting app with student, staff and admin workflows. It is designed for a beginner to run locally and extend.

## Features in this V2 bundle
- Student accounts, role-based access and hashed passwords.
- CSRF protection on POST forms, security headers, secure session settings and basic login-attempt throttling.
- Email verification when SMTP is configured; local mode skips verification so the project remains easy to run offline.
- Password reset links (30-minute expiry), email notifications on new reports and status changes.
- Fault photo upload and offline image integrity/quality screening with staff review. This is not semantic AI and cannot tell if a photo depicts the actual fault.
- Fault priority suggestions, status tracking, assignment, comments, search, filters, analytics and CSV export.
- Dashboard polling every 30 seconds; it prompts to refresh when data changes. This is near-live refresh, not WebSocket push.
- SQLite schema migration, test suite and setup/configuration examples.

## Run on Windows / VS Code
Open the folder containing `app.py` and `requirements.txt`, then run in PowerShell:

```powershell
& "$env:LOCALAPPDATA\Python\pythoncore-3.14-64\python.exe" -m venv venv
.\venv\Scripts\python.exe -m pip install --upgrade pip
.\venv\Scripts\python.exe -m pip install -r requirements.txt
.\venv\Scripts\python.exe app.py
```

Open http://127.0.0.1:5000. Keep the terminal open while using the app.

## Demo admin
- Email: `admin@campus.local`
- Password: `Admin@123`

Change or remove these demo credentials before any shared/network deployment.

## Email configuration (optional for local use)
Copy `.env.example` as a reference; environment variables are not automatically loaded from that file. Set variables in PowerShell before starting Flask, for example:

```powershell
$env:SECRET_KEY = "replace-with-a-long-random-secret"
$env:SMTP_HOST = "smtp.example.com"
$env:SMTP_PORT = "587"
$env:SMTP_USER = "your-smtp-username"
$env:SMTP_PASSWORD = "your-smtp-app-password"
$env:SMTP_FROM = "CampusFix <no-reply@example.com>"
```

Use an SMTP app password where supported. Do not hard-code credentials in source code. With SMTP configured, new student registrations require email verification. Password reset is only delivered through configured email. Without SMTP, the app runs locally and account creation skips verification; the forgot-password form safely explains that email must be configured.

## Run automated tests
```powershell
.\venv\Scripts\python.exe -m unittest discover -s tests -v
```

Tests use a temporary SQLite database. They do not overwrite your actual app database.

## Production checklist
This is an educational starter, not a fully audited production service. Before public deployment: use HTTPS, set a strong random `SECRET_KEY`, set `COOKIE_SECURE=1`, configure a real SMTP provider, change/remove demo admin credentials, use a production WSGI server, back up the database, add centralized monitoring, and consider per-IP rate limiting and institutional SSO. Do not use Flask's development server for public traffic.

## Image-screening limitation
Pillow validates actual image contents, dimensions and low-variation/stretched image patterns. It does **not** recognize image meaning, nudity, selfies, or fault relevance. Staff review is required. The included feature should not be described as full AI image classification.
