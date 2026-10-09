# AuditMate — Security Controls & Compliance Gap Tracker

AuditMate is an educational GRC (governance, risk and compliance) web application for tracking security controls, evidence metadata, compliance gaps, risk records, remediation tasks, audit activity and CSV/PDF control reports. It references ISO/IEC 27001 as a framework context but does not certify compliance. Seed records are illustrative.

## Features in this full-stack version
- Flask web app with server-rendered responsive interface
- Password-hashed login, sessions, CSRF protection, admin/analyst role field, secure headers
- SQLite default database via Flask-SQLAlchemy; configure MySQL with `DATABASE_URL`
- Dashboard totals and status chart based on database records
- Create/list/search/delete for controls, evidence, gaps, risks and remediation tasks
- Evidence upload restricted to PDF/PNG/JPG/TXT/CSV and 5 MB max, with authenticated downloads
- Audit activity log for application actions
- CSV and PDF control summary exports
- pytest starter test suite

## Run on Windows (PowerShell)
1. Install Python 3.11+ from python.org and ensure `python` works in PowerShell.
2. Extract this ZIP and `cd` into the `auditmate-fullstack` folder (the folder containing `run.py`).
3. Create and activate a virtual environment:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
Copy-Item .env.example .env
```

4. Edit `.env` and set a unique `SECRET_KEY` and strong `ADMIN_PASSWORD`. The first run creates the database and seeds illustrative controls.
5. Start the app:

```powershell
python run.py
```

6. Open http://127.0.0.1:5000. Default demo login is `admin` / `ChangeMe123!` only if you did not change `ADMIN_USERNAME` or `ADMIN_PASSWORD` before the database was first created. Change these credentials for any non-demo use.

## Run tests
```powershell
python -m pytest -q
```

## Optional MySQL
Set `DATABASE_URL` in `.env` to a SQLAlchemy-compatible MySQL URL, for example `mysql+pymysql://user:password@localhost/auditmate`. Install `pymysql` before using this option and create the database first. SQLite is the default and easiest local setup.

## Limitations and security notes
- This is an educational starter project, not a production-ready GRC platform. Have it reviewed before real organizational use.
- Admin/analyst roles are stored; fine-grained route permissions and user administration still need strengthening before multi-user deployment.
- Evidence files are restricted by extension and size; additional malware scanning/content inspection is recommended before real use.
- CSV/PDF reports currently summarize controls, not every record type.
- Framework mappings are illustrative and should be reviewed against licensed/official framework materials.
- No email notifications, MFA, password reset, or production database migration workflow yet.
- Do not upload confidential or unauthorized evidence. Keep `.env` and private database files out of GitHub.
