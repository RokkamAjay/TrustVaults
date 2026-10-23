# TrustVault

**Secure document sharing with a real audit trail.** TrustVault is a security-first document management project built with Flask, SQLAlchemy, PostgreSQL-compatible database access, private file storage, and pytest.

> **Security scope:** This is a hiring-challenge implementation and learning project, not a certified or production-audited document vault. Review `THREATS.md` before deployment. The hash chain is tamper-evident, not independently immutable. Do not upload real confidential documents until the deployment, secrets, storage, backups, and logging have been independently reviewed.

## Features

- Session-based authentication; password hashes are generated with Werkzeug.
- Roles: `admin`, `owner`, and `viewer`.
- Owner-based, per-document `read` and `edit` grants.
- Server-side permission checks on metadata, download, edit, delete, and permission endpoints.
- Private storage directory outside Flask's static directory; downloads are streamed through an authorised endpoint as attachments.
- Immediate revocation for subsequent requests (permission is queried from the database each time).
- Upload allowlist and basic file-signature/content checks (PDF, PNG, JPEG, UTF-8 text; 10 MB limit).
- Search by document name, owner, category, and date range.
- Audit events for authentication, uploads, metadata reads, downloads, changes, deletion, permission changes, search, and denied access attempts.
- SHA-256 chained audit records and an admin verification endpoint.
- Admin activity view and user administration endpoints.
- CSRF protection for browser/API state-changing requests, secure response headers, no-store responses.
- Automated tests for cross-user access, permission escalation, revocation, upload validation, admin access, and audit-chain tampering.

## Permission model

| Role | Allowed | Not automatically allowed |
|---|---|---|
| `admin` | Create/list/deactivate users; view all document metadata for investigation; read audit records and verify the chain | Reading or downloading document contents merely because they are an admin |
| `owner` | Upload documents; read/edit/delete own documents; grant/revoke read or edit access to own documents | Managing other users' documents or permissions |
| `viewer` | Read/download documents with an active `read` or `edit` grant | Upload, edit, delete, grant, revoke, administer users, view audit records |
| Granted `read` | Read metadata and download | Edit/delete/share |
| Granted `edit` | Read, download, edit metadata, soft-delete | Grant/revoke access; owner-only operations |

The authenticated user's identity and role come from the server-side session/database, never from request-supplied owner IDs. Administrators can see metadata for investigations but do not automatically get access to file contents. The UI is not a security boundary; every relevant route checks permissions.

## Requirements

- Python 3.11+ recommended.
- PostgreSQL for deployment; SQLite is supported for local development/tests.
- Git.

## Run locally

### Windows PowerShell

```powershell
py -3 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt
Copy-Item .env.example .env
# Edit .env and set SECRET_KEY to a long random value.
python scripts/seed_demo.py
python run.py
```

Open `http://127.0.0.1:5000`. The local seed script prints three demo accounts. These default demo credentials are for local development only; do not use them for a public deployment. Set unique environment variables before seeding a controlled demo environment.

### macOS/Linux

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
pip install -r requirements.txt
cp .env.example .env
# Edit .env and set a long random SECRET_KEY.
python scripts/seed_demo.py
python run.py
```

## Environment configuration

| Variable | Purpose |
|---|---|
| `SECRET_KEY` | Flask session and CSRF signing secret; use a random secret in deployment. |
| `DATABASE_URL` | SQLAlchemy URL. PostgreSQL example: `postgresql+psycopg://user:password@host:5432/trustvault`. |
| `STORAGE_PATH` | Private persistent directory, never under `app/static`. |
| `MAX_CONTENT_LENGTH` | Request limit in bytes; default 10 MiB. |
| `COOKIE_SECURE` | Set to `1` behind HTTPS so session cookies use Secure. |

## Seed demo accounts

`python scripts/seed_demo.py` creates these local demo roles by default:

- Admin: `admin@trustvault.demo`
- Owner: `owner@trustvault.demo`
- Viewer: `viewer@trustvault.demo`

The script prints passwords. Local-only default credentials are:

| Role | Email | Local-only password |
|---|---|---|
| Admin | `admin@trustvault.demo` | `ChangeThisAdmin-2026!` |
| Owner | `owner@trustvault.demo` | `ChangeThisOwner-2026!` |
| Viewer | `viewer@trustvault.demo` | `ChangeThisViewer-2026!` |

**Never use these defaults on a public deployment.** Before public deployment, set unique passwords through `DEMO_ADMIN_PASSWORD`, `DEMO_OWNER_PASSWORD`, and `DEMO_VIEWER_PASSWORD`, set unique emails if desired, seed the accounts, and put the actual disposable evaluator credentials in the README version you submit if the placement cell's instructions require it. Do not put personal or production secrets in source history. Use demo accounts with no real confidential documents.

## Run tests

```bash
pytest -q
```

Tests use an isolated in-memory SQLite database and temporary private storage. The negative tests should fail if a route's authorisation check is removed. Run tests after any change to security logic.

## Deployment outline

1. Provision a Python web service, managed PostgreSQL database, and persistent private file storage. Do not rely on an ephemeral filesystem for documents.
2. Set `SECRET_KEY`, `DATABASE_URL`, `STORAGE_PATH`, `COOKIE_SECURE=1`, and unique demo account passwords in the host's secret manager/environment configuration.
3. Install dependencies and run `python scripts/seed_demo.py` once as a controlled release step. This application currently uses `db.create_all()` at startup for challenge simplicity; for ongoing schema changes, add and use Alembic/Flask-Migrate migrations.
4. Start the web process with `gunicorn --workers 1 --bind 0.0.0.0:$PORT wsgi:app`. The single worker avoids concurrent audit-chain append races in this baseline; it is not a scale-out design. For multiple workers/instances, implement database-serialized audit append/checkpointing before scaling.
5. Ensure storage is not served by the host as a public static directory. Restrict database and storage access. Configure HTTPS, backups, monitoring, and a retention policy.
6. Verify `/health`, login for each role, upload/download, cross-user denial, revocation, audit verification, and tests against the deployed build.

## API summary

All state-changing browser/API calls require a valid CSRF token. Login uses a CSRF-protected HTML form. For authenticated API calls, obtain `csrf_token` from `GET /api/me` and send it as `X-CSRFToken`.

See [`docs/API.md`](docs/API.md) for endpoint-level role and permission requirements. See [`docs/SCHEMA.md`](docs/SCHEMA.md), [`THREATS.md`](THREATS.md), and [`PROMPTS.md`](PROMPTS.md).

## Known limitations / accepted risks

- Audit hash chaining detects accidental/partial tampering, but a database administrator capable of rewriting all rows can rebuild the chain. A separately controlled immutable/WORM sink and signed external checkpoints are not implemented.
- File validation is allowlist + signature/basic text validation, not full malware scanning or deep content disarm/reconstruction.
- Soft deletion retains the stored file for recovery; retention and permanent purge are not implemented.
- There is no document version history, MFA, password reset workflow, SSO, rate limiting, or malware scanning in this baseline.
- The UI uses a CDN-hosted Bootstrap stylesheet/script; for stricter supply-chain control, vendor and pin assets locally.
- Audit-chain append uses the latest row in the database and assumes one web worker. Multi-worker/replica production deployment needs a serialized append design and an external checkpoint.
- A revocation blocks subsequent requests; it cannot retract content a user already downloaded or screenshots they took while authorised.
- `db.create_all()` is used for initial challenge setup. Use migrations for production schema evolution.

## Challenge evidence

- Maintain `PROMPTS.md` as you actually use AI; do not invent entries, mistakes, dates, or commit hashes.
- Update `THREATS.md` when your design changes, and add a test for every material threat you claim to mitigate.
- Make commits as you work. Do not fabricate history.
- Record your own five-minute demo and be prepared to explain `can_read`, `can_edit`, `get_document`, revocation, and audit-chain limitations.

## Docker Compose (PostgreSQL + app)

Create a local `.env` file (never commit it) containing strong unique values:

```dotenv
SECRET_KEY=replace-with-a-long-random-secret
POSTGRES_PASSWORD=replace-with-a-unique-database-password
DEMO_ADMIN_PASSWORD=replace-with-a-unique-admin-demo-password
DEMO_OWNER_PASSWORD=replace-with-a-unique-owner-demo-password
DEMO_VIEWER_PASSWORD=replace-with-a-unique-viewer-demo-password
COOKIE_SECURE=0
PORT=8000
```

Then run:

```bash
docker compose up --build -d
# Create demo users once, using the app container:
docker compose exec web python scripts/seed_demo.py
```

Open `http://localhost:8000`. Use `COOKIE_SECURE=1` only when HTTPS is correctly terminated in front of the app. For a public deployment, use HTTPS, set secure cookies, restrict database networking, and use a persistent encrypted private storage volume. The Compose sample persists data but does not itself provide a managed backup or immutable audit sink.
