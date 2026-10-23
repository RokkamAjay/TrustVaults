# Deployment and final review checklist

- [ ] Confirm the placement cell's instructions about when the repository must become public; the original email and problem statement conflict.
- [ ] Use unique `SECRET_KEY`, database password, and demo account passwords.
- [ ] Use HTTPS and set `COOKIE_SECURE=1` in production.
- [ ] Use PostgreSQL and persistent private document storage; do not mount storage as a public static path.
- [ ] Verify demo credentials work for admin, owner, and viewer; use no real confidential documents.
- [ ] Run `pytest -q` in an environment with dependencies installed and record the actual result.
- [ ] Test the live deployment: upload, granted download, ungranted denial, read-only cannot edit, revoke then old URL fails, audit event appears.
- [ ] Check audit-chain verification and document its trust boundary.
- [ ] Inspect repository history and scan for `.env`, passwords, tokens, database files, and real documents.
- [ ] Confirm `README.md`, `API.md`, `SCHEMA.md`, `THREATS.md`, and `PROMPTS.md` reflect the final code.
- [ ] Replace prompt-journal placeholders with at least five real dated entries and actual commit links, including two access-control/audit entries.
- [ ] Add the actual deployed URL and evaluator credentials using the method approved by the placement cell.
- [ ] Record and watch the five-minute demo video.
- [ ] Submit before the portal locks.
