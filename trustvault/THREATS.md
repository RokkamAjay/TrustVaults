# TrustVault threat model

This document should evolve alongside the code. The mitigations below describe the current challenge baseline, not a claim of perfect security. Every material claim should have a corresponding automated test or a clearly stated reason why it cannot be fully tested locally.

## Assets and trust boundaries

- Confidential document contents and metadata.
- User identity, roles, and per-document grants.
- Audit history and evidence of refused access.
- Private file storage, database, application secrets, and deployment credentials.
- Trust boundary: browser input is untrusted; only the server-side authenticated session and current database grant determine access.

## Threats, mitigations, tests, and accepted risks

| Threat | Mitigation in this project | Test / verification | Residual risk / accepted limitation |
|---|---|---|---|
| Insecure direct object reference (change document ID) | Every document route fetches the document and checks owner/current grant on the server; inaccessible IDs return 404. | `test_ungranted_user_cannot_read_download_edit_delete_or_grant` | A missed new route could reintroduce the flaw; review every route and test it. |
| Direct download endpoint bypasses UI | Download route performs `can_read` on every request and uses private storage. | Cross-user download test and read-grant test | Already downloaded copies cannot be recalled. |
| Privilege escalation from read to edit | Edit routes call `can_edit`; permission value is DB-constrained to `read`/`edit`. | `test_read_grant_allows_download_but_not_edit` | Future endpoints must reuse the same policy helpers. |
| Stale link after permission revocation | No permanent public URL; each download re-queries current grant. | `test_revocation_blocks_next_request_and_is_audited` | A request already authorised and in progress may finish; revocation cannot recall content already delivered. |
| Forged owner ID / mass assignment | Document owner is assigned from authenticated `current_user`; API does not accept owner ID. | Review upload implementation; add regression test if owner fields are introduced. | Future schema/API changes can create this bug if the invariant is not preserved. |
| Disabled account continues using session | User loader checks `active` on subsequent requests. | Add an explicit deactivation-session regression test before submission. | Existing in-flight requests are not cancelled retroactively. |
| Public/static file path leakage | Random storage key; files stored outside `app/static`; authorised download endpoint only. | Inspect deployment filesystem/static route; cross-user download test. | Misconfigured host volume or backups could expose files outside Flask. |
| Malicious or oversized upload | Extension allowlist, basic signature/content checks, 10 MB limit, opaque filename. | `test_viewer_cannot_upload_and_disallowed_file_is_rejected`; add oversize test. | No malware scanning, archive inspection, or full file-format parser. Only PDF/PNG/JPEG/UTF-8 TXT accepted. |
| XSS through filenames, categories, audit details | HTML UI escapes rendered dynamic values; CSP and `nosniff` headers; attachment downloads. | Manual payload checks; add automated UI tests if time permits. | CSP permits inline scripts/styles for this simple UI and Bootstrap is CDN-hosted. |
| CSRF against state-changing routes | Flask-WTF CSRF protection and session cookies SameSite=Lax. | Verify state-changing requests fail without token in a non-test config. | Deployment must preserve correct HTTPS/origin configuration. |
| Password disclosure / weak password storage | Werkzeug password hashing; minimum 12-character password on admin user creation. | Inspect stored hashes; test user creation validation. | No MFA, rate limiting, password reset, or breached-password checks in baseline. |
| Audit row changed or deleted | Hash chain links canonical row data to prior hash; admin can verify chain. | `test_audit_chain_verifies_and_detects_row_tampering` | DB administrator can rewrite all rows and recompute hashes. No external WORM/checkpoint service implemented. |
| Denied access not recorded | Denied document access is committed to audit before returning 404. | Assert denied audit records after cross-user requests. | If the database is unavailable, logging may fail; current code logs server-side but cannot guarantee durable evidence while storage is down. |
| Audit chain concurrent append race | Baseline deployment guidance uses one worker. | Test suite is single-process. | Not safe for multi-worker/multi-instance concurrent appends without serialization; add DB locking and external checkpoints before scaling. |
| Search leaks other users' documents | Non-admin query scoped to owned or granted IDs and filtered again using live permission checks. | Add tests that search and counts never expose ungranted docs. | Admin intentionally sees metadata; that is a documented privileged capability. |
| Admin silently reads confidential content | Admin can inspect metadata/audit but is not automatically granted download permission. | `test_admin_can_review_audit_but_does_not_automatically_download_content` | Admin can grant themselves a role only if a future feature permits it; user management currently does not change roles. |
| SQL injection | SQLAlchemy parameterised query expressions; no raw SQL string concatenation. | Code review and fuzz inputs. | Review any future raw SQL and dynamic sort/filter implementation. |
| Secret leakage through Git | `.env` ignored; `.env.example` contains placeholders. | `git status --ignored`; scan repository before publishing. | A secret committed in history remains exposed even if later deleted; rotate it. |
| Permanent deletion / retention ambiguity | Soft deletion makes document unavailable while preserving file for possible recovery. | Test delete makes later read/download fail. | Purge, retention schedules, backup deletion and legal holds are not implemented. |
| File replaced or corrupted on disk | SHA-256 stored at upload. | Compare hash when reading if implemented as a future hardening step. | Current download does not recompute hash before each delivery. |

## Attack plan before submission

1. Try all document endpoints with an ungranted viewer and a guessed ID.
2. Try read-only grant against every mutation route.
3. Revoke a grant, then reuse the exact prior download URL/session.
4. Search for another user's document name and category; inspect returned IDs/counts.
5. Attempt a forged `owner_id`, role, storage key, or permission field in JSON.
6. Upload mismatched file signatures, empty files, oversized files, path-like names, and HTML/script content under allowed extensions.
7. Inspect whether denied events appear in the audit list and whether changing a row breaks verification.
8. Try accessing storage paths directly through `/static/` or guessed URLs.
9. Disable a user and try using the existing browser session again.
10. Simulate a database/audit write failure and document the behaviour honestly.

## Accepted risks and not implemented

No claim is made that this is production-certified. Malware scanning, MFA, rate limiting, immutable external audit storage, audit-chain concurrency for multiple workers, versioning, SSO, backup/restore drills, retention/purge, and a complete security review remain out of scope for this seven-day baseline. The most important residual risk is that the database operator can rewrite the entire audit chain unless external immutable checkpoints are added.
