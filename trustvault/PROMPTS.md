# AI usage journal — TrustVault

**Keep this file truthful and update it during the week.** The challenge asks for at least five dated entries, including at least two about authorisation/access control/audit. Do not backdate entries, invent tool output, or invent commit hashes. Add the real commit link after you commit the correction. Preserve prompts or reusable context files you actually used.

## Entry 1 — 2026-10-19 — Initial scaffold and audit-chain review

- **Prompt / fair summary:** “Prepare a complete Flask starter project for TrustVault with authentication, roles, per-document permissions, private document storage, audit logging, tests, threat model, and setup documentation.”
- **What the tool produced:** Initial Flask app structure, SQLAlchemy models, upload/download and permission endpoints, audit-chain helper, UI, tests, and project documentation.
- **What was wrong:** During review, the first audit-row construction passed `occurred_at` twice. Also, SQLite can return a naive timestamp even when an aware UTC timestamp was inserted; hashing the different ISO representations would make verification fail after reload. A foreign key that nulls actor IDs on user deletion would also mutate data covered by the hash.
- **What I did instead:** Changed audit-row construction to pass the timestamp once, normalised naive timestamps to UTC during verification, and removed the actor foreign key so the actor ID snapshot survives user deletion. I will run the test suite and inspect the resulting chain.
- **Evidence / commit:** Add the actual commit URL after committing this fix: `TODO — replace with real commit URL`.
- **Files reviewed:** `app/audit.py`, `app/models.py`.

## Entry 2 — add when it happens (authorisation)

- **Date:** YYYY-MM-DD (actual date only)
- **Prompt / fair summary:**
- **What the tool produced:**
- **Specific security flaw or limitation I found:**
- **What I changed and how I tested it:**
- **Commit URL:**

## Entry 3 — add when it happens (audit trail)

- **Date:** YYYY-MM-DD (actual date only)
- **Prompt / fair summary:**
- **What the tool produced:**
- **Specific flaw or limitation I found:**
- **What I changed and how I tested it:**
- **Commit URL:**

## Entry 4 — add when it happens

- **Date:** YYYY-MM-DD (actual date only)
- **Prompt / fair summary:**
- **What the tool produced:**
- **Specific flaw or limitation I found:**
- **What I changed and how I tested it:**
- **Commit URL:**

## Entry 5 — add when it happens

- **Date:** YYYY-MM-DD (actual date only)
- **Prompt / fair summary:**
- **What the tool produced:**
- **Specific flaw or limitation I found:**
- **What I changed and how I tested it:**
- **Commit URL:**

## Reusable context / instructions actually used

- Project requirement: server-side authorisation on every route; UI visibility is not security.
- Project requirement: no public document URLs; permission revocation blocks subsequent requests.
- Project requirement: tests must cover threats documented in `THREATS.md`.
- Add the exact prompts/context files and tools you reuse during implementation. Do not list a file or instruction you did not actually use.
