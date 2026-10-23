# Five-minute TrustVault demo plan

Record your own screen and voice. Use only the deployed build and demo accounts you have tested. Never include real confidential documents or secrets.

- **0:00–0:30 — Introduction:** Explain TrustVault, stack, and the security-first goal.
- **0:30–1:15 — Roles:** Sign in as owner, upload a harmless sample PDF/TXT, show it in the document list.
- **1:15–2:00 — Grant access:** Share the document with the viewer account using a `read` grant. Sign in as viewer and download it.
- **2:00–2:45 — Deny and revoke:** Try the same document as an ungranted user (show the denied response without exposing content). Revoke the viewer grant and show that the next download request fails.
- **2:45–3:30 — Audit:** Sign in as admin, show upload/download/grant/revoke/denied events, and run the audit-chain verification.
- **3:30–4:15 — Tests:** Show the automated cross-user and revocation tests and explain why they would fail if the permission check were removed.
- **4:15–5:00 — Design and limitations:** Explain `can_read`, `can_edit`, the download route, hash-chain limitations, and the most important accepted risks.

Keep the video within five minutes and make sure passwords/tokens are not visible in terminal history or screen recording.
