# CipherQ v18 — 12-step demo

Setup: backend and frontend running (see `RUN_WINDOWS.md` on Windows), one administrator seeded with
`scripts/seed_admin.py`. In development, seed a marked case only after the analyst account exists:

```powershell
Set-Location .\backend
$env:APP_ENV = "development"
.\.venv\Scripts\python.exe .\scripts\seed_dev_case.py --admin-user-id 1 --user-id 2
```

Replace the IDs with the active administrator and analyst IDs shown in **Admin Dashboard → Users & Roles**.
The exact case reference to enter in the frontend is `CASE-900001`; its resource is `vault:customer-records`.
The script refuses to overwrite an existing case and only deletes this fixture when its private fixture marker
still matches:

```powershell
.\.venv\Scripts\python.exe .\scripts\seed_dev_case.py --admin-user-id 1 --delete
```

This fixture is development-only and is not a real business record. Do not seed it in production or staging.
A webcam is needed for the face steps in the browser. The scripted equivalent of steps 1–12 is
`backend/scripts/e2e_workflow.py` (synthetic descriptors, no camera); its last run is in
`docs/evidence/e2e_report.json` (70/70). **Caveat to say aloud:** BB84 is a simulation, and the face step proves
descriptor similarity only, not liveness.

| # | Action (who) | Expected outcome |
|---|---|---|
| 1 | Register `analyst1` on the login page. Try choosing a higher role. | Account is `USER_LEVEL_1`; a requested elevated role is ignored. Login issues a server-side device and session id (no client-made ids). |
| 2 | Admin: **Admin Dashboard → Evidence Cases**: create `CASE-100200` (cap CONFIDENTIAL, resource `vault:customer-records`), assign `analyst1`. | Case saved; audit shows `EVIDENCE_CASE_CHANGED`. |
| 3 | Analyst: **Identity** → enrol face (re-enter password). Then verify. | Enrolment accepted; verification succeeds via a single-use challenge. The UI states liveness is **not established**. Replacing the enrolment later demands password + a fresh verification. |
| 4 | Analyst: **Quantum Lab** → create key session. | "Established" with QBER and effective-entropy figures, labelled *simulation*; **no key is shown**. With attack simulation enabled (dev only), an eavesdropper aborts the exchange and no key exists. |
| 5 | Analyst: **Create Intent** (purpose `CASE_INVESTIGATION`, reference `CASE-100200`, resource, operations, scope, ≤24 h) → submit → validate. | Intent `PENDING_APPROVAL`; scope is displayed; evidence marked verified. |
| 6 | Analyst: **Encryption** with the unapproved intent. | Decision `REQUIRE_APPROVAL`; nothing is encrypted. |
| 7 | Admin: **Intent Approval** → approve (requester trying to approve own intent is refused). | Intent `APPROVED` (CONFIDENTIAL needs 1 approval, RESTRICTED needs 2). |
| 8 | Analyst: **Encryption** → enter text → encrypt. | Decision `PERMIT`, a single-use context is consumed, record created; ciphertext preview only. Repeating with the same context fails (`CONTEXT_ALREADY_USED`). |
| 9 | Analyst: **Decryption** → decrypt the record. | New decision and context; plaintext returned. Using a different intent/resource/purpose is `DENY` with `PURPOSE_DRIFT`/`RESOURCE_DRIFT`. |
| 10 | Admin: close `CASE-100200`. Analyst retries a decrypt with a previously issued context, then requests a new decision. | Old context rejected (`CONTEXT_STALE`/`AUTHORIZATION_CHANGED`); new decision `DENY` (`CASE_CLOSED`). |
| 11 | Admin: revoke the analyst's session. Analyst tries again; files a reauthorization request; admin approves; analyst re-verifies face (challenge-bound). | Operations blocked with a revoked session; after approval + step-up, monitoring restarts, a fresh decision is `PERMIT` and encryption works again. Imposter probes during monitoring move the state to `REAUTH_REQUIRED`/`REVOKED` and block operations. |
| 12 | **Audit** page → verify chain. Optionally `python backend/scripts/verify_audit.py`. | "Valid": keyed MAC chain, head anchor and secondary sink all pass; entries show sequence numbers. Editing/deleting any DB audit row makes verification fail (see `test_60_audit.py`). |
