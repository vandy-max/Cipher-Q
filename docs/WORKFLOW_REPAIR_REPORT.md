# CipherQ v18 intent workflow repair

**Verification date:** 2026-10-19  
**Scope:** intent creation, authoritative evidence validation, approval gating, crypto workflow, Windows test and run instructions.

## Findings and changes

The FastAPI application entry point is `backend/api/main.py`; `POST /api/intents` is implemented in
`backend/api/routers/intents.py` and uses `intent_engine.schema.IntentRequest`. The schema already accepts the
optional `attachment` object with `filename`, `content_type`, and `content_base64`; the frontend sends those
same field names. `extra="forbid"` and the lowercase resource-name pattern remain unchanged. The Vite proxy
uses `VITE_API_PROXY_TARGET` or defaults to `http://localhost:8000`.

The authoritative evidence source is the administrator-maintained MongoDB `evidence_cases` collection behind
`LocalEvidenceProvider` in `backend/intent_engine/evidence.py`. It is a local case table, not an external case
system. For evidence-required classifications, the validator checks the matching case reference, open state,
record freshness, required case fields, requester assignment, allowed resource, and classification cap.
Attachments and user-supplied case IDs are not proof of evidence.

The key lifecycle gap was that approval relied on a prior `PENDING_APPROVAL` status and did not recheck the
case record. A case could be closed or become invalid after validation but before approval. Validation also
did not have an explicit machine-readable outcome for provider outages, and its result was not stored as a
version-bound record. On Windows, the test harness selected a nonexistent `/tmp` path for its audit sink.

Changes:

- Evidence lookup now turns PyMongo provider failures into `EVIDENCE_PROVIDER_UNAVAILABLE` and malformed
  authoritative records into `EVIDENCE_INVALID`; the response includes outcome, source, reason, and findings.
- Each validation result is integrity-sealed and stored with the intent ID, version, body hash, evidence
  source, outcome, findings, validator, and timestamp.
- Approval revalidates current authoritative evidence before recording a decision. If it no longer supports
  the intent, the intent returns to `DRAFT`, current approvals are withdrawn through append-only approval
  records, and protected operations remain blocked. An approved intent that is explicitly revalidated after
  evidence becomes invalid also loses its status and outstanding contexts.
- The frontend now displays finding details returned by the backend.
- Added a development-only seed utility for `CASE-900001`. It requires `APP_ENV=development`, a local
  `mongodb://` server, an active admin and an active non-admin requester; it inserts rather than upserts and
  refuses to replace an existing record. Cleanup requires the matching private fixture marker.
- Tests now use the platform temporary directory. POSIX-mode-only assertions are skipped on Windows, where
  `st_mode` does not report NTFS ACLs; the local generated environment and secret files are excluded from the
  source-tree scan. `.gitignore` now excludes generated `.dev_secrets*`.

## Modified files

| File | Reason |
|---|---|
| `.gitignore` | Keep generated local development secrets out of source packaging. |
| `backend/intent_engine/evidence.py` | Fail-closed typed provider errors, validate authoritative case fields, and support insert-only fixtures. |
| `backend/intent_engine/store.py` | Persist integrity-sealed evidence-validation records. |
| `backend/intent_engine/engine.py` | Return explicit outcomes, persist results, and revalidate/invalidate evidence-bound approvals. |
| `backend/scripts/seed_dev_case.py` | Safe, development-only seed and marker-checked cleanup utility. |
| `backend/tests/conftest.py` | Use a valid platform-specific temp path for the test audit sink. |
| `backend/tests/test_10_intent_flow.py` | Exercise the full requested message, audit records, provider failure, stale evidence, draft approval denial, and insert-only fixture behavior. |
| `backend/tests/test_60_audit.py` | Skip POSIX permission-bit assertion on Windows rather than misreading NTFS ACLs. |
| `backend/tests/test_80_ops_config.py` | Make mode checks platform-aware and exclude ignored local config/virtualenv files from the source scan. |
| `frontend/src/pages/CreateIntentPage.jsx` | Display evidence finding details instead of only a machine code. |
| `DEMO_GUIDE.md` | Document the exact development case and safe seed/cleanup steps. |
| `RUN_WINDOWS.md` | Add separate PowerShell backend/frontend commands and the correct Uvicorn module path. |
| `TEST_RESULTS.md` | Add this Windows follow-up's measured test and build results. |

## Development fixture

The exact case/business reference is **`CASE-900001`**, with resource **`vault:customer-records`** and
classification cap `CONFIDENTIAL`. This is explicitly a development fixture, not a real case. It is assigned
to one active non-admin user. Find the user IDs in **Admin Dashboard → Users & Roles**.

From the project root, after MongoDB and the backend environment are configured:

```powershell
Set-Location .\backend
$env:APP_ENV = "development"
.\.venv\Scripts\python.exe .\scripts\seed_dev_case.py --admin-user-id <ADMIN_ID> --user-id <ANALYST_ID>
```

The seeder does not overwrite a preexisting case. If the reference already exists, choose another reference
through the administrator-managed case UI rather than deleting or replacing that record. The seeded fixture
may be removed only if its marker is still present:

```powershell
.\.venv\Scripts\python.exe .\scripts\seed_dev_case.py --admin-user-id <ADMIN_ID> --delete
```

If an administrator edits the fixture through the UI, its marker is removed and the cleanup command refuses
to delete it. Do not use the fixture seeder against production, staging, or a non-local database.

## Windows commands

Start MongoDB first. These commands use the existing local key/database configuration; do not regenerate keys
or change the configured database to make the demo pass.

**Backend terminal:**

```powershell
Set-Location .\backend
py -3.12 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt -r requirements-dev.txt
.\.venv\Scripts\python.exe -m uvicorn api.main:app --host 127.0.0.1 --port 8000
```

Omit the `venv` creation line when the existing `backend\.venv` is already in use.

**Frontend terminal:**

```powershell
Set-Location .\frontend
npm ci
npm run dev -- --host 127.0.0.1
```

## Walkthrough and denied-operation demonstration

1. Create the analyst account, sign in, and complete the existing face verification, session/device, key
   session, and monitoring steps.
2. As an admin, seed `CASE-900001` using the commands above.
3. As the analyst, create an intent with purpose `CASE_INVESTIGATION`, business reference `CASE-900001`,
   resource `vault:customer-records`, operations `encrypt` and `decrypt`, classification `CONFIDENTIAL`,
   and a validity window no longer than 24 hours.
4. Validate evidence. Expected lifecycle: `DRAFT` → `PENDING_APPROVAL`, outcome `VERIFIED`, evidence source
   `local-case-table`. The result is stored against the exact intent version and body hash.
5. Confirm that an unapproved intent cannot obtain a crypto permit. As a different active administrator,
   approve the pending current version. The requester cannot approve their own intent.
6. Encrypt `CipherQ test message 001`, then decrypt the produced record using the permitted intent. The
   backend's existing crypto implementation and keys are used; audit events cover validation, approval,
   encryption, and decryption.
7. For a negative case, create an intent referring to syntactically valid but unknown case `CASE-999999`.
   Validation returns `CASE_NOT_FOUND`, leaves it `DRAFT`, creates no approval, and protected operations
   cannot proceed. The admin queue's default filter excludes drafts.
8. To demonstrate stale-evidence handling, validate a pending intent, close its case as admin, then attempt
   approval. The server rechecks evidence, refuses approval, and returns the intent to `DRAFT`.

## Verification

| Check | Result |
|---|---|
| Full backend suite, against a unique test database on local MongoDB | **222 passed, 0 failed, 2 skipped**, 1 existing Starlette/httpx deprecation warning; 237.56 s. |
| Skips | POSIX `0600` mode assertions; Windows `st_mode` cannot validate NTFS ACLs. |
| Focused intent/audit/config + previously timed-out monitoring test | **56 passed, 2 skipped**, 1 warning; 51.26 s. |
| Frontend `npm run build` | **Succeeded**, no chunk-size warning; initial JS bundle is about 221 kB and the lazy face-api chunk is about 1,315 kB minified. |
| Python compile check for modified backend files | **Succeeded.** |
| Fixture seeder CLI parse check | **Succeeded.** |

The positive workflow test exercises the actual FastAPI routes, local MongoDB-backed evidence provider,
approval, crypto endpoints, and audit records using the isolated test database. No production/working
application database or key material was reset or migrated. A live Uvicorn demonstration was not run against
the configured application database.

The Windows test skips do not prove Windows ACL privacy. The file mode checks remain meaningful on POSIX;
Windows ACL hardening is not established by this test suite.
