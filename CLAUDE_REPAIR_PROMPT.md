# Claude prompt — CipherQ v18 safe repair and end-to-end verification

You are repairing the **existing CipherQ v18 hardened project**, not rebuilding it. The primary project is `CipherQ_v18_HARDENED_login-fix(2).zip`; use `CipherQ_v17_GITHUB_READY.zip` only as a reference for intended older behavior where useful. v18 is authoritative for current security and workflow behavior.

## Non-negotiable constraints

1. Preserve the current React/Vite frontend, FastAPI backend, MongoDB/PyMongo data model, route names, API schemas, RBAC, intent lifecycle, audit chain, continuous intent-integrity workflow, QIRA features, face/step-up workflow, and quantum simulation. Do not replace or simplify the application.
2. The existing MongoDB database is `cipherq_new` and contains encrypted records. Preserve every existing record. Do not drop, rename, wipe, seed over, or migrate the database automatically. Never run `drop_database`, destructive reset scripts, or migration `--apply` without an explicit approved plan and a verified backup.
3. Preserve the existing encryption key material. Never generate a replacement keyring for the existing encrypted database, never put secrets into source control or the ZIP, and never print secrets. If the correct existing keyring is unavailable, stop and report that requirement; do not pretend the database is fixed.
4. Whole-document encryption and strict mode must remain enabled. Do not bypass encryption to make login work. Diagnose `InvalidTag`, mixed plaintext/encrypted documents, counter collisions, and `DuplicateKeyError` at the root cause. Use safe read-only diagnostics first. Never rewrite ciphertext with an unknown key.
5. Do not trust v17 defaults blindly. Keep v18 security controls and tests. Do not hardcode admin credentials or weaken password validation, rate limits, JWT validation, approval rules, or role checks.
6. The user needs a **single Windows command** to start the required app processes. Provide `START_CIPHERQ.bat` (or repair it) so it validates prerequisites, checks MongoDB connectivity, starts FastAPI with the backend `.env` explicitly loaded, and starts Vite. It must not destroy data or generate a new encryption key for `cipherq_new`. If secrets/keys are missing, fail closed with a clear message.

## Work plan (perform all stages, not just describe them)

### Stage 1 — inventory and root-cause diagnosis
- Unpack both archives into separate directories and produce a file-level comparison for backend auth, database session, encrypted store, config, schemas, frontend API client, and Vite proxy.
- Trace registration/login end to end: frontend request -> Vite `/api` proxy -> FastAPI route -> auth service -> encrypted repositories -> MongoDB -> audit write -> response.
- Confirm exactly which database and URI are effective at runtime. `.env` is not automatically read by Python just because the file exists; the launch command must load it explicitly (for example, Uvicorn `--env-file .env`) or use a verified equivalent.
- Reproduce failures with sanitized logs. Never print credentials, tokens, passwords, JWT secrets, keyring values, or decrypted user records.
- Identify the actual cause of any `InvalidTag`, plaintext-envelope mismatch, `DuplicateKeyError`, or login 500. Do not assume the cause.

### Stage 2 — minimal safe fixes
- Fix the root cause with the smallest change set. Keep the encrypted-store interface and authentication semantics compatible.
- Ensure `get_next_id`/counter logic works with encrypted collections and cannot collide with existing integer `_id` values. If counters are stored as plaintext while strict encryption is enabled, resolve the consistency issue without weakening strict mode or destroying data.
- Ensure the frontend uses `/api` and Vite proxies to `http://127.0.0.1:8000`; ensure backend starts with the intended `.env` and `MONGODB_DATABASE=cipherq_new` unless the user deliberately changes it.
- Add a safe MongoDB readiness check that returns only success/failure, not database names, secrets, or document content.
- Do not alter workflow behavior unrelated to the reproduced defect.

### Stage 3 — automated verification
- Run Python compilation and the complete backend test suite using the documented compatible Python version (Python 3.12 is preferred by the project docs).
- Run tests against an isolated disposable test database, never the user's `cipherq_new` production-like data. Confirm test fixtures cannot drop the user's configured database.
- Run frontend `npm ci` and `npm run build`.
- Add regression tests for the reproduced bug, successful registration/login, bad credentials, persistence across restart, encrypted writes/reads, counter IDs, and frontend-to-backend proxy behavior.
- Run a safe read-only database preflight against the configured target: ping MongoDB, report collection counts and envelope/plaintext counts only, and verify a known record can decrypt only if using the correct existing keyring. Never mutate the target during preflight.
- If any test cannot be run due to missing MongoDB, missing secrets, unavailable dependencies, or lack of the existing keyring, state that clearly. Do not fabricate a passing result.

## Required deliverables

1. A repaired ZIP containing the full project, the minimal code fixes, regression tests, and `START_CIPHERQ.bat` / `START_CIPHERQ.ps1` for one-command startup.
2. `FIX_REPORT.md` listing root causes, exact files changed, data-safety protections, and actual test commands/results.
3. `RUN_WINDOWS.md` with the exact one-command launch instruction and prerequisite setup.
4. A final concise summary of what is verified, what remains blocked, and any manual key-preservation step required.

Do the work directly on the files. Do not stop after writing a plan or prompt. Never claim “fully working” unless the relevant tests and database connection were actually executed successfully. Prioritize preserving existing encrypted data over making the app start at any cost.
