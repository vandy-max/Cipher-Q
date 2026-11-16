# CipherQ v18 — Test results

All figures below were produced in this session; nothing is estimated. Raw output: `docs/evidence/pytest_final.log`,
`docs/evidence/e2e_report.json`, `docs/evidence/pip_audit_final.txt`, `docs/evidence/npm_audit_final.json`.

## 1. Environment

| Item | Value |
|---|---|
| OS / kernel | Linux 6.18 (cloud container) |
| Python | 3.12.3 (venv with `backend/requirements.txt` + `requirements-dev.txt`; frozen list in `docs/evidence/pip_freeze_final.txt`) |
| Key pins | fastapi 0.143.0, starlette 1.7.0, pydantic 2.9.2, pymongo 4.18.2, cryptography 50.0.2, pyjwt 2.15.0, qiskit 2.5.2, qiskit-aer 0.17.2 |
| Node / npm | 22.22.0 / 10.9.4 (vite 8.2.1, react 18.3.1) |
| Database | **FerretDB 1.24.0 (SQLite backend) on 127.0.0.1:27017 — not MongoDB.** |
| Audit sink | local append-only file |

## 2. Commands and results

| # | Command (from repo root) | Result |
|---|---|---|
| 1 | `cd backend && python -m pytest -q -p no:cacheprovider --durations=5` | **220 passed, 0 failed, 0 skipped**, 1 warning (starlette `httpx` TestClient deprecation, harmless), 337 s |
| 2 | `python backend/scripts/e2e_workflow.py` against a live `uvicorn` + FerretDB (fresh data dir) | **70 / 70 steps passed** (`docs/evidence/e2e_report.json`) |
| 3 | `cd frontend && npm run build` (dependencies installed from `package-lock.json`) | Build succeeded (2553 modules; one >500 kB chunk warning, not an error) |
| 4 | `npm audit --omit=dev` | 0 vulnerabilities |
| 5 | `npm audit` (all) | 7 advisories (5 high, 2 moderate), all in the **dev/build-time** Tailwind 3 → chokidar/braces/postcss chain; the fix is a breaking Tailwind 4 migration, not done |
| 6 | `pip-audit --local` on the final environment | Only `pip` 24.0 (installer tooling, not a runtime dependency) is reported; all runtime packages clean |
| 7 | Headless-Chromium UI smoke (`docs/evidence/ui_smoke/*.py`, fake media device) | Pages for user and admin rendered without page errors; screenshots not shipped |
| 8 | Archive scan for secrets/keys/`.env` | see §5 |

Per-file test counts (command 1): `test_01_auth` 3 · `test_02_encrypted_store` 6 · `test_03_auth` 29 · `test_10_intent_flow` 11 ·
`test_20_purpose_drift` 23 (18 mandated acceptance tests + extras + the 10-step workflow) · `test_30_monitoring_identity` 27 ·
`test_40_crypto` 30 · `test_50_quantum` 13 · `test_60_audit` 15 · `test_70_abuse_authz` 36 · `test_80_ops_config` 27 = **220**.

Backend: 220 passed / 0 failed. Frontend: production build OK; **no frontend unit tests exist**. Database: exercised on FerretDB only.
End-to-end: 70/70 scripted API steps (intent → authorization → encryption → monitoring → revocation → reauthorization, plus
negative paths); the browser path was smoke-tested, not scripted end to end.

## 3. Baseline vs final

The unmodified v17 archive was run for comparison (`SECURITY_BASELINE.md`, `docs/evidence/poc*.py`, `baseline_results.json`): forged
admin JWT accepted, shipped key, race conditions and client-asserted monitoring all reproduced. The corresponding PoCs fail against v18
(each has a regression test listed in `CHANGELOG_SECURITY_HARDENING.md`).

## 4. Not executed / limitations

* **Real MongoDB** (replica set, TLS, auth) — not available here; multi-process atomicity untested (FINAL_SECURITY_AUDIT R-02).
* **Real webcam / liveness / cross-browser** — not tested; descriptors in tests are synthetic. Liveness is not established (R-01).
* **Frontend automated tests** — none; UI covered by build + exploratory smoke only. Browser-driven full workflow not automated.
* **Load, soak, DoS** — not performed. `GET /api/audit/verify` is O(n).
* **Physical QKD** — impossible here; BB84 is a classical simulation (Qiskit Aer).
* **External evidence/case system, KMS/HSM** — not integrated.
* **Independent review / penetration test** — not done; all testing was by the author of the fixes.
* Incident-resolution audit event verified by code review only.
* The test run uses the dev/test configuration; strict-environment start-up is covered by config tests (`test_80`), not by running a hardened production deployment.

## 6. Windows workflow repair follow-up — 2026-10-19

This is the latest result for the source tree after the intent/evidence workflow repair. It supersedes the
older frontend build and backend test counts above for this checkout; the historical Linux/FerretDB run is
preserved as context.

| Check | Result |
|---|---|
| Backend | `.\.venv\Scripts\python.exe -m pytest -q`: **222 passed, 0 failed, 2 skipped**, 1 Starlette/httpx deprecation warning; 237.56 s. |
| Skipped checks | POSIX `0600` mode assertions are skipped on Windows because `st_mode` does not report NTFS ACLs. |
| Frontend | `npm run build`: succeeded without chunk-size warnings. Initial JS bundle is approximately 221 kB; lazy face-api bundle is approximately 1,315 kB minified. |
| Python syntax | `compileall` for changed engine, fixture, and test modules succeeded. |
| Database safety | The suite used its generated `cipherq_t_*` test database; no configured application data or encryption keys were reset. |

The positive API integration test now creates a CONFIDENTIAL intent, validates authoritative case evidence,
obtains a separate admin approval, encrypts and decrypts `CipherQ test message 001`, and checks version-bound
validation records and audit events. Provider failure, unknown case, stale evidence at approval, draft
approval, and non-overwriting development fixture behavior are also covered. See
[`docs/WORKFLOW_REPAIR_REPORT.md`](./docs/WORKFLOW_REPAIR_REPORT.md) for the fixture procedure, commands,
modified-file list, and complete workflow walkthrough.
