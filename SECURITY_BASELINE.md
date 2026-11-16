# CipherQ v17 — Security Baseline (Phase 0)

> **Historical document.** This is the Phase-0 baseline of v17 written before any change. Current status of every finding: `FINAL_SECURITY_AUDIT.md` and `CHANGELOG_SECURITY_HARDENING.md`.

Baseline of the **unmodified** `CipherQ_v17_GITHUB_READY` archive
(SHA-256 `5b97ff25…8de8a8`, 162 files, 12 643 backend Python lines).
Written *before* any source change. Every "CONFIRMED (runtime)" finding was
reproduced against the original code, running the real FastAPI app against a
real Mongo-wire server (see *Environment*). Findings marked "static" come from
code reading only; findings marked "needs runtime" were not reproduced.

Evidence files are in `docs/evidence/` (`poc.py`, `poc_race.py`,
`poc_defaultsecret.py`, `baseline_results.json`, `baseline_endpoints.txt`,
`pip_audit_baseline.txt`, `npm_audit_baseline.json`).

## 1. Environment and what could actually be executed

| Item | Result |
|---|---|
| Original archive | Extracted read-only to a separate directory; hash recorded. Never modified. |
| Python 3.13 (machine default) | `pip install -r requirements.txt` **fails/hangs**: `numpy==1.26.4` and `qiskit-aer==0.15.1` publish no cp313 wheels, so pip falls back to a source build (CMake) that did not complete. |
| Python 3.12 | Pinned requirements install cleanly (wheels only). Used for all baseline runs. |
| MongoDB | `mongod` could not be obtained (download host blocked, no Docker daemon). A **real Mongo-wire server (FerretDB 1.24, SQLite backend)** was used instead. It is *not* `mongod`; compatibility was verified only for the operations CipherQ uses. |
| Backend tests in the archive | **None.** `backend/tests/` does not exist although the README says `pytest` runs "the intent-module unit tests". |
| Frontend | `npm ci` exit 0; `npm run build` (vite 8) exit 0, with a >500 kB chunk warning. |
| Dependency scan | `pip-audit` (OSV/PyPI): **54 advisories** (cryptography 43.0.1 ×10, PyJWT 2.9.0 ×21, python-multipart 0.0.9 ×14, pymongo 4.9.1 ×4, qiskit 1.2.4 ×3, python-dotenv 1.0.1 ×2). `npm audit`: **8** (6 high, 2 moderate). |
| Baseline functional run | Register → face enroll → session → monitoring start → intent create → L2 approve → encrypt → decrypt: **works** (HTTP 201/200, plaintext recovered). |

## 2. Architecture as found

* **Backend**: FastAPI, PyMongo, 15 routers, 56 route/method pairs (`docs/evidence/baseline_endpoints.txt`); `/docs`, `/redoc`, `/openapi.json` are also public.
* **Auth**: PBKDF2-HMAC-SHA256 (100 000 it.) + stateless HS256 JWT (`sub, username, role, exp` only), 24 h TTL. Role is taken from the token.
* **Database**: whole-document AES-256-GCM "application encryption" (`database/encrypted_store.py`) that re-implements the PyMongo API by *decrypting entire collections on every query*, keyed by a file/ENV key (`.whole_db_encryption_key`).
* **Intent**: `CID` (pydantic) → canonical JSON → SHA-256. Lifecycle draft→approved→used→… in one state field.
* **Crypto**: BB84 (Qiskit Aer) key returned **to the browser**; browser sends it back on encrypt/decrypt; HKDF(quantum key; salt=session_id; info = `intent_hash|operation|device|auth_state_hash`) → AES-256-GCM, AAD = `intent_hash|auth_state_hash`.
* **Authorization state**: SHA-256 over {intent hash, op, device, session, lifecycle class, policy-outcome signature, session version}.
* **Monitoring**: client posts face presence / confidence / liveness every 10 s; thresholds on consecutive failures move ACTIVE→WARNING→REAUTH_REQUIRED→REVOKED.
* **Audit**: SHA-256 hash chain (pipe-joined fields), unkeyed, stored through the same encrypted store.
* **Frontend**: React/Vite; token in `localStorage`; `device_id`/`session_id` generated client-side.

## 3. Findings register

Severity reflects *actual* exploitability and impact, not appearance. "Precondition" states what an attacker needs.

### Critical

**F-01 — Forgeable admin JWT under default configuration** — CONFIRMED (runtime, `poc_defaultsecret.py`)
`api/dependencies.py::resolve_jwt_secret` falls back to the public string `dev-secret-change-me` whenever `APP_ENV` is not literally `production`; `APP_ENV` defaults to `development`, and the shipped `.env` leaves `JWT_SECRET` commented out. A token forged with that secret and `role=ADMIN` for a **non-existent user id** returned `GET /api/users` → **200**, because role/user are never re-checked against the database.
*Precondition*: deployment started without both `APP_ENV=production` and `JWT_SECRET` (the shipped defaults). *Impact*: full authentication and authorization bypass, including administrator functions. *Fix*: no default secret; startup fails unless a ≥32-byte secret is present in every non-test mode; DB-backed principal resolution. *Tests*: `T-CFG-*`, `T-AUTH-FORGED-DEFAULT`.

### High

**F-02 — Secrets and key material shipped in the archive** — CONFIRMED (static + file listing)
`backend/.env` (identical to `.env.example`), `backend/database/.whole_db_encryption_key` (44-char base64 = 32-byte AES key) and `frontend/.env` are inside the ZIP although `.gitignore` excludes them; the archive is named "GITHUB_READY". The key encrypts every MongoDB document. The archive contains **no database dump**, so the key protects only whatever deployment reuses it; it must nevertheless be treated as compromised. `JWT_SECRET`/`AI_API_KEY` are placeholders only.
*Fix*: remove; placeholder templates; generator script; rotation tooling. *Tests*: `T-PKG-NO-SECRETS`.

**F-03 — Stateless, unrevocable, stale-role sessions** — CONFIRMED (runtime, B06)
No `jti`, no server-side session, no `iss/aud`. After a user's role was changed from ADMIN to USER_LEVEL_1 the old token still listed all users (200); after the user row was **deleted** the old token still authenticated (200). There is no account-disable flag, no logout, no revocation, 24 h lifetime.
*Fix*: per-request principal load from DB (role, `disabled`, `token_version`), `jti` registry with revocation, logout, short TTL.

**F-04 — Self-registration can obtain USER_LEVEL_2** — CONFIRMED (runtime, B04 returned 201 for `role=USER_LEVEL_2`)
USER_LEVEL_2 reads *all* users' intents, reads the **entire audit log**, and may approve other users' intents. Any anonymous visitor can therefore create two accounts, have one create an intent and the other approve it, defeating separation of duties and the approval gate.
*Fix*: self-registration yields USER_LEVEL_1 only; elevation by ADMIN only.

**F-05 — Client-held quantum key; no server-side key custody** — CONFIRMED (runtime, B09a; static)
`POST /api/quantum/generate-key` returns `quantum_key_hex` to the browser; `/api/encrypt` and `/api/decrypt` accept *any* hex key from the client. Consequences: the key is exposed to any script in the page (and, with F-14, to token thieves); the server cannot enforce key lifecycle, expiry or revocation; the client can encrypt under a key unrelated to any BB84 exchange (the BB84 step is optional in practice); aborted exchanges return an empty/unused key that the client may still ignore. The README's claim "no key ever persisted" means key loss = data loss and key custody is entirely off-server.
*Fix*: server-side key sessions; key never leaves the backend.

**F-06 — Concurrency destroys atomicity: duplicate ids, lost updates, one-shot intent bypass, lost audit events** — CONFIRMED (runtime, B17, `poc_race.py`)
`EncryptedCollection.find_one_and_update/update_one` are read→modify→`replace_one` with no compare-and-swap. Observed: 16 concurrent audit writes → many `DuplicateKeyError` (events **lost**, requests 500) and a broken chain; 8 concurrent `/api/encrypt` on one approved "one-shot" intent → **two succeeded** (201,201) and six returned 500. Session `version` bumps, counters and lifecycle transitions are equally racy.
*Fix*: optimistic-concurrency (CAS on the ciphertext nonce) in the encrypted store; atomic lifecycle/use-count consumption.

**F-07 — Continuous-monitoring evidence is entirely client-asserted** — CONFIRMED (runtime, B12)
With no face verification at all, a user created a session via `/sessions/{id}/refresh`, started monitoring with a self-asserted `face_confidence=0.99`, and a forged heartbeat (`face_present=true, liveness=true, confidence=0.99`) kept the status **ACTIVE** and the crypto gate open. A missing heartbeat never degrades state (no timeout).
*Fix*: server-computed match from a probe descriptor, heartbeat nonce chain, heartbeat-gap fail-closed, client liveness recorded as *unverified claim* only.

**F-08 — Biometric enrolment can be replaced by any token holder; match endpoint is an oracle** — CONFIRMED (runtime, B10b/B10d)
`POST /api/face/enroll` overwrites the template with no re-authentication or check of the old template (204 twice). `POST /api/face/verify` returns exact `distance` and `confidence` with no rate limit, so a token holder can hill-climb to a descriptor within threshold of the template (inference attack) or simply re-enrol an attacker face first. (Descriptor is never returned — a positive.)
*Fix*: re-auth + old-face check (or admin) for replacement; boolean-only response; attempt lockout; challenge binding.

### Medium

**F-09 — Whole-DB encryption design weaknesses** — static + runtime (B17)
(a) AAD = collection only: no `_id`, no key id, no version → ciphertext of document X can be copied into document Y of the same collection and rolled back to older versions undetected by a DB writer; (b) one key, no key id, no rotation/migration path (README references `scripts/…migrate…` that is not shipped); (c) `find()` decrypts the **entire collection** for every query → O(N) per request (availability/DoS); (d) `_id` and collection names in clear; (e) no CAS (F-06).

**F-10 — Audit log integrity is weaker than documented** — CONFIRMED (runtime, B17/B18)
Unkeyed SHA-256 chain: a DB writer can recompute the whole chain. Deleting the **last** entry left `verify` **valid** (tail truncation undetected). Field separator `|` is ambiguous (`reason` can contain `|`, shifting content between fields). Concurrent writers fork the chain (F-06). No separate sink. `/api/audit/logs` is unpaginated. Policy changes, incident resolution (device un-revoke), face enrolment and role changes are partly or not audited.

**F-11 — Intent `sender` is not bound to the authenticated user** — CONFIRMED (runtime, B13)
A user created an intent with `sender="SOMEONE-ELSE"`; accepted (201) and later encrypted/decrypted under it. Identity inside the authorization record can be spoofed.

**F-12 — Intent approval is a state flip, not an evidence-backed decision**
`transition → approved` runs the same generic policy/risk validation (device not revoked, within validity, allow-lists empty by default → permissive) and nothing verifies the *purpose* against any record. ADMIN-created zero-risk intents are **auto-approved** without a second person. "Used" is set after encryption but decrypt reuses the intent with `operation=encrypt`, so an intent for *encrypt* silently grants *decrypt* (scope conflation). No data-scope field, no case reference, no version-on-change semantics enforced.

**F-13 — Authorization service lacks independent ownership/device binding; fail-open guards**
`AuthorizationService.authorize` calls `get_or_create(session_id, user_id)` which returns an existing session regardless of owner/device. Ownership is enforced only indirectly (intent creation + hash equality). `/api/authorization/state` does not bind the submitted CID to the intent hash, letting a user probe another session's state hash. `create_intent` and `encrypt` wrap their monitoring/session checks in `hasattr(...)` guards and `getattr(user,"session_id",None)` (never set on `TokenPayload`) so the session-match check is dead code — a pattern that fails open if an attribute is missing.

**F-14 — Token and device identity handling in the browser**
Token in `localStorage` (readable by any XSS); `device_id` and `session_id` are random strings generated by the client (`useAuth.js`) — "device identity" is a client claim, not attestation; frontend `.env` hard-codes a hosted backend URL; `vercel.json` rewrites to it.

**F-15 — No rate limiting, lockout, or abuse controls** — CONFIRMED (runtime, B08/B09b/B11)
40 consecutive wrong logins all answered 401, none throttled. A **1 MB username** registered (201). `n_qubits` unbounded (4000 qubits ran in 0.8 s; larger values scale linearly and are unauthenticated-cost for any user). No body-size, timeout, concurrency or per-user quota.

**F-16 — Password hashing parameters** — static
PBKDF2-HMAC-SHA256 at 100 000 iterations (current OWASP guidance: ≥600 000, or scrypt/Argon2id); no maximum password length (CPU DoS with large bodies); no migration path.

**F-17 — Vulnerable / unreproducible dependencies** — CONFIRMED (scanners)
54 Python advisories and 8 npm advisories (see §1). No lockfile for Python; no Python version declared; `passlib[bcrypt]`, `pydantic-settings` and `python-multipart` are listed but never imported by the code (`grep`), enlarging attack surface (python-multipart alone has 14 advisories).

**F-18 — Missing security headers, exposed docs, information in health** — CONFIRMED (runtime, B01–B03)
No HSTS / X-Content-Type-Options / X-Frame-Options / CSP; Swagger UI public; `/api/health` discloses the database name and encryption flag; CORS uses `allow_methods=["*"]`, `allow_headers=["*"]` with credentials.

**F-19 — HKDF/AAD field encodings are ambiguous** — static
`info` and AAD are `|`-joined strings without length prefixes; a `device_id` containing `|` can shift bytes between fields. Operation is part of the key but the *same* CID/operation serves encrypt and decrypt. Nonce is random 96-bit under a key that is reused across records of the same (session, intent, state) — with random nonces this is acceptable at low volume but has no uniqueness guarantee or per-record key.

### Low / Informational

* **F-20 (Low)** NaN/Inf descriptor values crash `/api/face/verify` with HTTP 500 (CONFIRMED, B10c); descriptors are not range-checked.
* **F-21 (Low)** BB84 bit generation uses NumPy `default_rng` (PCG64, non-cryptographic) and the final key is `SHA256(bits ‖ token_bytes(8))`; abort/insufficient-key cases are signalled only by a flag. Default 256 qubits yields ≈102 final bits (<128).
* **F-22 (Low)** Policy rows are not validated or versioned; policy create/update/delete are not audited; `incidents/{id}/resolve` un-revokes a device without an audit event.
* **F-23 (Low)** Admin self-service `reauthenticate` can restore a revoked own session/device using only a client-supplied descriptor.
* **F-24 (Info)** Location check is advisory and client-asserted (documented as such).
* **F-25 (Info)** README is inconsistent with the archive: missing `docs/`, `scripts/seed_admin.py`, `scripts/generate_whole_db_encryption_key.py`, migration script, `tests/`; it publishes a default bootstrap admin password (`AdminSetup#2026`) for a script that is not shipped; it claims "this sandbox has no network access … syntax-checked but not executed".
* **F-26 (Info)** Qira AI provider key is read from env only (good); its output is advisory and does not gate crypto (good).

### Positive controls observed (verified at runtime)

* Tampered and `alg=none` JWTs → 401 (B07).
* Role-gated admin endpoints use `require_roles`; ownership checks via `require_owner_or_admin` on devices, sessions, monitoring, intents.
* Face descriptor is never returned by any endpoint.
* Policy engine denies expired/out-of-window intents; lifecycle machine rejects invalid transitions.

## 4. Potential issues requiring runtime verification (not reproduced at baseline)

| ID | Question | Planned test |
|---|---|---|
| P-1 | Stale `session_version` after refresh makes older records undecryptable (availability vs. binding trade-off) | `T-CRYPTO-STALE` (new design must define this explicitly) |
| P-2 | `reauthenticate` + approved request race (double consumption) | `T-MON-REAUTH-RACE` |
| P-3 | Qira `/ask` prompt-injection influence on advice | out of scope for authorization; advisory only |
| P-4 | FerretDB vs `mongod` behavioural differences | documented limitation |

## 5. Implementation plan (drives Phases 1–8)

1. **Config/keys**: central `config.py`, fail-closed startup, versioned keyring (HKDF-derived purpose keys), placeholders only, generator + rotation scripts, packaging test. Dependency upgrade on Python 3.12 + lock file.
2. **Auth**: DB-backed principals, `token_version`, `jti` registry, logout/revoke, disable account, scrypt with PBKDF2 migration, rate-limit/lockout, input limits, security headers, size/Content-Type guards, seed-admin script (no default password).
3. **Store**: CAS in `EncryptedCollection`, `_id`-direct reads, v2 envelope (key id, AAD with `_id`), v1 read-compat + migration script.
4. **Crypto**: server-side `quantum_key_sessions`, wrapped under keyring; canonical encoding (typed, length-safe); per-record DEK; context-bound key release; replay protection; CSPRNG BB84.
5. **Intent engine**: intent schema v2 (versioned, enums, case ref, scope, evidence refs), local evidence provider, deterministic purpose-drift rules, signed decisions, signed approval records, crypto contexts bound to a recomputed authorization-state hash.
6. **Monitoring/identity**: server-computed match, nonce chain, heartbeat-gap fail-closed, challenge-bound face step-up, protected enrolment.
7. **Audit**: keyed (HMAC) v2 chain with atomic append, head record, secondary sink, pagination, new event coverage.
8. **Tests + frontend + docs** as listed in the assignment.

No finding above is considered closed until a test in the hardened tree covers it (tracked in `FINAL_SECURITY_AUDIT.md`).
