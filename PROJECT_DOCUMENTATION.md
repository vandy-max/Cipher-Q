# CipherQ — Complete Project Documentation & Changelogs

> Consolidated archive of all project reports, security audits, phase changelogs, and deployment guides.

## Table of Contents

- **ADMIN NAVIGATION FIX REPORT** ($(ADMIN_NAVIGATION_FIX_REPORT.md.Name))
- **APPROVED REFINEMENTS REPORT** ($(APPROVED_REFINEMENTS_REPORT.md.Name))
- **AUTO RECIPIENT KEY PROVISIONING** ($(AUTO_RECIPIENT_KEY_PROVISIONING.md.Name))
- **BUILD VALIDATION** ($(BUILD_VALIDATION.txt.Name))
- **CHANGELOG SECURITY HARDENING** ($(CHANGELOG_SECURITY_HARDENING.md.Name))
- **CIPHERQ FINAL ENHANCEMENTS 2026-11-12** ($(CIPHERQ_FINAL_ENHANCEMENTS_2026-11-12.md.Name))
- **CIPHERQ SECURE SHARE AUTHORIZATION DENIED FIX** ($(CIPHERQ_SECURE_SHARE_AUTHORIZATION_DENIED_FIX.md.Name))
- **CIPHERQ SECURE SHARE BLANK PAGE FIX** ($(CIPHERQ_SECURE_SHARE_BLANK_PAGE_FIX.md.Name))
- **CIPHERQ VITE JSX PARSE FIX** ($(CIPHERQ_VITE_JSX_PARSE_FIX.md.Name))
- **CLAUDE PHASE1 PROMPT** ($(CLAUDE_PHASE1_PROMPT.md.Name))
- **CLAUDE PHASE2 PROMPT** ($(CLAUDE_PHASE2_PROMPT.md.Name))
- **CLAUDE PHASE3 PROMPT** ($(CLAUDE_PHASE3_PROMPT.md.Name))
- **CLAUDE REPAIR PROMPT** ($(CLAUDE_REPAIR_PROMPT.md.Name))
- **DEMO GUIDE** ($(DEMO_GUIDE.md.Name))
- **DOCKER DEPLOYMENT** ($(DOCKER_DEPLOYMENT.md.Name))
- **FINAL SECURITY AUDIT** ($(FINAL_SECURITY_AUDIT.md.Name))
- **FIX REPORT** ($(FIX_REPORT.md.Name))
- **IMPLEMENTATION REPORT THREE FEATURES** ($(IMPLEMENTATION_REPORT_THREE_FEATURES.md.Name))
- **INTENT SECURITY ARCHITECTURE** ($(INTENT_SECURITY_ARCHITECTURE.md.Name))
- **PHASE1 CHANGELOG** ($(PHASE1_CHANGELOG.md.Name))
- **PHASE1 PHASE2 PHASE3 INTEGRATION STATUS** ($(PHASE1_PHASE2_PHASE3_INTEGRATION_STATUS.md.Name))
- **PHASE2 CHANGELOG** ($(PHASE2_CHANGELOG.md.Name))
- **PHASE3 CHANGELOG** ($(PHASE3_CHANGELOG.md.Name))
- **PHASE3 TEST GUIDE** ($(PHASE3_TEST_GUIDE.md.Name))
- **PRODUCTION READINESS** ($(PRODUCTION_READINESS.md.Name))
- **QIRA SHARING MONITORING INTEGRATION** ($(QIRA_SHARING_MONITORING_INTEGRATION.md.Name))
- **QUICK START WINDOWS** ($(QUICK_START_WINDOWS.txt.Name))
- **RUN WINDOWS** ($(RUN_WINDOWS.md.Name))
- **SECURE SHARING WORKFLOW UPDATE** ($(SECURE_SHARING_WORKFLOW_UPDATE.md.Name))
- **SECURITY BASELINE** ($(SECURITY_BASELINE.md.Name))
- **SHARED DECRYPT CASE ASSIGNMENT FIX** ($(SHARED_DECRYPT_CASE_ASSIGNMENT_FIX.md.Name))
- **SIMPLE SECURE MESSAGING** ($(SIMPLE_SECURE_MESSAGING.md.Name))
- **TEST RESULTS** ($(TEST_RESULTS.md.Name))
- **TEST RESULTS PHASE2** ($(TEST_RESULTS_PHASE2.md.Name))

---


## ADMIN NAVIGATION FIX REPORT
*Source file: `ADMIN_NAVIGATION_FIX_REPORT.md`*

# CipherQ Admin Workspace Navigation Fix

## Scope
This patch addresses the administrator UI navigation visibility issue only. It does not change QIRA, backend code, APIs, database schemas, RBAC rules, cryptographic operations, monitoring logic, intent workflows, audit generation, or application business logic.

## Root cause addressed
The sidebar's visibility rules relied on exact role-string comparisons (`user.role === "ADMIN"`) in some places, while the authenticated role is persisted directly from the login response. A casing or whitespace variation could therefore cause the admin-specific navigation treatment to be skipped. Also, the sidebar's collapsed preference could make feature labels appear to have disappeared by rendering the navigation as icon-only.

## Changes
1. `frontend/src/components/layout/Sidebar.jsx`
   - Normalizes the role string using trim + uppercase before applying display rules.
   - Recognizes the existing administrator roles `ADMIN` and `USER_LEVEL_2` for full workspace navigation visibility.
   - Keeps the standard application feature groups visible to administrators even when monitoring re-authentication is pending. This affects navigation visibility only; existing operation-level security gates remain unchanged.
   - Keeps Policy Engine restricted to the existing `ADMIN` display role.
   - Keeps Admin Dashboard as an additional destination rather than replacing the normal CipherQ modules.
2. `frontend/src/components/layout/AppShell.jsx`
   - Starts the admin sidebar expanded so labels such as Audit, Risk Intelligence, Encryption and Decryption are visible immediately.
   - The admin can still manually collapse the sidebar.

## Navigation destinations checked
- Overview / Dashboard
- Identity
- Risk Intelligence
- Audit Trail
- Intent History
- Create Intent
- Encryption
- Decryption
- Secure Share
- Direct Messages
- Quantum Lab
- Admin Dashboard
- Policy Engine (ADMIN only)

Every listed destination has an existing render branch in `frontend/src/App.jsx`.

## Validation performed
- TypeScript JSX transpile/syntax check: PASS for both modified files.
- Static navigation check: PASS; every expected navigation ID exists and has a corresponding App render branch.
- Role-normalization check: PASS.
- Archive integrity check: PASS.
- Files modified: only the two frontend layout/navigation files above. No backend or QIRA files changed.

## Important behavior retained
- Backend RBAC remains the authorization boundary.
- Existing monitoring re-authentication requirements remain in force for protected operations.
- Encryption/decryption ownership, intent, key-session and integrity checks remain unchanged.
- Audit records and risk decisions continue to come from existing backend services; this patch does not fabricate or alter them.

## Test limitation
The full Vite production build and browser end-to-end tests were not run because frontend dependencies are not installed in the supplied project environment. The validation above is limited to syntax/transpile and static navigation checks.

---


## APPROVED REFINEMENTS REPORT
*Source file: `APPROVED_REFINEMENTS_REPORT.md`*

# CipherQ approved refinement report — 15 November 2026

This refinement was applied to a working copy of the uploaded project. The original ZIP was not modified.

## Approved changes

### 1. QIRA password expression
- Password-field focus continues to use the existing QIRA `processing` / closed-eye sprite.
- Removed the `cover` wing-overlay effect from the login and registration password reactions.
- Kept the existing mascot assets, position, size, and reaction priority system.
- Updated QIRA regression tests to assert that the password reaction has no wing overlay.

### 2. Admin dashboard navigation and content
- Inspected all eight existing Admin Dashboard tabs and retained their existing page components, route IDs, role gates, and API wiring.
- Added an in-flight guard to the Intent Approval polling request so a slow response cannot accumulate overlapping four-second requests.
- Corrected the Admin Live Monitoring status label so an individual failed frame does not independently show WARNING before the backend's third consecutive failure. Identity details remain visible separately.

### 3. Secure Share recipient independence
- Preserved the existing recipient-owned key-session provisioning, wrapped-key handling, recipient authorization, face step-up, expiry, integrity verification, and revocation checks.
- Added a regression test that creates an approved share, logs the sender out, and then verifies that the recipient can decrypt it with the recipient's own session.
- No sender-session dependency was added to recipient decryption, and no recipient authentication requirement was removed.

### 4. Live monitoring performance and QIRA synchronization
- Added `analyzeFace()` to run detection, landmarks, and descriptor extraction in one face-api pass.
- Changed the continuous-monitoring tick and returning-user verification path to use that combined result rather than running detection twice on the same frame.
- Kept the existing server-side identity comparison, heartbeat nonce, leader election, camera warm-up handling, and backend-authoritative monitoring snapshot.
- Updated the shared monitoring-state mapping so QIRA and monitoring surfaces follow the backend's status rather than promoting an aggregate risk score to a separate frontend-only HIGH-RISK state.

### 5. Authentication failure thresholds
- Updated defaults to WARNING at 3, RE-AUTHENTICATION at 6, and REVOKED at 8 consecutive face/liveness failures.
- The intermediate risk-increase threshold is also 3, so the warning begins at the requested third failure.
- Successful verification continues to reset the consecutive counter.
- Camera/network interruptions remain separate from identity failures.
- Existing records written with either previous default tuple (2/3/8/12 or 2/3/4/6) are interpreted using the new defaults without rewriting the database. Explicitly customized threshold tuples are preserved.
- Updated QIRA's deterministic baseline and advisory merge guard so QIRA cannot jump ahead of the backend's 3/6/8 face-failure sequence.

### 6. Performance
- Removed duplicate face detection/descriptor work per monitoring sample.
- Prevented overlapping Admin Intent Approval polling requests.
- Preserved the existing monitoring cadence and security checks rather than increasing polling frequency or bypassing checks for apparent speed.

## Files changed

- `frontend/src/qira/qiraReactionsExtended.js`
- `frontend/src/qira/qiraExtended.test.js`
- `frontend/src/components/qira/QiraDock.playful.test.jsx`
- `frontend/src/pages/AdminDashboard.jsx`
- `frontend/src/components/monitoring/monitoringState.js`
- `frontend/src/components/qira/QiraEventBridge.test.jsx`
- `frontend/src/services/faceIdentity.js`
- `frontend/src/context/MonitoringContext.jsx`
- `backend/monitoring/state.py`
- `backend/monitoring/service.py`
- `backend/api/repositories.py`
- `backend/qira/policy.py`
- `backend/qira/service.py`
- `backend/tests/test_31_monitoring_stabilization.py`
- `backend/tests/test_32_monitoring_threshold_policy.py`
- `backend/tests/test_33_secure_sharing.py`

## Verification performed

- Python compilation: passed (`python -m compileall`).
- Threshold and QIRA policy unit tests: passed (3 tests in `backend/tests/test_32_monitoring_threshold_policy.py`).
- Node syntax checks: passed for the changed standalone JavaScript modules (`faceIdentity.js`, `monitoringState.js`, `qiraReactionsExtended.js`, and `qiraExtended.test.js`).
- Full backend integration tests could not be run in this build environment because `pymongo` and `qiskit` are not installed and package installation is unavailable (network/DNS unavailable).
- Frontend tests and production build could not be run because `node_modules` is absent and `npm ci --offline` could not retrieve uncached packages.
- The sender-logout Secure Share regression test and browser/camera integration behaviour are included in the package but remain unverified here; run them in the project's normal development environment before deployment.

## Preservation checklist

- No database reset or migration was run.
- No `.env`, JWT secret, keyring, or generated key material was created or replaced.
- No encryption/decryption algorithm or key-derivation workflow was changed.
- No role, permission, intent, audit, deployment, or existing navigation workflow was removed.
- The original uploaded ZIP remains unchanged.

---


## AUTO RECIPIENT KEY PROVISIONING
*Source file: `AUTO_RECIPIENT_KEY_PROVISIONING.md`*

# Automatic Recipient Key Provisioning

This targeted update removes the manual recipient key-session activation prerequisite for Secure Share.

## Behavior
- The sender still needs their own active key session for the existing intent-bound encryption operation.
- The sender must pass the existing authenticated share authorization decision.
- The backend reuses an active key session owned by the recipient when one exists.
- If none exists, the backend creates a recipient-owned session through the existing KeySessionService.
- The per-user key-establishment rate limit is shared with the ordinary key-session endpoint.
- The session key remains wrapped by the existing QKEY_WRAP keyring mechanism. The sender/browser never receives the recipient key.
- The session is retained only through the computed share expiry.
- The recipient still needs normal login, a fresh face-verification grant, and an approved decrypt decision before plaintext is returned.

## Compatibility
- Existing requests with an explicit `recipient_key_session_id` continue to work and are ownership/status checked.
- Existing key-session, encryption, decryption, RBAC, audit, monitoring, and message workflows are not intentionally changed.
- This uses CipherQ's existing simulated BB84 key-session architecture. BB84 here is a software simulation, not physical quantum key distribution.

## Validation
- Python syntax compilation passed for the changed backend router and sharing integration test.
- The focused pytest module could not run in this environment because `pymongo` is not installed. Install the project's backend requirements and run `pytest tests/test_33_secure_sharing.py -q` from `backend` to execute the integration suite.
- Frontend production build was not run because frontend dependencies are not installed in this environment.

---


## BUILD VALIDATION
*Source file: `BUILD_VALIDATION.txt`*

CipherQ Simple Secure Messaging build validation

Passed:
- Python compileall for backend source.
- Direct-message AES-GCM/key-wrapping checks: sender and recipient can unwrap the same per-message DEK; a third party cannot; AAD substitution fails authentication.
- Direct-message request-model checks: valid text and file payloads accepted; incomplete payloads rejected.
- JavaScript syntax checks for frontend API and share payload utility.
- JSX syntax transpilation check for ShareMessagesPage.jsx.
- ZIP archive integrity check.

Not completed in this build environment:
- Full FastAPI + MongoDB integration tests (PyMongo is not installed in this isolated build environment and package registry access is unavailable).
- Vite production build and full frontend test suite (frontend node_modules are not installed; existing tests also require Vitest, which is not present in the package install available here).

Before using against real data, run the backend tests and `npm ci`, `npm run build`, and `npm test` on the target Windows machine with its configured MongoDB and original keyring. Do not generate replacement keys for an existing encrypted database.

---


## CHANGELOG SECURITY HARDENING
*Source file: `CHANGELOG_SECURITY_HARDENING.md`*

# CipherQ v17 → v18 — Security hardening changelog

Source of truth for "previous behaviour": `SECURITY_BASELINE.md` (reproduced against the unmodified v17 archive,
SHA-256 `5b97ff2552aa443e86a0d457b340d739ccf8586cc4217b006e300f17148de8a8`). The original ZIP was never modified.
Test names are in `backend/tests/` (file prefix in brackets). "Live e2e" = `backend/scripts/e2e_workflow.py`.
Finding ids F-xx refer to the baseline.

## A. Findings fixed

| ID | Sev | File(s) | Previous behaviour | New behaviour | Rationale | Verifying test |
|---|---|---|---|---|---|---|
| F-01 | Critical | `config.py`, `api/dependencies.py`, `authentication/jwt_service.py` | Fallback JWT secret `dev-secret-change-me` unless `APP_ENV=production`; role trusted from token; forged ADMIN token for a non-existent user got 200 on `/api/users`. | No default secret in any mode other than `development`/`test`; dev secret is random, 0600, git-ignored. Strict envs refuse to start without a ≥32-byte secret from a private file. JWT carries `iss/aud/jti/tv`; principal is loaded from the DB on every request. | Removes the public-secret auth bypass; token claims are no longer authority. | [03] `test_jwt_forgery_variants_rejected`, `test_role_claim_in_token_is_not_trusted`; [70] `test_validly_signed_but_unregistered_token_rejected`, `test_wrong_audience_issuer_and_unsigned`; [80] `test_no_default_secret_fallback_outside_development`, `test_production_fails_closed` |
| F-02 | High | repo tree, `.gitignore`, `config.py`, `scripts/generate_secrets.py` | ZIP shipped `backend/.env`, `database/.whole_db_encryption_key` (32-byte AES key), `frontend/.env`. | Files removed; only `.env.example` placeholders; generator writes 0600 files; the v17 key value is explicitly rejected at startup; packaging test scans the tree. **The v17 key must be treated as compromised.** | Secrets must not travel with source. | [80] `test_no_secrets_or_keys_in_source_tree`, `test_v17_shipped_key_is_rejected`, `test_generate_secrets_script`, `test_secret_files_must_be_private`, `test_settings_repr_does_not_leak_secrets` |
| F-03 | High | `api/dependencies.py`, `api/routers/auth.py`, `api/routers/users.py`, `database/models.py` | Stateless 24 h tokens; no revoke; role change/user delete did not affect live tokens. | 30 min tokens, `jti` registry, `token_version`, `disabled` flag; `/logout`, `/logout-all`; demotion/disable/unlock endpoints; last enabled admin cannot be removed. | Server-side authority over sessions. | [03] `test_demotion_invalidates_old_admin_token`, `test_disabled_account_loses_access_immediately_and_cannot_login`, `test_logout_revokes_only_that_token`, `test_logout_all_revokes_every_token`, `test_last_admin_cannot_be_demoted_or_disabled`; [70] `test_revoked_session_token_and_logout`, `test_expired_token_rejected` |
| F-04 | High | `api/routers/auth.py`, `api/schemas.py` | `role=USER_LEVEL_2` accepted at self-registration. | Registration always yields `USER_LEVEL_1`; unknown fields rejected; only an admin can change roles. | Separation of duties. | [03] `test_self_register_ignores_requested_role`, `test_register_rejects_unknown_fields`; [70] `test_cannot_self_promote`, `test_vertical_privilege_escalation_blocked`; live e2e "self-registration cannot create an admin" |
| F-05 | High | `keymgmt/key_sessions.py`, `api/routers/key_sessions.py`, `crypto/records.py`, `api/routers/crypto_ops.py` (new), removed `/encrypt`,`/decrypt`,`/quantum/generate-key` | BB84 key returned to the browser, which sent any hex key back to encrypt/decrypt. | Server-side key sessions (ACTIVE/ROTATED/REVOKED/EXPIRED/ABORTED); key wrapped under a keyring subkey; never returned; rotate, revoke (key destroyed), re-wrap; encryption only through an authorization-bound context. | Key custody and lifecycle on the server. | [40] `test_api_ciphertext_not_plaintext_and_no_key_in_responses`, `test_api_key_lifecycle_*`, `test_api_key_sessions_not_stored_in_clear`, `test_api_other_user_cannot_touch_key_session`; [50] `test_client_cannot_choose_key_material` |
| F-06 | High | `database/encrypted_store.py`, `audit/service.py`, `authentication/throttle.py` | read→modify→replace with no atomicity: lost updates, duplicate ids, one-shot intent used twice, lost audit events. | Per-collection lock + compare-and-swap on the stored envelope; atomic `get_next_id`, atomic consume; audit append retries on duplicate sequence. **Single process only**, see limitations. | Correctness under concurrency. | [02] `test_concurrent_increments_lose_no_updates`, `test_get_next_id_is_unique_under_concurrency`, `test_one_shot_consume_has_exactly_one_winner`; [20] `test_14b_concurrent_replay_has_one_winner`; [60] `test_concurrent_audit_writes_keep_a_valid_chain`; [03] `test_concurrent_duplicate_registration_single_winner` |
| F-07 | High | `monitoring/service.py`, `api/routers/monitoring.py`, `identity/stepup.py`, `api/schemas.py` | Client-asserted face confidence/liveness; forged heartbeat kept ACTIVE; no heartbeat timeout. | `/monitoring/start` needs a fresh server-side step-up grant; heartbeat carries `probe_descriptor` compared server-side plus a nonce chain (`prev_nonce`); client flags can only fail a tick; heartbeat gap latches `REAUTH_REQUIRED`; admins cannot forge a user's tick; owner can resync the nonce via GET. | Remove client-reported evidence from the trust path. | [30] `test_forged_heartbeat_cannot_keep_session_alive`, `test_heartbeat_replay_and_wrong_nonce_rejected`, `test_monitoring_interruption_latches_reauth`, `test_monitoring_requires_server_verified_stepup`, `test_repeated_failed_ticks_fail_closed_and_stepup_restores`, `test_owner_can_resync_nonce_admin_cannot` |
| F-08 | High | `api/routers/face.py`, `identity/stepup.py`, `authentication/face_auth.py` | Enrolment replaceable by any token holder; `/face/verify` returned distance/confidence unthrottled. | `/face/verify` removed. Enrol needs password re-entry (+ fresh step-up to replace); step-up uses single-use session-bound challenges, boolean response, replay-hash rejection, lockout; admin-only reset. Grants state `liveness="NOT_ESTABLISHED"`. | Block template overwrite and hill-climbing. | [30] `test_enrolment_replacement_requires_password_and_stepup`, `test_challenge_single_use_and_session_bound`, `test_verify_response_is_not_an_oracle`, `test_identical_descriptor_replay_rejected`, `test_lockout_after_repeated_failures`, `test_stepup_grant_states_no_liveness` |
| F-09 | Med | `database/encrypted_store.py`, `security/keyring.py`, `scripts/reencrypt.py` | AAD = collection only, single key, no rotation, full-collection decrypt per query. | Envelope v2: AAD = collection/`_id`/key id; versioned keyring with HKDF purpose subkeys; direct `_id` reads; migration/rotation script; v1 read-compat only with explicit legacy key. | Prevent cross-document copy/rollback, enable rotation. | [02] `test_ciphertext_moved_to_other_id_or_collection_is_rejected`, `test_tampered_ciphertext_rejected`, `test_stored_documents_are_ciphertext`; [80] `test_reencrypt_after_key_rotation_and_verify_audit` |
| F-10 | Med | `audit/hash_chain.py`, `audit/service.py`, `api/repositories.py`, `audit/events.py`, `api/routers/audit.py` | Unkeyed SHA-256 chain, tail truncation undetected, `\|` ambiguity, forks under concurrency, no second sink, missing events. | HMAC chain (audit-mac subkey) over a framed canonical body incl. sequence/timestamp/key id; sealed head record; append-only 0600 fsynced secondary sink, cross-checked on verify; sink failure fails closed in strict envs; new events (policy, enrolment, role, drift, contexts, admin bootstrap). | Tamper-evident against a DB-only attacker. | [60] all 15, esp. `test_deleted_last_record_detected`, `test_attacker_cannot_recompute_chain_without_key`, `test_secondary_sink_catches_full_db_rewrite`, `test_truncation_with_head_also_deleted_detected`, `test_sink_failure_fails_closed_when_required` |
| F-11 | Med | `intent_engine/schema.py`, `engine.py` | Client-supplied `sender` accepted. | `sender`, owner, required approvals, status, policy version are server-set; extra fields rejected. | Bind identity to the authenticated user. | [10] `test_client_cannot_set_server_fields` |
| F-12 | Med | `intent_engine/*`, `api/routers/intents.py`, `decisions.py`, `evidence.py` | Approval = state flip; admin intents auto-approved; encrypt intent granted decrypt; no scope/case. | Intent schema v2, versioned, MAC-sealed approvals bound to version/body hash, distinct approvers (2 for RESTRICTED), no self-approval, operations and data scope enforced, evidence from case table, deterministic drift rules, signed decisions and single-use authorization-bound contexts. See `INTENT_SECURITY_ARCHITECTURE.md`. | Core Phase-4 feature. | [10] all; [20] 18 acceptance tests + 5 extras |
| F-13 | Med | `api/routers/authorization.py`, `intent_engine/engine.py` | Sessions get-or-created for any id/owner; dead `hasattr` guards that fail open; state probe unbound. | Server issues device/session ids bound to the caller; `refresh` cannot create; `reauthenticate` needs a challenge; engine verifies session owner/device/validity on every decision, fails closed on error. | Remove fail-open guards. | [30] `test_refresh_cannot_create_sessions`, `test_session_creation_requires_owned_unrevoked_device`, `test_revoked_device_blocks_operations`; [70] `test_horizontal_access_to_devices_sessions_blocked`, `test_cannot_start_monitoring_on_foreign_session`; [20] 05, 06 |
| F-14 | Med | `frontend/src/hooks/useAuth.js`, `services/api.js` | Client-generated device/session ids; v17 calls with client key. | Ids issued by the API; client holds only opaque ids; old endpoints removed. **Token remains in `localStorage`** (residual). | Device identity no longer a client claim. | Live e2e; [20] 17 (frontend manipulation) |
| F-15 | Med | `security/ratelimit.py`, `security/http.py`, `authentication/throttle.py`, `api/routers/key_sessions.py`, `config.py` | No throttling, 1 MB username accepted, unbounded qubits. | IP + account throttles with lockout (pessimistic attempt counting), body-size and content-type guards, field bounds, qubit cap, concurrency gate, per-user quota. | Abuse resistance. | [03] `test_ip_rate_limit_on_login`, `test_lockout_*`, `test_oversized_body_rejected`; [50] `test_excessive_qubits_rejected`, `test_per_user_quota`, `test_concurrency_gate_sheds_load`; [70] `test_concurrent_login_attempts_are_throttled`, `test_oversized_bodies_and_strings` |
| F-16 | Med | `authentication/password.py`, `config.py` | PBKDF2 100k, no length cap. | scrypt (log_n ≥ 15 enforced in strict envs), max length, password must not contain username, legacy PBKDF2 hashes verify and upgrade. | Current KDF guidance. | [03] `test_weak_passwords_rejected`, `test_password_may_not_contain_username` |
| F-17 | Med | `requirements*.txt`, `frontend/package*.json` | 54 Python advisories; unused `passlib`, `pydantic-settings`, `python-multipart`; no lock. | Pinned, upgraded dependencies on Python 3.12; unused packages removed. `pip-audit` of the final environment: runtime packages clean (only `pip` tooling reported); `npm audit --omit=dev`: 0. 7 npm advisories remain in **dev/build-time** tailwind→postcss chain (fix requires a breaking Tailwind 4 migration). | Supply chain. | `docs/evidence/pip_audit_final.txt`, `npm_audit_final.json` |
| F-18 | Med | `security/http.py`, `api/main.py`, `config.py` | No security headers, public Swagger, verbose health, wildcard CORS. | Headers (HSTS option, nosniff, frame deny, CSP, cache-control), docs off in strict envs, minimal health, exact-origin CORS with explicit methods/headers, Host allow-list. | Hardening. | [03] `test_security_headers_present`, `test_cors_rejects_unlisted_origin`; [01] `test_health_is_minimal`; [70] `test_docs_disabled_in_strict_env_config` |
| F-19 | Med | `security/canonical.py`, `crypto/records.py`, `intent_engine/engine.py` | `\|`-joined HKDF info/AAD; shared key across records. | Typed, NFC, float-free, length-framed canonical encoding; per-record DEK wrapped under a derived RWK; AAD binds record/owner/intent/version/resource/classification/size. | Remove ambiguity. | [40] `test_unit_canonicalisation_is_unambiguous`, `test_unit_wrong_key_and_wrong_binding_fail`, `test_unit_roundtrip_and_fresh_randomness` |
| F-20 | Low | `api/routers/face.py`, `api/schemas.py` | NaN/Inf descriptor → 500. | Strict descriptor validation (length 128, finite, range, non-degenerate). | Input validation. | [70] `test_nan_face_descriptor_not_500`; [30] `test_descriptor_validation` |
| F-21 | Low | `quantum/bb84.py`, `quantum/service.py` | Non-crypto RNG for bit choice; short key; abort only a flag. | `secrets`-based choices; QBER threshold abort → no key; entropy accounting; minimum sifted material; explicit simulation notice. | Honest simulation. | [50] `test_bb84_unit_entropy_accounting_and_abort`, `test_eavesdropping_is_detected_and_no_key_established`, `test_insufficient_sifted_material_rejected` |
| F-22 | Low | `api/routers/policies.py`, `api/routers/security.py`, `intent_engine/engine.py` | Policy create/update/delete and incident resolution (which un-revokes a device) were not audited. | Policy changes emit `POLICY_CHANGED` and incident resolution emits `QIRA_INCIDENT_RESOLVED`, both naming the acting admin; the policy-set hash is part of the policy version that every decision and context binds to. *Incident-resolution auditing is covered by code review only — no automated test creates an incident.* | Accountability. | [70] `test_policy_changes_are_audited`; [20] `test_13_stale_policy_decision_not_honoured` |
| F-23 | Low | `api/routers/authorization.py`, `reauth_requests.py` | Self-service `reauthenticate` with a client descriptor. | Needs a single-use challenge + server-side match; revoked device/session also needs admin-approved request. | Prevent self-restore. | [30] `test_reauthenticate_needs_challenge_and_rejects_replay`, `test_regular_user_cannot_reauthenticate_revoked_session_without_admin_approval` |
| F-25 | Info | `README.md`, `docs/OPERATIONS.md` | README inconsistent, published a default admin password. | Rewritten; no default credentials. | Accuracy. | review |
| F-24, F-26 | Info | — | Location advisory/client-asserted; Qira advisory. | **Unchanged** (documented). | — | — |

## B. Issues found by the new tests during hardening

| Issue | File | Before | After | Test |
|---|---|---|---|---|
| Login throttle race: 20 concurrent wrong guesses were all evaluated | `authentication/throttle.py` | counted after verification | atomic `$inc` *before* verification (`begin_attempt`) | [70] `test_concurrent_login_attempts_are_throttled` |
| `monitoring.stop` crashed (naive vs aware datetime) | `monitoring/service.py` | `TypeError` | `_aware()` normalisation | [30] `test_monitoring_stop_removes_authorization` |
| `reauthenticate` not challenge-bound; sessions creatable from client ids via refresh/reauth | `api/routers/authorization.py`, `schemas.py` | descriptor replay possible | challenge-bound; 404 for unknown sessions | [30] `test_reauthenticate_needs_challenge_and_rejects_replay`, `test_refresh_cannot_create_sessions` |
| Invalidated contexts reported as replay (409) | `intent_engine/engine.py` | 409 | 403 `CONTEXT_INVALIDATED` | [20] 15, 15b |
| Naive datetimes from audit repo | `api/repositories.py` | mixed tz | normalised to UTC | [60] |
| Test route leaked into route-matrix | `tests/test_03_auth.py` | pollution | cleanup + exclusion | [70] route matrix |

## C. New components

`backend/intent_engine/`, `backend/security/`, `backend/keymgmt/`, `backend/identity/`, `backend/crypto/records.py`,
`backend/scripts/{generate_secrets,seed_admin,reencrypt,verify_audit,e2e_workflow}.py`, `backend/tests/` (the
original archive had **no** tests), frontend integration (api client, step-up, key sessions, intents v2, decisions,
approval/evidence admin UI, audit verification display).

---


## CIPHERQ FINAL ENHANCEMENTS 2026-11-12
*Source file: `CIPHERQ_FINAL_ENHANCEMENTS_2026-11-12.md`*

# CipherQ focused enhancements — 12 November 2026

This update is based on the previously supplied `CipherQ_SharedRecipient_Decrypt_CaseFix.zip`.
It preserves the previous approved-share recipient decryption case-assignment fix.

## 1. Secure Share uses the Create Intent attachment
- The Secure Share composer no longer accepts a free-text message or a second file upload.
- It displays the attachment metadata from the selected approved intent.
- On send, the client retrieves the CID attachment through the authenticated intent attachment endpoint, bound to the sender's authenticated session, device and selected sender key session.
- The backend verifies intent integrity, approval, validity, evidence, session/device and key-session ownership before returning the attachment bytes.
- The client builds the existing `CIPHERQ_ATTACHMENT_V1` payload and passes it through the existing encryption and secure-share path.
- The recipient's existing decryption pipeline recognizes the attachment envelope, verifies SHA-256 and offers the original file for download.
- Direct Messages remain the place for text conversations. Existing legacy text shares remain readable for backwards compatibility.

## 2. Monitoring and QIRA
- The existing serialized monitoring heartbeat cadence and backend-authoritative status flow are preserved.
- QIRA now also mirrors the monitoring backend connection state: temporary backend/network unavailability raises the existing `api.unavailable` reaction; a restored connection clears that reaction.
- Existing warning, re-authentication and revoked reactions remain unchanged. Connectivity loss is not misclassified as a confirmed security attack.

## 3. Administrator visibility
- Administrator accounts retain visibility of all standard navigation areas even when the monitoring UI is blocked.
- Backend authorization remains authoritative; no API/RBAC guard was relaxed.
- Admin dashboard tabs wrap responsively instead of relying on a horizontally clipped tab strip.

## Regression and compatibility
- Added backend regression coverage for authenticated retrieval of an approved CID attachment using the sender's key session.
- Existing attachment integrity validation and existing recipient share/decryption checks are retained.
- No database reset, migration, or key regeneration is required.

## Validation performed in the packaging environment
- Python syntax compilation: changed backend modules.
- JSX/TS transpilation syntax check: changed frontend modules.
- ZIP integrity check.
- Full MongoDB integration tests and full Vite production build require the project's installed dependencies and configured MongoDB and were not run in this packaging environment.

---


## CIPHERQ SECURE SHARE AUTHORIZATION DENIED FIX
*Source file: `CIPHERQ_SECURE_SHARE_AUTHORIZATION_DENIED_FIX.md`*

# Secure Share AUTHORIZATION_DENIED correction

## Root cause
The Secure Share frontend retrieves the approved Create Intent attachment before encrypting it. The backend incorrectly evaluated this owner-only source-attachment retrieval as a `decrypt` operation. Intents that correctly permit `encrypt` and `share` but do not permit standalone `decrypt` were therefore rejected with `AUTHORIZATION_DENIED`.

The previous path also converted all unmet authorization preconditions into the same generic error, obscuring monitoring re-authentication requirements.

## Changes
- Evaluate sender retrieval of their own approved CID attachment as `encrypt`, not `decrypt`.
- Continue to enforce owner/recipient eligibility, approved intent state, integrity, approvals, validity, evidence, session/device ownership, monitoring, active sender key-session ownership, scope and use limits.
- Return the actual authorization reason code when a precondition fails instead of collapsing it into `AUTHORIZATION_DENIED`.
- Secure Share now detects the backend-authoritative `reauth_required` monitoring state and presents the existing challenge-bound face re-authentication flow before fetching the CID attachment.
- After successful reauthentication and monitoring restoration, the original share submission is retried.
- A revoked device remains blocked and must go through administrator approval; no monitoring or RBAC check is bypassed.
- Regression test now verifies CID attachment retrieval for an intent that permits `encrypt` and `share` without granting standalone `decrypt`.

## Validation
- Modified backend Python files compile successfully.
- Modified ShareMessagesPage JSX syntax check passes.
- ZIP integrity check passes.
- Backend integration test collection could not run in this packaging environment because `pymongo` is not installed. Run `pytest tests/test_10_intent_flow.py -q` in the project's configured backend virtual environment.

---


## CIPHERQ SECURE SHARE BLANK PAGE FIX
*Source file: `CIPHERQ_SECURE_SHARE_BLANK_PAGE_FIX.md`*

# Secure Share blank-page fix

## Root cause
`ShareCard` rendered both Sent and Received rows using `fmt(...)`, but the function was not defined or imported in `ShareMessagesPage.jsx`. Once a share existed and the Sent/Received list attempted to render a card, React threw a runtime ReferenceError and the page appeared blank.

## Fix
- Added the shared `formatTimestamp` import and a local `fmt` adapter.
- Converts numeric share timestamps from backend Unix seconds to milliseconds before formatting.
- Handles missing/invalid optional timestamps using the shared formatter's safe fallback.
- The existing Sent/Received cards, sender/recipient labels, status badges, validity timestamps, and decrypt navigation remain intact.
- Recipient decryption continues to pass the share ID to the existing Decryption workflow, which uses the approved share record and existing authorization/face-verification checks.

## Validation
- ShareMessagesPage JSX syntax check: passed.
- Existing file/text share payload tests: 5 passed.
- Full browser interaction and MongoDB-backed recipient/sender test still needs to be run in the user's configured environment.

---


## CIPHERQ VITE JSX PARSE FIX
*Source file: `CIPHERQ_VITE_JSX_PARSE_FIX.md`*

# Vite dependency-scan JSX parse fix

## Root cause
`frontend/src/components/monitoring/monitoringState.js` contained the Secure Share React page JSX instead of the monitoring-state utility functions. Vite correctly rejected JSX in a `.js` utility module during dependency scanning.

## Fix
- Restored `monitoringState.js` as a plain JavaScript utility module.
- Restored the backend-authoritative monitoring-state labels and `deriveMonitoringState` / `monitoringReason` helpers.
- Kept the actual Secure Share page in `frontend/src/pages/ShareMessagesPage.jsx`.
- No monitoring cadence, authorization, encryption, decryption, sharing, or RBAC workflow was changed by this correction.

## Validation
- Scanned all 91 frontend JS/JSX/TS/TSX source files with the TypeScript parser: passed.
- `monitoringState.js` no longer contains JSX.
- ZIP integrity check: passed.
- A Vite production build was not run in this packaging environment because frontend `node_modules` is not installed. Run `npm ci` then `npm run build` in the frontend folder to validate with the project's exact Vite toolchain.

---


## CLAUDE PHASE1 PROMPT
*Source file: `CLAUDE_PHASE1_PROMPT.md`*

# Claude Prompt — CipherQ Phase 1 only: Same-user encryption/decryption continuity

You are modifying an existing CipherQ v18 codebase, not creating a new application. Treat the supplied ZIP as the source of truth. Work only on Phase 1: same-user encryption/decryption with key continuity. Do not implement user-to-user sharing changes, attachment encryption changes, or live-monitoring changes in this phase.

## Required behavior
A user creates an approved intent with `valid_from` and `valid_until`. During that validity window, the same authenticated user must be able to encrypt a message and later decrypt that exact saved record, including after logout/login or from another device. The user must retrieve the original ciphertext and the system must recover the original record's key; do not re-encrypt the stored record just because a device or login session changes.

## Security model
- Bind record ownership to the authenticated server-side immutable user ID, never a client-supplied owner ID or username.
- Treat device ID and login session ID as current authorization/audit context, not as the permanent owner identity or as the only means to recover the record's encryption key.
- For a new device, require a new valid session and the existing device ownership, revocation, monitoring, risk, step-up/face-auth, policy, intent approval, and evidence checks. Do not bypass these controls and do not copy or spoof the old device/session IDs.
- Permit cross-device continuation only for decryption of a record owned by the authenticated actor and the same approved intent/version. Encryption and sharing must retain their existing binding behavior.
- Do not permit another user to access the record by changing request fields or guessing IDs.
- Do not weaken AEAD, integrity, RBAC, intent approvals, evidence, audit, rate limits, or fail-closed behavior.

## Key continuity and validity
- Inspect the existing `keymgmt/key_sessions.py`, `crypto/records.py`, `crypto/sharing.py`, `intent_engine/engine.py`, `intent_engine/drift.py`, `api/routers/crypto_ops.py`, key-session routes, frontend encryption/decryption pages, and existing tests before changing code.
- Set the default key-session lifetime to exactly 24 hours (86,400 seconds), matching the encrypted-record maximum lifetime of 24 hours (86,400 seconds). Update both the Settings dataclass default and environment parsing default, and update backend/.env.example. Keep an owner's key session recoverable at least until the latest still-valid record using it expires, while never extending beyond each record's allowed expiry. A record must still expire at the earlier of its 24-hour record limit and the approved intent valid_until. Add a regression test asserting the default is 86,400 seconds. Never silently regenerate a missing, revoked, expired, or corrupt key.
- A record's expiry must be no later than both the approved intent `valid_until` and the existing record-retention limit. Check the validity window on every encrypt/decrypt request server-side.
- Existing ciphertext and encrypted database records must remain intact. Do not change database names, delete data, rotate keyrings, migrate records, or alter secrets unless absolutely required and explicitly documented. If backward compatibility needs a migration, implement it safely and default to dry-run.
- The same message record ID and ciphertext should be used when decrypting from another device. Randomized encryption may create different ciphertext for a separate encryption operation; that is expected.

## Edge cases to test
1. Same device and same login session round-trip.
2. Same user after logout/login with a new session.
3. Same user on a second newly registered device with a new session, successful step-up, and active monitoring.
4. Different user attempts record lookup/decryption.
5. Spoofed user ID, owner ID, device ID, session ID, or record ID.
6. Device revoked; session expired/revoked; monitoring stopped or failed; step-up missing/stale.
7. Before `valid_from`, exactly at the allowed boundary, after `valid_until`, and malformed/reversed validity windows.
8. Key session expires, is rotated, revoked, or its wrapped key is corrupt; no silent key regeneration.
9. Tampered ciphertext, nonce, authentication tag, wrapped DEK, record metadata, or key reference.
10. Server restart and database persistence; two concurrent requests; duplicate insert/update races.
11. Older records and existing encrypted database documents remain readable where their original keys and validity permit.
12. Record expiry is no later than intent expiry, and key-session availability covers each live record.

## Implementation requirements
- Make the smallest safe changes to the existing architecture; do not replace the crypto or authorization subsystems.
- Add deterministic unit tests and API integration tests using the project's existing test helpers. Update frontend code only if the existing flow cannot naturally use the current authorized session/device for decrypt.
- Ensure API responses never expose quantum keys, wrapping keys, plaintext in logs, or secret values.
- Run formatting/static checks if configured, compile all changed Python files, run all existing tests, and add regression tests. Do not claim tests passed if they were not run. Report any environment-dependent tests blocked by missing MongoDB/dependencies.
- Inspect the final diff for unintended changes. Preserve unrelated features and existing database/key files.

## Deliverables
Return a runnable ZIP of the full existing project with only Phase 1 changes, a concise changelog, the exact files changed, test commands/results, known limitations, and setup/run instructions. Exclude `.env`, private key material, `.dev_secrets*`, virtual environments, `node_modules`, caches, and build artifacts. Do not proceed to Phase 2 until the user has evaluated Phase 1 and explicitly approves it.

---


## CLAUDE PHASE2 PROMPT
*Source file: `CLAUDE_PHASE2_PROMPT.md`*

# Claude Prompt — CipherQ Phase 2 Secure Sharing (Minimal Patch)

Use the supplied `CipherQ_Phase1_Same_User_Key_Continuity_24H.zip` as the baseline and inspect the included `PHASE2_CHANGELOG.md` and `TEST_RESULTS_PHASE2.md`.

Implement/verify Phase 2 only: secure user-to-user sharing, recipient-bound intent, recipient inbox, per-share administrator approval, and access control. Do not rebuild CipherQ or modify unrelated working features. Preserve Phase 1 same-user key continuity, the 24-hour key-session default and record maximum, existing crypto algorithms, key management, authentication, RBAC, intent lifecycle, device/session checks, face verification, audit, and monitoring.

Before changing code, inspect the current implementation. Make only the smallest necessary changes. Never reset the database, rotate keys, bypass authorization, or expose plaintext/raw keys in logs or notifications.

Required behavior:
1. Intent creation can explicitly enable `share` and bind one stable recipient user ID; usernames are display/selection values only.
2. Sender creates a share for an existing owned ciphertext and a valid approved intent bound to that recipient.
3. The server selects/verifies a recipient-owned active key session when no recipient key-session ID is provided by the client.
4. A share that passes sender authorization is stored as `PENDING_ADMIN`, not immediately accessible.
5. If sender authorization initially requires approval, the share remains `PENDING` until the sender re-activates after intent approval; sender activation must transition it to `PENDING_ADMIN`, never directly to `APPROVED`.
6. Only an authenticated database-authorized `ADMIN` may approve a `PENDING_ADMIN` share through the backend. A recipient cannot decrypt while status is `PENDING` or `PENDING_ADMIN`.
7. The recipient can list approved shares and decrypt the exact shared record using the existing secure operation pipeline.
8. Sender can revoke a pending or approved share. Recipient rejection, expiry, key rotation/rewrap, and audit events must remain consistent.
9. Unrelated users, forged recipient IDs, modified share IDs, pending requests, revoked shares, expired intents, and tampered ciphertext must be denied safely.
10. Keep Phase 1 self-encryption and cross-device same-user decryption intact.

Test the real backend and frontend wherever the environment permits. Do not report a test as passed unless it ran. Update tests for the explicit administrator approval gate. Run the backend suite and frontend build, and provide the actual output. If dependencies/services are unavailable, report that blocker honestly.

Return one complete runnable ZIP of the modified project, with a per-file changelog, Windows run instructions, and test report. Do not include real credentials or private keys. Do not implement attachment encryption or live-monitoring redesign in this phase.

---


## CLAUDE PHASE3 PROMPT
*Source file: `CLAUDE_PHASE3_PROMPT.md`*

# Claude Prompt — Review and Harden CipherQ Phase 3 Attachments

You are modifying an existing CipherQ project. This is an incremental patch, not a rebuild.

Start from this Phase 3 candidate and inspect the current Phase 1 key-continuity and Phase 2 user-sharing/administrator-approval code before changing anything.

## Goal
Ensure attachments are encrypted and decrypted using the existing protected cryptographic workflow. Preserve normal text encryption/decryption, same-user key continuity, recipient-specific access, administrator approval, intent validity, RBAC, face/step-up checks, audit, and monitoring.

## Constraints
- Do not rewrite or redesign the project.
- Do not replace the encryption algorithm, key-management system, database, schemas, or auth architecture unless a demonstrated blocker requires a documented minimal change.
- Do not reset databases, delete records, or rotate keys.
- Do not implement unrelated phases or change live monitoring.
- Do not trust filename, MIME type, file size, user ID, recipient ID, or approval status supplied by the browser without server-side validation.
- Do not store plaintext files or key material in logs or persistent storage.
- Keep a conservative file size limit unless the backend request guard, Pydantic limits, and resource-exhaustion risks are explicitly reviewed together.

## Required review and improvements
1. Trace how the current file envelope passes through `useSecureOperation`, the decision endpoint, `/api/crypto/encrypt`, encrypted record storage, and `/api/crypto/decrypt`.
2. Verify the envelope is encrypted as plaintext by the existing server-side encryption mechanism; the frontend must never receive encryption keys.
3. Validate decoded envelope structure, filename length/characters, MIME type, original size, base64 validity, and consistency between declared and actual byte lengths.
4. Prevent malformed envelopes from causing unsafe downloads or unbounded memory use.
5. Preserve exact file bytes across encrypt/decrypt for text files, PDFs, images, zero-byte files if policy allows, binary files, Unicode filenames, and files with spaces or unusual extensions.
6. Ensure decryption downloads are only offered after server authorization and successful authenticated decryption.
7. Ensure a shared attachment cannot be decrypted by a recipient until the existing administrator approval workflow authorizes it.
8. Verify the intent's byte limit and API body limits are enforced server-side. Do not bypass policy by counting only the source file while ignoring the envelope overhead.
9. Keep the 500 KiB limit if a larger secure path cannot be verified. If larger files are needed, propose a separate multipart/streaming design rather than silently raising limits.
10. Add unit/integration tests for malformed base64, corrupted envelopes, invalid filenames, oversize requests, tampered ciphertext, missing keys, expired intents/records, unauthorized users, pending/rejected shares, and successful recipient download after approval.
11. Run the available backend tests and frontend production build. Report actual commands, results, failures, and any tests blocked by dependencies or missing MongoDB.

## Deliverable
Return one complete runnable ZIP of the existing project with only necessary changes, a file-by-file changelog, Windows run instructions, and truthful test results. Never claim unexecuted tests passed. Preserve all working Phase 1 and Phase 2 features.

---


## CLAUDE REPAIR PROMPT
*Source file: `CLAUDE_REPAIR_PROMPT.md`*

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

---


## DEMO GUIDE
*Source file: `DEMO_GUIDE.md`*

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

---


## DOCKER DEPLOYMENT
*Source file: `DOCKER_DEPLOYMENT.md`*

# CipherQ Docker deployment

This adds container packaging and persistent storage only. It does not replace or
modify the existing authentication, intent, authorization, monitoring, approval,
sharing, attachment-encryption, or QIRA workflows.

## What is persisted

- `cipherq_mongodb_data`: MongoDB's `/data/db` directory. CipherQ already writes
  monitoring session summaries and monitoring event snapshots to its MongoDB
  collections (`monitoring_sessions` and `monitoring_events`). The Docker volume
  keeps those records when containers are recreated.
- `cipherq_dev_secrets`: the existing development `.dev_secrets.json` file,
  preserving the same generated encryption keyring/JWT secret across restarts.

Monitoring summaries are stored by the existing application in MongoDB, not
inside the Dockerfile or container image.

## Start (Windows PowerShell / macOS / Linux)

From the project root (the folder containing `docker-compose.yml`):

```bash
docker compose up --build -d
```

Open:

```text
http://localhost:8080
```

Check service status and logs:

```bash
docker compose ps
docker compose logs -f backend
docker compose logs -f mongo
```

Stop containers without deleting saved data:

```bash
docker compose down
```

Start again:

```bash
docker compose up -d
```

## Important data-retention warning

Do **not** run `docker compose down -v` if you want to keep monitoring summaries,
MongoDB records, and the persisted development secrets. The `-v` option deletes
the named volumes.

The existing monitoring repository applies its own retention limits (including
the existing 90-day monitoring-session cleanup and per-session event cap).
Docker persistence does not override those application retention rules.

## Existing database / encryption-key safety

This compose file starts a fresh local MongoDB volume named `cipherq_mongodb_data`.
It does not automatically attach to or migrate an existing MongoDB database.
If you need to use an existing CipherQ database, configure the correct MongoDB
URI and restore/provide the exact keyring that encrypted that database before
starting the application. Never generate a new keyring for an existing encrypted
database; doing so can make its records undecryptable.

This compose configuration uses `APP_ENV=development` for local evaluation.
Do not expose it as a production deployment. Production/staging require explicit
managed secrets, TLS, authenticated MongoDB, and the strict settings already
enforced by the application.

---


## FINAL SECURITY AUDIT
*Source file: `FINAL_SECURITY_AUDIT.md`*

# CipherQ v18 — Final security audit (Phase 9)

Scope: the hardened tree in this archive versus the unmodified v17 baseline (`SECURITY_BASELINE.md`).
Method: re-review of every baseline finding against the new code, a fresh pass over the new subsystems
(static review plus the adversarial suite), the live end-to-end run, dependency scans and a secrets scan.
This was performed by the same engineer/assistant that wrote the fixes. **It is not an independent review.**

## 1. Verdict

| Question | Answer |
|---|---|
| Critical findings open | **0** (baseline: 1, F-01) |
| High findings open | **1** — R-01: no liveness / presentation-attack detection (inherent limit; documented; not fixable inside this prototype). Baseline had 7 High (F-02…F-08), all fixed. |
| Approved for production | **NO** |
| Suitable for | Demonstration, internal evaluation and a starting point for an independent security review |

Reasons for "no": R-01 remains open; no independent review or penetration test; the evidence source is a
local table; atomicity is single-process; the test database was FerretDB, not MongoDB; BB84 is a simulation.
See `PRODUCTION_READINESS.md`.

## 2. Baseline findings — status

Each is verified by the test(s) named in `CHANGELOG_SECURITY_HARDENING.md`.

| ID | Baseline sev | Status | Note |
|---|---|---|---|
| F-01 forgeable admin JWT / default secret | Critical | **Fixed** | no default secret; DB-backed principal; `iss/aud/jti/tv` |
| F-02 shipped secrets | High | **Fixed** | files removed, v17 key rejected at startup, tree scan test. The v17 key remains compromised for anyone who held the old ZIP. |
| F-03 stateless sessions | High | **Fixed** | |
| F-04 self-service USER_LEVEL_2 | High | **Fixed** | |
| F-05 client-held quantum key | High | **Fixed** | server-side key sessions |
| F-06 non-atomic store | High | **Fixed for one process** | see R-02 |
| F-07 client-asserted monitoring | High | **Fixed** | server-side probe, nonce chain, gap latch. Presence of a live person is still not proven (R-01). |
| F-08 enrolment overwrite / match oracle | High | **Fixed** | |
| F-09…F-19 (Medium) | Medium | **Fixed** | F-14: token still in `localStorage` (R-04) |
| F-20…F-23 (Low) | Low | **Fixed** | F-22 incident-resolve audit verified by review only |
| F-24 location advisory, F-26 Qira advisory | Info | **Unchanged** | documented |
| F-25 README | Info | **Fixed** | |

## 3. Residual findings register (new tree)

| ID | Sev | Finding | Evidence / status |
|---|---|---|---|
| R-01 | **High** | **No liveness.** Step-up and heartbeat compare a descriptor computed in the browser. Anyone able to produce a *non-identical* descriptor close to the template (a photo, a replay with noise, a script on the user's machine) passes. Identical replay is rejected, lockout and challenges are in place, grants record `liveness="NOT_ESTABLISHED"`, and the UI says so. | `test_stepup_grant_states_no_liveness`, `test_identical_descriptor_replay_rejected`. Open: requires a trusted authenticator (FIDO2/WebAuthn, vendor liveness) — external dependency. |
| R-02 | Medium (High if multi-process) | Atomic conditional writes rely on an in-process per-collection lock. With several workers/instances, one-shot consumption, counters and the audit head could race. Audit entries are still protected by the unique `_id = seq` and the keyed chain detects forks. | `test_02_*`, `test_20::14b` (single process). Not tested on a replica-set MongoDB. |
| R-03 | Medium | Evidence is a local admin-maintained case table. An administrator who edits the table and approves can authorise anything; intent evidence is only as strong as that table. Admin actions are audited. | By design; no external system integrated. |
| R-04 | Medium | SPA keeps the bearer token in `localStorage`; any XSS exposes it. CSP for the SPA depends on the host serving `dist/`. Token lifetime is 30 min and tokens are revocable. | Residual from F-14. |
| R-05 | Medium | Rate limiter and lockout counters: lockout is DB-backed, IP/endpoint limits are in-process (reset on restart, not shared). | `test_ip_rate_limit_on_login`. |
| R-06 | Medium | Keyring and secrets are files on the application host; no HSM/KMS, no key escrow. Host compromise exposes everything the process can decrypt. | `docs/OPERATIONS.md`. |
| R-07 | Low | `GET /api/audit/logs` is unpaginated and `verify` is O(n). | Admin/L2 only. |
| R-08 | Low | `/api/authorization/devices/{id}/trust` reveals whether an id is known/foreign to the caller (existence oracle on a 128-bit random id; effectively unguessable). | Documented design. |
| R-09 | Low | Dev/build tooling advisories: `pip` 24.0 in the venv; 7 `npm audit` advisories in the Tailwind 3 → postcss chain (dev only; `--omit=dev` is clean). | `docs/evidence/pip_audit_final.txt`, `npm_audit_final.json`. |
| R-10 | Low | Incident-resolution audit event has no automated test. | review only |
| R-11 | Info | BB84 is simulated. Not physical QKD, not "quantum-proof"; effective-entropy accounting is reported but offers no physical security guarantee. | label shown in API and UI |
| R-12 | Info | Qira advisory output and the location check are advisory and never gate cryptographic operations. | unchanged |
| R-13 | Info | No independent review, penetration test or formal verification. | — |

## 4. Re-verification of high-risk properties

| Property | How checked |
|---|---|
| No path returns key material | `test_api_ciphertext_not_plaintext_and_no_key_in_responses`; response schemas have no key field; live e2e "no key material in response". |
| Single-use contexts, one winner under concurrency | `test_14_*`, `test_14b_*`. |
| Any relevant state change kills an issued context | `test_09`, `test_10`, `test_15`, `test_15b`, live e2e steps for evidence change and revocation. |
| Records and decisions are tamper-evident | `test_12`, `test_12b`. |
| Audit chain resists DB-only attacker | `test_60_*`: modified/deleted-middle/deleted-last/truncated-with-head/full rewrite (sink catches it)/forged entries without the key. |
| Fail-closed configuration | `test_production_fails_closed`, `test_no_default_secret_fallback_outside_development`. |
| No secrets in the archive | `test_no_secrets_or_keys_in_source_tree`; archive grep performed at packaging (see `TEST_RESULTS.md`). |
| Input hardening | `test_70_*`, `test_03_*`: oversized bodies, content types, malformed JSON, NaN descriptors, unknown fields, route-matrix authentication check for every OpenAPI path. |

## 5. Items reviewed with no finding

Constant-time comparisons and uniform login failure; JWT algorithm pinning (none/forged rejected); error
sanitisation (no stack traces, no secret echo in validation errors); CORS exact-origin; Host allow-list;
no `eval/exec/pickle/subprocess/yaml.load` in application code; no non-CSPRNG use in security paths
(`secrets`/OS CSPRNG throughout, including BB84); no fail-open `hasattr` guards remain in the request path
(one leftover in `refresh` was removed during this audit).

## 6. What an independent reviewer should look at first

1. `intent_engine/engine.py` (`gather`, `decide`, `open_context`) and `drift.py`.
2. `database/encrypted_store.py` concurrency semantics on real MongoDB.
3. `identity/stepup.py` and `monitoring/service.py` — replace descriptor matching with a standard authenticator.
4. Key handling in `keymgmt/key_sessions.py` and `crypto/records.py`.
5. Deployment configuration (`docs/OPERATIONS.md`), especially the audit sink shipping.

---


## FIX REPORT
*Source file: `FIX_REPORT.md`*

# CipherQ v18 packaging and startup-safety report

## Changes made in this packaging pass

- Added `START_CIPHERQ.bat` and `START_CIPHERQ.ps1` for one-command Windows startup of FastAPI and Vite.
- The launcher explicitly starts Uvicorn with `--env-file .env`; this avoids assuming that Python automatically loads `.env`.
- Added `backend/scripts/preflight_mongodb.py`, a read-only connectivity check that does not print credentials or driver exception text.
- The launcher fails closed when the existing development key file is absent and no key/JWT secret is configured in `.env`. This protects existing whole-document encrypted records from accidental startup with a newly generated key.
- Added `RUN_WINDOWS.md` and `CLAUDE_REPAIR_PROMPT.md`.

## Verification performed here

- Python source compilation (`python -m compileall -q backend`) passed.
- The full FastAPI/MongoDB tests and frontend build were **not run** in this packaging environment because PyMongo and the user's MongoDB/keyring are not available here. Therefore this package is not represented as runtime-verified against `cipherq_new`.

## Remaining required verification

1. Confirm MongoDB is running and the configured URI points to the intended local/remote instance.
2. Restore the exact existing key material used for the encrypted `cipherq_new` database; do not generate new keys.
3. Run the backend test suite against an isolated test database and `npm run build`.
4. Verify login and database reads against `cipherq_new` with the original keyring before treating the repair as complete.

No database was connected to, changed, migrated, or deleted during this packaging pass.

---


## IMPLEMENTATION REPORT THREE FEATURES
*Source file: `IMPLEMENTATION_REPORT_THREE_FEATURES.md`*

# CipherQ QIRA Enhanced — Three Feature Implementation Report

## Scope

This update targets only the three requested areas:

1. Create Intent simplification and supporting file attachments.
2. Intent History Secure Share action.
3. Intent-bound sender-to-recipient encrypted sharing.

The project architecture, existing MongoDB collections, key hierarchy, authentication/RBAC services, QIRA assets and animations were preserved.

## Implemented changes

### 1. Create Intent and file payloads

- Removed the old **Allow User-to-User Sharing** panel and its recipient selector from Create Intent.
- Kept the existing Operations control. Secure Share permission is declared there as the `share` operation; the backend requires both `encrypt` and `share`. The recipient is selected later in the dedicated Secure Share workflow.
- Removed redundant maximum-byte explanatory copy and retained the **Maximum Bytes Per Operation** field.
- Changed the default **Maximum Bytes Per Operation** value from 4,096 to **2,000,000 bytes**.
- Removed the Create Intent content-type selection; payload type is determined by whether a file is attached.
- Added the eight requested attachment formats: PDF, JPG, JPEG, PNG, DOC, DOCX, XLS and XLSX.
- Enforced the 1 MB limit and extension/content checks in the frontend and backend.
- Kept the attachment inside the encrypted, integrity-sealed intent version.
- Added a handoff from the created intent to Encryption. The selected file is wrapped as the actual `CIPHERQ_ATTACHMENT_V1` plaintext payload; it is not replaced with a placeholder message.
- The encryption API validates/canonicalizes that file envelope before sealing it.
- Decryption verifies the SHA-256 digest before enabling the recovered file download.

### 2. Intent History

- Added **Secure Share** after Decryption and before Revoke.
- The action is shown only for an approved intent that permits both `encrypt` and `share`.
- The selected intent ID is carried into the Secure Share page.

### 3. Secure Share workflow

- Replaced the Secure Share page's former direct-message UI with a workflow built on the existing `/api/crypto/shares` service.
- Added approved intent selection, sender active key-session selection, recipient selection, subject, message and optional attachment.
- Recipient selection happens at send time. Backend validation checks that the recipient exists and is enabled.
- The backend chooses an active recipient key session when one is not supplied by the client, then validates its ownership and status before re-wrapping the record key.
- The selected message or file is encrypted as a `CIPHERQ_SHARE_V1` payload through the existing CipherQ crypto-record workflow.
- The existing recipient key-envelope, approval, inbox, expiry, revocation and audit mechanisms are retained.
- Added sent and received share lists. Senders can decrypt their source record; recipients decrypt the recipient-bound share through the existing Decryption workflow and their own authenticated session.
- Added file-plus-message support. Attachment digest verification is performed after decryption.
- Legacy recipient-bound share intents and API calls remain supported.
- The previous direct-messaging interface was preserved as a separate **Direct Messages** page and sidebar route rather than being discarded.

## Attachment validation

Accepted formats and MIME types:

| Extension | MIME type |
|---|---|
| `.pdf` | `application/pdf` |
| `.jpg`, `.jpeg` | `image/jpeg` |
| `.png` | `image/png` |
| `.doc` | `application/msword` |
| `.docx` | `application/vnd.openxmlformats-officedocument.wordprocessingml.document` |
| `.xls` | `application/vnd.ms-excel` |
| `.xlsx` | `application/vnd.openxmlformats-officedocument.spreadsheetml.sheet` |

Maximum file size: 1,048,576 bytes (1 MiB).

Validation checks include filename extension, MIME agreement, file signatures, Office package entries for DOCX/XLSX, legacy Office compound-file markers for DOC/XLS, declared size and SHA-256 integrity.

## Modified existing files

### Backend
- `backend/intent_engine/engine.py`
- `backend/intent_engine/schema.py`
- `backend/intent_engine/drift.py`
- `backend/crypto/share_payload.py`
- `backend/api/routers/crypto_ops.py`
- `backend/tests/test_10_intent_flow.py`
- `backend/tests/test_33_secure_sharing.py`

### Frontend
- `frontend/src/App.jsx`
- `frontend/src/pages/CreateIntentPage.jsx`
- `frontend/src/pages/IntentHistoryPage.jsx`
- `frontend/src/pages/EncryptionPage.jsx`
- `frontend/src/pages/DecryptionPage.jsx`
- `frontend/src/pages/ShareMessagesPage.jsx`
- `frontend/src/utils/sharePayload.js`
- `frontend/src/components/layout/Sidebar.jsx`

## New files

- `backend/tests/test_35_attachment_validation.py`
- `frontend/src/pages/DirectMessagesPage.jsx`

## Validation results in this build environment

| Check | Result |
|---|---|
| Python backend `compileall` | Passed |
| Attachment validation unit tests | 13 passed |
| Frontend JSX/JS syntax transpilation | Passed for 9 changed frontend files |
| Secure Share API integration tests | Not executed: `pymongo` is not installed in this environment |
| Full backend regression suite | Not verified: MongoDB/PyMongo runtime unavailable |
| Frontend production build | Not verified: `npm run build` could not execute Vite (`vite: Permission denied`) |
| Frontend test suite | Not verified: installed frontend dependencies, including Vitest, are unavailable |
| Browser/MongoDB end-to-end workflow | Not executed |

The 13 passing tests are focused attachment-validation tests. They are not evidence that the full sender-to-recipient workflow has passed against MongoDB.

## Preservation checks

- No database reset, recreation or migration was performed.
- No encryption key, keyring, JWT secret or `.env` file was regenerated or intentionally modified.
- No KIRA/QIRA mascot assets, components, animations or blue animated elements were modified.
- Existing direct messaging was retained under its own page.
- No new MongoDB collection is introduced by this change.

## Run instructions (Windows)

1. Extract the ZIP into a separate folder. Do not overwrite your working project yet.
2. Preserve and use the exact existing `backend\.env` and `backend\.dev_secrets.json` (or the exact keyring/secret files configured by that `.env`) that belong to the MongoDB database you intend to open. Do not generate replacement keys.
3. Confirm the configured MongoDB service is running and that `MONGODB_DATABASE` points to the intended database.
4. Run `START_CIPHERQ.bat`. The included launcher creates/uses a Python 3.11 virtual environment, installs `backend\requirements.txt`, checks MongoDB connectivity, installs frontend dependencies with `npm ci` when needed, and starts FastAPI and Vite.
5. Open `http://127.0.0.1:5173`.
6. Before a demo, create an approved intent with both `encrypt` and `share` in Operations, an adequate byte limit, and at least four remaining uses for encryption, share authorization, sender decryption and recipient decryption.
7. Establish active key sessions for the sender and recipient. The recipient's active key session is selected and checked by the backend.
8. Test sender encryption, share delivery, administrator approval if requested, recipient login/face verification/decryption, sender decryption, file download, and share revocation.

For manual checks:
- Backend: from `backend`, run `python -m pytest tests/ -q`.
- Frontend: from `frontend`, run `npm ci`, then `npm run build` and `npm test`.

Do not point a fresh installation or newly generated secrets at an existing encrypted database. The current test environment did not include the dependencies or MongoDB needed to certify the full runtime workflow.

---


## INTENT SECURITY ARCHITECTURE
*Source file: `INTENT_SECURITY_ARCHITECTURE.md`*

# CipherQ v18 — Intent Integrity and Purpose-Drift Architecture

Scope: the subsystem in `backend/intent_engine/` plus the pieces it binds to (`security/`, `keymgmt/`,
`monitoring/`, `identity/`, `audit/`). It is a **prototype-grade** access-authorization design. It does not
include an "Authorization Epoch" subsystem; freshness comes from recomputing authoritative state (§5).

## 1. Problem

An approved intent can be abused after approval: reused for another purpose, resource, operation, user,
session or device; used after the underlying business case changed; or replayed. The prototype therefore
treats an intent as a **claim** that is re-checked against authoritative server-side records on every
operation, and releases key material only through a single-use context that is cryptographically bound to
that re-checked state.

## 2. Components

| Component | File | Responsibility |
|---|---|---|
| Intent schema v2 | `intent_engine/schema.py` | Strict pydantic model. Purpose, classification, operations are enums; resource/reference/session/device are regex-bounded; validity ≤ 24 h; unknown fields rejected. Owner, sender, required approvals, status and policy version are **server-set** and never accepted from the client. |
| Evidence provider | `intent_engine/evidence.py` | Interface plus a **local administrator-maintained case table** (`LocalEvidenceProvider`). The only evidence kind is `CASE`. A user's own statement is never evidence. |
| Drift rules | `intent_engine/drift.py` | Pure function `evaluate(facts)`: same facts → same reasons. Reasons have severity `VIOLATION` (→ DENY), `REQUIRES` (→ step-up or approval) or `SIGNAL` (reported only). No model, no free-text scoring. |
| Store | `intent_engine/store.py` | Versioned intent bodies, approvals, decisions and contexts. Every record is MAC-sealed (`security/integrity.py`, HMAC-SHA256 with the `authorization-signing` purpose subkey) over a canonical encoding. |
| Engine | `intent_engine/engine.py` | `create_intent / new_version / validate / approve / revoke`, `decide`, `open_context`. |
| Crypto records | `crypto/records.py` (format v3) | Per-record DEK wrapped under a record-wrapping key derived from the session key. |
| Keyring | `security/keyring.py` | Versioned keys with id; HKDF purpose subkeys (db-encryption, quantum-key-wrap, crypto-context-wrap, authorization-signing, audit-mac). |

## 3. Intent lifecycle

`DRAFT → (validate) → PENDING_APPROVAL → (approvals ≥ required) → APPROVED`, or `REJECTED`, `REVOKED`,
`EXPIRED`, `EXHAUSTED` (terminal). Any new version re-enters `DRAFT`; approvals are bound to
`(intent_id, version, body_hash)` and do not carry over. Approval rules (server policy, not client input):

* PUBLIC 0 approvals; INTERNAL/CONFIDENTIAL 1; RESTRICTED 2 distinct approvers.
* The requester can never approve their own intent (including admins).
* Evidence (verified, assigned, OPEN case whose resource scope and classification cap cover the request) is
  mandatory from INTERNAL upward; a fresh step-up is mandatory for RESTRICTED.
* Approvals are MAC-sealed records; a tampered approval no longer counts (`INTENT_RECORD_TAMPERED`).

## 4. Decision outcomes

`decide(actor, request)` returns one of:

| Outcome | Meaning |
|---|---|
| `PERMIT` | All checks pass. A signed decision and a single-use crypto context are issued. |
| `DENY` | At least one `VIOLATION` (e.g. `PURPOSE_DRIFT`, `RESOURCE_DRIFT`, `OPERATION_DRIFT`, `SCOPE_EXCEEDED`, `CASE_CLOSED`, `USER_REMOVED_FROM_CASE`, `DEVICE_REVOKED`, `SESSION_INVALID`, `INTENT_EXPIRED`, `INTENT_EXHAUSTED`, `INTENT_RECORD_TAMPERED`, `MONITORING_REVOKED`, `RISK_GATE_DENIED`). |
| `REQUIRE_STEP_UP` | Only `REQUIRES:STEP_UP` reasons (e.g. RESTRICTED data, elevated risk without a fresh challenge-bound verification). |
| `REQUIRE_APPROVAL` | Only `REQUIRES:APPROVAL` reasons (intent not yet approved / approvals insufficient). |

Every decision (including DENY) is recorded and audited; the decision carries the policy version, the intent
body hash, the reasons, and a MAC. `GET /api/decisions/{id}` reports `integrity_ok`.

## 5. Authorization-bound crypto context (no epoch counter)

On PERMIT the engine computes `H = SHA-256("CIPHERQ|AUTHZ-STATE|v2", canonical(state))`, where the state is
*recomputed from stored records on every call* (`IntentEngine.gather`), not taken from the request:
acting user (enabled, role); intent (id, version, effective status, count of valid approvals, body hash,
integrity result); session (exists, valid, version, owner, device); device (revoked, owner); monitoring class
(permit / reauth / block / error); evidence findings (ref, case status, case revision, ok, code); key-session
status; policy version and legacy-policy failures; and, once a decision exists, its status and revision.

```
wrap_key = HKDF-SHA256( ikm = subkey("crypto-context-wrap"), salt = context_id, info = frame("CIPHERQ|CTX|v1", H) )
context  = AES-256-GCM( wrap_key, session_qkey,  aad = context_id|decision_id|user|intent|version|ks|op|record )
```

`open_context` (called by `/api/crypto/encrypt|decrypt`) re-gathers the state, recomputes `H` and derives the
key again. If any relevant record changed, the derived key differs and decryption of the context fails closed
(`CONTEXT_STALE` / `AUTHORIZATION_CHANGED`). Additional checks: owner, request-vs-decision binding for
purpose/resource/operation/session/device/intent/key session (`CONTEXT_BINDING_MISMATCH`, logged as drift),
expiry (`CONTEXT_EXPIRED`), invalidation (`CONTEXT_INVALIDATED`, 403) and single use via an atomic consume
(`CONTEXT_ALREADY_USED`, 409; exactly one winner under concurrency). The session key is released into memory
only for the duration of the call and zeroised afterwards.

Consequence: *revoking a session, closing a case, removing a user from a case, changing a policy version,
withdrawing an approval, or stopping monitoring after a context was issued makes that context unusable*,
without a global counter.

## 6. Ten-step workflow (implemented and tested)

1. Authenticate (DB-backed principal, `jti` registry, `token_version`). 2. Create intent (schema v2).
3. Validate against the evidence provider. 4. Approval by a different principal (2 for RESTRICTED).
5. Step-up (single-use challenge, server-side descriptor comparison). 6. Monitoring starts (needs a fresh
grant). 7. `POST /api/decisions` → PERMIT + context. 8. `POST /api/crypto/encrypt|decrypt` opens the context.
9. State change (revoke / case closed / …) → context rejected, new decision denied or step-up required.
10. Reauthorization (admin-approved request + challenge-bound step-up) → fresh decision → fresh context.
Tests: `tests/test_20_purpose_drift.py::test_workflow_authorization_state_change` and the live script
`backend/scripts/e2e_workflow.py` (70 checks).

## 7. Identity and monitoring assumptions

* Face matching is **descriptor similarity computed on the server** against the enrolled template. Single-use
  challenges, replay-hash rejection, lockout and a non-oracle response are implemented.
* **Liveness is NOT established.** The grant records `liveness="NOT_ESTABLISHED"`. A recorded or synthetic
  descriptor from the user's own device would pass; this is a known limit of the prototype.
* Monitoring: heartbeat nonce chain (`prev_nonce`), server-side `probe_descriptor` comparison, a heartbeat-gap
  latch → `REAUTH_REQUIRED`; client "present/camera" flags can only cause failure, never success.

## 8. Threat model (what is and is not defended)

| Defended (tested) | Not defended / out of scope |
|---|---|
| Purpose, resource, operation, user, session, device drift after approval | A malicious administrator who can edit the case table *and* approve (single trust domain) |
| Replay of decisions/contexts; concurrent replay | Compromise of the server process memory or the keyring file |
| Tampering with approvals/decisions/intents at rest (MAC) | Database-level collusion with possession of the keyring |
| Stale authorization after revocation/closure | Coercion, shoulder surfing, presentation attacks on the camera (no liveness) |
| Client-asserted facts (liveness, confidence, device id) | Real business evidence integration (only a local table) |
| Timing/oracle on step-up | Physical QKD properties — BB84 is a *simulation* |

BB84 here is a Qiskit Aer simulation used as a key-establishment *demonstration*. It is not physical QKD,
provides no information-theoretic guarantee in this deployment, and the system must not be described as
"quantum-proof".

---


## PHASE1 CHANGELOG
*Source file: `PHASE1_CHANGELOG.md`*

# CipherQ Phase 1 — Same-user encryption/decryption continuity

## Scope
This package changes only Phase 1. User-to-user sharing behavior, attachment encryption behavior, and live monitoring behavior are not intentionally changed.

## Changes
- Ciphertext records now expire no later than the approved intent's `valid_until`, and no later than the existing 24-hour record lifetime.
- When a record is created, its owner's active key session is extended to cover the record's server-computed expiry. The default key-session lifetime is now 24 hours (86,400 seconds), matching the 24-hour maximum record lifetime. Both the Settings dataclass and environment fallback use this default; an explicit KEY_SESSION_TTL_SECONDS setting still overrides it. Live record usage may extend an active key session to the record’s computed expiry, bounded by the record’s approved validity window.
- The same owner may resume decryption from a new authenticated device/login session, provided the current session and device pass the existing ownership, session-validity, device-revocation, monitoring, risk/step-up, intent approval, intent validity, record ownership, and key availability checks.
- Encryption and sharing remain bound to the original intent session/device.
- Added API-level regression tests for owner decryption from a new authorized device and for key-session lifetime covering record validity.
- Removed local `.env` and development secret files from the deliverable. Configure the project using the provided `.env.example` and your own secrets.

## Security semantics
- Stable user ID owns the record.
- Login session ID and device ID are authorization/audit context, not encryption-key derivation inputs for the saved ciphertext.
- The original record ciphertext and key reference are reused; device changes do not re-encrypt the record.
- The server does not silently replace missing or destroyed keys. Explicitly revoked/expired key sessions remain unavailable.
- A record cannot be decrypted outside its approved intent window, even if a key session remains available for another record.

## Validation performed in this environment
- Python compile check passed for backend API, key management, crypto, intent engine, and tests.
- Pure cryptographic unit tests: 18 passed.
- Full API tests could not run in this environment because `pymongo` is not installed and no MongoDB test service is available here. Run the full suite in the project's supported environment before relying on the ZIP for production.

## Before running
1. Back up your existing database and keep your current secret/key files private.
2. Install backend dependencies from `backend/requirements.txt` in your existing virtual environment.
3. Configure `backend/.env` from `backend/.env.example` using your existing correct keyring and database settings; do not rotate or replace keys just to test this feature.
4. Start MongoDB and run the complete backend test suite before replacing your working project.


### Lifetime alignment update
- Set default key-session lifetime to 86,400 seconds (24 hours).
- Encrypted-record maximum lifetime remains 86,400 seconds (24 hours), and actual expiry is still capped by the approved intent validity end.
- Updated `backend/.env.example` and added a configuration regression test.

---


## PHASE1 PHASE2 PHASE3 INTEGRATION STATUS
*Source file: `PHASE1_PHASE2_PHASE3_INTEGRATION_STATUS.md`*

# CipherQ Phase 1 + Phase 2 + Phase 3 integration status

This package is the Phase 3 attachment candidate, which already includes the Phase 1 24-hour key-session/record lifetime work and Phase 2 recipient-bound sharing with server-side administrator approval. The changes in this integration pass increase the attachment source-file limit from 500 KiB to 1 MiB and raise the default request body/data-scope limits to account for base64/JSON overhead.

## Security-critical behavior retained
- Same-owner decryption from a fresh authorized login/device is allowed only when record ownership and intent ownership match the authenticated user, and the current session/device, monitoring, risk/step-up, intent validity, record validity, and key checks pass.
- User-to-user sharing remains recipient-bound and requires administrator approval before recipient decryption. Other users cannot decrypt another user's record.
- Encryption keys are not regenerated and no database migration is performed by this package.

## Validation performed in this packaging pass
- Backend Python compileall: PASS.
- Targeted pytest run: BLOCKED during collection because `pymongo` is not installed in the packaging environment (`ModuleNotFoundError`). No claim of full backend integration test success is made.
- Browser round-trip and frontend production build: NOT run in this environment.

## Before evaluating locally
1. Keep your existing MongoDB databases and encryption key files unchanged.
2. Confirm `backend/.env` selects the intended database and uses the existing matching keyring/secrets. Do not copy or generate keys as a workaround.
3. If `MAX_BODY_BYTES` is explicitly set in `backend/.env`, set it to `3145728` (3 MiB) for 1 MiB attachments; an explicit smaller value overrides the new default.
4. Create an approved intent with `max_bytes` at least as large as the serialized attachment envelope (2,097,152 bytes supports the 1 MiB source-file limit). Existing intents keep their prior byte scope and may need a deliberate authorized revision or a new intent.
5. Run the backend tests in the project's configured virtual environment, then `npm ci` and `npm run build` in `frontend`, and verify the 1 MiB attachment round-trip and cross-session owner decryption plus recipient share approval flow.

---


## PHASE2 CHANGELOG
*Source file: `PHASE2_CHANGELOG.md`*

# CipherQ Phase 2 — User-to-User Secure Sharing

## Baseline and scope

This package is an incremental candidate built on `CipherQ_Phase1_Same_User_Key_Continuity_24H.zip`. It preserves the existing application and adds recipient-bound sharing plus a per-share administrator approval gate. Phase 1's 24-hour defaults and same-user key-continuity changes are retained. Attachment encryption and live-monitoring redesign are out of scope.

## Changes

- `backend/api/routers/crypto_ops.py`
  - Added a minimal authenticated recipient list endpoint.
  - Allows the backend to select the recipient's most recent active key session when the sender does not submit a key-session ID. The server still verifies that the selected key session belongs to the intended recipient.
  - Changes successful sender authorization from immediate recipient access to `PENDING_ADMIN`.
  - Changes sender activation of an intent-pending share to `PENDING_ADMIN`, not direct recipient access.
  - Adds administrator-only pending queue and approval endpoint. Only a database-authenticated `ADMIN` actor can approve; recipient decryption remains blocked until status becomes `APPROVED`.
  - Allows sender revocation before and after approval; handles expiry for the new state.
  - Adds non-secret sharing metadata for the recipient inbox.
- `backend/tests/test_10_intent_flow.py`
  - Updated sharing workflow assertions to require administrator approval before recipient access.
  - Added checks that a recipient cannot obtain a decrypt decision while approval is pending and that a non-admin cannot approve a share.
- `frontend/src/pages/CreateIntentPage.jsx`
  - Adds an explicit option to authorize sharing in an intent and bind that intent to a selected recipient.
- `frontend/src/pages/ShareMessagesPage.jsx`
  - Adds a Secure Sharing page for sender requests, recipient inbox/status, sender activation/revocation, and the admin approval queue.
- `frontend/src/pages/DecryptionPage.jsx`
  - Adds administrator-approved received shares to the record picker while retaining the existing own-record flow.
- `frontend/src/services/api.js`
  - Adds typed API wrappers for recipients, sharing requests, approval, rejection, and revocation.
- `frontend/src/components/layout/Sidebar.jsx`, `frontend/src/App.jsx`
  - Adds the Secure Sharing page to existing navigation and routing.

## Security behavior

- Shared records stay inaccessible to recipients while `PENDING` or `PENDING_ADMIN`.
- Approval is server-side and role-checked; UI visibility is not treated as authorization.
- The backend continues to bind the share to the sender's record and an approved intent whose recipient ID matches the recipient.
- No plaintext or raw encryption key is sent to the recipient during share creation or approval.
- Existing self-encryption/decryption routes and Phase 1 key-continuity configuration were not intentionally changed.

## Verification performed

- `python -m compileall -q backend`: passed.
- Targeted pytest collection was attempted but blocked before test execution because this environment does not have `pymongo` installed (`ModuleNotFoundError: No module named 'pymongo'`).
- Frontend dependency installation/build was attempted, but package installation could not complete in this environment (offline npm cache miss and network command timeout). Therefore the frontend production build and full end-to-end workflow are **not verified here**.

## Required local acceptance checks

1. Create an intent with `encrypt`, `decrypt`, and `share`, a specific recipient, and obtain normal admin intent approval.
2. Encrypt a record using that intent.
3. Submit a share request; verify status is `PENDING_ADMIN` and recipient decrypt is denied.
4. Sign in as an administrator and approve the share in Secure Sharing.
5. Sign in as the recipient and decrypt the shared record.
6. Verify an ordinary user cannot approve, an unrelated user cannot decrypt, and sender revocation blocks future access.
7. Re-run the full backend test suite and `npm ci && npm run build` on a machine with dependencies available.

This is an evaluation candidate, not a claim that integration testing has passed.

---


## PHASE3 CHANGELOG
*Source file: `PHASE3_CHANGELOG.md`*

# CipherQ Phase 3 — Attachment Encryption Candidate

## Scope
This candidate builds on the Phase 2 user-to-user sharing ZIP. It adds a minimal attachment path to the existing Encrypt/Decrypt screens, reusing the current server-side cryptographic operation and authorization pipeline.

## Changed files
- `frontend/src/pages/EncryptionPage.jsx`: adds a Text message / File attachment selector; reads the selected file as bytes, packages filename/MIME type/original size/content into a versioned envelope, then submits that envelope through the existing authorized encryption workflow. Enforces a 1 MiB (1,048,576-byte) source-file limit. The request guard defaults to 3 MiB to allow JSON/base64 envelope overhead, and the intent data-scope ceiling is 2 MiB so an attachment envelope can fit within the approved byte scope.
- `frontend/src/pages/DecryptionPage.jsx`: recognizes the encrypted attachment envelope after the existing decrypt operation and offers a downloaded file with its original name and MIME type. Ordinary text decryption remains supported.
- `CLAUDE_PHASE3_PROMPT.md`: gives Claude focused instructions for reviewing and hardening this candidate without rebuilding the application.
- `PHASE3_TEST_GUIDE.md`: manual tests and known constraints.

## Security notes
- File bytes and metadata are packaged before being sent to the existing encryption API; they are not uploaded as plaintext to a new endpoint.
- This uses the existing server-side authorization, encryption, record persistence, and (where applicable) Phase 2 sharing approval path.
- The frontend limit is not a substitute for server-side limits. The current API schema and request guard still impose their own maximum request sizes.
- The intent's `max_bytes` must be large enough for the serialized envelope, which is larger than the original file due to base64 and metadata overhead.
- Browser downloads occur only after the existing decrypt API succeeds. A user should clear decrypted content when finished.

## Validation status
- Source edits and ZIP structure were checked.
- Full frontend production build was not run: `node_modules` is not present in this environment, and dependency installation is not available here.
- Backend integration tests were not run as part of this attachment UI change. Phase 2's prior test limitations still apply.
- This is an evaluation candidate, not a claim of fully verified production readiness.


## Phase integration repair update
- Confirmed this candidate contains Phase 1 24-hour key-session/record lifetime settings and same-owner cross-session decryption checks, plus Phase 2 recipient-bound sharing with administrator approval and recipient-only decryption.
- Raised the original attachment limit from 500 KiB to 1 MiB; increased the default API request-body limit to 3 MiB to allow base64/JSON overhead; raised the intent data-scope maximum to 2 MiB to accommodate the serialized envelope. Explicit `MAX_BODY_BYTES` values in a local `.env` override the default and must be at least `3145728` for 1 MiB attachments. Existing intents retain their own `max_bytes`; create a new intent or safely revise the existing approved intent scope to at least the serialized envelope size.
- The decryption authorization continues to require an authenticated, valid current session/device, active monitoring/step-up policy where applicable, record ownership or an approved recipient share, record/intent binding, key availability, and validity windows. It does not bypass these controls.

---


## PHASE3 TEST GUIDE
*Source file: `PHASE3_TEST_GUIDE.md`*

# Phase 3 Attachment Test Guide

## Setup
1. Extract this ZIP into a new folder; do not overwrite the Phase 2 folder.
2. Use your existing local environment and database. Do not reset the database or rotate encryption keys.
3. Install the existing backend/frontend dependencies using the project's Windows setup guide.
4. Start the application and log in as an authorized user.

## Manual tests
1. Encrypt and decrypt a short text message; verify text behavior is unchanged.
2. Encrypt a small `.txt` attachment; decrypt it and compare downloaded bytes with the original.
3. Repeat with a PDF, PNG/JPG image, and a file with spaces and Unicode characters in its filename.
4. Verify the original filename and MIME type are retained where the browser supports them.
5. Try an attachment just below the 500 KiB limit and verify the operation follows normal intent size policy.
6. Try a file larger than 500 KiB; the UI must reject it before sending an encryption request.
7. Try an intent whose `max_bytes` is too small for the serialized attachment envelope; expect normal server-side denial, not a bypass.
8. Tamper with ciphertext or use an invalid record ID; decryption must fail safely.
9. Test attachment records shared through Phase 2: the recipient must not decrypt while approval is pending and should only decrypt after approval and all existing policy checks.
10. Test unauthorized users, expired intents, expired records, invalid key sessions, and server restart persistence.
11. Confirm text encryption, Phase 1 same-user continuity, Phase 2 sharing, admin approval, audit, and live monitoring regressions remain unchanged.

## Known limitation
The current implementation uses the existing JSON/base64 API. The client-side attachment limit is 500 KiB and the serialized envelope is larger than the source file. For larger attachments, implement a dedicated streaming/multipart path with server-side size limits and authenticated chunk/finalization semantics in a later, separately tested change. Do not simply raise limits without reviewing the request guard and API schema.


## Updated 1 MiB attachment limit
- A source file may be up to 1,048,576 bytes. Create an approved intent whose `max_bytes` is at least the serialized attachment envelope size (use 2,097,152 bytes for a 1 MiB file).
- Set `MAX_BODY_BYTES=3145728` or leave it unset to use the updated 3 MiB default. A smaller explicit value in `backend/.env` overrides the default and will reject large requests.
- Verify 1 MiB encrypt/decrypt round-trip and reject a file larger than 1 MiB.

---


## PRODUCTION READINESS
*Source file: `PRODUCTION_READINESS.md`*

# CipherQ v18 — Production readiness

**Decision: NOT approved for production.** One High finding (R-01, no liveness) is open and there has been no
independent review. This document lists what exists, what is only partly verified, and what is missing.

## 1. Implemented and tested (in the build environment)

* Fail-closed configuration; no default secrets; secret files must be private; v17 key rejected.
* DB-backed principals, revocable tokens (`jti`, `token_version`), logout/logout-all, account disable/unlock, lockout, scrypt.
* Whole-document encryption v2 (AAD = collection/_id/key id), versioned keyring, HKDF purpose subkeys, re-encryption tool.
* Server-side key sessions (create/rotate/revoke/re-wrap); key never returned; BB84 **simulation** with QBER abort.
* Intent schema v2, approvals bound to version, separation of duties, local evidence provider, deterministic
  drift rules, signed decisions, single-use authorization-bound contexts, record format v3.
* Challenge-bound step-up, enrolment protection, monitoring nonce chain and heartbeat-gap latch.
* Keyed audit chain with head and secondary sink; sink failure fails closed in strict environments.
* Security headers, CORS/Host allow-lists, body-size/content-type limits, input bounds, sanitised errors.
* Frontend integrated with all of the above; production build succeeds; live end-to-end run 70/70.
* Test counts and exact commands: `TEST_RESULTS.md`.

## 2. Implemented but incompletely tested

| Item | Gap |
|---|---|
| Multi-process / multi-instance deployment | Atomicity is an in-process lock; never run against more than one worker or on a replica-set MongoDB. |
| Real MongoDB | All tests ran on FerretDB 1.24 (SQLite). Behaviour on `mongod` (TLS, auth, least-privilege user, indexes) not exercised. |
| Audit sink shipping off-host, backup/restore, key rotation in a running system | Scripts exist and are unit/integration tested locally; no restore drill. |
| TLS termination, reverse proxy, `X-Forwarded-For` handling | Not exercised. |
| Browser camera flow | Exercised through headless UI smoke screenshots and API-level synthetic descriptors; no real-webcam/cross-browser testing. |
| Incident-resolution audit event | Code review only. |
| Load / soak / DoS behaviour | Only bounded-concurrency unit tests; no load test. |

## 3. Not implemented

* Liveness / presentation-attack detection; a trusted authenticator (WebAuthn/FIDO2) for step-up.
* External business-evidence integration (case-management/ticketing system); evidence is a local table.
* Shared (distributed) rate limiting; audit-log pagination; incremental audit verification.
* HSM/KMS-backed keys; secret-manager integration beyond files/environment.
* Multi-tenant isolation; data retention/deletion policy; privacy review of biometric templates (GDPR/DPDP etc.).
* Physical QKD (BB84 here is a simulation and must not be marketed as quantum-proof).

## 4. External dependencies required

MongoDB (replica set, TLS, auth); TLS-terminating reverse proxy; secret manager or HSM; log shipping / WORM
storage for the audit sink; an identity provider or authenticator with liveness; an evidence system of record;
monitoring/alerting (see `docs/OPERATIONS.md` §9).

## 5. Independent review required before any production use

Independent code and architecture review focused on `intent_engine`, the encrypted store, step-up/monitoring and
key handling (`FINAL_SECURITY_AUDIT.md` §6); penetration test against a staging deployment on real MongoDB;
cryptographic review of record format v3 and the context-wrap derivation; privacy/legal review of biometric
processing.

---


## QIRA SHARING MONITORING INTEGRATION
*Source file: `QIRA_SHARING_MONITORING_INTEGRATION.md`*

# QIRA + secure-sharing integration notes

## Scope
- Phase 1/2/3 remains the base application. Existing backend authorization, encryption, intent, and key-session code is retained.
- QIRA presentation/reaction engine, sprite assets, dock, and monitoring-event bridge are integrated from the supplied QIRA project. QIRA is presentation-only and does not authorize cryptographic actions.
- Secure Sharing and Decryption pages refresh automatically every 4 seconds while visible and refresh again when the browser window regains focus. The recipient's approved share list is filtered against their authenticated user ID.
- The existing backend requires the sender's approved sharing intent, sender authorization, an active recipient key session, and administrator approval before a share becomes decryptable. This is intentional access control, not a delivery delay.
- The backend's existing record validity remains capped at 24 hours and cannot exceed the associated intent's validity window.
- Existing monitoring provider/backend logic is retained; QIRA observes meaningful monitoring transitions and does not drive the monitoring state.

## Run
1. Keep the existing backend `.env` and key material if using an existing encrypted database. Never generate replacement keys for that database.
2. Start MongoDB and backend using the project's existing launcher.
3. In `frontend`, run `npm ci` and then `npm run dev` (or `npm run build`).
4. Log in as sender and recipient in separate browser profiles. Ensure the recipient has an active key session.
5. Sender: create/use an approved intent that explicitly names the recipient and permits `share`; encrypt a record under that intent; submit the share; complete sender authorization; have an administrator approve it.
6. Recipient: open Secure Sharing and Decryption. The approved share should appear automatically within approximately four seconds while the page is visible. Select the shared record and its authorization, then run decryption.
7. Test expiry, revoked shares, wrong recipient, inactive recipient key session, missing approvals, and expired intent. These cases should remain denied.

## Validation caveat
This integration has been source-reviewed and syntax checks are performed separately. A true two-account end-to-end test requires the user's MongoDB, matching existing key material, valid accounts, active key sessions, and administrator approval; those runtime prerequisites are not embedded or simulated here.

---


## QUICK START WINDOWS
*Source file: `QUICK_START_WINDOWS.txt`*

CipherQ v18 — Windows quick start (3 steps)

1. Start MongoDB (Windows service or your existing local MongoDB server).
2. Open this extracted folder and double-click START_CIPHERQ.bat.
   The launcher creates backend/.venv if needed, installs Python requirements,
   installs frontend packages if needed, checks MongoDB, and starts API + UI.
3. Open http://127.0.0.1:5173 and sign in with your existing account.

Important:
- Keep backend/.env and backend/.dev_secrets.json / .dev_secrets_v2 unchanged
  when using an existing encrypted database. They must match that database.
- Never regenerate keys or run migration scripts as a startup step.
- If startup stops at the MongoDB/key preflight, resolve that prerequisite first;
  do not reset or delete the database.
- Attachments are optional PDF/TXT/PNG/JPG files up to 3 MB and are stored inside
  the encrypted, integrity-sealed intent version.
- Approval requires successful evidence validation and a different admin account
  from the requester. Drafts that fail validation are visible in Admin Dashboard
  under "Draft / needs validation", but cannot be approved until validation succeeds.

---


## RUN WINDOWS
*Source file: `RUN_WINDOWS.md`*

# Windows quick start (safe mode)

## One command

Open PowerShell in the extracted `CipherQ_v18_HARDENED` folder and run:

```powershell
.\START_CIPHERQ.bat
```

This checks MongoDB connectivity, installs backend dependencies into `backend\.venv` if needed, installs frontend dependencies if `frontend\node_modules` is absent, then opens separate terminals for FastAPI and Vite. The API is `http://127.0.0.1:8000`; the UI is `http://127.0.0.1:5173`.

## Separate PowerShell terminals

Python 3.11 and Node.js 20+ are required. Start MongoDB first. From the project root:

**Terminal 1 — backend**

```powershell
Set-Location .\backend
py -3.11 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt -r requirements-dev.txt
.\.venv\Scripts\python.exe -m uvicorn api.main:app --host 127.0.0.1 --port 8000
```

If `backend\.venv` already exists, omit the `py -3.11 -m venv .venv` line. These commands do not require
PowerShell script activation. Do not replace the existing database or key material. Ensure `backend\.env`
contains the existing database name and matching key configuration before starting the API.

**Terminal 2 — frontend**

```powershell
Set-Location .\frontend
npm ci
npm run dev -- --host 127.0.0.1
```

Vite proxies `/api` to `http://localhost:8000` by default. To use another backend address, set
`VITE_API_PROXY_TARGET` before starting Vite.

## Important: existing encrypted database

- The launcher defaults a newly created `.env` to `MONGODB_DATABASE=cipherq_new`. If `backend\.env` already exists, it is not overwritten.
- Copy the **existing** `backend\.dev_secrets.json` from the project that currently decrypts `cipherq_new` into this project's `backend` folder before launching, unless you already configure the exact same keyring and JWT secret through environment variables or secret files.
- Do not delete or regenerate `.dev_secrets.json` for an existing encrypted database. A new key cannot decrypt old ciphertext.
- Start MongoDB before running the launcher. The launcher checks connectivity and exits without changing data if MongoDB is unreachable or the existing key material is missing.
- The `.env` file must remain local and must not be committed. Do not paste secrets into chat or Claude.

## If startup stops

Read the message in the first terminal. Fix the prerequisite it names and rerun `START_CIPHERQ.bat`. If login returns HTTP 500, inspect the backend terminal for the sanitized request path and error type. Do not run migration scripts with `--apply` or drop a database as a troubleshooting step.

---


## SECURE SHARING WORKFLOW UPDATE
*Source file: `SECURE_SHARING_WORKFLOW_UPDATE.md`*

# CipherQ Secure Sharing workflow update

This is a targeted change to the Secure Sharing feature. Existing authentication, RBAC, intent integrity, monitoring, encryption/decryption pages, audit chain, key-session management, and administrator workflows remain in place.

## Updated sender / recipient flow

1. The sender selects a registered recipient, writes a message or selects a supported file, and clicks **Encrypt and send**.
2. CipherQ encrypts the payload using the existing intent-bound crypto path and re-wraps the data key for the recipient's active key session.
3. If the approved sharing policy returns `PERMIT`, the share is delivered directly to the recipient's Inbox. If policy requires elevated approval, the existing approval path remains in effect.
4. The recipient must complete a fresh, challenge-bound face verification before opening/decrypting. The backend checks the face grant as well; hiding the UI prompt is not enough to bypass it.
5. The sender can use **Decrypt my copy** in Sent to decrypt the original sender-owned record during its validity period.
6. Both participants can open a private conversation. Conversation replies are encrypted at rest under a share-specific HKDF-derived key from the shared record DEK, and the API returns plaintext only to an authenticated participant after a fresh face step-up. Each reply is limited to 500 characters and three sentences; a thread is limited to 40 replies.
7. The recipient can send a `RECEIVED` or `THANKS` acknowledgement. The sender sees the acknowledgement in Sent.

## One-time sharing intent setup

The existing intent architecture is retained. Create and approve one sharing intent per sender/recipient pair (not one per message):

- Enable user-to-user sharing and select the intended recipient.
- Keep both `encrypt` and `decrypt` enabled; the share operation is added by the sharing toggle.
- The form now raises the suggested `max_uses` to 100 and `max_bytes` to 12 MiB when sharing is enabled.
- The share composer auto-selects the approved intent for that recipient when there is exactly one eligible intent.

An already exhausted intent remains exhausted. Create a new approved version/intent for future messages rather than editing database counters.

## File size and format

The current MongoDB document and nested-base64 architecture cannot safely support literally unlimited file sizes. This update raises the supported per-file cap from approximately 800 KiB to **8 MiB**. Supported extensions remain PDF, DOC/DOCX, XLSX, PPTX, PNG/JPG/JPEG, GIF, WEBP, TXT and CSV. The request body ceiling is 16 MiB and the intent byte ceiling is 12 MiB to accommodate the nested envelope/base64 overhead. Larger files require a separate chunked encrypted-object-storage design and are intentionally not claimed as supported here.

## Security notes

- Share delivery still requires a valid, approved intent bound to the intended recipient and the existing authorization decision.
- Ordinary `PERMIT` shares become immediately available in Inbox; `REQUIRE_APPROVAL` requests continue through the existing approval path.
- Sender and recipient remain the only participants allowed to access the share and its conversation.
- Conversation text is not stored as plaintext in MongoDB. It is authenticated-encrypted and bound to the share ID, message ID and sender ID.
- Recipient face verification is enforced by both the UI and backend before shared-content decryption/opening. Conversation reads and writes also require a fresh face grant.
- Revocation and expiry prevent further access through CipherQ; they cannot erase content already downloaded by a participant.

## Validation status for this archive

- Python source compilation: passed.
- Frontend JSX/JavaScript syntax parsing: passed.
- Record seal/rewrap/DEK extraction round-trip: passed.
- Integration tests were updated, but could not be executed in this build environment because MongoDB/PyMongo was unavailable.
- A full Vite production build could not be executed because npm dependency installation could not reach the package registry. Run the project test/build commands locally after dependencies are installed.


## Automatic recipient key provisioning (targeted update)

- Manual recipient key-session activation is no longer a prerequisite for sending.
- The sender's own active key session remains required for the existing intent-bound encryption workflow.
- On an authorized share request, the backend reuses an active recipient-owned key session when available. Otherwise it provisions a new recipient-owned session through the existing `KeySessionService.create` path.
- The session remains bound to the recipient user ID. Its key is wrapped under the configured QKEY_WRAP keyring sub-key and remains inside the backend; it is never returned to the sender or browser.
- The recipient must still authenticate, obtain the required fresh face-verification grant, and pass the existing decrypt intent/RBAC checks.
- The new session is retained only up to the computed share expiry. Revocation/expiry semantics are unchanged.
- Legacy requests that explicitly provide `recipient_key_session_id` remain supported and are still validated against the recipient owner.

---


## SECURITY BASELINE
*Source file: `SECURITY_BASELINE.md`*

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

---


## SHARED DECRYPT CASE ASSIGNMENT FIX
*Source file: `SHARED_DECRYPT_CASE_ASSIGNMENT_FIX.md`*

# Shared recipient decryption authorization fix

## Symptom
An approved recipient could be denied with `USER_REMOVED_FROM_CASE` while decrypting a file shared by another user. The evidence validator was re-checking the recipient against the sender's supporting case on every decrypt.

## Change
Evidence/case assignment is still checked during the sender's share authorization. For a subsequent decrypt, the backend now skips that recipient-specific case-assignment re-check only when the request is for an `APPROVED` share, the authenticated actor is the exact recipient, the share owner is the intent owner, and the share is bound to the requested intent.

The existing checks remain in place: account enabled state, approved/current intent and integrity, intent validity and use limits, share status and expiry, recipient ownership, session/device validity, recipient monitoring/risk policy, key-session ownership, fresh face step-up, authenticated encryption/integrity, revocation and audit.

The sender's live session or monitoring state is not used to authorize recipient decryption after delivery. Recipient decryption still requires the recipient's own valid authenticated session and all recipient-side controls.

## Regression test
`backend/tests/test_33_secure_sharing.py::test_approved_share_recipient_can_decrypt_without_case_assignment` creates and delivers a share, removes the recipient from the supporting case, and verifies the recipient can still decrypt the approved share.

## Validation
Python syntax compilation passed for the modified engine and regression test. Run the full backend integration suite against the configured MongoDB instance before production use.

---


## SIMPLE SECURE MESSAGING
*Source file: `SIMPLE_SECURE_MESSAGING.md`*

# CipherQ Simple Secure Messaging

## User workflow

1. Sign in to CipherQ as usual.
2. Open **Secure Sharing** and choose **New message**.
3. Search for a registered recipient.
4. Enter a message, attach an optional file (maximum 1 MiB), or do both.
5. Click **Encrypt and send**.
6. The message appears in the sender's **Sent** tab and the recipient's **Inbox**.
7. The recipient clicks **Decrypt and read**. The sender can independently click **Decrypt my copy** in Sent.

Messages are available for 24 hours by default. The sender can revoke a message before expiry. Inbox and Sent refresh automatically while the page is open.

## Security model

- Requires a valid authenticated CipherQ account for every API operation.
- Only the sender and designated recipient can list or decrypt a message.
- Each message uses a fresh random 256-bit AES-GCM data-encryption key and 96-bit nonce.
- The data key is separately wrapped for the sender and recipient using HKDF-SHA256 from the configured CipherQ keyring's dedicated purpose-separated `DIRECT_MESSAGE_WRAP` subkey. The key ID is stored so retained historical keyring entries can decrypt older messages after key rotation.
- AES-GCM associated data binds the ciphertext to the message ID, sender, recipient, creation time, expiry time, and key ID. Wrapped keys are also bound to message ID and user ID.
- Ciphertext and key envelopes are stored in the existing MongoDB database abstraction, so whole-document database encryption remains active when configured.
- The backend never writes plaintext message content to audit logs. It records send, decrypt, and revoke events only.
- Face step-up, per-message intent selection, per-message administrator approval, and recipient QKD-session setup are not used by this simple messaging path. Existing identity, intent, QKD, monitoring, authorization, crypto, and audit workflows remain available and unchanged elsewhere in CipherQ.

**Important security scope:** this is authenticated, server-managed encryption at rest and in transit when deployed over HTTPS. It is not end-to-end encryption: the application server can derive the wrapping keys. Do not describe it as end-to-end encrypted.

## Limits and behavior

- File attachment maximum: 1 MiB (1,048,576 bytes), any file type.
- Text maximum: 20,000 characters.
- Message expiry: 24 hours by default; API accepts a shorter expiry, never longer than 24 hours.
- Sender can decrypt their own sent message until it expires or is revoked.
- Recipient can decrypt after delivery until it expires or is revoked.
- Sender revocation blocks future decryption through CipherQ. It cannot erase plaintext or files already downloaded.
- Message status is `DELIVERED`, `READ`, `REVOKED`, or `EXPIRED`.

## API

- `GET /api/messages/recipients?q=...`
- `GET /api/messages?folder=inbox|sent`
- `POST /api/messages`
- `POST /api/messages/{message_id}/decrypt`
- `POST /api/messages/{message_id}/revoke`

The existing `/api/crypto/*` and intent endpoints are not removed or modified by this feature.

---


## TEST RESULTS
*Source file: `TEST_RESULTS.md`*

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

---


## TEST RESULTS PHASE2
*Source file: `TEST_RESULTS_PHASE2.md`*

# Phase 2 Test Report

## Checks run in the build environment

- Backend Python compilation (`python -m compileall -q backend`): **PASS**.
- Targeted backend pytest (`pytest -q tests/test_10_intent_flow.py -k share`): **BLOCKED before collection** because `pymongo` is not installed in the environment.
- Frontend build: **NOT RUN to completion**. `npm ci --offline` failed because a dependency tarball was absent from the local npm cache; the online attempt timed out. No successful production build is claimed.

## Status

Phase 2 ZIP is an **evaluation candidate**. The backend integration tests, MongoDB-backed flow, and browser UI still need to be run locally with the project's dependencies and a configured test database. See `PHASE2_CHANGELOG.md` for the acceptance checklist.

---

