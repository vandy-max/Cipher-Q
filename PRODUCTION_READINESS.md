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
