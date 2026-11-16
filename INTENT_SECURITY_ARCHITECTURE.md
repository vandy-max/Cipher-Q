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
