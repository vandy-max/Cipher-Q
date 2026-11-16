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
