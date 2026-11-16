# CipherQ — Live Monitoring Stabilization Report

Scope: Live Monitoring only. Untouched original is preserved in `_ORIGINAL_UNMODIFIED/` inside the delivered ZIP (byte-identical to the uploaded project). Authentication/JWT/RBAC, crypto (AES-GCM/HKDF/BB84/keymgmt), intent, Qira, config.py, dependencies.py and identity/stepup.py were NOT modified (verified by `diff -rq` against the original: only the files below differ).

## 1. Modified Files Report

| File | Original issue | Modification | Justification |
|---|---|---|---|
| backend/monitoring/service.py | Hash-chained audit log fully re-verified (O(audit size), decrypts every entry) on **every** heartbeat; concurrent refresh/denied-request paths unlocked (races -> duplicates); heartbeat-lapse audit entry repeated each tick; plain session expiry revoked the stored session (forcing admin approval for non-admins); active listing scanned/decrypted all rows | TTL + single-flight audit-integrity cache (`MONITORING_AUDIT_VERIFY_TTL_SECONDS`, default 30 s; informational field only, never changes posture); `session_lock`; `refresh()`/`report_denied_request()` under the per-session lock; lapse audited once; expiry alone no longer revokes the session (revocation, device revocation, critical risk, failure thresholds unchanged); `list_active`, `list_session_summaries` | Fewer reads, no duplicate alerts/races, no needless admin-approval requests; security posture unchanged |
| backend/api/repositories.py | Every heartbeat did a CAS write of the full monitoring row + event-count scan | Write-behind hot state: healthy heartbeats update memory; security-significant changes (status/state/risk/failure counts/revocation) flush immediately; otherwise flush every `MONITORING_PERSIST_INTERVAL_SECONDS` (30 s; `0` = legacy write-through), on stop/revoke, and at process exit; in-memory event counting; index lookup by session; throttled housekeeping | DB write per heartbeat removed; evidence/audit still persisted immediately |
| backend/api/routers/monitoring.py | Concurrent start/retire could create duplicate live sessions; a step-up probe error in heartbeat surfaced as 500 | start/retire under session lock; probe error treated as failed tick; new `GET /api/monitoring/admin/sessions` (ADMIN only, limit 1–500, 2 s cache) | No duplicates; no 500 on lockout; admin summaries/history |
| backend/api/schemas.py | — | `MonitoringSessionSummaryResponse` (additive) | Admin summary contract |
| backend/tests/test_30_monitoring_identity.py | Two tests encoded the old per-heartbeat-write contract / tampered the DB directly | Updated to the write-behind contract (+`reset_hot_state()`) | Intentional contract change, documented |
| backend/tests/test_31_monitoring_stabilization.py | — | 15 new tests | Coverage |
| frontend/src/context/MonitoringContext.jsx | Multiple tabs each ran a heartbeat loop + camera; fixed-rate retry hammered a failing API; any error could end monitoring; 409 treated as failure; hidden tab injected a failed identity tick; no offline handling | Leader election (Web Locks + BroadcastChannel, one loop/camera per session); capped exponential backoff; error classification (only auth/forbidden/revoked/expired end monitoring; 404 re-attaches); 409 re-syncs nonce without counting failure; pause when offline/resume on `online`; no forced failure on tab hide; stable messages (no 5xx detail exposed) | Stability, recovery, fewer API calls |
| frontend/src/components/monitoring/MonitoringBadge.jsx | Missing step-up grant or expiry shown as "revoked / admin approval" | Uses classifier: expired/step-up -> face-only recovery; revoked -> admin approval | No unnecessary approval requests (RBAC preserved server-side) |
| frontend/src/components/monitoring/monitoringErrors.js, monitoringLeader.js (new) | — | Helpers | — |
| frontend/src/components/monitoring/AdminMonitoringSessionsPanel.jsx (new), pages/AdminDashboard.jsx, services/api.js | No admin session summary/history view | "Monitoring Sessions" tab; `listMonitoringSessions` | Admin dashboard accuracy |
| frontend/.env.example | Documented 10 s interval | Comment updated to 2500 ms default | Doc accuracy |
| frontend/tests/monitoring-helpers.test.js, monitoring-context.spec.jsx (new) | — | node:test + vitest/jsdom tests | Coverage |

**API change (additive only, no callers broken):** `GET /api/monitoring/admin/sessions`. All existing endpoints/schemas unchanged.

## 2. Testing Report

Executed environment: mongomock (no mongod available; FerretDB download blocked) — real DB-engine behavior not exercised. jsdom with mocked API/camera — no real browser, camera, or network exercised.

Suites (final run): backend **251 passed, 4 failed** — the same 4 fail on the untouched original (`test_oversized_body_rejected`, `test_expired_record_is_rejected_using_server_timestamp`, `test_seed_admin_script_bootstrap_and_refusals`, `test_reencrypt_after_key_rotation_and_verify_audit`; pre-existing, unrelated modules, not touched). Frontend node:test **11/11**, vitest/jsdom provider **10/10**, `vite build` succeeds.

| # | Scenario | Expected | Actual (tests executed) | Result |
|---|---|---|---|---|
| 1 | Normal & suspicious activity | Healthy stays ACTIVE; mismatches escalate and persist immediately | test_30 healthy heartbeats; test_31 `security_change_is_persisted_immediately` (3 mismatches -> warning in DB) | PASS (synthetic descriptors) |
| 2 | False positives | Lockout/409/tab-hide/expiry/lapse not mis-flagged | `heartbeat_during_account_lockout…`, `lapse_is_audited_once`, `expired_session_requires_face_reauth…`, provider 409 + tab-hide tests | PASS for the covered causes; real-camera false-positive rate NOT measured |
| 3 | Session expiry & logout | Expired -> face-only re-auth; revoked -> admin approval; stop removes authorization; 401 ends monitoring | test_31 expiry/revoked tests, test_30 stop test, provider 401 test | PASS |
| 4 | Refresh & restart | Existing session re-attached, no new start, single loop | provider test (mocked API) | PASS (jsdom only; not real browser) |
| 5 | Network disconnect/reconnect | Backoff, "connection lost", no termination, recovery, pause offline | provider tests (network, 5xx, offline/online) | PASS (simulated) |
| 6 | Multiple concurrent users | No duplicate sessions/workload | `concurrent_starts_create_one_live_session`, two-tab leader test, `other_user_cannot_read_or_stop` | PASS for these; no multi-process/load test executed |
| 7 | Duplicate heartbeat/alert prevention | Replay/wrong nonce rejected; lapse audited once; events bounded | test_30 replay/bounded tests, test_31 lapse test | PASS |
| 8 | Recovery after API failures | Flush failure doesn't break heartbeat; 5xx/404 recover | `flush_failure_does_not_break_heartbeat`, provider 5xx/404 tests | PASS |
| 9 | DB write frequency & aggregation | No write per heartbeat for monitoring rows | benchmark below; `healthy_heartbeats_cause_no_session_or_event_flush` | PASS |
| 10 | Admin summaries/history | ADMIN only, accurate content | `admin_sessions_summary_access_and_content` | PASS (API); UI tab built, not rendered in a browser |
| 11 | Evidence saving & dashboard sync | Evidence persisted, visible to admin without refresh | backend persistence/summary tested; panel polls | PARTIAL: UI sync not executed in a browser |
| 12 | Monitoring after device revocation | Start blocked, ops blocked, no resume | `device_revocation_blocks_monitoring_start`, test_30 revoked-device test, `stopped_or_revoked_session_cannot_resume_heartbeats` | PASS |

Not executed: real face-login E2E with a camera, real mongod, multi-worker deployment, load testing, long-duration soak.

## 3. Performance Comparison (40 heartbeats, mongomock, same harness on original vs modified; `benchmark_test.py`)

| Metric | Before | After |
|---|---|---|
| DB reads / heartbeat | 14.1 | 8.1 |
| DB writes / heartbeat (total) | 4.0 | 3.0 |
| `monitoring_sessions` writes / heartbeat | 1.0 | 0.0 (flush ≤ every 30 s or on security change) |
| audit_logs + audit_head reads / heartbeat | 2.0 | 0 (verified ≤ every 30 s) |
| Mean / p95 latency per heartbeat (mongomock) | 9.0 / 11.4 ms | 6.3 / 7.4 ms |
| Duplicate events (40 heartbeats) | 1 | 1 (lapse dedupe covered by test) |
| Frontend heartbeat loops per user with N tabs | N | 1 (leader) |
| Frontend retry cadence during outage | fixed interval | capped exponential backoff (12 -> <8 calls in 30 s simulated) |
| Recovery after outage | next fixed tick | immediate on `online`; ≤ one backoff cap otherwise |

Latency is on a tiny in-memory audit chain; with a real DB and a large audit log the saving grows with audit size (before: O(n) per heartbeat). Remaining per-heartbeat writes: `identity_probe_hashes` x2 (single-use probe replay protection — a security control, intentionally unchanged) and `authz_devices` x1 (authorization module, out of scope).

## 4. Behavior changes & remaining issues
- Write-behind: a process crash can lose up to `MONITORING_PERSIST_INTERVAL_SECONDS` of non-significant heartbeat counters (never security changes). **Multi-worker deployments must set `MONITORING_PERSIST_INTERVAL_SECONDS=0`** (state is per process).
- Audit-integrity result may be up to 30 s stale (informational field only).
- Plain expiry no longer revokes the stored session; crypto remains blocked until face re-auth.
- Heartbeat-gap fail-closed policy (45 s) intentionally unchanged: background-tab timer throttling can still cause a lapse.
- Hidden-tab forced-failure removed (it produced false positives).
- Frontend hook behavior verified only in jsdom with mocks.
- `test_audit_tamper_still_reported` is a weak test (monkeypatched verifier).

## 5. Final Verification
- Original vs modified diff: only the files in section 1 differ; auth/JWT/RBAC, crypto/BB84/HKDF, quantum/keymgmt, intent, Qira, config.py, dependencies.py, identity/stepup.py are byte-identical to the original.
- Full backend suite: all auth, RBAC, encryption, key-rotation-independent, intent and Qira tests pass except the 4 pre-existing failures that fail identically on the original.
- Admin monitoring access: ADMIN-only endpoint tested (non-admin denied); existing monitoring endpoints' contracts unchanged.
- Not verified in a live environment: items under "Not executed" above.

---
# 7. Secure Sharing completion (separate task)

## 7.1 Files modified / added (Secure Sharing only)
| File | Change |
|---|---|
| backend/api/routers/crypto_ops.py | Recipient search (`GET /recipients?q=`); share-envelope validation inside `/encrypt` (only for `CIPHERQ_SHARE_V1` payloads); optional `kind` and `expires_in_minutes` on `POST /shares`; duplicate-request protection (unresolved shares only); usernames and `opened_ts`/`last_access_ts`/`approved_ts` in share views; new `POST /shares/{id}/open` |
| backend/crypto/share_payload.py (new) | Server-side validation/sanitising of text and file envelopes |
| backend/audit/events.py | One new event: `SHARE_OPENED` |
| backend/tests/test_33_secure_sharing.py (new) | 22 end-to-end tests (real API; sender, recipient, third user, admin) |
| frontend/src/pages/ShareMessagesPage.jsx | Rewritten as Inbox / New share / Sent / Approvals (compose → encrypt → share, inbox decrypt) |
| frontend/src/utils/sharePayload.js (new) | Envelope build/parse, SHA-256 check, status labels |
| frontend/src/pages/DecryptionPage.jsx | Additive: renders `CIPHERQ_SHARE_V1` envelopes (text/attachment paths unchanged) |
| frontend/src/services/api.js | `listShareRecipients(q)`, `openShare` |
| frontend/tests/share-payload.test.js, share-page.spec.jsx (new) | Frontend tests |
Not touched: sharing crypto (`crypto/records.py` seal/rewrap, `keymgmt`), intent engine, evidence, monitoring, auth/RBAC, admin dashboard, Qira.

## 7.2 Existing foundation reused
`/encrypt` + AES-GCM sealed records (`crypto/records.py`), intent-bound share authorization (`/decisions`, `eng.decide`), recipient key-session re-wrap (`crec.rewrap`), `crypto_shares` lifecycle (PENDING → PENDING_ADMIN → APPROVED / REJECTED / REVOKED / EXPIRED), admin approval, recipient decrypt through the decision + single-use crypto context, audit log. No second sharing system was created.

## 7.3 Encryption and recipient decryption
1. The sender picks a recipient and an approved intent that names that recipient and allows `encrypt` + `share` (this intent is the "security/approval policy").
2. The browser wraps the text or file in a `CIPHERQ_SHARE_V1` envelope (subject, description, filename, size, SHA-256, content) and asks for an `encrypt` decision for exactly that byte count.
3. `/encrypt` validates and rebuilds the envelope server-side (sanitised filename, allow-listed type, MIME derived from the extension, magic-byte check, digest/size check) and refuses anything that would be larger than the authorised size. It then seals it with a fresh random DEK under AES-GCM; the DEK is wrapped under the sender's key session with the record context (record, owner, intent, resource, classification, size) as associated data.
4. `POST /shares` re-checks recipient eligibility and the share decision, then **re-wraps the DEK under the recipient's own key session** (`rewrap`). The ciphertext is unchanged; no key, password or token is shared and no key material ever reaches the browser. Status becomes PENDING_ADMIN (or PENDING if the intent still needs approval).
5. An administrator approves. Only then can the recipient obtain a decision (otherwise 404). The recipient decrypts with their own authenticated session, device, step-up and key session; the server verifies the GCM tags and context, and refuses on any mismatch, expiry, revocation or recipient change. The browser re-verifies the file's SHA-256 before offering the download.

## 7.4 Test results (actually executed)
- Backend full suite: **277 passed, 4 failed** — the same 4 that fail on the untouched original (`test_oversized_body_rejected`, `test_expired_record_is_rejected_using_server_timestamp`, 2 in `test_80_ops_config`).
- Frontend: node:test **16/16**; vitest/jsdom **14/14** (10 monitoring, 4 sharing page); `vite build` succeeds. A JS-built envelope was confirmed byte-identical to the backend's canonical form.

| # | Scenario | Result | Evidence |
|---|---|---|---|
| 1,2 | Text user1 → user2, decrypted exactly (unicode/newlines), lifecycle statuses | PASS | `test_text_sender_to_recipient_roundtrip_with_status_lifecycle` |
| 3,4,5 | PDF sent, decrypted, byte-identical + SHA-256 | PASS | `test_pdf_roundtrip_is_byte_identical` |
| 6 | Recipient cannot reach sender's key/source record | PASS | `test_recipient_cannot_reach_sender_key_or_source_record` |
| 7 | Third user cannot read/open/revoke/approve a share; anonymous denied | PASS | `test_third_user_and_anonymous_cannot_touch_a_share` |
| 8 | Other organization | **NOT TESTABLE AS SPECIFIED** — CipherQ has no organization/tenant model (single deployment = one organization). Covered instead: disabled/unknown users are not recipients and are rejected server-side | `test_disabled_or_unknown_users_are_not_valid_recipients` |
| 9,10 | Tampered ciphertext, swapped/wrong wrapped key, recipient substitution fail closed | PASS | `test_tampered_ciphertext_and_wrong_key_fail_closed`, `test_recipient_substitution_is_rejected` |
| 11 | Expired shares rejected; expiry can only shorten | PASS | `test_expiry_is_enforced_and_sender_can_only_shorten` |
| 12 | Revoked share cannot be retrieved again | PASS | `test_revoked_and_pending_shares_cannot_be_retrieved` |
| 13 | Pending approval blocks access | PASS | same test |
| 14 | Repeated requests do not duplicate | PASS (unresolved shares) | `test_repeated_share_request_is_idempotent` |
| 15 | Hand-constructed unauthorised calls fail | PASS | tests 7, 13 |
| 16 | Invalid uploads create no record/share | PASS (8 variants) | `test_invalid_payloads_create_no_record_or_share` |
| 17 | Existing encrypt/decrypt unchanged | PASS | `test_ordinary_encryption_is_unchanged…` + full suite |
| 18 | Existing intent/evidence/case flows | PASS | full suite (test_10, test_20, test_32) |

## 7.5 Testing with User 1 and User 2
1. Register/log in as two users (User 1 sender, User 2 recipient) and an administrator; each user completes face enrolment and creates an active key session (the recipient must have one).
2. Admin → Evidence Cases: create a case, assign User 1 **and User 2** (picker).
3. User 1 → Create Intent: operations `encrypt`, `decrypt`, `share`; recipient = User 2; the case reference; submit; admin approves.
4. User 1 → Secure Sharing → New share: search/select User 2, choose the intent, text or file, optional subject/description/expiry → Review → Encrypt and send. (Complete step-up if asked.) If the status is "Sent · awaiting sender authorization", press Authorize request under Sent.
5. Admin → Secure Sharing → Approvals → Approve.
6. User 2 → Secure Sharing → Inbox → Open and decrypt (step-up if asked). Read the text or download the file; the integrity line must say verified.
7. User 1 can see Opened / Decrypted; Revoke makes the item unavailable to User 2 again.

## 7.6 Limitations / known issues
- **No organization model**: all enabled users of a deployment are one organization; no employee-ID field exists (search is by username / user ID). Cross-organization denial cannot be implemented without a schema change outside this scope.
- **File size ≤ ~800 KB**: the shared `/encrypt` endpoint caps the request at 1.5 M base64 characters; chunked/streaming large-file sharing is not implemented. Upload "progress" is staged (Encrypting → Creating share), not byte-level.
- Subject, description and filename are encrypted, so the inbox shows sender, kind (sender-declared), size and status before decryption, not the subject. `kind` is display metadata only.
- Recipient notification is the auto-refreshing Inbox (4 s polling); no email/push.
- Revocation stops retrieval through CipherQ; it cannot recall plaintext already decrypted or downloaded.
- Duplicate protection covers unresolved shares (double click/retry); the existing, tested behaviour of deliberately re-sharing a record that already has an approved share is preserved.
- The "Opened" state is recorded when the recipient presses Open and decrypt.
- Browser behaviour was verified in jsdom with mocked APIs and by build only, not in a real browser with camera/step-up; real MongoDB not used (mongomock).
- Test isolation note: `test_20` leaves a global policy that denies `share`; `test_33` removes and restores policies locally instead of editing that test.
- ZIP hygiene: `backend/.env` (present in the uploaded project) is excluded from this ZIP; the launcher recreates it from `.env.example`. Copy your own `.env` and `.dev_secrets.json` back locally. The earlier ZIPs I sent contained that `.env`.
