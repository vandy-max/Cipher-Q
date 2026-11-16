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
