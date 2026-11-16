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
