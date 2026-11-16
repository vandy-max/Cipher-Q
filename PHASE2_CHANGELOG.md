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
