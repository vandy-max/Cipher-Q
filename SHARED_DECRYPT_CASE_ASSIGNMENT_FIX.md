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
