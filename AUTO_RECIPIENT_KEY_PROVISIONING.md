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
