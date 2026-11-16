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
