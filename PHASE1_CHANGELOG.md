# CipherQ Phase 1 — Same-user encryption/decryption continuity

## Scope
This package changes only Phase 1. User-to-user sharing behavior, attachment encryption behavior, and live monitoring behavior are not intentionally changed.

## Changes
- Ciphertext records now expire no later than the approved intent's `valid_until`, and no later than the existing 24-hour record lifetime.
- When a record is created, its owner's active key session is extended to cover the record's server-computed expiry. The default key-session lifetime is now 24 hours (86,400 seconds), matching the 24-hour maximum record lifetime. Both the Settings dataclass and environment fallback use this default; an explicit KEY_SESSION_TTL_SECONDS setting still overrides it. Live record usage may extend an active key session to the record’s computed expiry, bounded by the record’s approved validity window.
- The same owner may resume decryption from a new authenticated device/login session, provided the current session and device pass the existing ownership, session-validity, device-revocation, monitoring, risk/step-up, intent approval, intent validity, record ownership, and key availability checks.
- Encryption and sharing remain bound to the original intent session/device.
- Added API-level regression tests for owner decryption from a new authorized device and for key-session lifetime covering record validity.
- Removed local `.env` and development secret files from the deliverable. Configure the project using the provided `.env.example` and your own secrets.

## Security semantics
- Stable user ID owns the record.
- Login session ID and device ID are authorization/audit context, not encryption-key derivation inputs for the saved ciphertext.
- The original record ciphertext and key reference are reused; device changes do not re-encrypt the record.
- The server does not silently replace missing or destroyed keys. Explicitly revoked/expired key sessions remain unavailable.
- A record cannot be decrypted outside its approved intent window, even if a key session remains available for another record.

## Validation performed in this environment
- Python compile check passed for backend API, key management, crypto, intent engine, and tests.
- Pure cryptographic unit tests: 18 passed.
- Full API tests could not run in this environment because `pymongo` is not installed and no MongoDB test service is available here. Run the full suite in the project's supported environment before relying on the ZIP for production.

## Before running
1. Back up your existing database and keep your current secret/key files private.
2. Install backend dependencies from `backend/requirements.txt` in your existing virtual environment.
3. Configure `backend/.env` from `backend/.env.example` using your existing correct keyring and database settings; do not rotate or replace keys just to test this feature.
4. Start MongoDB and run the complete backend test suite before replacing your working project.


### Lifetime alignment update
- Set default key-session lifetime to 86,400 seconds (24 hours).
- Encrypted-record maximum lifetime remains 86,400 seconds (24 hours), and actual expiry is still capped by the approved intent validity end.
- Updated `backend/.env.example` and added a configuration regression test.
