# CipherQ Phase 1 + Phase 2 + Phase 3 integration status

This package is the Phase 3 attachment candidate, which already includes the Phase 1 24-hour key-session/record lifetime work and Phase 2 recipient-bound sharing with server-side administrator approval. The changes in this integration pass increase the attachment source-file limit from 500 KiB to 1 MiB and raise the default request body/data-scope limits to account for base64/JSON overhead.

## Security-critical behavior retained
- Same-owner decryption from a fresh authorized login/device is allowed only when record ownership and intent ownership match the authenticated user, and the current session/device, monitoring, risk/step-up, intent validity, record validity, and key checks pass.
- User-to-user sharing remains recipient-bound and requires administrator approval before recipient decryption. Other users cannot decrypt another user's record.
- Encryption keys are not regenerated and no database migration is performed by this package.

## Validation performed in this packaging pass
- Backend Python compileall: PASS.
- Targeted pytest run: BLOCKED during collection because `pymongo` is not installed in the packaging environment (`ModuleNotFoundError`). No claim of full backend integration test success is made.
- Browser round-trip and frontend production build: NOT run in this environment.

## Before evaluating locally
1. Keep your existing MongoDB databases and encryption key files unchanged.
2. Confirm `backend/.env` selects the intended database and uses the existing matching keyring/secrets. Do not copy or generate keys as a workaround.
3. If `MAX_BODY_BYTES` is explicitly set in `backend/.env`, set it to `3145728` (3 MiB) for 1 MiB attachments; an explicit smaller value overrides the new default.
4. Create an approved intent with `max_bytes` at least as large as the serialized attachment envelope (2,097,152 bytes supports the 1 MiB source-file limit). Existing intents keep their prior byte scope and may need a deliberate authorized revision or a new intent.
5. Run the backend tests in the project's configured virtual environment, then `npm ci` and `npm run build` in `frontend`, and verify the 1 MiB attachment round-trip and cross-session owner decryption plus recipient share approval flow.
