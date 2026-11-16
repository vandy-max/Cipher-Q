# Phase 3 Attachment Test Guide

## Setup
1. Extract this ZIP into a new folder; do not overwrite the Phase 2 folder.
2. Use your existing local environment and database. Do not reset the database or rotate encryption keys.
3. Install the existing backend/frontend dependencies using the project's Windows setup guide.
4. Start the application and log in as an authorized user.

## Manual tests
1. Encrypt and decrypt a short text message; verify text behavior is unchanged.
2. Encrypt a small `.txt` attachment; decrypt it and compare downloaded bytes with the original.
3. Repeat with a PDF, PNG/JPG image, and a file with spaces and Unicode characters in its filename.
4. Verify the original filename and MIME type are retained where the browser supports them.
5. Try an attachment just below the 500 KiB limit and verify the operation follows normal intent size policy.
6. Try a file larger than 500 KiB; the UI must reject it before sending an encryption request.
7. Try an intent whose `max_bytes` is too small for the serialized attachment envelope; expect normal server-side denial, not a bypass.
8. Tamper with ciphertext or use an invalid record ID; decryption must fail safely.
9. Test attachment records shared through Phase 2: the recipient must not decrypt while approval is pending and should only decrypt after approval and all existing policy checks.
10. Test unauthorized users, expired intents, expired records, invalid key sessions, and server restart persistence.
11. Confirm text encryption, Phase 1 same-user continuity, Phase 2 sharing, admin approval, audit, and live monitoring regressions remain unchanged.

## Known limitation
The current implementation uses the existing JSON/base64 API. The client-side attachment limit is 500 KiB and the serialized envelope is larger than the source file. For larger attachments, implement a dedicated streaming/multipart path with server-side size limits and authenticated chunk/finalization semantics in a later, separately tested change. Do not simply raise limits without reviewing the request guard and API schema.


## Updated 1 MiB attachment limit
- A source file may be up to 1,048,576 bytes. Create an approved intent whose `max_bytes` is at least the serialized attachment envelope size (use 2,097,152 bytes for a 1 MiB file).
- Set `MAX_BODY_BYTES=3145728` or leave it unset to use the updated 3 MiB default. A smaller explicit value in `backend/.env` overrides the default and will reject large requests.
- Verify 1 MiB encrypt/decrypt round-trip and reject a file larger than 1 MiB.
