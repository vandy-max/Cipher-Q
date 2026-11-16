# CipherQ Phase 3 — Attachment Encryption Candidate

## Scope
This candidate builds on the Phase 2 user-to-user sharing ZIP. It adds a minimal attachment path to the existing Encrypt/Decrypt screens, reusing the current server-side cryptographic operation and authorization pipeline.

## Changed files
- `frontend/src/pages/EncryptionPage.jsx`: adds a Text message / File attachment selector; reads the selected file as bytes, packages filename/MIME type/original size/content into a versioned envelope, then submits that envelope through the existing authorized encryption workflow. Enforces a 1 MiB (1,048,576-byte) source-file limit. The request guard defaults to 3 MiB to allow JSON/base64 envelope overhead, and the intent data-scope ceiling is 2 MiB so an attachment envelope can fit within the approved byte scope.
- `frontend/src/pages/DecryptionPage.jsx`: recognizes the encrypted attachment envelope after the existing decrypt operation and offers a downloaded file with its original name and MIME type. Ordinary text decryption remains supported.
- `CLAUDE_PHASE3_PROMPT.md`: gives Claude focused instructions for reviewing and hardening this candidate without rebuilding the application.
- `PHASE3_TEST_GUIDE.md`: manual tests and known constraints.

## Security notes
- File bytes and metadata are packaged before being sent to the existing encryption API; they are not uploaded as plaintext to a new endpoint.
- This uses the existing server-side authorization, encryption, record persistence, and (where applicable) Phase 2 sharing approval path.
- The frontend limit is not a substitute for server-side limits. The current API schema and request guard still impose their own maximum request sizes.
- The intent's `max_bytes` must be large enough for the serialized envelope, which is larger than the original file due to base64 and metadata overhead.
- Browser downloads occur only after the existing decrypt API succeeds. A user should clear decrypted content when finished.

## Validation status
- Source edits and ZIP structure were checked.
- Full frontend production build was not run: `node_modules` is not present in this environment, and dependency installation is not available here.
- Backend integration tests were not run as part of this attachment UI change. Phase 2's prior test limitations still apply.
- This is an evaluation candidate, not a claim of fully verified production readiness.


## Phase integration repair update
- Confirmed this candidate contains Phase 1 24-hour key-session/record lifetime settings and same-owner cross-session decryption checks, plus Phase 2 recipient-bound sharing with administrator approval and recipient-only decryption.
- Raised the original attachment limit from 500 KiB to 1 MiB; increased the default API request-body limit to 3 MiB to allow base64/JSON overhead; raised the intent data-scope maximum to 2 MiB to accommodate the serialized envelope. Explicit `MAX_BODY_BYTES` values in a local `.env` override the default and must be at least `3145728` for 1 MiB attachments. Existing intents retain their own `max_bytes`; create a new intent or safely revise the existing approved intent scope to at least the serialized envelope size.
- The decryption authorization continues to require an authenticated, valid current session/device, active monitoring/step-up policy where applicable, record ownership or an approved recipient share, record/intent binding, key availability, and validity windows. It does not bypass these controls.
