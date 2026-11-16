# Claude Prompt — Review and Harden CipherQ Phase 3 Attachments

You are modifying an existing CipherQ project. This is an incremental patch, not a rebuild.

Start from this Phase 3 candidate and inspect the current Phase 1 key-continuity and Phase 2 user-sharing/administrator-approval code before changing anything.

## Goal
Ensure attachments are encrypted and decrypted using the existing protected cryptographic workflow. Preserve normal text encryption/decryption, same-user key continuity, recipient-specific access, administrator approval, intent validity, RBAC, face/step-up checks, audit, and monitoring.

## Constraints
- Do not rewrite or redesign the project.
- Do not replace the encryption algorithm, key-management system, database, schemas, or auth architecture unless a demonstrated blocker requires a documented minimal change.
- Do not reset databases, delete records, or rotate keys.
- Do not implement unrelated phases or change live monitoring.
- Do not trust filename, MIME type, file size, user ID, recipient ID, or approval status supplied by the browser without server-side validation.
- Do not store plaintext files or key material in logs or persistent storage.
- Keep a conservative file size limit unless the backend request guard, Pydantic limits, and resource-exhaustion risks are explicitly reviewed together.

## Required review and improvements
1. Trace how the current file envelope passes through `useSecureOperation`, the decision endpoint, `/api/crypto/encrypt`, encrypted record storage, and `/api/crypto/decrypt`.
2. Verify the envelope is encrypted as plaintext by the existing server-side encryption mechanism; the frontend must never receive encryption keys.
3. Validate decoded envelope structure, filename length/characters, MIME type, original size, base64 validity, and consistency between declared and actual byte lengths.
4. Prevent malformed envelopes from causing unsafe downloads or unbounded memory use.
5. Preserve exact file bytes across encrypt/decrypt for text files, PDFs, images, zero-byte files if policy allows, binary files, Unicode filenames, and files with spaces or unusual extensions.
6. Ensure decryption downloads are only offered after server authorization and successful authenticated decryption.
7. Ensure a shared attachment cannot be decrypted by a recipient until the existing administrator approval workflow authorizes it.
8. Verify the intent's byte limit and API body limits are enforced server-side. Do not bypass policy by counting only the source file while ignoring the envelope overhead.
9. Keep the 500 KiB limit if a larger secure path cannot be verified. If larger files are needed, propose a separate multipart/streaming design rather than silently raising limits.
10. Add unit/integration tests for malformed base64, corrupted envelopes, invalid filenames, oversize requests, tampered ciphertext, missing keys, expired intents/records, unauthorized users, pending/rejected shares, and successful recipient download after approval.
11. Run the available backend tests and frontend production build. Report actual commands, results, failures, and any tests blocked by dependencies or missing MongoDB.

## Deliverable
Return one complete runnable ZIP of the existing project with only necessary changes, a file-by-file changelog, Windows run instructions, and truthful test results. Never claim unexecuted tests passed. Preserve all working Phase 1 and Phase 2 features.
