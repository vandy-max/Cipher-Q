# CipherQ Secure Sharing workflow update

This is a targeted change to the Secure Sharing feature. Existing authentication, RBAC, intent integrity, monitoring, encryption/decryption pages, audit chain, key-session management, and administrator workflows remain in place.

## Updated sender / recipient flow

1. The sender selects a registered recipient, writes a message or selects a supported file, and clicks **Encrypt and send**.
2. CipherQ encrypts the payload using the existing intent-bound crypto path and re-wraps the data key for the recipient's active key session.
3. If the approved sharing policy returns `PERMIT`, the share is delivered directly to the recipient's Inbox. If policy requires elevated approval, the existing approval path remains in effect.
4. The recipient must complete a fresh, challenge-bound face verification before opening/decrypting. The backend checks the face grant as well; hiding the UI prompt is not enough to bypass it.
5. The sender can use **Decrypt my copy** in Sent to decrypt the original sender-owned record during its validity period.
6. Both participants can open a private conversation. Conversation replies are encrypted at rest under a share-specific HKDF-derived key from the shared record DEK, and the API returns plaintext only to an authenticated participant after a fresh face step-up. Each reply is limited to 500 characters and three sentences; a thread is limited to 40 replies.
7. The recipient can send a `RECEIVED` or `THANKS` acknowledgement. The sender sees the acknowledgement in Sent.

## One-time sharing intent setup

The existing intent architecture is retained. Create and approve one sharing intent per sender/recipient pair (not one per message):

- Enable user-to-user sharing and select the intended recipient.
- Keep both `encrypt` and `decrypt` enabled; the share operation is added by the sharing toggle.
- The form now raises the suggested `max_uses` to 100 and `max_bytes` to 12 MiB when sharing is enabled.
- The share composer auto-selects the approved intent for that recipient when there is exactly one eligible intent.

An already exhausted intent remains exhausted. Create a new approved version/intent for future messages rather than editing database counters.

## File size and format

The current MongoDB document and nested-base64 architecture cannot safely support literally unlimited file sizes. This update raises the supported per-file cap from approximately 800 KiB to **8 MiB**. Supported extensions remain PDF, DOC/DOCX, XLSX, PPTX, PNG/JPG/JPEG, GIF, WEBP, TXT and CSV. The request body ceiling is 16 MiB and the intent byte ceiling is 12 MiB to accommodate the nested envelope/base64 overhead. Larger files require a separate chunked encrypted-object-storage design and are intentionally not claimed as supported here.

## Security notes

- Share delivery still requires a valid, approved intent bound to the intended recipient and the existing authorization decision.
- Ordinary `PERMIT` shares become immediately available in Inbox; `REQUIRE_APPROVAL` requests continue through the existing approval path.
- Sender and recipient remain the only participants allowed to access the share and its conversation.
- Conversation text is not stored as plaintext in MongoDB. It is authenticated-encrypted and bound to the share ID, message ID and sender ID.
- Recipient face verification is enforced by both the UI and backend before shared-content decryption/opening. Conversation reads and writes also require a fresh face grant.
- Revocation and expiry prevent further access through CipherQ; they cannot erase content already downloaded by a participant.

## Validation status for this archive

- Python source compilation: passed.
- Frontend JSX/JavaScript syntax parsing: passed.
- Record seal/rewrap/DEK extraction round-trip: passed.
- Integration tests were updated, but could not be executed in this build environment because MongoDB/PyMongo was unavailable.
- A full Vite production build could not be executed because npm dependency installation could not reach the package registry. Run the project test/build commands locally after dependencies are installed.


## Automatic recipient key provisioning (targeted update)

- Manual recipient key-session activation is no longer a prerequisite for sending.
- The sender's own active key session remains required for the existing intent-bound encryption workflow.
- On an authorized share request, the backend reuses an active recipient-owned key session when available. Otherwise it provisions a new recipient-owned session through the existing `KeySessionService.create` path.
- The session remains bound to the recipient user ID. Its key is wrapped under the configured QKEY_WRAP keyring sub-key and remains inside the backend; it is never returned to the sender or browser.
- The recipient must still authenticate, obtain the required fresh face-verification grant, and pass the existing decrypt intent/RBAC checks.
- The new session is retained only up to the computed share expiry. Revocation/expiry semantics are unchanged.
- Legacy requests that explicitly provide `recipient_key_session_id` remain supported and are still validated against the recipient owner.
