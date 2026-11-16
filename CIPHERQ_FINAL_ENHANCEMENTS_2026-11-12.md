# CipherQ focused enhancements — 12 November 2026

This update is based on the previously supplied `CipherQ_SharedRecipient_Decrypt_CaseFix.zip`.
It preserves the previous approved-share recipient decryption case-assignment fix.

## 1. Secure Share uses the Create Intent attachment
- The Secure Share composer no longer accepts a free-text message or a second file upload.
- It displays the attachment metadata from the selected approved intent.
- On send, the client retrieves the CID attachment through the authenticated intent attachment endpoint, bound to the sender's authenticated session, device and selected sender key session.
- The backend verifies intent integrity, approval, validity, evidence, session/device and key-session ownership before returning the attachment bytes.
- The client builds the existing `CIPHERQ_ATTACHMENT_V1` payload and passes it through the existing encryption and secure-share path.
- The recipient's existing decryption pipeline recognizes the attachment envelope, verifies SHA-256 and offers the original file for download.
- Direct Messages remain the place for text conversations. Existing legacy text shares remain readable for backwards compatibility.

## 2. Monitoring and QIRA
- The existing serialized monitoring heartbeat cadence and backend-authoritative status flow are preserved.
- QIRA now also mirrors the monitoring backend connection state: temporary backend/network unavailability raises the existing `api.unavailable` reaction; a restored connection clears that reaction.
- Existing warning, re-authentication and revoked reactions remain unchanged. Connectivity loss is not misclassified as a confirmed security attack.

## 3. Administrator visibility
- Administrator accounts retain visibility of all standard navigation areas even when the monitoring UI is blocked.
- Backend authorization remains authoritative; no API/RBAC guard was relaxed.
- Admin dashboard tabs wrap responsively instead of relying on a horizontally clipped tab strip.

## Regression and compatibility
- Added backend regression coverage for authenticated retrieval of an approved CID attachment using the sender's key session.
- Existing attachment integrity validation and existing recipient share/decryption checks are retained.
- No database reset, migration, or key regeneration is required.

## Validation performed in the packaging environment
- Python syntax compilation: changed backend modules.
- JSX/TS transpilation syntax check: changed frontend modules.
- ZIP integrity check.
- Full MongoDB integration tests and full Vite production build require the project's installed dependencies and configured MongoDB and were not run in this packaging environment.
