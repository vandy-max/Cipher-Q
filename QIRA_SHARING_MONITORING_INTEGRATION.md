# QIRA + secure-sharing integration notes

## Scope
- Phase 1/2/3 remains the base application. Existing backend authorization, encryption, intent, and key-session code is retained.
- QIRA presentation/reaction engine, sprite assets, dock, and monitoring-event bridge are integrated from the supplied QIRA project. QIRA is presentation-only and does not authorize cryptographic actions.
- Secure Sharing and Decryption pages refresh automatically every 4 seconds while visible and refresh again when the browser window regains focus. The recipient's approved share list is filtered against their authenticated user ID.
- The existing backend requires the sender's approved sharing intent, sender authorization, an active recipient key session, and administrator approval before a share becomes decryptable. This is intentional access control, not a delivery delay.
- The backend's existing record validity remains capped at 24 hours and cannot exceed the associated intent's validity window.
- Existing monitoring provider/backend logic is retained; QIRA observes meaningful monitoring transitions and does not drive the monitoring state.

## Run
1. Keep the existing backend `.env` and key material if using an existing encrypted database. Never generate replacement keys for that database.
2. Start MongoDB and backend using the project's existing launcher.
3. In `frontend`, run `npm ci` and then `npm run dev` (or `npm run build`).
4. Log in as sender and recipient in separate browser profiles. Ensure the recipient has an active key session.
5. Sender: create/use an approved intent that explicitly names the recipient and permits `share`; encrypt a record under that intent; submit the share; complete sender authorization; have an administrator approve it.
6. Recipient: open Secure Sharing and Decryption. The approved share should appear automatically within approximately four seconds while the page is visible. Select the shared record and its authorization, then run decryption.
7. Test expiry, revoked shares, wrong recipient, inactive recipient key session, missing approvals, and expired intent. These cases should remain denied.

## Validation caveat
This integration has been source-reviewed and syntax checks are performed separately. A true two-account end-to-end test requires the user's MongoDB, matching existing key material, valid accounts, active key sessions, and administrator approval; those runtime prerequisites are not embedded or simulated here.
