# CipherQ v18 — Operations guide

This guide covers what an operator must do. Items marked **(untested here)** were not exercised in the
build environment (no `mongod`, no TLS terminator, no multi-host deployment).

## 1. Secrets

`python backend/scripts/generate_secrets.py --out /etc/cipherq` writes (mode 0600, owner-only directory):
`jwt_secret`, `keyring` (`<id>:<base64 32 bytes>[,…]`), `active_key_id`. Point the service at them:

```
APP_ENV=production
JWT_SECRET_FILE=/etc/cipherq/jwt_secret
CIPHERQ_KEYRING_FILE=/etc/cipherq/keyring
CIPHERQ_ACTIVE_KEY_ID=1
AUDIT_SINK_PATH=/var/lib/cipherq/audit.sink      # append-only file, ideally on separate storage / shipped off-host
ALLOWED_ORIGINS=https://app.example.com
ALLOWED_HOSTS=api.example.com
MONGODB_URI=mongodb://cipherq_app:<pw>@db:27017/cipherq?tls=true&authSource=cipherq
```

Strict environments (`staging`, `production`) refuse to start on: missing/short/world-readable secrets, the
v17 key that shipped in the original archive, a non-TLS or credential-less Mongo URI, `*` or non-https
origins, enabled docs, `ADMIN_SELF_APPROVAL`, scrypt `log_n < 15`, or no audit sink.
Never commit these files; keep `.env` out of images. Use your orchestrator's secret store where possible.

## 2. First administrator

`python backend/scripts/seed_admin.py --username <u> --email <e>` (password prompted, or `--password-file`
with mode 0600). It refuses when an admin already exists unless `--allow-additional`, and writes an audit
event. There is no default account and no default password.

## 3. Key rotation and re-encryption

1. `generate_secrets.py --out … --add-key` adds a key and keeps old ones readable.
2. Update `CIPHERQ_ACTIVE_KEY_ID`, restart.
3. After a backup, with the app quiesced: `python backend/scripts/reencrypt.py` re-encrypts every document
   to the active key (idempotent; documents failing authentication are reported, never rewritten).
4. Retire the old key only after `verify_audit.py` and a restore test succeed.

Audit entries carry the key id (`kid`) that sealed them; keep old keys as long as old audit entries must be
verifiable. Migrating a v17 database: set `CIPHERQ_LEGACY_V1_DB_KEY` to the old key for the migration only.
v17 intents and audit entries are **not** carried over (different formats); archive them.

## 4. Audit integrity

* Chain: keyed HMAC per entry with sequence number, previous MAC and sealed head record.
* Secondary sink: every entry is also appended (O_APPEND, fsync, 0600) to `AUDIT_SINK_PATH`; in strict
  environments a sink failure makes the audited operation fail (fail closed). Ship the sink off-host
  (WORM bucket / syslog relay) **(untested here)**; a local file only protects against DB-only tampering.
* `python backend/scripts/verify_audit.py` verifies DB + head + sink offline (exit 1 if invalid).
* Verification is O(n); for large logs run it on a schedule against a replica.

## 5. Database

* **Use real MongoDB** for any multi-process deployment. The encrypted store provides atomic conditional
  writes through an in-process per-collection lock; this is correct for one process only. The test
  environment used FerretDB (SQLite) which also lacks cross-connection conditional-write atomicity.
  Replica-set `findOneAndUpdate` semantics should be used for a multi-instance deployment **(untested here)**.
* Create a least-privilege user (readWrite on the `cipherq` database only); enable TLS and authentication.
* Documents are application-encrypted (AES-256-GCM, AAD = collection/_id/key id). Ids and collection names
  are visible to the database operator; so are sizes and timestamps.

## 6. Backup and recovery

Back up (a) the database, (b) the audit sink, (c) the keyring file — **separately and encrypted**, with
different access controls. A database backup without the keyring is unreadable by design; a keyring loss is
total data loss. Restore test: restore the DB and sink, run `verify_audit.py`, then log in and decrypt a known record **(restore procedure untested here)**.

## 7. TLS and reverse proxy

The app speaks plain HTTP; terminate TLS at a reverse proxy, set `TRUSTED_PROXY_COUNT` to the number of
proxies so client IPs for rate limiting are taken from `X-Forwarded-For` correctly, and set `ALLOWED_HOSTS`.
HSTS is emitted by the app when `ENABLE_HSTS=true`. The rate limiter and login throttle counters are
partly in-process: run behind a single worker, or replace with a shared store **(limitation)**.

## 8. Frontend

`npm ci && npm run build`, serve `dist/` with a CSP appropriate to your host; the SPA stores the bearer token
in `localStorage` (XSS would expose it — see `FINAL_SECURITY_AUDIT.md`). `vercel.json` rewrites `/api` to a
backend URL that must be edited for your deployment.

## 9. Monitoring of the system itself

Alert on audit events `STEPUP_FAILURE`, `PURPOSE_DRIFT_DETECTED`, `CONTEXT_REJECTED`/`CONTEXT_INVALIDATED`, `ACCOUNT_LOCKED`, and on any
`verify_audit.py` failure. Rotate the JWT secret by restarting with a new file (all tokens become invalid).

## 10. Encrypted records and sharing

Encrypted records are stored in MongoDB with their owner, intent/version, resource, creation time, fixed
24-hour expiry, and key-session identifier. The per-record DEK is wrapped by the authorized key session;
the key material is not stored beside the ciphertext. Logging out revokes the current JWT only. A later
login issues a new token and re-runs database-backed authentication and authorization; it does not delete
records or extend their original expiry. Key-session expiry or revocation still prevents use even while a
record's 24-hour window remains open.

To share a record, create an intent that names the recipient by stable `recipient_user_id` and includes
`encrypt`, `decrypt`, and `share` in its allowed operations. Encrypt under that same intent. The sender then
posts the source record ID and the recipient's active `recipient_key_session_id` to `POST /api/crypto/shares`;
the API derives the recipient identity from the integrity-checked intent and verifies that the key session
belongs to that user. A share remains `PENDING` when intent approval is required. After approval, the sender
calls `POST /api/crypto/shares/{share_id}/activate` using a fresh authenticated session. Activation rechecks
the current intent, approvals, source record, recipient, and both key sessions before rewrapping the DEK
under the recipient's key session. The sender's private key or the root keyring is never exposed.

The recipient lists shares with `GET /api/crypto/shares`, requests a fresh `decrypt` authorization decision
for the share ID, and then calls `POST /api/crypto/decrypt`. The server rechecks recipient identity,
approval/intent state, expiry, resource, key-session ownership, and share status. `POST
/api/crypto/shares/{share_id}/reject` rejects a pending share; the sender can revoke a pending or approved
share with `POST /api/crypto/shares/{share_id}/revoke`. Revocation blocks future server-mediated access;
it cannot retract plaintext the recipient already decrypted or copied. Share and access decisions are
written to the audit trail.

### Evidence case administration

Administrators can browse the most recently updated local evidence cases in the Admin Dashboard or use
`GET /api/evidence/cases?limit=50&offset=0` (admin role required; `limit` is capped at 100). The editor
includes starter templates for investigations, incidents, audit, regulatory review, and service requests.
Templates only fill suggested title, classification cap, and resource values in the browser; they do not
create or save case records. The reference and real assigned user IDs still need to be entered and checked.

Saving creates or updates an encrypted document in `evidence_cases` containing the case reference (`_id`),
title, OPEN/CLOSED status, classification cap, allowed resources, assigned user IDs, server `updated_at`,
and revision number. A save also records an `EVIDENCE_CASE_CHANGED` audit event with the administrator and
case/revision details. Case records do not contain intent attachments, encrypted payloads, encryption keys,
or user profile data. Updating a case changes authoritative evidence and can make existing authorization
contexts stale; protected operations recheck the current case.

If startup or login reports AES-GCM `InvalidTag` while reading `login_throttle`, do not reset the database or
generate a replacement key. The failure now identifies the envelope version and key ID without exposing
key material. Verify that the running service points at the intended database and that its keyring contains
the original key for that ID; for a v1 envelope, verify `CIPHERQ_LEGACY_V1_DB_KEY`. An authentication failure
can also indicate a changed collection/document binding or tampering, so preserve the record for investigation.
When the throttle store cannot be authenticated or reached, login fails closed with HTTP 503; it never skips
the throttle check or issues a token. Server logs include the request ID and non-secret storage diagnostic.
