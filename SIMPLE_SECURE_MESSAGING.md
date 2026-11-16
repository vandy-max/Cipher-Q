# CipherQ Simple Secure Messaging

## User workflow

1. Sign in to CipherQ as usual.
2. Open **Secure Sharing** and choose **New message**.
3. Search for a registered recipient.
4. Enter a message, attach an optional file (maximum 1 MiB), or do both.
5. Click **Encrypt and send**.
6. The message appears in the sender's **Sent** tab and the recipient's **Inbox**.
7. The recipient clicks **Decrypt and read**. The sender can independently click **Decrypt my copy** in Sent.

Messages are available for 24 hours by default. The sender can revoke a message before expiry. Inbox and Sent refresh automatically while the page is open.

## Security model

- Requires a valid authenticated CipherQ account for every API operation.
- Only the sender and designated recipient can list or decrypt a message.
- Each message uses a fresh random 256-bit AES-GCM data-encryption key and 96-bit nonce.
- The data key is separately wrapped for the sender and recipient using HKDF-SHA256 from the configured CipherQ keyring's dedicated purpose-separated `DIRECT_MESSAGE_WRAP` subkey. The key ID is stored so retained historical keyring entries can decrypt older messages after key rotation.
- AES-GCM associated data binds the ciphertext to the message ID, sender, recipient, creation time, expiry time, and key ID. Wrapped keys are also bound to message ID and user ID.
- Ciphertext and key envelopes are stored in the existing MongoDB database abstraction, so whole-document database encryption remains active when configured.
- The backend never writes plaintext message content to audit logs. It records send, decrypt, and revoke events only.
- Face step-up, per-message intent selection, per-message administrator approval, and recipient QKD-session setup are not used by this simple messaging path. Existing identity, intent, QKD, monitoring, authorization, crypto, and audit workflows remain available and unchanged elsewhere in CipherQ.

**Important security scope:** this is authenticated, server-managed encryption at rest and in transit when deployed over HTTPS. It is not end-to-end encryption: the application server can derive the wrapping keys. Do not describe it as end-to-end encrypted.

## Limits and behavior

- File attachment maximum: 1 MiB (1,048,576 bytes), any file type.
- Text maximum: 20,000 characters.
- Message expiry: 24 hours by default; API accepts a shorter expiry, never longer than 24 hours.
- Sender can decrypt their own sent message until it expires or is revoked.
- Recipient can decrypt after delivery until it expires or is revoked.
- Sender revocation blocks future decryption through CipherQ. It cannot erase plaintext or files already downloaded.
- Message status is `DELIVERED`, `READ`, `REVOKED`, or `EXPIRED`.

## API

- `GET /api/messages/recipients?q=...`
- `GET /api/messages?folder=inbox|sent`
- `POST /api/messages`
- `POST /api/messages/{message_id}/decrypt`
- `POST /api/messages/{message_id}/revoke`

The existing `/api/crypto/*` and intent endpoints are not removed or modified by this feature.
