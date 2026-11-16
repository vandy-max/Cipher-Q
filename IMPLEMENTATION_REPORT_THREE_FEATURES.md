# CipherQ QIRA Enhanced — Three Feature Implementation Report

## Scope

This update targets only the three requested areas:

1. Create Intent simplification and supporting file attachments.
2. Intent History Secure Share action.
3. Intent-bound sender-to-recipient encrypted sharing.

The project architecture, existing MongoDB collections, key hierarchy, authentication/RBAC services, QIRA assets and animations were preserved.

## Implemented changes

### 1. Create Intent and file payloads

- Removed the old **Allow User-to-User Sharing** panel and its recipient selector from Create Intent.
- Kept the existing Operations control. Secure Share permission is declared there as the `share` operation; the backend requires both `encrypt` and `share`. The recipient is selected later in the dedicated Secure Share workflow.
- Removed redundant maximum-byte explanatory copy and retained the **Maximum Bytes Per Operation** field.
- Changed the default **Maximum Bytes Per Operation** value from 4,096 to **2,000,000 bytes**.
- Removed the Create Intent content-type selection; payload type is determined by whether a file is attached.
- Added the eight requested attachment formats: PDF, JPG, JPEG, PNG, DOC, DOCX, XLS and XLSX.
- Enforced the 1 MB limit and extension/content checks in the frontend and backend.
- Kept the attachment inside the encrypted, integrity-sealed intent version.
- Added a handoff from the created intent to Encryption. The selected file is wrapped as the actual `CIPHERQ_ATTACHMENT_V1` plaintext payload; it is not replaced with a placeholder message.
- The encryption API validates/canonicalizes that file envelope before sealing it.
- Decryption verifies the SHA-256 digest before enabling the recovered file download.

### 2. Intent History

- Added **Secure Share** after Decryption and before Revoke.
- The action is shown only for an approved intent that permits both `encrypt` and `share`.
- The selected intent ID is carried into the Secure Share page.

### 3. Secure Share workflow

- Replaced the Secure Share page's former direct-message UI with a workflow built on the existing `/api/crypto/shares` service.
- Added approved intent selection, sender active key-session selection, recipient selection, subject, message and optional attachment.
- Recipient selection happens at send time. Backend validation checks that the recipient exists and is enabled.
- The backend chooses an active recipient key session when one is not supplied by the client, then validates its ownership and status before re-wrapping the record key.
- The selected message or file is encrypted as a `CIPHERQ_SHARE_V1` payload through the existing CipherQ crypto-record workflow.
- The existing recipient key-envelope, approval, inbox, expiry, revocation and audit mechanisms are retained.
- Added sent and received share lists. Senders can decrypt their source record; recipients decrypt the recipient-bound share through the existing Decryption workflow and their own authenticated session.
- Added file-plus-message support. Attachment digest verification is performed after decryption.
- Legacy recipient-bound share intents and API calls remain supported.
- The previous direct-messaging interface was preserved as a separate **Direct Messages** page and sidebar route rather than being discarded.

## Attachment validation

Accepted formats and MIME types:

| Extension | MIME type |
|---|---|
| `.pdf` | `application/pdf` |
| `.jpg`, `.jpeg` | `image/jpeg` |
| `.png` | `image/png` |
| `.doc` | `application/msword` |
| `.docx` | `application/vnd.openxmlformats-officedocument.wordprocessingml.document` |
| `.xls` | `application/vnd.ms-excel` |
| `.xlsx` | `application/vnd.openxmlformats-officedocument.spreadsheetml.sheet` |

Maximum file size: 1,048,576 bytes (1 MiB).

Validation checks include filename extension, MIME agreement, file signatures, Office package entries for DOCX/XLSX, legacy Office compound-file markers for DOC/XLS, declared size and SHA-256 integrity.

## Modified existing files

### Backend
- `backend/intent_engine/engine.py`
- `backend/intent_engine/schema.py`
- `backend/intent_engine/drift.py`
- `backend/crypto/share_payload.py`
- `backend/api/routers/crypto_ops.py`
- `backend/tests/test_10_intent_flow.py`
- `backend/tests/test_33_secure_sharing.py`

### Frontend
- `frontend/src/App.jsx`
- `frontend/src/pages/CreateIntentPage.jsx`
- `frontend/src/pages/IntentHistoryPage.jsx`
- `frontend/src/pages/EncryptionPage.jsx`
- `frontend/src/pages/DecryptionPage.jsx`
- `frontend/src/pages/ShareMessagesPage.jsx`
- `frontend/src/utils/sharePayload.js`
- `frontend/src/components/layout/Sidebar.jsx`

## New files

- `backend/tests/test_35_attachment_validation.py`
- `frontend/src/pages/DirectMessagesPage.jsx`

## Validation results in this build environment

| Check | Result |
|---|---|
| Python backend `compileall` | Passed |
| Attachment validation unit tests | 13 passed |
| Frontend JSX/JS syntax transpilation | Passed for 9 changed frontend files |
| Secure Share API integration tests | Not executed: `pymongo` is not installed in this environment |
| Full backend regression suite | Not verified: MongoDB/PyMongo runtime unavailable |
| Frontend production build | Not verified: `npm run build` could not execute Vite (`vite: Permission denied`) |
| Frontend test suite | Not verified: installed frontend dependencies, including Vitest, are unavailable |
| Browser/MongoDB end-to-end workflow | Not executed |

The 13 passing tests are focused attachment-validation tests. They are not evidence that the full sender-to-recipient workflow has passed against MongoDB.

## Preservation checks

- No database reset, recreation or migration was performed.
- No encryption key, keyring, JWT secret or `.env` file was regenerated or intentionally modified.
- No KIRA/QIRA mascot assets, components, animations or blue animated elements were modified.
- Existing direct messaging was retained under its own page.
- No new MongoDB collection is introduced by this change.

## Run instructions (Windows)

1. Extract the ZIP into a separate folder. Do not overwrite your working project yet.
2. Preserve and use the exact existing `backend\.env` and `backend\.dev_secrets.json` (or the exact keyring/secret files configured by that `.env`) that belong to the MongoDB database you intend to open. Do not generate replacement keys.
3. Confirm the configured MongoDB service is running and that `MONGODB_DATABASE` points to the intended database.
4. Run `START_CIPHERQ.bat`. The included launcher creates/uses a Python 3.11 virtual environment, installs `backend\requirements.txt`, checks MongoDB connectivity, installs frontend dependencies with `npm ci` when needed, and starts FastAPI and Vite.
5. Open `http://127.0.0.1:5173`.
6. Before a demo, create an approved intent with both `encrypt` and `share` in Operations, an adequate byte limit, and at least four remaining uses for encryption, share authorization, sender decryption and recipient decryption.
7. Establish active key sessions for the sender and recipient. The recipient's active key session is selected and checked by the backend.
8. Test sender encryption, share delivery, administrator approval if requested, recipient login/face verification/decryption, sender decryption, file download, and share revocation.

For manual checks:
- Backend: from `backend`, run `python -m pytest tests/ -q`.
- Frontend: from `frontend`, run `npm ci`, then `npm run build` and `npm test`.

Do not point a fresh installation or newly generated secrets at an existing encrypted database. The current test environment did not include the dependencies or MongoDB needed to certify the full runtime workflow.
