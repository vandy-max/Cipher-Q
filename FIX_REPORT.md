# CipherQ v18 packaging and startup-safety report

## Changes made in this packaging pass

- Added `START_CIPHERQ.bat` and `START_CIPHERQ.ps1` for one-command Windows startup of FastAPI and Vite.
- The launcher explicitly starts Uvicorn with `--env-file .env`; this avoids assuming that Python automatically loads `.env`.
- Added `backend/scripts/preflight_mongodb.py`, a read-only connectivity check that does not print credentials or driver exception text.
- The launcher fails closed when the existing development key file is absent and no key/JWT secret is configured in `.env`. This protects existing whole-document encrypted records from accidental startup with a newly generated key.
- Added `RUN_WINDOWS.md` and `CLAUDE_REPAIR_PROMPT.md`.

## Verification performed here

- Python source compilation (`python -m compileall -q backend`) passed.
- The full FastAPI/MongoDB tests and frontend build were **not run** in this packaging environment because PyMongo and the user's MongoDB/keyring are not available here. Therefore this package is not represented as runtime-verified against `cipherq_new`.

## Remaining required verification

1. Confirm MongoDB is running and the configured URI points to the intended local/remote instance.
2. Restore the exact existing key material used for the encrypted `cipherq_new` database; do not generate new keys.
3. Run the backend test suite against an isolated test database and `npm run build`.
4. Verify login and database reads against `cipherq_new` with the original keyring before treating the repair as complete.

No database was connected to, changed, migrated, or deleted during this packaging pass.
