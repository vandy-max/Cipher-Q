# Windows quick start (safe mode)

## One command

Open PowerShell in the extracted `CipherQ_v18_HARDENED` folder and run:

```powershell
.\START_CIPHERQ.bat
```

This checks MongoDB connectivity, installs backend dependencies into `backend\.venv` if needed, installs frontend dependencies if `frontend\node_modules` is absent, then opens separate terminals for FastAPI and Vite. The API is `http://127.0.0.1:8000`; the UI is `http://127.0.0.1:5173`.

## Separate PowerShell terminals

Python 3.11 and Node.js 20+ are required. Start MongoDB first. From the project root:

**Terminal 1 — backend**

```powershell
Set-Location .\backend
py -3.11 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt -r requirements-dev.txt
.\.venv\Scripts\python.exe -m uvicorn api.main:app --host 127.0.0.1 --port 8000
```

If `backend\.venv` already exists, omit the `py -3.11 -m venv .venv` line. These commands do not require
PowerShell script activation. Do not replace the existing database or key material. Ensure `backend\.env`
contains the existing database name and matching key configuration before starting the API.

**Terminal 2 — frontend**

```powershell
Set-Location .\frontend
npm ci
npm run dev -- --host 127.0.0.1
```

Vite proxies `/api` to `http://localhost:8000` by default. To use another backend address, set
`VITE_API_PROXY_TARGET` before starting Vite.

## Important: existing encrypted database

- The launcher defaults a newly created `.env` to `MONGODB_DATABASE=cipherq_new`. If `backend\.env` already exists, it is not overwritten.
- Copy the **existing** `backend\.dev_secrets.json` from the project that currently decrypts `cipherq_new` into this project's `backend` folder before launching, unless you already configure the exact same keyring and JWT secret through environment variables or secret files.
- Do not delete or regenerate `.dev_secrets.json` for an existing encrypted database. A new key cannot decrypt old ciphertext.
- Start MongoDB before running the launcher. The launcher checks connectivity and exits without changing data if MongoDB is unreachable or the existing key material is missing.
- The `.env` file must remain local and must not be committed. Do not paste secrets into chat or Claude.

## If startup stops

Read the message in the first terminal. Fix the prerequisite it names and rerun `START_CIPHERQ.bat`. If login returns HTTP 500, inspect the backend terminal for the sanitized request path and error type. Do not run migration scripts with `--apply` or drop a database as a troubleshooting step.
