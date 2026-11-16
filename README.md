# CipherQ v18 — hardened privileged-access prototype

CipherQ binds encryption access to a **structured, approved intent** that is re-checked against authoritative
server-side state on every operation (purpose-drift detection), with server-side key custody, challenge-bound
step-up, continuous monitoring, and a keyed tamper-evident audit chain.

> **Honest status.** This is a hardened *prototype*, **not approved for production**.
> BB84 is a Qiskit **simulation**, not physical QKD, and the system is not "quantum-proof".
> Face matching is descriptor similarity only: **liveness is not established**.
> Business evidence comes from a local, administrator-maintained case table, not an external system.
> No independent security review has been done. See `PRODUCTION_READINESS.md`.

## Documents

| File | Purpose |
|---|---|
| `SECURITY_BASELINE.md` | Phase-0 audit of the unmodified v17 archive (26 findings) |
| `FINAL_SECURITY_AUDIT.md` | Second audit of this tree; findings register and residual risk |
| `INTENT_SECURITY_ARCHITECTURE.md` | Intent / drift engine design |
| `CHANGELOG_SECURITY_HARDENING.md` | Every change: file, before, after, rationale, verifying test |
| `TEST_RESULTS.md` | Exact commands, environment, results, limitations |
| `DEMO_GUIDE.md` | 12-step demo |
| `PRODUCTION_READINESS.md` | What is / is not ready |
| `docs/OPERATIONS.md` | Secrets, keys, backup, TLS, rotation, audit sink |
| `docs/evidence/` | Baseline and final scan output, PoCs, live e2e report |

## Quick start (development)

Requirements: Python **3.12** (the pinned numpy/qiskit-aer wheels do not exist for 3.13), Node 20+, a MongoDB
(or Mongo-wire compatible) server on `localhost:27017`.

```bash
cd backend
python3.12 -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt -r requirements-dev.txt
cp .env.example .env            # APP_ENV=development creates a random 0600 dev secret file on first start
uvicorn api.main:app --port 8000

# bootstrap the first administrator (interactive password; no default account exists)
python scripts/seed_admin.py --username admin --email admin@example.com

cd ../frontend && npm ci && npm run dev      # http://localhost:5173, proxies /api to :8000
```

Production-like settings (`APP_ENV=staging|production`) are fail-closed: the process refuses to start without
file-based secrets (`python scripts/generate_secrets.py --out /etc/cipherq`), an audit sink path, exact CORS
origins and allowed hosts, and a Mongo URI with credentials and TLS. See `docs/OPERATIONS.md`.

## Tests

```bash
cd backend && pytest -q                         # needs a Mongo-wire server on 127.0.0.1:27017
python scripts/e2e_workflow.py --base http://127.0.0.1:8000 --admin-user <u> --admin-password-file <f>
cd frontend && npm test && npm run build
```

## Roles

* `USER_LEVEL_1` — the only role self-registration can produce.
* `USER_LEVEL_2` — assigned by an administrator; may read intents/audit per RBAC and approve others' intents.
* `ADMIN` — created only by `scripts/seed_admin.py`; manages users, evidence cases, approvals, revocations.

Approval is never self-service: the requester cannot approve their own intent (administrators included).

## Layout

`backend/api` routers and dependencies · `backend/intent_engine` schema, evidence, drift rules, engine ·
`backend/security` keyring, canonical encoding, integrity MACs · `backend/crypto` record format v3 ·
`backend/keymgmt` server-side key sessions · `backend/quantum` BB84 simulation · `backend/identity` step-up ·
`backend/monitoring` continuous monitoring · `backend/audit` keyed chain + sink · `backend/scripts` operations ·
`backend/tests` · `frontend/src` React/Vite UI.

## Windows one-command startup

See `RUN_WINDOWS.md`. With MongoDB running and the existing v18 key material in place, run `START_CIPHERQ.bat` from this directory. It checks MongoDB before opening the FastAPI and Vite terminals and does not reset the database.

## Phase 2 — Secure Sharing

The Secure Sharing navigation page uses the simplified direct-message workflow documented in `SIMPLE_SECURE_MESSAGING.md`: select a user, write a message or attach a file up to 1 MiB, then encrypt and send. Inbox and Sent are refreshed automatically. Both participants can decrypt during the 24-hour validity period. The previous intent-bound share endpoints remain in the backend for compatibility; this page uses the new dedicated messaging API and does not change other CipherQ workflows.

## Phase 3 attachment evaluation
This candidate adds a conservative file attachment path to the existing encryption/decryption screens. See `PHASE3_CHANGELOG.md` and `PHASE3_TEST_GUIDE.md` for scope, constraints, and validation status. It is not yet a fully verified release; run the listed regression tests in your configured Windows/MongoDB environment before relying on it.


## Simple Secure Messaging

The Secure Sharing navigation page now offers a direct-message experience: Inbox, New message, and Sent. Messages and optional files (maximum 1 MiB) are encrypted automatically. Both sender and recipient can decrypt while the message remains valid (24 hours by default). No per-message intent selection, recipient QKD setup, face step-up, or administrator approval is required for this separate messaging path. Existing CipherQ intent, QKD, encryption/decryption, RBAC, monitoring, and audit workflows remain available. See `SIMPLE_SECURE_MESSAGING.md` for the security model and API details.
