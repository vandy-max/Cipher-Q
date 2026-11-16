# CipherQ Docker deployment

This adds container packaging and persistent storage only. It does not replace or
modify the existing authentication, intent, authorization, monitoring, approval,
sharing, attachment-encryption, or QIRA workflows.

## What is persisted

- `cipherq_mongodb_data`: MongoDB's `/data/db` directory. CipherQ already writes
  monitoring session summaries and monitoring event snapshots to its MongoDB
  collections (`monitoring_sessions` and `monitoring_events`). The Docker volume
  keeps those records when containers are recreated.
- `cipherq_dev_secrets`: the existing development `.dev_secrets.json` file,
  preserving the same generated encryption keyring/JWT secret across restarts.

Monitoring summaries are stored by the existing application in MongoDB, not
inside the Dockerfile or container image.

## Start (Windows PowerShell / macOS / Linux)

From the project root (the folder containing `docker-compose.yml`):

```bash
docker compose up --build -d
```

Open:

```text
http://localhost:8080
```

Check service status and logs:

```bash
docker compose ps
docker compose logs -f backend
docker compose logs -f mongo
```

Stop containers without deleting saved data:

```bash
docker compose down
```

Start again:

```bash
docker compose up -d
```

## Important data-retention warning

Do **not** run `docker compose down -v` if you want to keep monitoring summaries,
MongoDB records, and the persisted development secrets. The `-v` option deletes
the named volumes.

The existing monitoring repository applies its own retention limits (including
the existing 90-day monitoring-session cleanup and per-session event cap).
Docker persistence does not override those application retention rules.

## Existing database / encryption-key safety

This compose file starts a fresh local MongoDB volume named `cipherq_mongodb_data`.
It does not automatically attach to or migrate an existing MongoDB database.
If you need to use an existing CipherQ database, configure the correct MongoDB
URI and restore/provide the exact keyring that encrypted that database before
starting the application. Never generate a new keyring for an existing encrypted
database; doing so can make its records undecryptable.

This compose configuration uses `APP_ENV=development` for local evaluation.
Do not expose it as a production deployment. Production/staging require explicit
managed secrets, TLS, authenticated MongoDB, and the strict settings already
enforced by the application.
