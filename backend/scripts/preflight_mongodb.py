"""Read-only MongoDB connectivity preflight. Never prints the URI or credentials."""
from __future__ import annotations

import os
import sys
from pathlib import Path


def read_env(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    if not path.is_file():
        raise RuntimeError("backend .env file was not found")
    for raw in path.read_text(encoding="utf-8-sig").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip().strip('"').strip("'")
        if key and key not in values:
            values[key] = value
    return values


def main() -> int:
    try:
        from pymongo import MongoClient
        env_path = Path(sys.argv[1]).resolve() if len(sys.argv) > 1 else Path(__file__).resolve().parents[1] / ".env"
        values = read_env(env_path)
        uri = os.environ.get("MONGODB_URI") or values.get("MONGODB_URI") or "mongodb://localhost:27017"
        database = os.environ.get("MONGODB_DATABASE") or values.get("MONGODB_DATABASE") or "cipherq"
        with MongoClient(uri, serverSelectionTimeoutMS=4000, connectTimeoutMS=4000) as client:
            client.admin.command("ping")
            # A read-only operation against the selected DB verifies the configured database handle.
            client[database].list_collection_names()
        print("MongoDB connection and selected database: OK")
        return 0
    except Exception as exc:  # do not print exception text; drivers may include URI details
        print(f"MongoDB preflight failed ({type(exc).__name__}). Check that MongoDB is running and backend/.env is correct.")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
