"""
MongoDB client and database access.

MONGODB_URI and MONGODB_DATABASE are read from the environment, e.g.:
  MONGODB_URI=mongodb://localhost:27017
  MONGODB_DATABASE=ibqc

Production hardening (see docs/SECURITY_MONGODB.md for the full
picture — authentication, TLS, encryption-at-rest, key management,
backups):

  APP_ENV=production refuses to start (see `assert_production_ready`
  below, called from `api/main.py` exactly like the existing JWT
  secret / CORS origin fail-fast checks) unless MONGODB_URI:
    - is not the bare local development default, and
    - carries credentials (a `user:pass@` authority) or an explicit
      `authSource`, and
    - requests TLS (`tls=true` / `ssl=true`, or a `mongodb+srv://`
      scheme, which implies TLS).

  This module never itself enables MongoDB's native
  encryption-at-rest — that is a `mongod`/Atlas *server*-side
  configuration (WiredTiger `--enableEncryption`, an Atlas cluster
  setting, etc.), not a pymongo client option, and is documented
  separately rather than faked here.
"""
from __future__ import annotations

import os
from collections.abc import Generator

from pymongo import MongoClient
from pymongo.collection import ReturnDocument
from pymongo.database import Database

from config import assert_mongo_uri_ready, get_settings
from database.encrypted_store import EncryptedDatabase

_settings = get_settings()
MONGODB_URI = _settings.mongodb_uri
MONGODB_DATABASE = _settings.mongodb_database
MONGODB_TLS_CA_FILE = os.environ.get("MONGODB_TLS_CA_FILE") or None
MONGODB_SERVER_SELECTION_TIMEOUT_MS = int(os.environ.get("MONGODB_SERVER_SELECTION_TIMEOUT_MS", "10000"))


def assert_production_ready(app_env: str, mongodb_uri: str) -> None:
    """Kept for API compatibility; the logic lives in ``config``."""
    if (app_env or "development").strip().lower() in ("production", "staging"):
        assert_mongo_uri_ready(mongodb_uri)


def _build_client_kwargs() -> dict:
    kwargs: dict = {
        "serverSelectionTimeoutMS": MONGODB_SERVER_SELECTION_TIMEOUT_MS,
        "socketTimeoutMS": int(os.environ.get("MONGODB_SOCKET_TIMEOUT_MS", "20000")),
        "connectTimeoutMS": 10000,
        "maxPoolSize": int(os.environ.get("MONGODB_MAX_POOL_SIZE", "50")),
    }
    if MONGODB_TLS_CA_FILE:
        kwargs["tlsCAFile"] = MONGODB_TLS_CA_FILE
    return kwargs


# pymongo connects lazily, so constructing the client at import is safe.
client: MongoClient = MongoClient(MONGODB_URI, **_build_client_kwargs())
raw_db: Database = client[MONGODB_DATABASE]
db = EncryptedDatabase(raw_db) if _settings.whole_db_encryption else raw_db


def get_db() -> Generator[Database, None, None]:
    """FastAPI dependency: yields the MongoDB database handle."""
    yield db


def get_next_id(collection_name: str) -> int:
    """
    Atomically allocate the next integer id for `collection_name`.

    MongoDB documents default to an ObjectId `_id`, but the existing
    API response schemas (`api/schemas.py`) declare id fields as
    plain `int` (e.g. `record_id: int`, `intent_id: int`,
    `PolicyResponse.id: int`) and those schemas are not being changed
    as part of this migration. To keep ids working as ints end to end,
    every collection stores an application-assigned integer `_id`,
    handed out here via a dedicated `counters` collection — the
    standard MongoDB pattern for auto-increment-style ids.

    Self-healing seed: `scripts/migrate_entire_database_to_encrypted.py`
    preserves each document's original integer `_id` when migrating a
    collection into encrypted envelopes, but it never touches the
    `counters` collection. On a freshly migrated database `counters` is
    therefore empty, so the very first `get_next_id()` call for any
    already-populated collection (e.g. `audit_logs`, written on every
    login) would otherwise start again at seq=1 and immediately collide
    with real, pre-existing data — the exact
    `DuplicateKeyError: ... audit_logs index: _id_ dup key: { _id: 1 }`
    seen after enabling whole-document encryption. So: the first time a
    collection's counter is created, seed it from that collection's
    current highest integer `_id` rather than from zero.
    """
    if db.counters.find_one({"_id": collection_name}) is None:
        highest = 0
        for doc in db[collection_name].find({}):
            doc_id = doc.get("_id")
            if isinstance(doc_id, int) and doc_id > highest:
                highest = doc_id
        # $setOnInsert only takes effect if this call is the one that
        # creates the counter doc; if another request wins the race,
        # this is a harmless no-op and the increment below still applies.
        db.counters.update_one(
            {"_id": collection_name},
            {"$setOnInsert": {"seq": highest}},
            upsert=True,
        )

    counter = db.counters.find_one_and_update(
        {"_id": collection_name},
        {"$inc": {"seq": 1}},
        upsert=True,
        return_document=ReturnDocument.AFTER,
    )
    return counter["seq"]
