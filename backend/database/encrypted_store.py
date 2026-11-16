"""Transparent whole-document AES-256-GCM encryption for CipherQ's MongoDB layer.

Hardened in v18 (see SECURITY_BASELINE.md F-06, F-09):

* **Envelope v2**: ``{_id, _enc: "CIPHERQ-WHOLE-DOC-v2", kid, nonce, ciphertext}``.
  The AES key is a purpose-separated sub-key (``security.keyring``); ``kid``
  selects it, so keys can be rotated without guessing.
* **AAD binds collection AND ``_id`` AND ``kid``** (length-framed).  A database
  writer can no longer copy the ciphertext of document X into document Y or into
  another collection and have it decrypt.  (Rolling a document back to an
  *older valid ciphertext of itself* is still possible for someone with raw
  database write access; this is documented in the threat model.)
* **Envelope v1** (legacy, collection-only AAD) is *read-only compatible* when
  ``CIPHERQ_LEGACY_V1_DB_KEY`` is configured, so existing data stays readable
  during migration; every write produces v2. ``scripts/rotate_keys.py``
  re-encrypts all documents.
* **Atomic writes**: every read-modify-write is a compare-and-swap on the
  stored nonce (unique per write), retried on contention.  This restores the
  atomicity that MongoDB's native ``find_one_and_update`` provides and that the
  v17 implementation lost (duplicate ids, lost updates, one-shot bypass).
* **Direct ``_id`` reads**: queries that pin ``_id`` no longer decrypt the
  whole collection.

Application code continues to use ordinary dictionaries and a PyMongo-like API.
Queries on other fields are evaluated after decryption (the database cannot
index ciphertext), so those remain O(collection size); callers on hot paths
must key by ``_id``.
"""
from __future__ import annotations

import copy
import threading
import re
from collections import OrderedDict
from dataclasses import dataclass
from typing import Any, Iterable

from bson import BSON, ObjectId
from bson.binary import Binary
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from pymongo.errors import DuplicateKeyError

from security.canonical import frame
from security.keyring import DB_ENCRYPTION, Keyring, get_keyring

import os

MARKER_V1 = "CIPHERQ-WHOLE-DOC-v1"
MARKER_V2 = "CIPHERQ-WHOLE-DOC-v2"
_MARKER = MARKER_V2  # backwards-compatible alias
_NONCE_BYTES = 12
_MAX_CAS_RETRIES = 64
_CACHE_MAX = 4096


class EncryptedDocumentError(RuntimeError):
    """A stored encrypted document cannot be authenticated or decoded safely."""


def encryption_enabled() -> bool:
    from config import get_settings
    return get_settings().whole_db_encryption


def strict_enabled() -> bool:
    from config import get_settings
    if get_settings().strict:
        return True
    return os.getenv("CIPHERQ_ENCRYPTION_STRICT", "true").strip().lower() in {"1", "true", "yes", "on"}


def _id_repr(doc_id: Any) -> bytes:
    if isinstance(doc_id, bool):
        raise ValueError("boolean _id is not supported")
    if isinstance(doc_id, int):
        return b"i:" + str(doc_id).encode()
    if isinstance(doc_id, str):
        return b"s:" + doc_id.encode("utf-8")
    if isinstance(doc_id, ObjectId):
        return b"o:" + str(doc_id).encode()
    raise ValueError(f"unsupported _id type {type(doc_id).__name__}")


def _aad_v2(collection_name: str, doc_id: Any, kid: int) -> bytes:
    return frame(b"CipherQ|WHOLE-DOC|v2", collection_name.encode("utf-8"), _id_repr(doc_id),
                 str(kid).encode())


def _aad_v1(collection_name: str) -> bytes:
    return f"CipherQ|{MARKER_V1}|{collection_name}".encode("utf-8")


def is_encrypted_document(document: dict[str, Any]) -> bool:
    return (isinstance(document, dict) and document.get("_enc") in (MARKER_V1, MARKER_V2)
            and "nonce" in document and "ciphertext" in document)


def encrypt_document(document: dict[str, Any], collection_name: str,
                     keyring: Keyring | None = None) -> dict[str, Any]:
    if not isinstance(document, dict) or "_id" not in document:
        raise ValueError("CipherQ encrypted documents require a MongoDB _id")
    keyring = keyring or get_keyring()
    kid = keyring.active_id
    payload = {k: copy.deepcopy(v) for k, v in document.items() if k != "_id"}
    nonce = os.urandom(_NONCE_BYTES)
    sealed = AESGCM(keyring.subkey(DB_ENCRYPTION, kid)).encrypt(
        nonce, BSON.encode(payload), _aad_v2(collection_name, document["_id"], kid))
    return {"_id": document["_id"], "_enc": MARKER_V2, "kid": kid,
            "nonce": Binary(nonce), "ciphertext": Binary(sealed)}


def decrypt_document(document: dict[str, Any], collection_name: str,
                     keyring: Keyring | None = None) -> dict[str, Any]:
    if not is_encrypted_document(document):
        if strict_enabled():
            raise RuntimeError(f"Plaintext MongoDB document detected in encrypted collection '{collection_name}'")
        return copy.deepcopy(document)
    marker = document["_enc"]
    try:
        if marker == MARKER_V2:
            keyring = keyring or get_keyring()
            kid = int(document["kid"])
            key = keyring.subkey(DB_ENCRYPTION, kid)
            aad = _aad_v2(collection_name, document["_id"], kid)
        else:
            from config import get_settings
            legacy = get_settings().legacy_v1_db_key
            if legacy is None:
                raise EncryptedDocumentError(
                    "legacy v1 document found but CIPHERQ_LEGACY_V1_DB_KEY is not configured")
            key, aad = legacy, _aad_v1(collection_name)
        plaintext = AESGCM(key).decrypt(bytes(document["nonce"]), bytes(document["ciphertext"]), aad)
        payload = BSON(plaintext).decode()
    except InvalidTag as exc:
        key_info = (f"key id {document.get('kid')}" if marker == MARKER_V2
                    else "legacy v1 key (CIPHERQ_LEGACY_V1_DB_KEY)")
        raise EncryptedDocumentError(
            f"CipherQ AES-GCM authentication failed in collection '{collection_name}' "
            f"({marker}, {key_info}); verify the configured keyring, database identity, "
            "and envelope binding. No stored data was changed."
        ) from exc
    except (ValueError, TypeError, KeyError) as exc:
        # no key material, plaintext or ids in the message
        raise EncryptedDocumentError(
            f"CipherQ could not decrypt a document in collection '{collection_name}'") from exc
    payload["_id"] = document["_id"]
    return payload


# ---------------------------------------------------------------------
# Query evaluation (after decryption)
# ---------------------------------------------------------------------

def _get_path(doc: dict[str, Any], path: str) -> Any:
    value: Any = doc
    for part in path.split("."):
        if not isinstance(value, dict) or part not in value:
            return _MISSING
        value = value[part]
    return value


def _set_path(doc: dict[str, Any], path: str, value: Any) -> None:
    parts = path.split(".")
    cur = doc
    for part in parts[:-1]:
        if not isinstance(cur.get(part), dict):
            cur[part] = {}
        cur = cur[part]
    cur[parts[-1]] = copy.deepcopy(value)


def _unset_path(doc: dict[str, Any], path: str) -> None:
    parts = path.split(".")
    cur: Any = doc
    for part in parts[:-1]:
        if not isinstance(cur, dict) or part not in cur:
            return
        cur = cur[part]
    if isinstance(cur, dict):
        cur.pop(parts[-1], None)


class _Missing:
    pass


_MISSING = _Missing()


def _condition(value: Any, exists: bool, expected: Any) -> bool:
    if not isinstance(expected, dict) or not any(str(k).startswith("$") for k in expected):
        return exists and value == expected
    for op, rhs in expected.items():
        if op == "$exists":
            if exists != bool(rhs):
                return False
        elif op == "$ne":
            if exists and value == rhs:
                return False
        elif op == "$in":
            if not exists or value not in rhs:
                return False
        elif op == "$nin":
            if exists and value in rhs:
                return False
        elif op == "$gt":
            if not exists or not value > rhs:
                return False
        elif op == "$gte":
            if not exists or not value >= rhs:
                return False
        elif op == "$lt":
            if not exists or not value < rhs:
                return False
        elif op == "$lte":
            if not exists or not value <= rhs:
                return False
        elif op == "$eq":
            if not exists or value != rhs:
                return False
        elif op == "$regex":
            if not exists or not isinstance(value, str) or re.search(rhs, value) is None:
                return False
        else:
            raise NotImplementedError(f"CipherQ encrypted query operator not supported: {op}")
    return True


def matches(doc: dict[str, Any], query: dict[str, Any]) -> bool:
    for field_name, expected in query.items():
        if field_name == "$and":
            if not all(matches(doc, q) for q in expected):
                return False
            continue
        if field_name == "$or":
            if not any(matches(doc, q) for q in expected):
                return False
            continue
        if field_name == "$nor":
            if any(matches(doc, q) for q in expected):
                return False
            continue
        value = _get_path(doc, field_name)
        if not _condition(None if value is _MISSING else value, value is not _MISSING, expected):
            return False
    return True


def _apply_update(doc: dict[str, Any], update: dict[str, Any], inserting: bool = False) -> dict[str, Any]:
    if not any(str(k).startswith("$") for k in update):
        replacement = copy.deepcopy(update)
        replacement.setdefault("_id", doc["_id"])
        return replacement
    out = copy.deepcopy(doc)
    for op, fields in update.items():
        if op == "$set":
            for path, value in fields.items():
                _set_path(out, path, value)
        elif op == "$unset":
            for path in fields:
                _unset_path(out, path)
        elif op == "$inc":
            for path, amount in fields.items():
                current = _get_path(out, path)
                if current is _MISSING:
                    current = 0
                _set_path(out, path, current + amount)
        elif op == "$setOnInsert":
            if inserting:
                for path, value in fields.items():
                    _set_path(out, path, value)
        else:
            raise NotImplementedError(f"CipherQ encrypted update operator not supported: {op}")
    return out


@dataclass
class EncryptedCursor:
    documents: list[dict[str, Any]]

    def sort(self, key_or_list: Any, direction: int | None = None):
        pairs = key_or_list if isinstance(key_or_list, list) else [(key_or_list, direction or 1)]
        for key, order in reversed(pairs):
            self.documents.sort(key=lambda d: (_get_path(d, key) is _MISSING, _get_path(d, key)),
                                reverse=(order < 0))
        return self

    def limit(self, n: int):
        self.documents = self.documents[:n]
        return self

    def skip(self, n: int):
        self.documents = self.documents[n:]
        return self

    def __iter__(self):
        return iter(copy.deepcopy(self.documents))

    def __next__(self):
        return next(iter(self.documents))


class _UpdateResult:
    def __init__(self, matched: bool, modified_count: int = 0, upserted_id: Any = None):
        self.matched_count = 1 if matched else 0
        self.modified_count = modified_count if modified_count else (1 if matched else 0)
        self.upserted_id = upserted_id


class _DeleteResult:
    def __init__(self, count: int):
        self.deleted_count = count


def _pinned_id(filter_: dict) -> tuple[bool, Any]:
    """If the filter pins ``_id`` to a concrete value (or ``$in`` list), return it."""
    if "_id" not in filter_:
        return False, None
    v = filter_["_id"]
    if isinstance(v, dict):
        if set(v) == {"$eq"}:
            return True, v["$eq"]
        if set(v) == {"$in"}:
            return True, {"$in": list(v["$in"])}
        return False, None
    return True, v


# In-process serialisation of read-modify-write cycles per collection.
# Rationale: the CAS (conditional replace on the stored nonce) is atomic on a real
# MongoDB, but the FerretDB/SQLite backend used for local tests does NOT guarantee
# atomic conditional writes across connections (measured: up to 10/12 concurrent
# winners for one conditional replace).  The lock makes a single API process correct
# on either backend; multi-process deployments MUST use real MongoDB (documented in
# PRODUCTION_READINESS.md).
_WRITE_LOCKS: dict[str, threading.RLock] = {}
_WRITE_LOCKS_GUARD = threading.Lock()


def _write_lock(name: str) -> threading.RLock:
    with _WRITE_LOCKS_GUARD:
        lk = _WRITE_LOCKS.get(name)
        if lk is None:
            lk = _WRITE_LOCKS[name] = threading.RLock()
        return lk


class EncryptedCollection:
    def __init__(self, raw_collection, keyring: Keyring | None = None):
        self._raw = raw_collection
        self._keyring = keyring
        self.name = raw_collection.name
        # Per-document decrypt cache keyed on the exact stored (nonce, ciphertext):
        # a changed document has a new nonce so it can never be served stale.
        self._decrypt_cache: "OrderedDict[Any, tuple[Any, dict[str, Any]]]" = OrderedDict()
        self._decrypt_cache_lock = threading.RLock()

    # -- internals ----------------------------------------------------
    def _decrypt_cached(self, raw_doc: dict) -> dict[str, Any]:
        doc_id = raw_doc.get("_id")
        fingerprint = (raw_doc.get("nonce"), raw_doc.get("ciphertext"))
        with self._decrypt_cache_lock:
            cached = self._decrypt_cache.get(doc_id)
            if cached is not None and cached[0] == fingerprint:
                self._decrypt_cache.move_to_end(doc_id)
        if cached is not None and cached[0] == fingerprint:
            return copy.deepcopy(cached[1])
        decrypted = decrypt_document(raw_doc, self.name, self._keyring)
        with self._decrypt_cache_lock:
            self._decrypt_cache[doc_id] = (fingerprint, copy.deepcopy(decrypted))
            while len(self._decrypt_cache) > _CACHE_MAX:
                self._decrypt_cache.popitem(last=False)
        return decrypted

    def _raw_candidates(self, filter_: dict) -> Iterable[dict]:
        pinned, value = _pinned_id(filter_)
        if pinned:
            if isinstance(value, dict) and "$in" in value:
                return list(self._raw.find({"_id": {"$in": value["$in"]}}))
            return list(self._raw.find({"_id": value}))
        return list(self._raw.find({}))

    def _all(self) -> list[dict[str, Any]]:
        return [self._decrypt_cached(d) for d in self._raw.find({})]

    def _first_match(self, filter_: dict, sort: Any = None) -> tuple[dict | None, dict | None]:
        pairs = []
        for raw in self._raw_candidates(filter_):
            dec = self._decrypt_cached(raw)
            if matches(dec, filter_):
                pairs.append((raw, dec))
        if not pairs:
            return None, None
        if sort is not None:
            order = EncryptedCursor([d for _, d in pairs]).sort(sort).documents
            first_id = order[0]["_id"]
            for raw, dec in pairs:
                if dec["_id"] == first_id:
                    return raw, dec
        raw, dec = pairs[0]
        return raw, dec

    def _matching_raw(self, filter_: dict) -> list[dict]:
        return [raw for raw in self._raw_candidates(filter_) if matches(self._decrypt_cached(raw), filter_)]

    def _cas_replace(self, raw: dict, new_doc: dict) -> bool:
        res = self._raw.replace_one({"_id": raw["_id"], "nonce": raw["nonce"]},
                                    encrypt_document(new_doc, self.name, self._keyring))
        return res.matched_count == 1

    # -- reads --------------------------------------------------------
    def find(self, filter: dict | None = None, *args, **kwargs) -> EncryptedCursor:
        filter = filter or {}
        docs = [self._decrypt_cached(raw) for raw in self._raw_candidates(filter)]
        return EncryptedCursor([d for d in docs if matches(d, filter)])

    def find_one(self, filter: dict | None = None, *args, **kwargs):
        cursor = self.find(filter or {})
        sort_spec = kwargs.get("sort")
        if sort_spec is not None:
            cursor.sort(sort_spec)
        if kwargs.get("skip"):
            cursor.skip(kwargs["skip"])
        if kwargs.get("limit"):
            cursor.limit(kwargs["limit"])
        for d in cursor:
            return d
        return None

    def count_documents(self, filter: dict | None = None, *args, **kwargs) -> int:
        return len(self.find(filter or {}).documents)

    # -- writes -------------------------------------------------------
    def insert_one(self, document: dict, *args, **kwargs):
        return self._raw.insert_one(encrypt_document(document, self.name, self._keyring), *args, **kwargs)

    def insert_many(self, documents: Iterable[dict], *args, **kwargs):
        encrypted = [encrypt_document(d, self.name, self._keyring) for d in documents]
        return self._raw.insert_many(encrypted, *args, **kwargs)

    def _upsert_base(self, filter_: dict) -> dict:
        base = {k: copy.deepcopy(v) for k, v in filter_.items()
                if not str(k).startswith("$") and not isinstance(v, dict)}
        if "_id" not in base:
            base["_id"] = ObjectId()
        return base

    def _update_one_impl(self, filter: dict, update: dict, upsert: bool = False, *args, **kwargs):
        for _ in range(_MAX_CAS_RETRIES):
            raw, old = self._first_match(filter)
            if raw is not None:
                if self._cas_replace(raw, _apply_update(old, update)):
                    return _UpdateResult(True)
                continue  # lost the race -> re-read and re-evaluate the filter
            if not upsert:
                return _UpdateResult(False)
            new = _apply_update(self._upsert_base(filter), update, inserting=True)
            try:
                self._raw.insert_one(encrypt_document(new, self.name, self._keyring))
            except DuplicateKeyError:
                continue
            return _UpdateResult(False, upserted_id=new["_id"])
        raise RuntimeError(f"too much write contention on collection '{self.name}'")

    def update_one(self, *a, **k):
        with _write_lock(self.name):
            return self._update_one_impl(*a, **k)

    def replace_one(self, *a, **k):
        with _write_lock(self.name):
            return self._replace_one_impl(*a, **k)

    def find_one_and_update(self, *a, **k):
        with _write_lock(self.name):
            return self._find_one_and_update_impl(*a, **k)

    def delete_one(self, *a, **k):
        with _write_lock(self.name):
            return self._delete_one_impl(*a, **k)

    def update_many(self, filter: dict, update: dict, *args, **kwargs):
        modified = 0
        for raw in self._matching_raw(filter):
            res = self.update_one({"_id": raw["_id"], **{k: v for k, v in filter.items() if k != "_id"}}, update)
            modified += res.matched_count
        return _UpdateResult(bool(modified), modified)

    def _replace_one_impl(self, filter: dict, replacement: dict, *args, **kwargs):
        for _ in range(_MAX_CAS_RETRIES):
            raw, _old = self._first_match(filter)
            if raw is None:
                return _UpdateResult(False)
            rep = copy.deepcopy(replacement)
            rep.setdefault("_id", raw["_id"])
            if self._cas_replace(raw, rep):
                return _UpdateResult(True)
        raise RuntimeError(f"too much write contention on collection '{self.name}'")

    def _find_one_and_update_impl(self, filter: dict, update: dict, *args, **kwargs):
        from pymongo.collection import ReturnDocument
        want_after = kwargs.get("return_document") == ReturnDocument.AFTER or (
            args and args[0] == ReturnDocument.AFTER)
        upsert = bool(kwargs.get("upsert"))
        sort = kwargs.get("sort")
        for _ in range(_MAX_CAS_RETRIES):
            raw, old = self._first_match(filter, sort=sort)
            if raw is not None:
                new = _apply_update(old, update)
                if self._cas_replace(raw, new):
                    return copy.deepcopy(new if want_after else old)
                continue
            if not upsert:
                return None
            new = _apply_update(self._upsert_base(filter), update, inserting=True)
            try:
                self._raw.insert_one(encrypt_document(new, self.name, self._keyring))
            except DuplicateKeyError:
                continue
            return copy.deepcopy(new) if want_after else None
        raise RuntimeError(f"too much write contention on collection '{self.name}'")

    def _delete_one_impl(self, filter: dict, *args, **kwargs):
        for _ in range(_MAX_CAS_RETRIES):
            raw, _old = self._first_match(filter)
            if raw is None:
                return _DeleteResult(0)
            res = self._raw.delete_one({"_id": raw["_id"], "nonce": raw["nonce"]})
            if res.deleted_count == 1:
                return _DeleteResult(1)
        raise RuntimeError(f"too much write contention on collection '{self.name}'")

    def delete_many(self, filter: dict | None = None, *args, **kwargs):
        n = 0
        for raw in self._matching_raw(filter or {}):
            n += self._raw.delete_one({"_id": raw["_id"], "nonce": raw["nonce"]}).deleted_count
        return _DeleteResult(n)

    def create_index(self, *args, **kwargs):
        keys = args[0] if args else kwargs.get("keys")
        if keys in ("_id", [("_id", 1)], [("_id", -1)]):
            return self._raw.create_index(*args, **kwargs)
        raise RuntimeError("Creating indexes on encrypted application fields is not supported by whole-document encryption")


class EncryptedDatabase:
    """Small Database facade that exposes encrypted collections."""

    def __init__(self, raw_database, keyring: Keyring | None = None):
        self._raw = raw_database
        self.name = raw_database.name
        self._keyring = keyring or get_keyring()
        self._collections: dict[str, EncryptedCollection] = {}

    def __getitem__(self, collection_name: str) -> EncryptedCollection:
        # reuse the collection object so its decrypt cache survives across requests
        col = self._collections.get(collection_name)
        if col is None:
            col = EncryptedCollection(self._raw[collection_name], self._keyring)
            self._collections[collection_name] = col
        return col

    def __getattr__(self, name: str):
        if name.startswith("_"):
            raise AttributeError(name)
        return self[name]

    def list_collection_names(self, *args, **kwargs):
        return self._raw.list_collection_names(*args, **kwargs)

    @property
    def raw(self):
        return self._raw

    @property
    def client(self):
        return self._raw.client
