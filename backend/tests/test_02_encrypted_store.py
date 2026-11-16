"""Encrypted document layer: confidentiality, AAD binding, CAS atomicity under real concurrency."""
import threading
import uuid
from concurrent.futures import ThreadPoolExecutor

import pytest


def test_stored_documents_are_ciphertext(db, raw_db):
    col = f"t_{uuid.uuid4().hex[:6]}"
    db[col].insert_one({"_id": 1, "secret": "TOP-SECRET-MARKER"})
    raw = raw_db[col].find_one({"_id": 1})
    assert raw["_enc"] == "CIPHERQ-WHOLE-DOC-v2"
    assert "TOP-SECRET-MARKER" not in str(raw)
    assert db[col].find_one({"_id": 1})["secret"] == "TOP-SECRET-MARKER"


def test_encrypted_records_survive_a_fresh_database_wrapper(db, raw_db):
    from database.encrypted_store import EncryptedDatabase
    from security.keyring import get_keyring

    col = f"restart_{uuid.uuid4().hex[:6]}"
    db[col].insert_one({"_id": "stable", "value": "persistent"})

    reopened = EncryptedDatabase(raw_db, get_keyring())

    assert reopened[col].find_one({"_id": "stable"})["value"] == "persistent"


def test_invalid_tag_diagnostic_identifies_key_id_without_changing_record(db, raw_db):
    import os

    from cryptography.exceptions import InvalidTag

    from database.encrypted_store import decrypt_document
    from security.keyring import Keyring

    col = f"badkey_{uuid.uuid4().hex[:6]}"
    db[col].insert_one({"_id": "stable", "value": "persistent"})
    raw = raw_db[col].find_one({"_id": "stable"})
    before = dict(raw)
    wrong_keyring = Keyring({raw["kid"]: os.urandom(32)}, raw["kid"])

    with pytest.raises(RuntimeError, match=f"key id {raw['kid']}") as exc:
        decrypt_document(raw, col, wrong_keyring)

    assert isinstance(exc.value.__cause__, InvalidTag)
    assert raw_db[col].find_one({"_id": "stable"}) == before


def test_ciphertext_moved_to_other_id_or_collection_is_rejected(db, raw_db):
    a, b = f"a_{uuid.uuid4().hex[:6]}", f"b_{uuid.uuid4().hex[:6]}"
    db[a].insert_one({"_id": 1, "v": "x"})
    db[a].insert_one({"_id": 2, "v": "y"})
    raw = raw_db[a].find_one({"_id": 1})
    # splice doc 1's envelope under id 2 of same collection
    raw_db[a].replace_one({"_id": 2}, {**raw, "_id": 2})
    with pytest.raises(Exception):
        db[a].find_one({"_id": 2})
    # splice into another collection
    raw_db[b].insert_one({**raw, "_id": 1})
    with pytest.raises(Exception):
        db[b].find_one({"_id": 1})


def test_tampered_ciphertext_rejected(db, raw_db):
    col = f"t_{uuid.uuid4().hex[:6]}"
    db[col].insert_one({"_id": 1, "v": "x"})
    raw = raw_db[col].find_one({"_id": 1})
    ct = bytearray(raw["ciphertext"]); ct[0] ^= 1
    raw_db[col].update_one({"_id": 1}, {"$set": {"ciphertext": bytes(ct)}})
    with pytest.raises(Exception):
        db[col].find_one({"_id": 1})


def test_decrypt_cache_is_safe_under_concurrent_eviction(db, monkeypatch):
    import database.encrypted_store as encrypted_store

    col = f"cache_{uuid.uuid4().hex[:6]}"
    collection = db[col]
    collection.insert_many({"_id": i, "value": i} for i in range(64))
    monkeypatch.setattr(encrypted_store, "_CACHE_MAX", 8)

    def read_many(worker):
        for offset in range(128):
            doc_id = (worker * 7 + offset) % 64
            assert collection.find_one({"_id": doc_id})["value"] == doc_id

    with ThreadPoolExecutor(16) as ex:
        list(ex.map(read_many, range(16)))


def test_get_next_id_is_unique_under_concurrency(db):
    from database.session import get_next_id
    name = f"ctr_{uuid.uuid4().hex[:6]}"
    with ThreadPoolExecutor(16) as ex:
        ids = list(ex.map(lambda _: get_next_id(name), range(80)))
    assert len(set(ids)) == 80 and sorted(ids) == list(range(min(ids), min(ids) + 80))


def test_concurrent_increments_lose_no_updates(db):
    col = f"inc_{uuid.uuid4().hex[:6]}"
    db[col].insert_one({"_id": 1, "n": 0})
    def bump(_):
        db[col].update_one({"_id": 1}, {"$inc": {"n": 1}})
    with ThreadPoolExecutor(16) as ex:
        list(ex.map(bump, range(60)))
    assert db[col].find_one({"_id": 1})["n"] == 60


def test_one_shot_consume_has_exactly_one_winner(db):
    col = f"once_{uuid.uuid4().hex[:6]}"
    db[col].insert_one({"_id": 1, "used": False})
    barrier = threading.Barrier(12)
    def consume(_):
        barrier.wait()
        return db[col].update_one({"_id": 1, "used": False}, {"$set": {"used": True}}).modified_count
    with ThreadPoolExecutor(12) as ex:
        wins = sum(ex.map(consume, range(12)))
    assert wins == 1
