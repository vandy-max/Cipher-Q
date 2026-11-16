#!/usr/bin/env python3
"""Re-encrypt every stored document under the ACTIVE keyring key.

Use after ``generate_secrets.py --add-key`` (key rotation) or to migrate v17 / envelope-v1 documents
(set CIPHERQ_LEGACY_V1_DB_KEY to the old whole-database key so they can be read).  Idempotent; run with the
application stopped or quiesced, after a backup.  Documents that fail authentication are reported, never
silently rewritten.  Audit entries are untouched (their MAC is independent of storage encryption).

NOTE: v17 intents / audit entries do not carry over: the v18 intent engine and keyed audit chain use new
collections and formats.  Archive the old ones; do not treat them as authoritative.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))


def main() -> None:
    from database.session import db, raw_db
    done = bad = 0
    for name in raw_db.list_collection_names():
        if name.startswith("system.") or name == "identity_probe_hashes":   # probe hashes are stored unencrypted by design
            continue
        for raw in raw_db[name].find({}, {"_id": 1}):
            try:
                doc = db[name].find_one({"_id": raw["_id"]})
                if doc is None:
                    continue
                db[name].replace_one({"_id": raw["_id"]}, doc)
                done += 1
            except Exception as exc:  # noqa: BLE001
                bad += 1
                print(f"FAILED {name}/{raw['_id']}: {type(exc).__name__}", file=sys.stderr)
    print(f"re-encrypted {done} documents; {bad} failures")
    sys.exit(1 if bad else 0)


if __name__ == "__main__":
    main()
