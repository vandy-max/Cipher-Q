#!/usr/bin/env python3
"""Safely migrate plaintext MongoDB documents to CipherQ v18 encrypted envelopes.

Run only after stopping the API, taking a verified database backup, and confirming
MONGODB_URI / MONGODB_DATABASE point at the intended database. Dry-run is default.
"""
from __future__ import annotations
import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--apply', action='store_true', help='write encrypted envelopes (default is dry-run)')
    args = parser.parse_args()

    from config import get_settings
    from database.session import raw_db
    from database.encrypted_store import encrypt_document, is_encrypted_document
    from security.keyring import get_keyring

    settings = get_settings()
    if not settings.whole_db_encryption:
        print('ABORT: whole-document encryption is disabled in current configuration.', file=sys.stderr)
        return 2

    keyring = get_keyring()
    seen = plaintext = migrated = failed = 0
    skipped = {'system collections and identity_probe_hashes': 0}
    names = raw_db.list_collection_names()
    print(f'Database: {settings.mongodb_database}; collections: {len(names)}; mode: {"APPLY" if args.apply else "DRY RUN"}')
    if args.apply:
        print('WARNING: ensure the API is stopped and a verified backup exists.')

    for name in names:
        if name.startswith('system.') or name == 'identity_probe_hashes':
            continue
        collection = raw_db[name]
        for doc in collection.find({}):
            seen += 1
            if is_encrypted_document(doc):
                continue
            plaintext += 1
            if not args.apply:
                continue
            try:
                sealed = encrypt_document(doc, name, keyring)
                result = collection.replace_one({'_id': doc['_id']}, sealed)
                if result.matched_count != 1:
                    raise RuntimeError('document changed or disappeared during migration')
                migrated += 1
            except Exception as exc:  # fail closed; never print document contents
                failed += 1
                print(f'FAILED collection={name!r} id={doc.get("_id")!r} error={type(exc).__name__}', file=sys.stderr)

    print(f'Documents scanned: {seen}; plaintext documents: {plaintext}; migrated: {migrated}; failures: {failed}')
    if not args.apply and plaintext:
        print('Dry run only. After backup and stopping the API, rerun with --apply.')
    if args.apply and failed:
        print('Some documents were not migrated. Keep the API stopped and investigate before retrying.', file=sys.stderr)
        return 1
    return 0

if __name__ == '__main__':
    raise SystemExit(main())
