#!/usr/bin/env python3
"""Create or safely remove the marked development-only case evidence fixture.

Run from ``backend`` with ``APP_ENV=development``. The fixture is written through
the same local evidence provider used by the intent validator and never overwrites
an existing case reference.
"""
from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path
from urllib.parse import urlsplit

from pymongo.errors import DuplicateKeyError

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

FIXTURE_REF = "CASE-900001"
FIXTURE_MARKER = "cipherq-development-case-v1"
FIXTURE_TITLE = "CipherQ development test case (not a real case)"
FIXTURE_RESOURCE = "vault:customer-records"


def main() -> None:
    from dotenv import load_dotenv

    load_dotenv()
    if os.environ.get("APP_ENV", "").strip().lower() != "development":
        raise SystemExit("refusing to run: set APP_ENV=development explicitly")

    parser = argparse.ArgumentParser()
    parser.add_argument("--admin-user-id", required=True, type=int)
    parser.add_argument("--user-id", type=int, help="active non-admin requester for fixture creation")
    parser.add_argument("--delete", action="store_true", help="remove only the exact marked fixture")
    args = parser.parse_args()
    if not args.delete and args.user_id is None:
        parser.error("--user-id is required unless --delete is specified")

    from api.repositories import MongoAuditLogRepository, MongoUserRepository
    from audit.events import AuditEvent
    from audit.service import AuditLogService, FileSink
    from config import get_settings
    from database.session import db
    from intent_engine.evidence import (
        DEVELOPMENT_FIXTURE_MARKER,
        EVIDENCE_COLLECTION,
        LocalEvidenceProvider,
    )
    from security.keyring import get_keyring

    settings = get_settings()
    mongo_uri = urlsplit(settings.mongodb_uri)
    if mongo_uri.scheme != "mongodb" or mongo_uri.hostname not in {"localhost", "127.0.0.1", "::1"}:
        raise SystemExit("refusing to seed: development fixtures require a local mongodb:// server")
    users = MongoUserRepository(db)
    admin = users.get_by_id(args.admin_user_id)
    if admin is None or admin.disabled or admin.role != "ADMIN":
        raise SystemExit("--admin-user-id must identify an active administrator")

    audit = AuditLogService(
        MongoAuditLogRepository(db),
        get_keyring(),
        FileSink(settings.audit_sink_path) if settings.audit_sink_path else None,
        sink_fail_closed=settings.strict,
    )
    provider = LocalEvidenceProvider(db)
    cases = db[EVIDENCE_COLLECTION]

    if args.delete:
        existing = cases.find_one({"_id": FIXTURE_REF})
        if existing is None:
            raise SystemExit(f"no fixture exists for {FIXTURE_REF}")
        if existing.get("fixture_marker") != DEVELOPMENT_FIXTURE_MARKER:
            raise SystemExit(f"refusing to delete {FIXTURE_REF}: fixture marker does not match")
        result = cases.delete_one({"_id": FIXTURE_REF, "fixture_marker": DEVELOPMENT_FIXTURE_MARKER})
        if result.deleted_count != 1:
            raise SystemExit(f"refusing to delete {FIXTURE_REF}: fixture changed during cleanup")
        audit.record(AuditEvent.EVIDENCE_CASE_CHANGED, "success", user_id=admin.id,
                     reason=f"development fixture {FIXTURE_REF} removed")
        print(f"Removed marked development fixture {FIXTURE_REF}.")
        return

    requester_id = args.user_id
    if requester_id is None:
        parser.error("--user-id is required unless --delete is specified")
    requester = users.get_by_id(requester_id)
    if requester is None or requester.disabled or requester.role == "ADMIN":
        raise SystemExit("--user-id must identify an active non-admin requester")
    if cases.find_one({"_id": FIXTURE_REF}) is not None:
        raise SystemExit(f"refusing to overwrite existing case {FIXTURE_REF}")
    try:
        case = provider.create_case(
            FIXTURE_REF,
            title=FIXTURE_TITLE,
            classification_cap="CONFIDENTIAL",
            allowed_resources=[FIXTURE_RESOURCE],
            assigned_user_ids=[requester.id],
            fixture_marker=DEVELOPMENT_FIXTURE_MARKER,
        )
    except DuplicateKeyError as exc:
        raise SystemExit(f"refusing to overwrite existing case {FIXTURE_REF}") from exc
    audit.record(AuditEvent.EVIDENCE_CASE_CHANGED, "success", user_id=admin.id,
                 resource=FIXTURE_RESOURCE, reason=f"development fixture {FIXTURE_REF} created for user={requester.id}")
    print(f"Created {case.ref} (revision {case.revision}) for requester user {requester.id}.")
    print(f"Enter {FIXTURE_REF} as the case/business reference in the frontend.")


if __name__ == "__main__":
    main()
