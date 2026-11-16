#!/usr/bin/env python3
"""Offline audit-chain verification (database + head + secondary sink). Exit 0 = valid, 1 = INVALID."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))


def main() -> None:
    from api.repositories import MongoAuditLogRepository
    from audit.service import AuditLogService, FileSink
    from config import get_settings
    from database.session import db
    from security.keyring import get_keyring
    st = get_settings()
    svc = AuditLogService(MongoAuditLogRepository(db), get_keyring(), FileSink(st.audit_sink_path) if st.audit_sink_path else None)
    r = svc.verify_integrity()
    print("VALID" if r.valid else f"INVALID: {r.reason}", f"entries={r.checked_entries}", r.checks)
    sys.exit(0 if r.valid else 1)


if __name__ == "__main__":
    main()
