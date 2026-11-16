#!/usr/bin/env python3
"""Safe administrative bootstrap.

Self-registration only ever creates USER_LEVEL_1.  The first administrator is created out-of-band with this script:

* refuses to run if an administrator already exists (unless --allow-additional);
* the password is read from a prompt (getpass) or from --password-file (mode 0600), NEVER from argv/env, and
  must satisfy the same policy as normal registration;
* no default credentials exist anywhere in the code base;
* the action is written to the keyed audit chain.

    cd backend && python scripts/seed_admin.py --username alice.admin --email alice@example.org
"""
import argparse
import getpass
import os
import stat
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--username", required=True)
    ap.add_argument("--email", required=True)
    ap.add_argument("--password-file")
    ap.add_argument("--allow-additional", action="store_true")
    a = ap.parse_args()

    if a.password_file:
        p = Path(a.password_file)
        if os.name == "posix" and p.stat().st_mode & (stat.S_IRWXG | stat.S_IRWXO):
            sys.exit("password file must be chmod 600")
        password = p.read_text().strip()
    else:
        password = getpass.getpass("Administrator password: ")
        if password != getpass.getpass("Repeat: "):
            sys.exit("passwords differ")

    from api.repositories import MongoAuditLogRepository, MongoUserRepository
    from audit.events import AuditEvent
    from audit.service import AuditLogService, FileSink
    from authentication.password import PasswordPolicyError, hash_password_v2, validate_password_policy
    from authentication.service import EMAIL_RE, USERNAME_RE, normalize_username
    from config import get_settings
    from database.session import db
    from security.keyring import get_keyring

    username = normalize_username(a.username)
    if not USERNAME_RE.match(username) or not EMAIL_RE.match(a.email):
        sys.exit("invalid username or email")
    try:
        validate_password_policy(password, username)
    except PasswordPolicyError as exc:
        sys.exit(f"password rejected: {exc}")
    users = MongoUserRepository(db)
    if not a.allow_additional and any(u.role == "ADMIN" and not u.disabled for u in users.list_all()):
        sys.exit("an administrator already exists; use --allow-additional to create another")
    user = users.create(username, a.email.strip(), hash_password_v2(password), "", "ADMIN")
    st = get_settings()
    AuditLogService(MongoAuditLogRepository(db), get_keyring(),
                    FileSink(st.audit_sink_path) if st.audit_sink_path else None).record(
        AuditEvent.ADMIN_BOOTSTRAPPED, "success", reason=f"admin user id={user.id} created via seed_admin.py")
    print(f"administrator '{username}' created (id {user.id})")


if __name__ == "__main__":
    main()
