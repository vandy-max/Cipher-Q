import getpass
from api.repositories import MongoUserRepository
from authentication.password import (
    hash_password_v2,
    validate_password_policy,
    PasswordPolicyError,
)
from database.session import db

username = input("Admin username [admin]: ").strip() or "admin"
users = MongoUserRepository(db)
user = users.get_by_username(username)

if user is None:
    raise SystemExit(f"User '{username}' not found. No changes made.")

if user.role != "ADMIN":
    raise SystemExit("This account is not an ADMIN. No changes made.")

password = getpass.getpass("New admin password: ")
confirm = getpass.getpass("Confirm new password: ")

if password != confirm:
    raise SystemExit("Passwords do not match. No changes made.")

try:
    validate_password_policy(password, username)
except PasswordPolicyError as exc:
    raise SystemExit(f"Password rejected: {exc}")

users.update_password_hash(user.id, hash_password_v2(password))
users.bump_token_version(user.id)

print(f"Password updated for admin '{username}'. Other users were not changed.")
