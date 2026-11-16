#!/usr/bin/env python3
"""Generate deployment secrets into 0600 files. Nothing is printed except the file paths.

    python scripts/generate_secrets.py --out /etc/cipherq          # new JWT secret + keyring (id 1)
    python scripts/generate_secrets.py --out /etc/cipherq --add-key  # ADD key id N+1 and make it the active key

Files: jwt_secret, keyring (``<id>:<b64>`` lines joined by commas), active_key_id.
Point JWT_SECRET_FILE / CIPHERQ_KEYRING_FILE / CIPHERQ_ACTIVE_KEY_ID at them.  Never commit them; keep
an offline, encrypted backup of the keyring: losing it makes every encrypted record unrecoverable.
After --add-key run ``scripts/reencrypt.py`` to move stored documents to the new key (old key stays
in the ring so existing data remains readable until then).
"""
import argparse
import base64
import os
import secrets
import sys
from pathlib import Path


def _write(path: Path, text: str, overwrite: bool) -> None:
    if path.exists() and not overwrite:
        sys.exit(f"refusing to overwrite {path} (use --add-key to rotate)")
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as fh:
        fh.write(text)
    os.chmod(path, 0o600)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", required=True, type=Path)
    ap.add_argument("--add-key", action="store_true")
    a = ap.parse_args()
    a.out.mkdir(parents=True, exist_ok=True, mode=0o700)
    kr_path, act_path, jwt_path = a.out / "keyring", a.out / "active_key_id", a.out / "jwt_secret"
    newkey = base64.urlsafe_b64encode(secrets.token_bytes(32)).decode()
    if a.add_key:
        if not kr_path.exists():
            sys.exit("no existing keyring to extend")
        parts = [p for p in kr_path.read_text().strip().split(",") if p]
        nid = max(int(p.split(":")[0]) for p in parts) + 1
        _write(kr_path, ",".join(parts + [f"{nid}:{newkey}"]), True)
        _write(act_path, str(nid), True)
        print(f"added key id {nid} and made it active ->", kr_path)
        return
    _write(jwt_path, secrets.token_urlsafe(64), False)
    _write(kr_path, f"1:{newkey}", False)
    _write(act_path, "1", False)
    print("wrote", jwt_path, kr_path, act_path, "(mode 0600)")


if __name__ == "__main__":
    main()
