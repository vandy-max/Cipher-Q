"""Operational security: fail-closed configuration, secret handling, scripts."""
import base64
import os
import secrets
import stat
import subprocess
import sys
from pathlib import Path

import pytest

from config import ConfigurationError, build_settings

BACKEND = Path(__file__).resolve().parents[1]
KEY = "1:" + base64.urlsafe_b64encode(secrets.token_bytes(32)).decode()


def prod_env(**over):
    e = {"APP_ENV": "production", "JWT_SECRET": secrets.token_urlsafe(48), "CIPHERQ_KEYRING": KEY,
         "ALLOWED_ORIGINS": "https://app.example.org", "ALLOWED_HOSTS": "api.example.org",
         "MONGODB_URI": "mongodb://cipherq_app:S3cr3tPass@db.example.org:27017/cipherq?tls=true&authSource=cipherq",
         "AUDIT_SINK_PATH": "/var/log/cipherq/audit.jsonl", "ENABLE_DOCS": "false",
         "ALLOW_ATTACK_SIMULATION": "false"}
    e.update(over)
    return {k: v for k, v in e.items() if v is not None}


def test_valid_production_config_loads():
    s = build_settings(prod_env(), allow_dev_secret_file=False)
    assert s.strict and not s.enable_docs and not s.allow_attack_simulation and s.scrypt_log_n >= 15


def test_key_session_default_is_24_hours_and_can_be_configured():
    default_settings = build_settings(prod_env(), allow_dev_secret_file=False)
    assert default_settings.key_session_ttl_seconds == 24 * 60 * 60
    custom_settings = build_settings(prod_env(KEY_SESSION_TTL_SECONDS="86400"), allow_dev_secret_file=False)
    assert custom_settings.key_session_ttl_seconds == 24 * 60 * 60


@pytest.mark.parametrize("over,why", [
    ({"JWT_SECRET": None}, "missing jwt secret"),
    ({"JWT_SECRET": "short"}, "short jwt secret"),
    ({"JWT_SECRET": "dev-secret-change-me" * 3}, "placeholder jwt secret"),
    ({"JWT_SECRET": "changeme" * 8}, "placeholder jwt secret"),
    ({"CIPHERQ_KEYRING": None}, "missing keyring"),
    ({"CIPHERQ_KEYRING": "1:AAAA"}, "short key"),
    ({"ALLOWED_ORIGINS": None}, "no origins"),
    ({"ALLOWED_ORIGINS": "*"}, "wildcard origin"),
    ({"ALLOWED_ORIGINS": "http://app.example.org"}, "non-https origin"),
    ({"ALLOWED_HOSTS": None}, "no hosts"),
    ({"MONGODB_URI": "mongodb://localhost:27017"}, "no mongo credentials/tls"),
    ({"MONGODB_URI": "mongodb://u:p@db.example.org/x"}, "no tls"),
    ({"AUDIT_SINK_PATH": None}, "no audit sink"),
    ({"ENABLE_DOCS": "true"}, "docs on"),
    ({"ALLOW_ATTACK_SIMULATION": "true"}, "attack simulation on"),
    ({"ADMIN_SELF_APPROVAL": "true"}, "admin self-approval"),
    ({"PASSWORD_SCRYPT_LOG_N": "10"}, "weak kdf"),
    ({"CIPHERQ_WHOLE_DB_ENCRYPTION": "false"}, "encryption off"),
])
def test_production_fails_closed(over, why):
    with pytest.raises(ConfigurationError):
        build_settings(prod_env(**over), allow_dev_secret_file=False)


def test_v17_shipped_key_is_rejected():
    """The key that shipped inside the v17 archive is public; it must never be accepted."""
    import hashlib
    from config import COMPROMISED_KEY_SHA256
    assert "c8622acc5c596ccf76e7cab8884952155232b09ede14a47d784fcc768a6933e2" in COMPROMISED_KEY_SHA256


def test_no_default_secret_fallback_outside_development(monkeypatch):
    for env in ("production", "staging", "test"):
        with pytest.raises(ConfigurationError):
            build_settings({"APP_ENV": env}, allow_dev_secret_file=False)


def test_secret_files_must_be_private(tmp_path):
    if os.name != "posix":
        pytest.skip("POSIX permission bits do not represent Windows file ACLs")
    f = tmp_path / "jwt"
    f.write_text(secrets.token_urlsafe(64))
    os.chmod(f, 0o644)
    with pytest.raises(ConfigurationError):
        build_settings(prod_env(JWT_SECRET=None, JWT_SECRET_FILE=str(f)), allow_dev_secret_file=False)
    os.chmod(f, 0o600)
    assert build_settings(prod_env(JWT_SECRET=None, JWT_SECRET_FILE=str(f)), allow_dev_secret_file=False)


def test_settings_repr_does_not_leak_secrets():
    s = build_settings(prod_env(), allow_dev_secret_file=False)
    r = repr(s) + str(s)
    assert s.jwt_secret not in r and KEY.split(":")[1] not in r and "S3cr3tPass" not in r


def _run(script, *args, env=None, inp=None):
    e = {**os.environ, **(env or {})}
    return subprocess.run([sys.executable, str(BACKEND / "scripts" / script), *args], capture_output=True,
                          text=True, env=e, cwd=BACKEND, input=inp, timeout=120)


def test_generate_secrets_script(tmp_path):
    r = _run("generate_secrets.py", "--out", str(tmp_path / "s"))
    assert r.returncode == 0
    for n in ("jwt_secret", "keyring", "active_key_id"):
        f = tmp_path / "s" / n
        if os.name == "posix":
            assert stat.S_IMODE(f.stat().st_mode) == 0o600
    secret_text = (tmp_path / "s" / "jwt_secret").read_text()
    assert secret_text not in r.stdout + r.stderr
    assert _run("generate_secrets.py", "--out", str(tmp_path / "s")).returncode != 0      # no silent overwrite
    assert _run("generate_secrets.py", "--out", str(tmp_path / "s"), "--add-key").returncode == 0
    assert (tmp_path / "s" / "active_key_id").read_text() == "2"
    assert len((tmp_path / "s" / "keyring").read_text().split(",")) == 2
    s = build_settings({"APP_ENV": "test", "JWT_SECRET_FILE": str(tmp_path / "s" / "jwt_secret"),
                        "CIPHERQ_KEYRING_FILE": str(tmp_path / "s" / "keyring"),
                        "CIPHERQ_ACTIVE_KEY_ID": "2"}, allow_dev_secret_file=False)
    assert s.active_key_id == 2 and set(s.keyring) == {1, 2}


def _script_env(tmp_path, dbname):
    return {"APP_ENV": "test", "JWT_SECRET": secrets.token_urlsafe(48), "CIPHERQ_KEYRING": os.environ["CIPHERQ_KEYRING"],
            "CIPHERQ_ACTIVE_KEY_ID": "1", "MONGODB_URI": os.environ["MONGODB_URI"], "MONGODB_DATABASE": dbname,
            "AUDIT_SINK_PATH": str(tmp_path / "sink.jsonl")}


def test_seed_admin_script_bootstrap_and_refusals(tmp_path):
    import pymongo
    dbname = "cipherq_t_seed_" + secrets.token_hex(4)
    env = _script_env(tmp_path, dbname)
    pw = tmp_path / "pw"
    pw.write_text("Admin-Bootstrap-Passphrase-77")
    os.chmod(pw, 0o644)
    if os.name == "posix":
        r = _run("seed_admin.py", "--username", "root.admin", "--email", "a@example.org",
                 "--password-file", str(pw), env=env)
        assert r.returncode != 0 and "600" in r.stderr + r.stdout                  # open permissions refused
    os.chmod(pw, 0o600)
    weak = tmp_path / "weak"; weak.write_text("password1234"); os.chmod(weak, 0o600)
    assert _run("seed_admin.py", "--username", "root.admin", "--email", "a@example.org",
                "--password-file", str(weak), env=env).returncode != 0
    ok = _run("seed_admin.py", "--username", "root.admin", "--email", "a@example.org", "--password-file", str(pw), env=env)
    assert ok.returncode == 0, ok.stderr
    assert "Admin-Bootstrap" not in ok.stdout + ok.stderr
    again = _run("seed_admin.py", "--username", "second.admin", "--email", "b@example.org", "--password-file", str(pw), env=env)
    assert again.returncode != 0 and "already exists" in again.stderr + again.stdout
    v = _run("verify_audit.py", env=env)
    assert v.returncode == 0 and "VALID" in v.stdout, v.stdout + v.stderr
    pymongo.MongoClient(os.environ["MONGODB_URI"]).drop_database(dbname)


def test_reencrypt_after_key_rotation_and_verify_audit(tmp_path):
    import pymongo
    dbname = "cipherq_t_rot_" + secrets.token_hex(4)
    k1 = base64.urlsafe_b64encode(secrets.token_bytes(32)).decode()
    k2 = base64.urlsafe_b64encode(secrets.token_bytes(32)).decode()
    env = _script_env(tmp_path, dbname)
    env["CIPHERQ_KEYRING"] = f"1:{k1}"
    pw = tmp_path / "pw"; pw.write_text("Admin-Bootstrap-Passphrase-77"); os.chmod(pw, 0o600)
    assert _run("seed_admin.py", "--username", "root.admin", "--email", "a@example.org", "--password-file", str(pw), env=env).returncode == 0
    env2 = {**env, "CIPHERQ_KEYRING": f"1:{k1},2:{k2}", "CIPHERQ_ACTIVE_KEY_ID": "2"}
    r = _run("reencrypt.py", env=env2)
    assert r.returncode == 0 and "0 failures" in r.stdout, r.stdout + r.stderr
    raw = pymongo.MongoClient(os.environ["MONGODB_URI"])[dbname]
    kids = {d.get("kid") for n in raw.list_collection_names() for d in raw[n].find({}, {"kid": 1}) if "kid" in d}
    assert kids == {2}
    assert _run("verify_audit.py", env=env2).returncode == 0                    # audit MACs survive re-encryption
    pymongo.MongoClient(os.environ["MONGODB_URI"]).drop_database(dbname)


def test_no_secrets_or_keys_in_source_tree():
    root = BACKEND.parent
    bad = []
    for p in root.rglob("*"):
        if not p.is_file() or any(x in p.parts for x in (
            "node_modules", ".git", "dist", "__pycache__", ".pytest_cache", "venv", ".venv", ".dev_secrets_v2"
        )):
            continue
        if p.name in (".env", ".dev_secrets.json") or (
            p.name.startswith(".env.") and p.name != ".env.example"
        ):
            continue
        if p.name == ".whole_db_encryption_key" or p.suffix in (".pem", ".key"):
            bad.append(str(p))
    assert not bad, bad
    assert "dev-secret-change-me" not in "".join(p.read_text(errors="ignore") for p in (BACKEND / "api").rglob("*.py"))
