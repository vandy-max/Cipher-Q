"""
Central, fail-closed configuration for CipherQ.

Design rules (see docs/KEY_MANAGEMENT.md):

* There are NO static default secrets anywhere in the code base.
* ``APP_ENV`` is one of ``production`` | ``staging`` | ``development`` | ``test``.
  Anything else (including a typo such as ``prod``) is rejected, so a
  misspelt production flag can never silently select development defaults.
* ``production`` and ``staging`` require every secret to be supplied
  explicitly (environment variable or ``*_FILE`` path) and validate it.
* ``development`` may auto-generate random, per-checkout secrets into
  ``backend/.dev_secrets.json`` (mode 0600, git-ignored, never packaged).
  This file is *never* read in production/staging.
* ``test`` requires the test harness to inject secrets; it never touches the
  developer secrets file.
* Secrets never appear in ``repr()`` / logs: ``Settings`` renders redacted.

Pure functions (``build_settings``, ``validate_settings``) take an explicit
mapping so they are unit-testable without touching ``os.environ``.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import secrets
import stat
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path
from typing import Mapping
from urllib.parse import urlsplit

VALID_ENVS = ("production", "staging", "development", "test")
STRICT_ENVS = ("production", "staging")

_BACKEND_DIR = Path(__file__).resolve().parent
DEV_SECRETS_PATH = _BACKEND_DIR / ".dev_secrets.json"

# SHA-256 of raw key bytes that were shipped inside the v17 archive and must
# be treated as compromised. Production refuses to start with them.
COMPROMISED_KEY_SHA256 = frozenset(
    {"c8622acc5c596ccf76e7cab8884952155232b09ede14a47d784fcc768a6933e2"}
)

_PLACEHOLDER_MARKERS = (
    "change-me", "changeme", "change_me", "dev-secret", "example", "placeholder",
    "your-secret", "<", "secret123", "password",
)

MIN_JWT_SECRET_BYTES = 32
KEY_BYTES = 32


class ConfigurationError(RuntimeError):
    """Raised at startup when configuration is missing or unsafe."""


# ---------------------------------------------------------------------
# Data types
# ---------------------------------------------------------------------

@dataclass(frozen=True)
class Settings:
    app_env: str
    jwt_secret: str = field(repr=False)
    jwt_ttl_minutes: int
    jwt_issuer: str
    jwt_audience: str
    keyring: Mapping[int, bytes] = field(repr=False)   # key_id -> 32 raw bytes
    active_key_id: int
    legacy_v1_db_key: bytes | None = field(repr=False, default=None)
    mongodb_uri: str = field(repr=False, default="mongodb://localhost:27017")
    mongodb_database: str = "cipherq"
    allowed_origins: tuple[str, ...] = ()
    allowed_hosts: tuple[str, ...] = ()
    enable_docs: bool = False
    whole_db_encryption: bool = True
    allow_self_register: bool = True
    max_body_bytes: int = 16 * 1_048_576
    request_timeout_seconds: int = 120
    max_qubits: int = 2048
    quantum_concurrency: int = 4
    quantum_per_user_per_hour: int = 30
    login_max_failures: int = 5
    login_lockout_seconds: int = 900
    heartbeat_max_gap_seconds: int = 45
    decision_ttl_seconds: int = 300
    context_ttl_seconds: int = 120
    key_session_ttl_seconds: int = 24 * 60 * 60
    audit_sink_path: str | None = None
    admin_self_approval: bool = False
    hsts: bool = True
    scrypt_log_n: int = 15
    trusted_proxies: int = 0
    login_ip_per_10min: int = 40
    register_ip_per_hour: int = 10
    heavy_ip_per_minute: int = 30
    stepup_ttl_seconds: int = 300
    challenge_ttl_seconds: int = 60
    allow_attack_simulation: bool = False

    @property
    def strict(self) -> bool:
        return self.app_env in STRICT_ENVS

    def __repr__(self) -> str:  # never leak secrets via repr/logging
        return (f"Settings(app_env={self.app_env!r}, keyring_ids={sorted(self.keyring)}, "
                f"active_key_id={self.active_key_id}, mongodb_database={self.mongodb_database!r}, "
                "secrets=<redacted>)")


# ---------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------

def _b64key(raw: str, label: str) -> bytes:
    try:
        key = base64.urlsafe_b64decode(raw.strip().encode("ascii") + b"=" * (-len(raw.strip()) % 4))
    except Exception as exc:  # noqa: BLE001
        raise ConfigurationError(f"{label} is not valid url-safe base64") from exc
    if len(key) != KEY_BYTES:
        raise ConfigurationError(f"{label} must decode to exactly {KEY_BYTES} bytes")
    return key


def _truthy(v: str | None, default: bool) -> bool:
    if v is None or v.strip() == "":
        return default
    return v.strip().lower() in {"1", "true", "yes", "on"}


def _int(env: Mapping[str, str], name: str, default: int, lo: int, hi: int) -> int:
    raw = env.get(name)
    if raw is None or raw.strip() == "":
        return default
    try:
        val = int(raw)
    except ValueError as exc:
        raise ConfigurationError(f"{name} must be an integer") from exc
    if not lo <= val <= hi:
        raise ConfigurationError(f"{name} must be between {lo} and {hi}")
    return val


def _read_secret_file(path: str, label: str) -> str:
    p = Path(path)
    if not p.is_file():
        raise ConfigurationError(f"{label}: file not found")
    mode = p.stat().st_mode
    if os.name == "posix" and mode & (stat.S_IRWXG | stat.S_IRWXO):
        raise ConfigurationError(
            f"{label}: file permissions are too open (chmod 600 required)")
    return p.read_text(encoding="utf-8").strip()


def parse_keyring(spec: str) -> dict[int, bytes]:
    """``"1:<b64>,2:<b64>"`` or a JSON object ``{"1": "<b64>"}``."""
    spec = spec.strip()
    ring: dict[int, bytes] = {}
    if spec.startswith("{"):
        try:
            items = json.loads(spec).items()
        except json.JSONDecodeError as exc:
            raise ConfigurationError("CIPHERQ_KEYRING is not valid JSON") from exc
    else:
        items = []
        for part in spec.split(","):
            if not part.strip():
                continue
            if ":" not in part:
                raise ConfigurationError("CIPHERQ_KEYRING entries must look like '<id>:<base64>'")
            kid, _, val = part.partition(":")
            items.append((kid, val))
    for kid, val in items:
        try:
            kid_i = int(kid)
        except ValueError as exc:
            raise ConfigurationError("keyring ids must be integers") from exc
        if kid_i < 1 or kid_i > 65535:
            raise ConfigurationError("keyring ids must be in 1..65535")
        if kid_i in ring:
            raise ConfigurationError(f"duplicate keyring id {kid_i}")
        ring[kid_i] = _b64key(str(val), f"keyring entry {kid_i}")
    if not ring:
        raise ConfigurationError("CIPHERQ_KEYRING is empty")
    return ring


def _load_or_create_dev_secrets() -> dict:
    """Development only: random per-checkout secrets, persisted 0600."""
    if DEV_SECRETS_PATH.exists():
        return json.loads(DEV_SECRETS_PATH.read_text(encoding="utf-8"))
    data = {
        "jwt_secret": secrets.token_urlsafe(48),
        "keyring": {"1": base64.urlsafe_b64encode(secrets.token_bytes(KEY_BYTES)).decode()},
        "active_key_id": 1,
    }
    fd = os.open(DEV_SECRETS_PATH, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        json.dump(data, fh)
    return data


# ---------------------------------------------------------------------
# Build + validate
# ---------------------------------------------------------------------

def build_settings(env: Mapping[str, str], *, allow_dev_secret_file: bool | None = None) -> Settings:
    app_env = (env.get("APP_ENV") or "development").strip().lower()
    if app_env not in VALID_ENVS:
        raise ConfigurationError(f"APP_ENV must be one of {VALID_ENVS}, got {app_env!r}")
    strict = app_env in STRICT_ENVS
    if allow_dev_secret_file is None:
        allow_dev_secret_file = app_env == "development"

    # ---- JWT secret -------------------------------------------------
    jwt_secret = env.get("JWT_SECRET") or ""
    if not jwt_secret and env.get("JWT_SECRET_FILE"):
        jwt_secret = _read_secret_file(env["JWT_SECRET_FILE"], "JWT_SECRET_FILE")
    dev: dict | None = None

    # ---- Keyring ----------------------------------------------------
    spec = env.get("CIPHERQ_KEYRING") or ""
    if not spec and env.get("CIPHERQ_KEYRING_FILE"):
        spec = _read_secret_file(env["CIPHERQ_KEYRING_FILE"], "CIPHERQ_KEYRING_FILE")
    active_raw = env.get("CIPHERQ_ACTIVE_KEY_ID")

    if (not jwt_secret or not spec) and allow_dev_secret_file:
        dev = _load_or_create_dev_secrets()
        jwt_secret = jwt_secret or dev["jwt_secret"]
        if not spec:
            spec = json.dumps(dev["keyring"])
            active_raw = active_raw or str(dev["active_key_id"])

    if not jwt_secret:
        raise ConfigurationError("JWT_SECRET (or JWT_SECRET_FILE) is required")
    if not spec:
        raise ConfigurationError("CIPHERQ_KEYRING (or CIPHERQ_KEYRING_FILE) is required")

    keyring = parse_keyring(spec)
    if active_raw is None:
        if len(keyring) == 1:
            active_raw = str(next(iter(keyring)))
        else:
            raise ConfigurationError("CIPHERQ_ACTIVE_KEY_ID is required when several keys are configured")
    try:
        active_key_id = int(active_raw)
    except ValueError as exc:
        raise ConfigurationError("CIPHERQ_ACTIVE_KEY_ID must be an integer") from exc
    if active_key_id not in keyring:
        raise ConfigurationError("CIPHERQ_ACTIVE_KEY_ID does not exist in the keyring")

    legacy = env.get("CIPHERQ_LEGACY_V1_DB_KEY")
    legacy_key = _b64key(legacy, "CIPHERQ_LEGACY_V1_DB_KEY") if legacy else None

    origins = tuple(o.strip() for o in (env.get("ALLOWED_ORIGINS") or "").split(",") if o.strip())
    hosts = tuple(h.strip() for h in (env.get("ALLOWED_HOSTS") or "").split(",") if h.strip())
    if not strict and not origins:
        origins = ("http://localhost:5173", "http://127.0.0.1:5173",
                   "http://localhost:3000", "http://127.0.0.1:3000")

    settings = Settings(
        app_env=app_env,
        jwt_secret=jwt_secret,
        jwt_ttl_minutes=_int(env, "JWT_TTL_MINUTES", 30, 1, 24 * 60),
        jwt_issuer=env.get("JWT_ISSUER", "cipherq"),
        jwt_audience=env.get("JWT_AUDIENCE", "cipherq-api"),
        keyring=keyring,
        active_key_id=active_key_id,
        legacy_v1_db_key=legacy_key,
        mongodb_uri=env.get("MONGODB_URI", "mongodb://localhost:27017"),
        mongodb_database=env.get("MONGODB_DATABASE", "cipherq"),
        allowed_origins=origins,
        allowed_hosts=hosts,
        enable_docs=_truthy(env.get("ENABLE_DOCS"), default=not strict),
        whole_db_encryption=_truthy(env.get("CIPHERQ_WHOLE_DB_ENCRYPTION"), default=True),
        allow_self_register=_truthy(env.get("ALLOW_SELF_REGISTER"), default=True),
        max_body_bytes=_int(env, "MAX_BODY_BYTES", 16 * 1_048_576, 1024, 16 * 1024 * 1024),
        request_timeout_seconds=_int(env, "REQUEST_TIMEOUT_SECONDS", 120, 5, 600),
        max_qubits=_int(env, "MAX_QUBITS", 2048, 8, 8192),
        quantum_concurrency=_int(env, "QUANTUM_CONCURRENCY", 4, 1, 64),
        quantum_per_user_per_hour=_int(env, "QUANTUM_PER_USER_PER_HOUR", 30, 1, 10_000),
        login_max_failures=_int(env, "LOGIN_MAX_FAILURES", 5, 1, 100),
        login_lockout_seconds=_int(env, "LOGIN_LOCKOUT_SECONDS", 900, 1, 86_400),
        heartbeat_max_gap_seconds=_int(env, "HEARTBEAT_MAX_GAP_SECONDS", 45, 5, 3600),
        decision_ttl_seconds=_int(env, "DECISION_TTL_SECONDS", 300, 5, 3600),
        context_ttl_seconds=_int(env, "CONTEXT_TTL_SECONDS", 120, 5, 3600),
        key_session_ttl_seconds=_int(env, "KEY_SESSION_TTL_SECONDS", 24 * 60 * 60, 30, 7 * 86_400),
        audit_sink_path=env.get("AUDIT_SINK_PATH") or None,
        admin_self_approval=_truthy(env.get("ADMIN_SELF_APPROVAL"), default=False),
        hsts=_truthy(env.get("ENABLE_HSTS"), default=True),
        scrypt_log_n=_int(env, "PASSWORD_SCRYPT_LOG_N", 15, 10, 20),
        trusted_proxies=_int(env, "TRUSTED_PROXY_COUNT", 0, 0, 5),
        login_ip_per_10min=_int(env, "LOGIN_IP_PER_10MIN", 40, 1, 100_000),
        register_ip_per_hour=_int(env, "REGISTER_IP_PER_HOUR", 10, 1, 100_000),
        heavy_ip_per_minute=_int(env, "HEAVY_IP_PER_MINUTE", 30, 1, 100_000),
        stepup_ttl_seconds=_int(env, "STEPUP_TTL_SECONDS", 300, 10, 3600),
        challenge_ttl_seconds=_int(env, "CHALLENGE_TTL_SECONDS", 60, 5, 600),
        allow_attack_simulation=_truthy(env.get("ALLOW_ATTACK_SIMULATION"), default=not strict),
    )
    validate_settings(settings)
    return settings


def validate_settings(s: Settings) -> None:
    """Raises ``ConfigurationError`` for unsafe configuration.

    Basic structural checks apply to every environment; the strict checks
    apply to ``production`` and ``staging`` only.
    """
    if len(s.jwt_secret.encode("utf-8")) < MIN_JWT_SECRET_BYTES:
        raise ConfigurationError(f"JWT_SECRET must be at least {MIN_JWT_SECRET_BYTES} bytes")
    for kid, key in s.keyring.items():
        if hashlib.sha256(key).hexdigest() in COMPROMISED_KEY_SHA256:
            raise ConfigurationError(
                f"keyring id {kid} is a key that shipped inside the CipherQ v17 archive "
                "and is compromised; generate a new key (scripts/generate_secrets.py)")
    if not s.strict:
        return

    low = s.jwt_secret.lower()
    if any(m in low for m in _PLACEHOLDER_MARKERS) or len(set(s.jwt_secret)) < 12:
        raise ConfigurationError("JWT_SECRET looks like a placeholder; generate a random secret")
    if len({bytes(k) for k in s.keyring.values()}) != len(s.keyring):
        raise ConfigurationError("keyring contains duplicate key material")
    if any(len(set(k)) < 8 for k in s.keyring.values()):
        raise ConfigurationError("keyring contains a low-entropy key")
    if not s.whole_db_encryption:
        raise ConfigurationError("CIPHERQ_WHOLE_DB_ENCRYPTION must stay enabled in production")
    if not s.allowed_origins:
        raise ConfigurationError("ALLOWED_ORIGINS must be set (comma-separated https origins)")
    for origin in s.allowed_origins:
        if origin == "*" or not origin.startswith("https://"):
            raise ConfigurationError(f"ALLOWED_ORIGINS entry {origin!r} must be an https:// origin")
    if not s.allowed_hosts:
        raise ConfigurationError("ALLOWED_HOSTS must be set in production")
    if s.admin_self_approval:
        raise ConfigurationError("ADMIN_SELF_APPROVAL must be disabled in production")
    if s.scrypt_log_n < 15:
        raise ConfigurationError("PASSWORD_SCRYPT_LOG_N must be >= 15 in production")
    if not s.audit_sink_path:
        raise ConfigurationError("AUDIT_SINK_PATH (append-only secondary audit sink) must be set in production")
    if s.enable_docs:
        raise ConfigurationError("ENABLE_DOCS must be disabled in production")
    if s.allow_attack_simulation:
        raise ConfigurationError("ALLOW_ATTACK_SIMULATION must be disabled in production")
    assert_mongo_uri_ready(s.mongodb_uri)


def assert_mongo_uri_ready(uri: str) -> None:
    """Production MongoDB must be authenticated and use TLS."""
    if uri.strip() == "mongodb://localhost:27017":
        raise ConfigurationError("MONGODB_URI is still the unauthenticated development default")
    parsed = urlsplit(uri)
    query = parsed.query.lower()
    tls = parsed.scheme == "mongodb+srv" or "tls=true" in query or "ssl=true" in query
    if not (parsed.username or "authsource=" in query):
        raise ConfigurationError("MONGODB_URI must carry credentials (least-privilege user)")
    if not tls:
        raise ConfigurationError("MONGODB_URI must request TLS (tls=true or mongodb+srv://)")


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    try:  # development convenience; explicit environment variables always win
        from dotenv import load_dotenv
        load_dotenv()
    except ImportError:  # pragma: no cover
        pass
    return build_settings(os.environ)


def reset_settings_cache() -> None:  # test helper
    get_settings.cache_clear()
