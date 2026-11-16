from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from functools import lru_cache

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pymongo.database import Database

from audit.service import AuditLogService, FileSink
from authentication.throttle import LoginThrottle
from config import get_settings
from authentication.throttle import LoginThrottle
from config import get_settings
from authentication.face_auth import FaceAuthService
from authentication.jwt_service import InvalidTokenError, JWTService, TokenExpiredError, TokenPayload
from authentication.service import AuthenticationService
from database.session import get_db
from monitoring.service import MonitoringService
from policy.context_collector import SecurityContextCollector
from policy.engine import PolicyEngine
from policy.geofence import LocationGeofenceService
from policy.ml_risk import MLRiskModel
from policy.risk import RiskEngine
from quantum.service import QuantumKeyExchangeService
from security.keyring import get_keyring

from .repositories import (
    MongoAuditLogRepository,
    MongoDeviceRepository,
    MongoFaceDescriptorRepository,
    MongoMonitoringRepository,
    MongoSessionRepository,
    MongoTokenRepository,
    MongoTokenRepository,
    MongoTrustedLocationRepository,
    MongoUserRepository,
    PolicyRepository,
)

_bearer_scheme = HTTPBearer(auto_error=False)


@lru_cache
def get_jwt_service() -> JWTService:
    st = get_settings()
    return JWTService(secret=st.jwt_secret, ttl_minutes=st.jwt_ttl_minutes,
                      issuer=st.jwt_issuer, audience=st.jwt_audience)


def get_login_throttle(db: Database = Depends(get_db)) -> LoginThrottle:
    st = get_settings()
    return LoginThrottle(db, st.login_max_failures, st.login_lockout_seconds)


def get_token_repository(db: Database = Depends(get_db)) -> MongoTokenRepository:
    return MongoTokenRepository(db)


def get_auth_service(
    db: Database = Depends(get_db),
    jwt_service: JWTService = Depends(get_jwt_service),
    throttle: LoginThrottle = Depends(get_login_throttle),
) -> AuthenticationService:
    return AuthenticationService(MongoUserRepository(db), jwt_service,
                                 tokens=MongoTokenRepository(db), throttle=throttle)


def get_user_repository(db: Database = Depends(get_db)) -> MongoUserRepository:
    return MongoUserRepository(db)


def get_audit_service(db: Database = Depends(get_db)) -> AuditLogService:
    st = get_settings()
    sink = FileSink(st.audit_sink_path) if st.audit_sink_path else None
    return AuditLogService(MongoAuditLogRepository(db), get_keyring(), sink,
                           sink_fail_closed=st.strict)


def get_face_auth_service(db: Database = Depends(get_db)) -> FaceAuthService:
    return FaceAuthService(MongoFaceDescriptorRepository(db))


def get_policy_engine() -> PolicyEngine:
    return PolicyEngine()


def get_policy_config_repository(db: Database = Depends(get_db)) -> PolicyRepository:
    return PolicyRepository(db)


def get_risk_engine() -> RiskEngine:
    return RiskEngine()


@lru_cache
def get_ml_risk_model() -> MLRiskModel:
    # Stateless hand-specified model (see policy/ml_risk.py module
    # docstring) — one shared instance is fine, mirrors get_risk_engine.
    return MLRiskModel()


def get_quantum_service() -> QuantumKeyExchangeService:
    return QuantumKeyExchangeService()


def get_device_repository(db: Database = Depends(get_db)) -> MongoDeviceRepository:
    return MongoDeviceRepository(db)


def get_session_repository(db: Database = Depends(get_db)) -> MongoSessionRepository:
    return MongoSessionRepository(db)


def get_trusted_location_repository(
    db: Database = Depends(get_db),
) -> MongoTrustedLocationRepository:
    return MongoTrustedLocationRepository(db)


def get_geofence_service(
    repo: MongoTrustedLocationRepository = Depends(get_trusted_location_repository),
) -> LocationGeofenceService:
    return LocationGeofenceService(repo)


def get_security_context_collector(
    device_repo: MongoDeviceRepository = Depends(get_device_repository),
    session_repo: MongoSessionRepository = Depends(get_session_repository),
    audit_service: AuditLogService = Depends(get_audit_service),
) -> SecurityContextCollector:
    return SecurityContextCollector(device_repo, session_repo, audit_service)


def get_monitoring_repository(db: Database = Depends(get_db)) -> MongoMonitoringRepository:
    return MongoMonitoringRepository(db)


def get_monitoring_service(
    monitoring_repo: MongoMonitoringRepository = Depends(get_monitoring_repository),
    device_repo: MongoDeviceRepository = Depends(get_device_repository),
    session_repo: MongoSessionRepository = Depends(get_session_repository),
    risk_engine: RiskEngine = Depends(get_risk_engine),
    audit_service: AuditLogService = Depends(get_audit_service),
) -> MonitoringService:
    return MonitoringService(
        monitoring_repo,
        device_repo,
        session_repo,
        risk_engine=risk_engine,
        audit_service=audit_service,
        max_heartbeat_gap_seconds=get_settings().heartbeat_max_gap_seconds,
    )


def get_security_incident_repository(db: Database = Depends(get_db)):
    from qira.repository import SecurityIncidentRepository

    return SecurityIncidentRepository(db)


def get_reauth_request_repository(db: Database = Depends(get_db)):
    from authorization.reauth_requests import ReauthRequestRepository

    return ReauthRequestRepository(db)


def get_qira_service(
    monitoring_service: MonitoringService = Depends(get_monitoring_service),
    device_repo: MongoDeviceRepository = Depends(get_device_repository),
    session_repo: MongoSessionRepository = Depends(get_session_repository),
    audit_service: AuditLogService = Depends(get_audit_service),
    incident_repo=Depends(get_security_incident_repository),
):
    from qira.service import QiraSecurityService

    return QiraSecurityService(
        monitoring_service=monitoring_service,
        device_repo=device_repo,
        session_repo=session_repo,
        audit_service=audit_service,
        incident_repo=incident_repo,
    )


@dataclass(frozen=True)
class Principal:
    """Authenticated caller as loaded from the DATABASE on every request.

    The role, enabled flag and token version are never taken from the JWT
    alone: a demoted / disabled / logged-out user loses access immediately.
    """

    user_id: int
    username: str
    role: str
    jti: str
    token_version: int
    expires_at: datetime


@dataclass(frozen=True)
class Principal:
    """Authenticated caller as loaded from the DATABASE on every request.

    The role, enabled flag and token version are never taken from the JWT
    alone: a demoted / disabled / logged-out user loses access immediately.
    """

    user_id: int
    username: str
    role: str
    jti: str
    token_version: int
    expires_at: datetime


def get_current_user(
    credentials: HTTPAuthorizationCredentials | None = Depends(_bearer_scheme),
    jwt_service: JWTService = Depends(get_jwt_service),
    db: Database = Depends(get_db),
) -> Principal:
    deny = HTTPException(status.HTTP_401_UNAUTHORIZED, "authentication required",
                         headers={"WWW-Authenticate": "Bearer"})
    if credentials is None or credentials.scheme.lower() != "bearer":
        raise deny
    try:
        payload = jwt_service.decode_token(credentials.credentials)
    except (TokenExpiredError, InvalidTokenError) as exc:
        raise deny from exc
    user = MongoUserRepository(db).get_by_id(payload.user_id)
    if user is None or user.disabled or user.token_version != payload.token_version:
        raise deny
    if not MongoTokenRepository(db).is_active(payload.jti, user.id):
        raise deny
    return Principal(user_id=user.id, username=user.username, role=user.role, jti=payload.jti,
                     token_version=user.token_version, expires_at=payload.expires_at)


# ---------------------------------------------------------------------
# Intent Integrity & Purpose Drift Engine wiring
# ---------------------------------------------------------------------
from keymgmt.key_sessions import KeySessionService  # noqa: E402
from identity.stepup import StepUpService  # noqa: E402
from intent_engine.engine import Actor, Deps, IntentEngine  # noqa: E402
from intent_engine.evidence import LocalEvidenceProvider  # noqa: E402


def get_actor(user: Principal = Depends(get_current_user)) -> Actor:
    return Actor(user.user_id, user.username, user.role)


def get_key_session_service(db: Database = Depends(get_db),
                            quantum: QuantumKeyExchangeService = Depends(get_quantum_service)) -> KeySessionService:
    st = get_settings()
    return KeySessionService(db, get_keyring(), quantum, ttl_seconds=st.key_session_ttl_seconds,
                             max_qubits=st.max_qubits)


def get_stepup_service(db: Database = Depends(get_db),
                       face: FaceAuthService = Depends(get_face_auth_service)) -> StepUpService:
    st = get_settings()
    return StepUpService(db, face, challenge_ttl=st.challenge_ttl_seconds, stepup_ttl=st.stepup_ttl_seconds)


def get_evidence_provider(db: Database = Depends(get_db)) -> LocalEvidenceProvider:
    return LocalEvidenceProvider(db)


def get_intent_engine(
    db: Database = Depends(get_db),
    users: MongoUserRepository = Depends(get_user_repository),
    sessions: MongoSessionRepository = Depends(get_session_repository),
    devices: MongoDeviceRepository = Depends(get_device_repository),
    keys: KeySessionService = Depends(get_key_session_service),
    stepup: StepUpService = Depends(get_stepup_service),
    evidence: LocalEvidenceProvider = Depends(get_evidence_provider),
    policy_repo: PolicyRepository = Depends(get_policy_config_repository),
    monitoring: MonitoringService = Depends(get_monitoring_service),
    collector: SecurityContextCollector = Depends(get_security_context_collector),
    risk_engine: RiskEngine = Depends(get_risk_engine),
    ml: MLRiskModel = Depends(get_ml_risk_model),
    audit: AuditLogService = Depends(get_audit_service),
) -> IntentEngine:
    from policy import ai_risk_service

    def monitoring_state(session_id: str, user_id: int):
        rec = monitoring.get_by_session(session_id)
        if rec is None or rec.stopped or rec.user_id != user_id:
            return None
        return monitoring.refresh(rec.monitoring_session_id).status.value

    def risk(actor: Actor, cid):
        r = ai_risk_service.assess(collector=collector, risk_engine=risk_engine, user_id=actor.user_id, cid=cid,
                                   face_confidence=None, ml_model=ml, fold_device_session_revocation_into_score=False)
        return r.action, r.risk_level

    return IntentEngine(Deps(db=db, keyring=get_keyring(), settings=get_settings(), users=users, sessions=sessions,
                             devices=devices, monitoring_state=monitoring_state, evidence=evidence, keys=keys,
                             stepup=stepup, risk=risk, policy_rows=policy_repo.list_all, audit=audit))
