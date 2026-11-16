from monitoring.state import DEFAULT_THRESHOLDS, MonitoringThresholds


def test_default_face_failure_policy_matches_requested_sequence():
    assert DEFAULT_THRESHOLDS.warning_after == 3
    assert DEFAULT_THRESHOLDS.risk_increase_after == 3
    assert DEFAULT_THRESHOLDS.reauth_required_after == 6
    assert DEFAULT_THRESHOLDS.invalidate_after == 8


def test_custom_monitoring_thresholds_remain_configurable():
    thresholds = MonitoringThresholds(
        warning_after=3,
        risk_increase_after=3,
        reauth_required_after=5,
        invalidate_after=9,
    )
    assert thresholds.reauth_required_after == 5
    assert thresholds.invalidate_after == 9


def _qira_context(status, failures, risk="low"):
    from qira.schema import QiraContext

    return QiraContext(
        user_id=7, user_role="USER_LEVEL_1", monitoring_session_id="m1",
        device_id="d1", session_id="s1", monitoring_status=status,
        security_posture="normal", identity_state="identity_mismatch",
        face_present=True, liveness=True, consecutive_face_failures=failures,
        device_revoked=False, session_revoked=False, intent_id=None,
        intent_lifecycle_state=None, risk_level=risk, risk_score=0.0,
        audit_chain_intact=True, recent_event_types=(),
    )


def test_qira_baseline_follows_monitoring_3_6_8_thresholds():
    from qira.policy import compute_baseline
    from qira.schema import RecommendedAction, TamperSeverity

    severity, action, *_ = compute_baseline(_qira_context("active", 2, "low"))
    assert (severity, action) == (TamperSeverity.LOW, RecommendedAction.NONE)

    severity, action, *_ = compute_baseline(_qira_context("warning", 3, "medium"))
    assert (severity, action) == (TamperSeverity.MEDIUM, RecommendedAction.MONITOR)

    # Aggregate risk can rise from repeated face failures, but cannot bypass six.
    severity, action, *_ = compute_baseline(_qira_context("warning", 5, "high"))
    assert (severity, action) == (TamperSeverity.MEDIUM, RecommendedAction.MONITOR)

    severity, action, *_ = compute_baseline(_qira_context("reauth_required", 6, "high"))
    assert (severity, action) == (TamperSeverity.HIGH, RecommendedAction.REAUTHENTICATE)

    severity, action, *_ = compute_baseline(_qira_context("revoked", 8, "critical"))
    assert (severity, action) == (TamperSeverity.CRITICAL, RecommendedAction.REVOKE)
