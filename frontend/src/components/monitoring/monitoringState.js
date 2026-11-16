// SINGLE frontend mapping from the backend-authoritative monitoring
// snapshot to the UI state. Every monitoring surface must use this
// function; no component may invent its own SECURE/WARNING/REAUTH/
// REVOKED interpretation.

export const MONITORING_UI_META = {
  active: { label: "SECURE", tone: "text-cq-primary", dot: "bg-cq-secondary" },
  warning: { label: "WARNING", tone: "text-amber-500", dot: "bg-amber-500" },
  verification_pending: { label: "VERIFICATION PENDING", tone: "text-amber-500", dot: "bg-amber-500" },
  risk_detected: { label: "RISK DETECTED", tone: "text-amber-500", dot: "bg-amber-500" },
  reauth_required: { label: "RE-AUTHENTICATION REQUIRED", tone: "text-amber-500", dot: "bg-amber-500" },
  revoked: { label: "ACCESS REVOKED", tone: "text-cq-error", dot: "bg-cq-error" },
  off: { label: "OFF", tone: "text-cq-on-surface-variant", dot: "bg-cq-outline" },
};

export function deriveMonitoringState({ isMonitoring, snapshot, connectionState, reauthRequired = false }) {
  if (snapshot?.status === "revoked") return "revoked";
  if (snapshot?.status === "reauth_required" || reauthRequired) return "reauth_required";
  if (!isMonitoring && !snapshot) return "off";
  if (isMonitoring && !snapshot) return "verification_pending";
  // A lost connection must never hide an already-known revoked/reauth state.
  if (connectionState === "lost") return "warning";
  // The snapshot's aggregate risk score includes repeated face failures.
  // The backend has already applied the authoritative 3/6/8 state machine;
  // deriving a separate HIGH-RISK verdict from that aggregate score here
  // would make the UI/QIRA jump ahead of re-authentication at six failures.
  if (snapshot?.status === "warning") return "warning";
  if (snapshot?.status === "active") return "active";
  return isMonitoring ? "verification_pending" : "off";
}

export function monitoringReason(stateKey, snapshot, connectionState) {
  if (stateKey === "off") return null;
  if (stateKey === "verification_pending") return "Monitoring is starting or awaiting the first confirmed backend verification.";
  if (stateKey === "risk_detected") return snapshot?.reason || "The backend monitoring service has detected elevated risk.";
  if (connectionState === "lost") {
    return snapshot?.reason || "Lost contact with the monitoring backend. Last confirmed state is shown.";
  }
  if (snapshot?.reason) return snapshot.reason;
  if (stateKey === "reauth_required") return "Repeated identity verification failures require fresh authorization.";
  if (stateKey === "revoked") return "The backend has revoked this authorization state, but no detailed reason was supplied.";
  if (stateKey === "warning") return "A recoverable monitoring anomaly was detected. Monitoring continues.";
  return "Face identity confirmed, liveness confirmed, device/session authorization valid, and monitoring connection healthy.";
}
