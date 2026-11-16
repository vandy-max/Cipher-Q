/**
 * Map REAL backend/API outcomes onto QIRA events.
 *
 * Rules
 *  - Network failures and 5xx are "unavailable", never a security denial.
 *  - A denial is only reported as a specific reaction when the backend's own
 *    response matches it; anything unrecognised produces NO reaction rather
 *    than a guess.
 *  - Patterns below are taken from the backend's actual messages
 *    (api/rbac.py, crypto/service.py, api/routers/{decryption,encryption}.py,
 *    authorization.py). qiraClassify.contract.test.js re-checks them against
 *    the backend source so a reworded message is caught.
 */

export function errorText(err) {
  if (!err) return "";
  if (typeof err.detail === "string") return err.detail;
  if (err.detail && typeof err.detail === "object") {
    try { return JSON.stringify(err.detail); } catch { return ""; }
  }
  return typeof err.message === "string" ? err.message : "";
}

const NETWORK_RE = /failed to fetch|networkerror|load failed|network request failed|fetch failed/i;

export function isNetworkError(err) {
  if (!err) return false;
  if (typeof err.status === "number") return false; // got an HTTP response
  return err instanceof TypeError || err.name === "TypeError" || NETWORK_RE.test(err.message || "");
}

export function isUnavailableError(err) {
  if (!err) return false;
  if (isNetworkError(err)) return true;
  return typeof err.status === "number" && err.status >= 500;
}

export const RBAC_DENIED_RE = /requires one of the following roles|not authorized to .+ this resource/i;
export const INTENT_MISMATCH_RE = /intent hash mismatch|submitted intent does not match the approved intent/i;
export const RISK_REJECTED_RE = /request rejected: high risk assessment/i;
export const FACE_FAILED_RE = /face verification (failed|required)|face re-verification required/i;

export function isRbacDenied(err) {
  return err?.status === 403 && RBAC_DENIED_RE.test(errorText(err));
}

export function isIntentMismatch(err) {
  const s = err?.status;
  return (s === 403 || s === 409) && INTENT_MISMATCH_RE.test(errorText(err));
}

export function isRiskRejected(err) {
  return err?.status === 403 && RISK_REJECTED_RE.test(errorText(err));
}

export function isRiskStepUp(err) {
  return err?.status === 428;
}

export function isFaceFailure(err) {
  return (err?.status === 401 || err?.status === 403) && FACE_FAILED_RE.test(errorText(err));
}

/** Event id for an API error, or null when there is nothing honest to say. */
export function classifyApiError(err) {
  if (!err || isUnavailableError(err)) return null; // handled centrally (api.unavailable)
  if (isIntentMismatch(err)) return "intent.mismatch";
  if (isRbacDenied(err)) return "rbac.denied";
  if (isRiskRejected(err)) return "risk.high";
  if (isRiskStepUp(err)) return "risk.elevated";
  if (isFaceFailure(err)) return "face.failed";
  return null;
}

/** Risk level string (existing backend vocabulary) -> event id. */
export function riskEventForLevel(level) {
  switch (String(level || "").toLowerCase()) {
    case "low": return "risk.low";
    case "medium": return "risk.elevated";
    case "high":
    case "critical": return "risk.high";
    default: return null;
  }
}
