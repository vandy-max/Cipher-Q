// Pure helpers for Live Monitoring error handling (no React, unit-testable with `node --test`).
//
// The backend contract is unchanged: errors carry an HTTP status and a human-readable `detail`.
// This is the ONE place that turns them into a decision, so "temporary network trouble" is never
// confused with "a real security event", and "needs a face re-check" is never confused with
// "needs administrator approval".

/** @returns {"network"|"transient"|"auth"|"nonce"|"gone"|"stepup_required"|"device_revoked"|"session_expired"|"session_revoked"|"forbidden"|"unknown"} */
export function classifyMonitoringError(err) {
  if (!err) return "unknown";
  const status = err.status;
  if (status === undefined || status === null || status === 0 || err.name === "TypeError") return "network";
  if (status === 401) return "auth";
  if (status === 409) return "nonce";
  if (status === 404) return "gone";
  if (status === 408 || status === 425 || status === 429 || status >= 500) return "transient";
  if (status === 403) {
    const text = String(typeof err.detail === "string" ? err.detail : err.message || "").toLowerCase();
    if (text.includes("step-up")) return "stepup_required";
    if (text.includes("device is revoked") || text.includes("restore the device")) return "device_revoked";
    if (text.includes("expired")) return "session_expired";
    if (text.includes("revoked") || text.includes("session is invalid")) return "session_revoked";
    return "forbidden";
  }
  return "unknown";
}

/** Failures that must end local monitoring now (the backend has said the session is not usable). */
export function isTerminal(kind) {
  return ["auth", "forbidden", "device_revoked", "session_revoked", "session_expired"].includes(kind);
}

/** Failures that say nothing about security: keep monitoring, retry with backoff. */
export function isTemporary(kind) {
  return kind === "network" || kind === "transient";
}

/** A reauthentication that only needs a fresh FACE check (no administrator approval). */
export function needsFaceOnly(reasonCodeOrKind) {
  return ["session_expired", "stepup_required"].includes(reasonCodeOrKind);
}

/** Capped exponential backoff: failures=1 -> base, 2 -> 2*base, ... never above `max`. */
export function backoffDelay(failures, base, max) {
  if (!failures || failures < 1) return base;
  return Math.min(max, base * 2 ** (failures - 1));
}
