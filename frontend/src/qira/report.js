import { emitQira, clearQira } from "./index";
import { classifyApiError } from "./classify";

/** Emit the reaction (if any) that honestly describes a failed API call. */
export function reportApiError(err) {
  try {
    const id = classifyApiError(err);
    if (id) emitQira(id);
    return id;
  } catch {
    return null;
  }
}

// --- audit-chain verification: report real state CHANGES, not every poll ---
let lastAuditValid = null;

export function resetAuditMemory() {
  lastAuditValid = null;
}

/**
 * `result` is the backend /audit/verify response. `explicit` = the user asked
 * for this verification (always reacts); background polls only react when the
 * verified state actually changes.
 */
export function reportAuditVerification(result, { explicit = false } = {}) {
  try {
    if (!result || typeof result.valid !== "boolean") return;
    if (result.valid) {
      const changed = lastAuditValid !== true;
      lastAuditValid = true;
      clearQira(["audit.failed"]);
      if (changed || explicit) emitQira("audit.verified", explicit ? { force: true } : undefined);
    } else {
      const changed = lastAuditValid !== false;
      lastAuditValid = false;
      if (changed || explicit) emitQira("audit.failed");
    }
  } catch { /* presentation only */ }
}
