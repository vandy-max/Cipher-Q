import { createQiraEngine } from "./qiraEngine";
import { planFor } from "./qiraAnimator";
import { setApiObserver } from "../services/api";
import { isNetworkError } from "./classify";

/** Application-wide QIRA engine (one per page load). */
export const qiraEngine = createQiraEngine();

/** Fire-and-forget: a presentation failure must never affect a security flow. */
export function emitQira(id, detail) {
  try {
    return qiraEngine.trigger(id, detail);
  } catch {
    return false;
  }
}

export function releaseQira(id) {
  try { qiraEngine.release(id); } catch { /* ignore */ }
}

/** Resolve named warnings after a real recovery (scenario 29). */
export function clearQira(ids) {
  try { return qiraEngine.clear(ids); } catch { return false; }
}

export { REACTIONS, PRIORITY, SCENARIO_COUNT } from "./qiraReactions";

// Development-only handle for manual/visual QA (stripped from production builds).
if (import.meta.env?.DEV && typeof window !== "undefined") {
  window.__QIRA__ = { engine: qiraEngine, emit: emitQira, planFor };
}

// Connectivity: a response proves the backend is reachable; a 5xx or a network failure is
// "unavailable" (never a security denial). Presentation only.
setApiObserver((e) => {
  if (e.kind === "response") {
    if (e.status >= 500) emitQira("api.unavailable", { source: "api" });
    else clearQira(["api.unavailable"]);
  } else if (e.kind === "error" && isNetworkError(e.error)) {
    emitQira("api.unavailable", { source: "api" });
  }
});
