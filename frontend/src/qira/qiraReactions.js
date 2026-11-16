/**
 * QIRA reaction catalogue — the single source of truth for the 29
 * presentation scenarios.
 *
 * IMPORTANT: this is a PRESENTATION layer. A reaction can never grant,
 * deny, or alter access. Messages are fixed strings: they never include
 * tokens, biometric data, keys, hashes, or backend error text.
 *
 * Fields
 *   n          scenario number (1..29) from the product spec
 *   id         event identifier used by `emitQira(id)`
 *   message    exact user-facing text (null = no message)
 *   priority   1 (ambient) .. 5 (critical). Higher preempts lower; a lower
 *              priority reaction can never hide an unresolved higher one.
 *   durationMs how long a transient reaction stays foreground
 *   sticky     true => an UNRESOLVED warning: stays until resolved by
 *              `resolves`-style events (see `resolveIds` + alert.cleared)
 *   hold       true => stays foreground while a real operation is in
 *              flight, until `release(id)` (with `maxHoldMs` safety cap)
 *   warning    show the warning indicator
 *   cooldownMs ignore re-triggers of the same id inside this window
 *   visual     how the avatar moves: motion / glow / scan / tone (the pose itself is chosen in qiraSprites.js)
 *                motion  : head/body motion (nod|shake|tilt|lean|blink)
 *                glow    : 0..1 soft halo strength
 *                scan    : slow side-to-side sway (monitoring/risk "looking around")
 *                tone    : "neutral" | "warn" | "critical" | "ok" (halo tint)
 */

export const PRIORITY = Object.freeze({ AMBIENT: 1, INFO: 2, NOTICE: 3, ALERT: 4, CRITICAL: 5 });

export const REACTIONS = Object.freeze({
  "login.page": {
    n: 1, message: "Welcome to CipherQ.", priority: PRIORITY.AMBIENT, durationMs: 4200,
    visual: { motion: "blink", tone: "neutral" },
  },
  "login.success": {
    n: 2, message: "Identity verified. Welcome back.", priority: PRIORITY.INFO, durationMs: 3600,
    visual: { motion: "nod", glow: 0.55, tone: "ok" },
  },
  "login.failed": {
    n: 3, message: "Authentication failed. Please try again.", priority: PRIORITY.ALERT, durationMs: 4200,
    visual: { motion: "shake", tone: "warn" },
  },
  "face.requested": {
    n: 4, message: "Please position your face in the camera.", priority: PRIORITY.NOTICE, durationMs: 5000,
    visual: { motion: "lean", glow: 0.25, tone: "neutral" },
  },
  "face.success": {
    n: 5, message: "Face verification successful.", priority: PRIORITY.INFO, durationMs: 3200,
    visual: { motion: "nod", tone: "ok" },
  },
  "face.failed": {
    n: 6, message: "Verification failed. Access has not been granted.", priority: PRIORITY.ALERT, durationMs: 4600,
    visual: { tone: "warn" },
  },
  "intent.entered": {
    n: 7, message: "I'm checking your declared intent.", priority: PRIORITY.NOTICE, durationMs: 3600,
    visual: { motion: "tilt", tone: "neutral" },
  },
  "intent.match": {
    n: 8, message: "The request is consistent with the declared intent.", priority: PRIORITY.INFO, durationMs: 3600,
    visual: { glow: 0.35, tone: "ok" },
  },
  "intent.mismatch": {
    n: 9, message: "The requested action differs from the declared intent.", priority: PRIORITY.ALERT, durationMs: 5000,
    visual: { tone: "warn" }, warning: true,
  },
  "rbac.pass": {
    n: 10, message: "Your role permits this operation.", priority: PRIORITY.INFO, durationMs: 3000,
    visual: { motion: "nod", tone: "ok" }, cooldownMs: 4000,
  },
  "rbac.denied": {
    n: 11, message: "Your role does not permit this operation.", priority: PRIORITY.ALERT, durationMs: 4800,
    visual: { motion: "shake", tone: "warn" }, warning: true,
  },
  "risk.started": {
    n: 12, message: "Evaluating risk and contextual signals.", priority: PRIORITY.NOTICE, durationMs: 3000,
    hold: true, maxHoldMs: 20000, visual: { scan: true, tone: "neutral" }, cooldownMs: 3000,
  },
  "risk.low": {
    n: 13, message: "Risk is within the acceptable range.", priority: PRIORITY.INFO, durationMs: 3200,
    visual: { tone: "ok" }, cooldownMs: 6000,
  },
  "risk.elevated": {
    n: 14, message: "Elevated risk detected. Additional checks may be required.", priority: PRIORITY.ALERT, durationMs: 5200,
    visual: { motion: "lean", tone: "warn" }, warning: true, cooldownMs: 6000,
  },
  "risk.high": {
    n: 15, message: "High-risk activity detected.", priority: PRIORITY.CRITICAL, durationMs: 6000,
    visual: { tone: "critical" }, warning: true, cooldownMs: 6000,
  },
  "qkd.running": {
    n: 16, message: "Quantum key distribution simulation in progress.", priority: PRIORITY.NOTICE, durationMs: 3000,
    hold: true, maxHoldMs: 60000, visual: { glow: 1, tone: "neutral" },
  },
  "encrypt.success": {
    n: 17, message: "Data encrypted successfully.", priority: PRIORITY.INFO, durationMs: 3400,
    visual: { motion: "nod", glow: 0.4, tone: "ok" },
  },
  "decrypt.success": {
    n: 18, message: "Decryption and integrity checks completed.", priority: PRIORITY.INFO, durationMs: 3600,
    visual: { tone: "ok" },
  },
  "monitoring.starting": {
    n: 19, message: "Security monitoring is starting.", priority: PRIORITY.NOTICE, durationMs: 3000,
    hold: true, maxHoldMs: 20000, visual: { scan: true, tone: "neutral" },
  },
  "monitoring.active": {
    n: 20, message: "Monitoring is active.", priority: PRIORITY.INFO, durationMs: 3200,
    visual: { scan: true, glow: 0.2, tone: "ok" }, cooldownMs: 10000,
  },
  "intent.drift": {
    n: 21, message: "Your current activity may have drifted from the original intent.", priority: PRIORITY.ALERT, durationMs: 0,
    sticky: true, visual: { tone: "warn" }, warning: true,
  },
  "suspicious.activity": {
    n: 22, message: "Suspicious activity requires review.", priority: PRIORITY.ALERT, durationMs: 0,
    sticky: true, visual: { tone: "warn" }, warning: true,
  },
  "session.revoked": {
    n: 23, message: "Your session has been revoked.", priority: PRIORITY.CRITICAL, durationMs: 0,
    sticky: true, visual: { tone: "critical" }, warning: true,
  },
  "audit.verified": {
    n: 24, message: "Audit integrity verified.", priority: PRIORITY.INFO, durationMs: 3400,
    visual: { glow: 0.3, tone: "ok" }, cooldownMs: 15000,
  },
  "audit.failed": {
    n: 25, message: "Audit integrity verification failed.", priority: PRIORITY.CRITICAL, durationMs: 0,
    sticky: true, visual: { tone: "critical" }, warning: true,
  },
  "policy.updated": {
    n: 26, message: "Security policy updated. Reviewing the new state.", priority: PRIORITY.NOTICE, durationMs: 3800,
    visual: { glow: 0.3, tone: "neutral" },
  },
  "api.unavailable": {
    n: 27, message: "Security status is temporarily unavailable.", priority: PRIORITY.NOTICE + 0.5, durationMs: 0,
    sticky: true, visual: { tone: "warn" }, warning: true, cooldownMs: 15000,
  },
  "idle": {
    n: 28, message: null, priority: PRIORITY.AMBIENT, durationMs: 0,
    visual: { tone: "neutral" }, internal: true,
  },
  // 29 — return from an alert to a normal state. Carries no message of its
  // own; it resolves the sticky warnings named in `detail.clears` (never any
  // other) and lets the avatar ease back to idle.
  "alert.cleared": {
    n: 29, message: null, priority: PRIORITY.AMBIENT, durationMs: 0,
    visual: { tone: "neutral" }, internal: true,
  },
});

/** Sticky ids that a recovery signal may resolve. */
export const STICKY_IDS = Object.freeze(
  Object.entries(REACTIONS).filter(([, r]) => r.sticky).map(([id]) => id)
);

export const SCENARIO_COUNT = Object.keys(REACTIONS).length;

export function getReaction(id) {
  return REACTIONS[id] || null;
}
