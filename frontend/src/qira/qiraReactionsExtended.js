/**
 * QIRA extended reaction catalogue (QIRA 3.x refinement).
 *
 * The original 29 scenarios in `qiraReactions.js` are untouched. This file adds the
 * page / workflow / monitoring-state reactions, each triggered by a REAL event
 * (field focus, a validation result, an API outcome, the monitoring UI state).
 *
 * Rules (same as the core catalogue)
 *  - PRESENTATION only: a reaction can never grant, deny or change access.
 *  - Messages are fixed strings. They never contain passwords, tokens, biometric
 *    data, keys, hashes or backend/exception text.
 *  - `sprite` picks one of the 14 character-sheet poses (see qiraSprites.js);
 *    `visual.fx` adds lightweight overlays (cover wings, shield, scan ring, ...).
 *
 * Priority (higher preempts lower; an unresolved sticky warning is never hidden by
 * anything below its own priority):
 *   5    CRITICAL   high-risk monitoring, revoked session, audit failure
 *   4.6  AUTH       authentication / biometric results, password-hiding gesture
 *   4.4  OPERATION  active operation processing + results (encrypt / decrypt / ...)
 *   4    MONITOR    monitoring status changes (OFF / ACTIVE / WARNING)
 *   3.5  WORKFLOW   quantum + intent workflow events, validation hints
 *   2.5  USER       user interactions (focus, click, page acknowledgement)
 *   2    WELCOME    greetings
 *   1    IDLE       idle personality
 */

export const EXT_PRIORITY = Object.freeze({
  IDLE: 1,
  WELCOME: 2,
  USER: 2.5,
  WORKFLOW: 3.5,
  MONITOR: 4,
  OPERATION: 4.4,
  AUTH: 4.6,
  CRITICAL: 5,
});

const P = EXT_PRIORITY;
let n = 100;
const def = (sprite, message, priority, durationMs, visual = {}, extra = {}) => ({
  n: ++n,
  sprite,
  message,
  priority,
  durationMs,
  visual: { tone: "neutral", ...visual },
  ...extra,
});
const hold = (sprite, message, priority, visual, maxHoldMs = 45000) =>
  def(sprite, message, priority, 3000, visual, { hold: true, maxHoldMs });

export const EXTENDED_REACTIONS = Object.freeze({
  // ---- navigation / generic ---------------------------------------------------
  "nav.page": def("login", null, P.USER, 1400, { motion: "tilt" }),
  "page.encrypt": def("login", null, P.USER, 2200, { motion: "lean" }), // attentive
  "page.decrypt": def("thinking", null, P.USER, 2400), // thinking
  "page.intent": def("login", "Let's create a clear business intent!", P.WORKFLOW, 3800, { motion: "tilt" }), // curious
  "page.quantum": def("typing", "Welcome to the Quantum Lab!", P.WORKFLOW, 3800, { motion: "type", glow: 0.4, fx: ["quantum"] }),

  // ---- landing ----------------------------------------------------------------
  "landing.welcome": def("explaining", "Welcome to CipherQ! I'm QIRA, your security companion!", P.WELCOME, 6500, { motion: "wave", glow: 0.25, tone: "ok" }),
  "landing.return": def("explaining", "Welcome back to CipherQ!", P.WELCOME, 3800, { motion: "wave" }),
  "landing.start": def("success", "Let's go!", P.USER, 1800, { motion: "bounce" }),

  // ---- login / registration ---------------------------------------------------
  "login.welcome": def("explaining", "Welcome back!", P.WELCOME, 3400, { motion: "wave" }),
  "register.page": def("success", "Yay! A new member!", P.USER, 3400, { motion: "cheer", fx: ["sparkles"] }), // excited
  "field.username.login": def("login", "Let's get you signed in.", P.USER, 2800, { motion: "lean" }),
  "field.username.register": def("login", "What should I call you?", P.USER, 2800, { motion: "tilt" }), // curious
  "field.email": def("login", "Let's add your email.", P.USER, 2800, { motion: "lean" }), // attentive
  // Password focus uses the existing closed-eye sprite only. No wing/cover artwork is shown.
  "password.hide.login": hold("processing", "I won't peek!", P.AUTH + 0.1, {}, 600000),
  "password.hide.register": hold("processing", "I won't peek! Your secret is safe.", P.AUTH + 0.1, {}, 600000),
  "register.invalidEmail": def("surprised", "Hmm, that email doesn't look right.", P.WORKFLOW, 4000, { motion: "tilt" }), // confused
  "register.weakPassword": def("thinking", "Let's make that password stronger.", P.WORKFLOW, 4000),
  "field.missing": def("login", "Hey! One little detail is missing.", P.WORKFLOW, 3800, { motion: "tilt" }), // curious
  "login.missingUsername": def("login", "I think your username is missing.", P.WORKFLOW, 3800, { motion: "tilt" }),
  "login.missingPassword": def("login", "Don't forget your password!", P.WORKFLOW, 3800, { motion: "tilt" }),
  "login.processing": hold("alert", "Checking your credentials...", P.OPERATION, { tone: "neutral", glow: 0.25 }, 30000),
  "register.processing": hold("alert", "Setting up your account...", P.OPERATION, { glow: 0.25 }, 30000),
  "login.credentialsOk": def("loginSuccess", "Credentials accepted! One more step: a quick face check.", P.AUTH, 4200, { motion: "nod", glow: 0.4, tone: "ok" }),
  "login.complete": def("loginSuccess", "You're in! Welcome back!", P.AUTH, 3800, { motion: "nod", glow: 0.55, tone: "ok" }),
  "login.invalid": def("loginFailed", "Authentication failed. Please check your details.", P.AUTH, 4800, { motion: "shake", tone: "warn" }),
  "login.repeated": def("loginFailed", "Let's double-check your details.", P.AUTH, 4800, { motion: "shake", tone: "warn" }),
  "register.success": def("success", "You're officially part of CipherQ!", P.AUTH, 4800, { motion: "cheer", glow: 0.7, tone: "ok", fx: ["sparkles"] }),
  "register.failed": def("loginFailed", "That didn't work. Let's try again.", P.AUTH, 4800, { motion: "shake", tone: "warn" }),
  "net.error": def("surprised", "I'm having trouble connecting. Please try again.", P.AUTH, 4800, { motion: "tilt", tone: "warn" }),

  // ---- face (enrolment = new user, verify = returning user) -------------------
  "face.enroll.open": def("login", null, P.USER, 2600, { motion: "tilt" }), // curious
  "face.camera.request": def("login", null, P.USER, 2200, { motion: "lean" }), // looking at the camera
  "face.camera.ready.enroll": def("login", null, P.USER, 2200, { motion: "lean", glow: 0.2 }), // attentive
  "face.camera.ready.verify": def("login", "Ready for your identity check?", P.USER, 3200, { motion: "lean", glow: 0.2 }),
  "face.detected.enroll": def("loginSuccess", "There you are!", P.USER, 2600, { motion: "nod" }),
  "face.detected.verify": def("loginSuccess", "I can see you!", P.USER, 2600, { motion: "nod" }),
  "face.analyzing.enroll": hold("alert", "I'm analyzing your face for registration.", P.AUTH, { scan: true, glow: 0.5, fx: ["scan"] }, 60000),
  "face.analyzing.verify": hold("alert", "Your face is being analyzed. Please hold still.", P.AUTH, { scan: true, glow: 0.5, fx: ["scan"] }, 60000),
  "face.enroll.success": def("loginSuccess", "Face enrolled! You're all set.", P.AUTH, 3800, { motion: "cheer", glow: 0.6, tone: "ok" }),
  "face.enroll.failed": def("loginFailed", "Enrollment didn't go through. Let's try again.", P.AUTH, 5000, { motion: "shake", tone: "warn" }),
  "face.verified": def("loginSuccess", "Identity verified! Welcome back!", P.AUTH, 3800, { motion: "nod", glow: 0.6, tone: "ok" }),
  "face.mismatch": def("loginFailed", "Hmm, I couldn't verify your identity. Let's try again.", P.AUTH, 5200, { motion: "shake", tone: "warn" }),
  "face.notdetected": def("surprised", "Come a little closer to the camera.", P.AUTH, 4600, { motion: "lean", tone: "warn" }),
  "face.camera.error": def("surprised", "I can't access the camera. Please check its permission.", P.AUTH, 5600, { motion: "tilt", tone: "warn" }),

  // ---- live monitoring (mirrors the monitoring UI state; see QiraEventBridge) --
  "monitoring.off": def("typing", "Monitoring is currently OFF. I'm keeping busy here. Let's turn it on to secure your session!", P.MONITOR, 7500, { motion: "type" }),
  "monitoring.on": def("login", "Monitoring is active! Don't worry, I'm keeping an eye on your session.", P.MONITOR, 5200, { scan: true, glow: 0.6, tone: "ok", fx: ["shield"] }),
  "monitoring.warning": def("loginFailed", "Hey! Something unusual needs our attention. Please review the monitoring panel.", P.MONITOR, 0,
    { motion: "tiltHold", tone: "warn", glow: 0.4, fx: ["warn"] }, { sticky: true, warning: true }),
  "monitoring.highrisk": def("riskAlert", "High-risk activity detected! Please review immediately.", P.CRITICAL, 0,
    { motion: "protect", tone: "critical", glow: 0.6, fx: ["warn", "protect"] }, { sticky: true, warning: true }),
  "monitoring.reauth": def("loginFailed", "Re-authentication is required to continue.", P.MONITOR, 0,
    { motion: "tiltHold", tone: "warn", fx: ["warn"] }, { sticky: true, warning: true }),

  // ---- quantum lab (engineering mode) -----------------------------------------
  "quantum.connecting": hold("typing", "Connecting the quantum nodes...", P.WORKFLOW, { motion: "type", glow: 0.6, fx: ["quantum"] }, 60000),
  "quantum.ready": def("typing", "Your quantum session is ready!", P.WORKFLOW, 4200, { motion: "cheer", glow: 0.7, tone: "ok", fx: ["quantum"] }),
  "quantum.failed": def("loginFailed", "Oops! The quantum connection needs another try.", P.WORKFLOW, 5200, { motion: "shake", tone: "warn" }),

  // ---- encryption / decryption ------------------------------------------------
  "op.file.select": def("login", null, P.USER, 1800, { motion: "tilt" }), // curious
  "op.record.select": def("login", null, P.USER, 1800, { motion: "lean" }), // attentive
  "encrypt.processing": hold("alert", "Securing your file...", P.OPERATION, { glow: 0.5, fx: ["shield"] }, 60000),
  "encrypt.done": def("happy", "Your file is securely encrypted! Nice work!", P.OPERATION, 4200, { motion: "cheer", glow: 0.6, tone: "ok", fx: ["sparkles"] }),
  "encrypt.failed": def("loginFailed", "Something went wrong while securing the file. Let's check it.", P.OPERATION, 5200, { motion: "shake", tone: "warn" }),
  "decrypt.processing": hold("alert", "Decrypting your file...", P.OPERATION, { glow: 0.4 }, 60000),
  "decrypt.verify": hold("validation", "Verifying integrity...", P.OPERATION, { scan: true, glow: 0.5, fx: ["scan"] }, 60000),
  "decrypt.done": def("happy", "Decryption complete! Your file is ready.", P.OPERATION, 4200, { motion: "cheer", glow: 0.6, tone: "ok", fx: ["sparkles"] }),
  "decrypt.failed": def("loginFailed", "I couldn't complete that operation. Let's check the file and try again.", P.OPERATION, 5200, { motion: "shake", tone: "warn" }),
  "decrypt.integrityFailed": def("riskAlert", "The integrity check didn't pass, so the file stays locked.", P.OPERATION, 6000, { motion: "protect", tone: "critical", fx: ["warn"] }, { warning: true }),
  "auth.unauthorized": def("riskAlert", "This action isn't authorized. Please review your permissions.", P.OPERATION, 5600, { motion: "protect", tone: "critical", fx: ["warn"] }, { warning: true }),

  // ---- intent / authorization -------------------------------------------------
  "intent.start": def("thinking", null, P.WORKFLOW, 2400),
  "intent.justification": def("login", null, P.WORKFLOW, 2200, { motion: "lean" }), // attentive
  "intent.processing": hold("alert", "Checking your authorization...", P.OPERATION, { glow: 0.3 }, 30000),
  "intent.pending": def("thinking", "Your request is waiting for approval.", P.WORKFLOW, 4600),
  "intent.approved": def("success", "Great! Your request has been approved.", P.OPERATION, 4800, { motion: "cheer", glow: 0.7, tone: "ok", fx: ["sparkles"] }),
  "intent.recorded": def("happy", "Your decision has been recorded.", P.OPERATION, 3600, { motion: "nod", tone: "ok" }),
  "intent.rejected": def("loginFailed", "This request was rejected. You can review it and try again.", P.OPERATION, 5200, { motion: "shake", tone: "warn" }),
  "op.failed": def("loginFailed", "I couldn't complete that. Please review the details and try again.", P.OPERATION, 5200, { motion: "shake", tone: "warn" }),
});

/** Ids of every sticky monitoring-state reaction (cleared together on a real state change). */
export const MONITORING_STICKY_IDS = Object.freeze(["monitoring.warning", "monitoring.highrisk", "monitoring.reauth"]);
