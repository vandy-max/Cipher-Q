/**
 * QIRA's look: the poses of the supplied QIRA character sheet, cut out as
 * transparent sprites (public/qira/sprites/*.webp, trimmed, 2x). This module
 * only decides WHICH pose a reaction shows - it is pure data, no rendering.
 */
import META from "./spriteMeta.json";
import { EXTENDED_REACTIONS } from "./qiraReactionsExtended";

export const SPRITE_BASE = `${import.meta.env?.BASE_URL ?? "/"}qira/sprites/`;
/** Reference width (in sheet px) the stage is laid out against, see QiraSprite. */
export const SPRITE_REF = 200;

export const SPRITE_KEYS = Object.freeze(Object.keys(META));
export const spriteMeta = (key) => META[key] || META.login;
export const spriteUrl = (key) => `${SPRITE_BASE}${(META[key] || META.login).file}`;

export const NEUTRAL = "login";

/** Reaction id -> pose. Every one of the 29 scenarios (+ internal ones) is covered (see test). */
export const REACTION_SPRITE = Object.freeze({
  "login.page": "login",
  "login.success": "loginSuccess",
  "login.failed": "loginFailed",
  "face.requested": "explaining",
  "face.success": "success",
  "face.failed": "loginFailed",
  "intent.entered": "thinking",
  "intent.match": "happy",
  "intent.mismatch": "loginFailed",
  "rbac.pass": "happy",
  "rbac.denied": "loginFailed",
  "risk.started": "processing",
  "risk.low": "happy",
  "risk.elevated": "surprised",
  "risk.high": "riskAlert",
  "qkd.running": "processing",
  "encrypt.success": "validation",
  "decrypt.success": "validation",
  "monitoring.starting": "processing",
  "monitoring.active": "typing",
  "intent.drift": "surprised",
  "suspicious.activity": "riskAlert",
  "session.revoked": "riskAlert",
  "audit.verified": "validation",
  "audit.failed": "riskAlert",
  "policy.updated": "explaining",
  "api.unavailable": "thinking",
  "idle": "login",
  "alert.cleared": "login",
});

export const spriteForReaction = (id) => REACTION_SPRITE[id] || EXTENDED_REACTIONS[id]?.sprite || NEUTRAL;

/**
 * Resting pose when no reaction is showing. Mirrors the monitoring UI state
 * ("off" = QIRA works on its laptop) and the page context ("quantum" = engineer).
 */
export function restingSprite(ambient, context) {
  if (context === "quantum") return "typing";
  if (ambient === "off") return "typing";
  return NEUTRAL;
}

/** Cosmetic (social-layer) poses. Eyes-shut = the sheet's calm "Processing" pose. */
export const SOCIAL_SPRITE = Object.freeze({
  cover: "processing",   // password field: QIRA closes its eyes
  asleep: "processing",
  petted: "happy",
  flustered: "surprised",
  wave: "explaining",
  wink: "wink",
  blink: "processing",
});
