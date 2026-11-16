/**
 * Pure planning logic: turns the engine's foreground reaction (+ ambient
 * mode) into a small "plan" for the sprite avatar (which pose, how it moves,
 * halo tint). No DOM here, so it is unit-testable and cannot touch rendering.
 */
import { spriteForReaction, restingSprite, NEUTRAL } from "./qiraSprites";

export const TONE_COLOR = Object.freeze({
  neutral: null,
  ok: "#4ff0c0",
  warn: "#ffb23e",
  critical: "#ff4d5e",
  love: "#ff8fc7", // playful only (petting); never used by a security reaction
});

export const IDLE_PLAN = Object.freeze({
  key: 0, id: "idle", sprite: NEUTRAL, base: NEUTRAL, scan: false, motion: null, glow: 0, tone: "neutral", warning: false,
  fx: Object.freeze([]), ambientMotion: null,
});

/** Overlays that belong to the resting state (not to a transient reaction). */
function ambientFx(ambient, context) {
  const fx = [];
  if (ambient === "off") fx.push("laptopGlow");
  if (ambient === "active" || ambient === "monitoring") fx.push("shield");
  if (context === "quantum") fx.push("helmet", "quantum");
  return fx;
}

/**
 * @param active  engine snapshot.active (or null)
 * @param ambient "idle" | "monitoring"
 */
export function planFor(active, ambient = "idle", context = null) {
  const ambientScan = ambient === "monitoring" || ambient === "active";
  const base = restingSprite(ambient, context);
  const ambientMotion = base === "typing" ? "type" : null;
  const aFx = ambientFx(ambient, context);
  // An unresolved warning owns the foreground: monitoring-OK accessories are not
  // drawn over it (the engine only sets ambient "active" when nothing is wrong).
  if (!active) {
    return { ...IDLE_PLAN, sprite: base, base, scan: ambientScan, glow: ambientScan ? 0.35 : ambient === "off" ? 0.12 : 0, tone: ambientScan ? "ok" : "neutral", fx: aFx, ambientMotion };
  }
  const v = active.visual || {};
  const fx = [...new Set([...(v.fx || []), ...aFx.filter((f) => f === "helmet" || (!active.warning && f !== "laptopGlow"))])];
  return {
    key: active.key,
    id: active.id,
    sprite: spriteForReaction(active.id),
    base,
    scan: !!v.scan || ambientScan,
    motion: v.motion || null,
    glow: v.glow ?? (ambientScan ? 0.15 : 0),
    tone: v.tone || "neutral",
    warning: !!active.warning,
    fx,
    ambientMotion,
  };
}

const easeInOut = (x) => (x < 0.5 ? 2 * x * x : 1 - Math.pow(-2 * x + 2, 2) / 2);
const clamp01 = (x) => Math.min(1, Math.max(0, x));

/**
 * Body motion as a function of seconds since the reaction started.
 * Returns {dy, dx, rot, scale} in "stage units" (see QiraSprite); all zero
 * once finished so the avatar always settles back to rest.
 */
export function bodyMotion(kind, t) {
  const out = { dy: 0, dx: 0, rot: 0, scale: 0 };
  if (!kind || t < 0) return out;
  switch (kind) {
    case "nod": { const d = 0.8; if (t < d) out.dy = 3.2 * Math.sin((Math.PI * t) / d); break; }
    case "shake": { const d = 1.0; if (t < d) out.dx = 5 * Math.sin(2 * Math.PI * 2.4 * t) * (1 - t / d); break; }
    case "tilt": out.rot = 4 * easeInOut(clamp01(t / 0.6)); break;
    case "lean": out.scale = 0.035 * easeInOut(clamp01(t / 0.7)); break;
    case "blink": break; // handled by the avatar's own blink
    // a friendly wing wave: sways side to side for ~1.8 s
    case "wave": { const d = 1.8; if (t < d) { const k = 1 - t / d; out.rot = 5 * Math.sin(2 * Math.PI * 1.6 * t) * k; out.dx = 1.5 * Math.sin(2 * Math.PI * 1.6 * t) * k; } break; }
    // one happy bounce
    case "bounce": { const d = 0.7; if (t < d) out.dy = -7 * Math.abs(Math.sin((Math.PI * t) / d)); break; }
    // celebration: three decaying hops with a small squash
    case "cheer": { const d = 1.5; if (t < d) { const k = 1 - t / d; out.dy = -8 * k * Math.abs(Math.sin((Math.PI * 3 * t) / d)); out.rot = 2.5 * k * Math.sin(2 * Math.PI * 2 * t); } break; }
    // head tilt that STAYS (concerned) - released only when the reaction ends
    case "tiltHold": out.rot = 6 * easeInOut(clamp01(t / 0.5)); break;
    // serious / protective: braces slightly and stays braced
    case "protect": out.scale = 0.03 * easeInOut(clamp01(t / 0.4)); out.dy = 1.2 * easeInOut(clamp01(t / 0.4)); break;
    // password gesture: a quick playful squash-wiggle while the wings come up, then holds a small hunch
    case "cover": {
      const k = easeInOut(clamp01(t / 0.35));
      out.dy = 2 * k; out.scale = -0.015 * k;
      if (t < 0.7) out.rot = 3.5 * Math.sin(2 * Math.PI * 2.4 * t) * (1 - t / 0.7);
      break;
    }
    default: break;
  }
  return out;
}

/** Slow left/right sway used for the "scanning" look: -1..1 over time. */
export function scanSweep(t, periodS = 4.8) {
  return Math.sin((2 * Math.PI * t) / periodS);
}

/** Continuous (ambient) body motion for resting poses, e.g. typing at the laptop while monitoring is OFF. */
export function ambientBodyMotion(kind, t) {
  const out = { dy: 0, dx: 0, rot: 0 };
  if (kind === "type") {
    // fast tiny keystroke bobs + slow head sway, as if reading the screen while typing
    out.dy = 0.7 * Math.abs(Math.sin(t * 9.5)) * (0.6 + 0.4 * Math.sin(t * 1.3));
    out.rot = 1.1 * Math.sin(t * 1.1);
    out.dx = 0.8 * Math.sin(t * 0.7);
  }
  return out;
}
