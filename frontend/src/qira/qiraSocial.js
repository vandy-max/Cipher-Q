/**
 * QIRA "social" layer: purely cosmetic playfulness (eye/head following, being
 * petted, idle fidgets, dozing off, politely looking away at password fields).
 *
 * Hard rules (tested in qiraSocial.test.js):
 *  - It NEVER emits or clears a reaction and never touches the engine, auth,
 *    monitoring, risk or any API. It only produces numbers for the rig.
 *  - It is fully suppressed (weight -> 0, pokes ignored) whenever a real QIRA
 *    reaction is showing or a security warning is unresolved, so a playful
 *    animation can never hide or compete with a security message.
 *  - Reduced motion => inert.
 *
 * Framework-free and deterministic: time advances only through `tick(dt)`,
 * randomness is injected, so it is unit-testable without a browser.
 */

const DEG = Math.PI / 180;
const clamp = (v, a, b) => Math.min(b, Math.max(a, v));
const damp = (cur, target, rate, dt) => cur + (target - cur) * (1 - Math.exp(-rate * dt));

export const SOCIAL = Object.freeze({
  sleepAfterS: 75,        // no activity at all -> doze off
  pointerFreshS: 6,       // pointer counts as "looking at me" this long after it last moved
  typingFreshS: 2.5,
  comboWindowS: 3.5,
  ticklishAt: 5,          // pokes inside the window before QIRA gets flustered
  ticklishCooldownS: 3,
  happyHoldS: 1.35,
  microEveryS: [6, 12],
});

export function createSocial({ rand = Math.random, reducedMotion = false } = {}) {
  let t = 0;
  let allowed = false;
  let lastActivity = 0;
  let pointerAt = -Infinity;
  let typingAt = -Infinity;
  let target = { x: 0, y: 0 };      // where the pointer / focused field is, normalised -1..1 (screen space)
  let focusTarget = null;
  let cover = false;
  let waveUntil = -Infinity;
  let hover = false;
  let pokes = [];
  let happyUntil = -Infinity;
  let surpriseAt = -Infinity;
  let surpriseUntil = -Infinity;
  let cooldownUntil = -Infinity;
  let hopAt = -Infinity;
  let micro = null;                 // { kind, start, dur, x, y }
  let nextMicroAt = 4 + rand() * 4;
  let sleeping = false;
  let wakeAt = -Infinity;

  const cur = { weight: 0, gx: 0, gy: 0, perk: 0, sleepy: 0, love: 0, surprised: 0, tilt: 0, lean: 0 };
  const listeners = new Set();
  const emit = (type, data) => listeners.forEach((fn) => { try { fn(type, data); } catch { /* cosmetic */ } });

  const markActive = () => {
    lastActivity = t;
    if (sleeping) {
      sleeping = false;
      wakeAt = t;
      hopAt = t;
      waveUntil = t + 0.95;
      emit("sleep", false);
    }
  };

  const api = {
    /** Parent says whether playfulness is currently allowed (no reaction showing, no warning). */
    setAllowed(v) { allowed = !!v; },

    pointerMove(x, y) {
      if (reducedMotion) return;
      target = { x: clamp(x, -1, 1), y: clamp(y, -1, 1) };
      pointerAt = t;
      markActive();
    },
    /** The pointer left the application window: stop following it. */
    pointerLeave() { pointerAt = -Infinity; },
    /** Any other user activity (key, click, focus, tab return) just keeps QIRA awake. */
    activity() { if (!reducedMotion) markActive(); },
    setHover(v) { hover = !!v; if (v) markActive(); },
    /** Password-like field focused: QIRA politely covers its eyes (both wings). */
    setCover(v) { cover = !!v; if (v) markActive(); },
    /** A text field is focused/being typed in: QIRA reads along (x,y normalised toward the field). */
    typingAt(x, y) {
      if (reducedMotion) return;
      focusTarget = { x: clamp(x, -1, 1), y: clamp(y, -1, 1) };
      typingAt = t;
      markActive();
    },
    clearFocusTarget() { focusTarget = null; },
    /** Returning to the tab: a little hello. */
    greet() { if (reducedMotion || !allowed) return; markActive(); hopAt = t; waveUntil = t + 0.95; },

    /**
     * Pet QIRA. Returns {accepted, combo, hearts, ticklish}. Ignored (accepted:false)
     * while a real reaction/warning is showing, when reduced motion is on, or while
     * ticklish-cooling-down — so it cannot spam or cover anything important.
     */
    poke() {
      if (reducedMotion || !allowed || cover || t < cooldownUntil) {
        return { accepted: false, combo: 0, hearts: 0, ticklish: false };
      }
      markActive();
      pokes = pokes.filter((p) => t - p <= SOCIAL.comboWindowS);
      pokes.push(t);
      const combo = pokes.length;
      hopAt = t;
      if (combo >= SOCIAL.ticklishAt) {
        pokes = [];
        surpriseAt = t;
        surpriseUntil = t + 1.1;
        cooldownUntil = t + SOCIAL.ticklishCooldownS;
        happyUntil = -Infinity;
        return { accepted: true, combo, hearts: 0, ticklish: true };
      }
      happyUntil = t + SOCIAL.happyHoldS;
      return { accepted: true, combo, hearts: clamp(combo + 1, 2, 5), ticklish: false };
    },

    /** Advance by dt seconds; returns the per-frame social state for the rig. */
    tick(dtRaw) {
      const dt = clamp(dtRaw, 0, 0.1);
      t += dt;
      const on = allowed && !reducedMotion;
      cur.weight = damp(cur.weight, on ? 1 : 0, on ? 6 : 14, dt);
      if (!on) {
        // leaving social mode: drop every transient so nothing lingers under a real reaction
        micro = null;
        pokes = [];
        happyUntil = surpriseUntil = -Infinity;
      }

      // fall asleep after a long stretch of nothing
      if (on && !sleeping && t - lastActivity > SOCIAL.sleepAfterS) {
        sleeping = true;
        emit("sleep", true);
      }
      if (!on && sleeping) { sleeping = false; emit("sleep", false); }

      // idle fidgets (only when nobody is interacting)
      const pointerFresh = t - pointerAt < SOCIAL.pointerFreshS;
      const typingFresh = t - typingAt < SOCIAL.typingFreshS;
      if (on && !sleeping && !cover && !pointerFresh && !typingFresh && !micro && t >= nextMicroAt) {
        const r = rand();
        if (r < 0.4) micro = { kind: "glance", start: t, dur: 1.3, x: rand() < 0.5 ? -0.9 : 0.9, y: (rand() - 0.5) * 0.8 };
        else if (r < 0.65) micro = { kind: "curious", start: t, dur: 1.9, x: 0, y: 0 };
        else if (r < 0.82) micro = { kind: "wink", start: t, dur: 0.8, x: 0, y: 0 };
        else { micro = { kind: "hop", start: t, dur: 0.6, x: 0, y: 0 }; hopAt = t; }
        nextMicroAt = t + SOCIAL.microEveryS[0] + rand() * (SOCIAL.microEveryS[1] - SOCIAL.microEveryS[0]);
      }
      if (micro && t - micro.start > micro.dur) micro = null;

      // gaze target: typing target > fresh pointer > micro glance > rest
      let gx = 0, gy = 0, gazeActive = false;
      if (typingFresh && focusTarget) { gx = focusTarget.x; gy = focusTarget.y; gazeActive = true; }
      else if (pointerFresh) { gx = target.x; gy = target.y; gazeActive = true; }
      else if (micro?.kind === "glance") { gx = micro.x; gy = micro.y; gazeActive = true; }
      if (sleeping || cover) { gx = 0; gy = 0; gazeActive = false; }
      cur.gx = damp(cur.gx, gx, 7, dt);
      cur.gy = damp(cur.gy, gy, 7, dt);

      const justWoke = t - wakeAt < 0.9;
      const perkTarget = on && !sleeping && (hover || justWoke || t < happyUntil) ? 1 : 0;
      cur.perk = damp(cur.perk, perkTarget, 8, dt);
      cur.sleepy = damp(cur.sleepy, sleeping ? 1 : 0, sleeping ? 1.6 : 5, dt);
      const loveTarget = on && (t < happyUntil || (hover && !sleeping)) ? (t < happyUntil ? 1 : 0.35) : 0;
      cur.love = damp(cur.love, loveTarget, 6, dt);
      cur.surprised = damp(cur.surprised, on && t < surpriseUntil ? 1 : 0, 12, dt);
      const tiltTarget = micro?.kind === "curious" ? Math.sin(Math.PI * clamp((t - micro.start) / micro.dur, 0, 1)) : 0;
      cur.tilt = damp(cur.tilt, tiltTarget + (hover ? 0.4 : 0), 6, dt);

      const hopT = t - hopAt;
      const hop = on && hopT >= 0 && hopT < 0.45 ? Math.sin((Math.PI * hopT) / 0.45) : 0;

      return {
        weight: cur.weight,
        gazeActive: gazeActive && cur.weight > 0.3,
        gx: cur.gx, gy: cur.gy,
        perk: cur.perk,
        love: cur.love,
        sleepy: cur.sleepy,
        surprised: cur.surprised,
        shakeT: t - surpriseAt,            // seconds since the flustered shake started
        tilt: cur.tilt * 9 * DEG,
        hop,
        cover: on && cover,
        wave: on && !cover && t < waveUntil,
        wink: on && !cover && micro?.kind === "wink",
        happy: on && t < happyUntil,
      };
    },

    isSleeping: () => sleeping,
    on(fn) { listeners.add(fn); return () => listeners.delete(fn); },
    dispose() { listeners.clear(); },
  };

  return api;
}
