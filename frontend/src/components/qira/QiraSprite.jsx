import { useEffect, useRef, useState } from "react";
import { NEUTRAL, SOCIAL_SPRITE, SPRITE_KEYS, SPRITE_REF, spriteMeta, spriteUrl } from "../../qira/qiraSprites";
import { TONE_COLOR, ambientBodyMotion, bodyMotion, scanSweep } from "../../qira/qiraAnimator";
import { CoverWings, Helmet, LaptopGlow, QuantumCircuit, ScanRing, ShieldBadge, Sparkles } from "./QiraOverlays";
import "./QiraOverlays.css";

const FPS = 30;
const INTRO_EYES_CLOSED_S = 0.55; // QIRA "opens its eyes" when it first appears
const hexToRgb = (hex) => {
  const n = parseInt(hex.slice(1), 16);
  return [(n >> 16) & 255, (n >> 8) & 255, n & 255];
};

/** Poses a social animation may replace. A laptop/engineer base keeps its pose except for sleep/pet/startle. */
const SOCIAL_ON_ANY_BASE = new Set(["cover", "asleep", "flustered", "petted"]);

/**
 * QIRA, drawn from the supplied character-sheet poses.
 *
 * Presentation only. Which pose shows is decided by (1) the foreground QIRA
 * reaction (priority), else (2) the cosmetic social layer (petting, dozing...),
 * else (3) the resting pose for the current monitoring/page state (laptop when
 * monitoring is OFF or in the Quantum Lab, otherwise neutral) with breathing + blink.
 * Accessories (cover wings, helmet, shield, warning, quantum circuit...) are vector
 * overlays toggled through `data-fx` on the root, so they never cause React renders.
 * All per-frame motion is written straight to the DOM, and any failure here degrades
 * to the static portrait via `onError`.
 */
export default function QiraSprite({ planRef, socialRef, reducedMotion = false, onReady, onError }) {
  const rootRef = useRef(null);
  const puppetRef = useRef(null);
  const imgs = useRef({});
  const [loaded, setLoaded] = useState(false);

  useEffect(() => {
    const root = rootRef.current;
    const puppet = puppetRef.current;
    if (!root || !puppet) return undefined;

    const st = {
      t: 0, last: performance.now(), key: null, planKey: -1, reactionStart: 0,
      nextBlinkAt: 2.5 + Math.random() * 3, blinkUntil: -1, filter: "", fx: "", tone: "", introUntil: INTRO_EYES_CLOSED_S,
    };

    const show = (key) => {
      if (st.key === key) return;
      st.key = key;
      for (const [k, el] of Object.entries(imgs.current)) if (el) el.style.opacity = k === key ? "1" : "0";
      root.dataset.sprite = key;
    };
    show(NEUTRAL);

    const tick = () => {
      if (document.hidden) { st.last = performance.now(); return; }
      const now = performance.now();
      const dt = Math.min(0.1, Math.max(0, (now - st.last) / 1000));
      st.last = now;
      st.t += dt;

      const plan = planRef.current;
      const reactionOn = !!plan && plan.id !== "idle" && plan.id !== "alert.cleared";
      const base = (plan && plan.base) || NEUTRAL;
      if (plan && plan.key !== st.planKey) { st.planKey = plan.key; st.reactionStart = st.t; }

      let S = null;
      try { S = !reducedMotion && socialRef?.current ? socialRef.current.tick(dt) : null; } catch { S = null; }
      const w = S ? S.weight : 0;
      const social = !reactionOn && S && w > 0.3;

      // ---- which pose ---------------------------------------------------------
      let key = base;
      if (reactionOn) key = plan.sprite || NEUTRAL;
      else if (social) {
        let pick = null;
        if (S.cover) pick = "cover";
        else if (S.sleepy > 0.5) pick = "asleep";
        else if (S.surprised > 0.3) pick = "flustered";
        else if (S.happy) pick = "petted";
        else if (S.wave) pick = "wave";
        else if (S.wink) pick = "wink";
        if (pick && (base === NEUTRAL || SOCIAL_ON_ANY_BASE.has(pick))) key = SOCIAL_SPRITE[pick];
      }
      // Eyes open on arrival, then an occasional natural blink (neutral pose only)
      if (key === NEUTRAL && !reducedMotion) {
        if (st.t < st.introUntil) key = SOCIAL_SPRITE.blink;
        else {
          if (st.t >= st.nextBlinkAt) { st.blinkUntil = st.t + 0.12; st.nextBlinkAt = st.t + 3 + Math.random() * 3.5; }
          if (st.t < st.blinkUntil) key = SOCIAL_SPRITE.blink;
        }
      }
      show(key);

      // ---- accessories (data attributes only) ------------------------------------
      const fxList = plan && plan.fx ? plan.fx : [];
      let fx = fxList.join(" ");
      if (!reactionOn && S && S.cover) fx += " cover"; // legacy social cover still shows the wings
      if (fx !== st.fx) { st.fx = fx; root.dataset.fx = fx; }
      const tone = reactionOn ? plan.tone : "neutral";
      if (tone !== st.tone) { st.tone = tone; root.dataset.tone = tone; }

      if (reducedMotion) { puppet.style.transform = ""; puppet.style.filter = ""; return; }

      // ---- motion (stage units scale with the stage width) ---------------------
      const u = (root.clientWidth || 168) / 168;
      const sleepy = S ? S.sleepy : 0;
      const breathe = Math.sin((st.t * 2 * Math.PI) / (3.6 + 2 * sleepy));
      let x = 0, y = 0, rot = 0, sx = 1 - 0.006 * breathe, sy = 1 + 0.012 * breathe * (1 - 0.4 * sleepy);

      if (reactionOn) {
        const m = bodyMotion(plan.motion, st.t - st.reactionStart);
        x += m.dx; y += m.dy; rot += m.rot; sx += m.scale; sy += m.scale;
        if (plan.scan) { const s = scanSweep(st.t); x += s * 3; rot += s * 1.2; }
        if (plan.tone === "critical") sy += 0.01 * Math.sin(st.t * 7); // urgent but gentle pulse
        if (plan.motion === "type" || plan.ambientMotion === "type") {
          const a = ambientBodyMotion("type", st.t); x += a.dx; y += a.dy; rot += a.rot;
        }
      } else {
        if (plan && plan.ambientMotion) {
          const a = ambientBodyMotion(plan.ambientMotion, st.t); x += a.dx; y += a.dy; rot += a.rot;
        }
        if (S) {
          x += S.gx * 5 * w; y += S.gy * 2.5 * w;                 // lean toward the cursor / field
          rot += S.gx * 3 * w + (S.tilt * 180 / Math.PI) * 0.7 * w; // head-turn illusion + curious tilt
          y -= 3 * S.perk * w; sy += 0.02 * S.perk * w;
          y -= S.hop * 11 * w; sy -= 0.05 * S.hop * w;              // hop (squash a little at the top)
          y += 3.5 * sleepy; rot += 3.5 * sleepy;                    // droopy when dozing
          if (S.surprised > 0.01 && S.shakeT >= 0 && S.shakeT < 1.1) {
            x += 4.5 * Math.sin(2 * Math.PI * 3 * S.shakeT) * (1 - S.shakeT / 1.1) * S.surprised;
          }
        }
      }
      puppet.style.transform = `translate(${(x * u).toFixed(2)}px, ${(y * u).toFixed(2)}px) rotate(${rot.toFixed(2)}deg) scale(${sx.toFixed(4)}, ${sy.toFixed(4)})`;

      // ---- halo (tone + glow); playful pink blush only when nothing important shows ----
      let color = reactionOn ? TONE_COLOR[plan.tone] : null;
      let amt = reactionOn ? (plan.tone === "neutral" ? plan.glow * 0.5 : 0.55 + 0.45 * (plan.glow || 0)) : 0;
      if (!reactionOn && plan && plan.tone === "ok" && plan.glow > 0) { color = TONE_COLOR.ok; amt = plan.glow; } // monitoring ACTIVE: cyan-green protective glow
      if (!reactionOn && social && S.love > 0.05) { color = TONE_COLOR.love; amt = 0.6 * S.love; }
      const filter = color && amt > 0.02
        ? `drop-shadow(0 0 ${(5 + 9 * amt).toFixed(1)}px rgba(${hexToRgb(color).join(",")},${Math.min(0.9, 0.35 + 0.5 * amt).toFixed(2)}))`
        : "";
      if (filter !== st.filter) { st.filter = filter; puppet.style.filter = filter; }
    };

    const id = window.setInterval(() => { try { tick(); } catch (e) { window.clearInterval(id); onError?.(e); } }, reducedMotion ? 200 : 1000 / FPS);
    return () => window.clearInterval(id);
  }, [planRef, socialRef, reducedMotion, onError]);

  return (
    <div ref={rootRef} className="absolute inset-0" aria-hidden="true" data-testid="qira-sprite-root" data-sprite={NEUTRAL} data-fx="" data-tone="neutral">
      {/* soft ground shadow */}
      <div className="absolute inset-x-[20%] bottom-[1.5%] h-[8%] rounded-[50%] bg-black/45 blur-[6px]" />
      <div ref={puppetRef} className="absolute inset-0" style={{ transformOrigin: "50% 90%", willChange: "transform" }}>
        {(loaded ? SPRITE_KEYS : [NEUTRAL]).map((k) => {
          const m = spriteMeta(k);
          return (
            <div
              key={k}
              ref={(el) => {
                imgs.current[k] = el;
                if (el) el.style.opacity = (rootRef.current?.dataset.sprite || NEUTRAL) === k ? "1" : "0";
              }}
              style={{
                position: "absolute",
                left: "50%",
                top: "5%",
                width: `${(m.w / 2 / SPRITE_REF) * 100}%`,
                aspectRatio: `${m.w} / ${m.h}`,
                marginLeft: `${(-(m.ax / 2) / SPRITE_REF) * 100}%`,
                opacity: k === NEUTRAL ? 1 : 0,
                transition: "opacity 110ms ease-out",
                pointerEvents: "none",
                userSelect: "none",
              }}
            >
              <img
                src={spriteUrl(k)}
                alt=""
                draggable={false}
                decoding="async"
                data-sprite-img={k}
                onLoad={k === NEUTRAL ? () => { setLoaded(true); onReady?.(); } : undefined}
                onError={k === NEUTRAL ? () => onError?.(new Error("QIRA sprite failed to load")) : undefined}
                style={{ display: "block", width: "100%", height: "100%" }}
              />
              {/* pose-specific accessories live inside their pose's frame so they stay registered to the artwork */}
              {k === "processing" && <CoverWings />}
              {k === "typing" && (<><LaptopGlow /><Helmet /></>)}
            </div>
          );
        })}
        {/* stage-level accessories (follow the body, not a specific pose) */}
        <div className="qira-stage-fx" style={{ position: "absolute", inset: 0, pointerEvents: "none" }}>
          <ShieldBadge />
          <QuantumCircuit />
          <Sparkles />
          <ScanRing />
        </div>
      </div>
    </div>
  );
}
