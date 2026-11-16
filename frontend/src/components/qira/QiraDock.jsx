import { Component, useCallback, useEffect, useRef, useState } from "react";
import { AnimatePresence, motion } from "framer-motion";
import { ChevronDown, ChevronUp, Heart, ShieldAlert, Volume2, VolumeX, X } from "lucide-react";
import { useQiraReactions } from "../../context/QiraReactionContext";
import { planFor, IDLE_PLAN } from "../../qira/qiraAnimator";
import { createSocial } from "../../qira/qiraSocial";
import QiraPortrait from "./QiraPortrait";
import QiraSprite from "./QiraSprite";

const MIN_KEY = "ibqc_qira_minimized";
const QUIET_KEY = "ibqc_qira_quiet";

// Occasional, short click lines (never security related; shown at most every 9 s).
const CLICK_LINES = ["Hi there!", "Need a hand?", "I'm all feathers and ears!", "Psst... I'm watching your back."];

function readFlag(key) {
  try { return localStorage.getItem(key) === "1"; } catch { return false; }
}
function writeFlag(key, on) {
  try { localStorage.setItem(key, on ? "1" : "0"); } catch { /* storage may be blocked */ }
}

function usePrefersReducedMotion() {
  const [reduced, setReduced] = useState(() => !!window.matchMedia?.("(prefers-reduced-motion: reduce)")?.matches);
  useEffect(() => {
    const mq = window.matchMedia?.("(prefers-reduced-motion: reduce)");
    if (!mq) return undefined;
    const on = () => setReduced(mq.matches);
    mq.addEventListener?.("change", on);
    return () => mq.removeEventListener?.("change", on);
  }, []);
  return reduced;
}

/** Any render/load error inside the avatar degrades to the fallback; it never reaches the app. */
class CanvasBoundary extends Component {
  state = { failed: false };
  static getDerivedStateFromError() { return { failed: true }; }
  componentDidCatch(err) {
    console.warn("[QIRA] avatar unavailable, using fallback:", err?.message || err);
    this.props.onError?.(err);
  }
  render() { return this.state.failed ? null : this.props.children; }
}

const BUBBLE_TONE = {
  neutral: "border-white/10",
  ok: "border-emerald-300/30",
  warn: "border-amber-400/50",
  critical: "border-rose-400/60",
};

function Bubble({ active, visible, onDismiss }) {
  const tone = active?.visual?.tone || "neutral";
  return (
    <AnimatePresence>
      {visible && active?.message && (
        <motion.div
          key={active.key}
          initial={{ opacity: 0, x: 8, scale: 0.97 }}
          animate={{ opacity: 1, x: 0, scale: 1 }}
          exit={{ opacity: 0, x: 6 }}
          transition={{ duration: 0.18, ease: "easeOut" }}
          data-testid="qira-bubble"
          aria-hidden="true"
          className={`pointer-events-auto relative mb-6 max-w-[240px] sm:max-w-[280px] rounded-cq-md border ${BUBBLE_TONE[tone] || BUBBLE_TONE.neutral} bg-cq-surface-container-high px-3.5 py-2.5 pr-8 text-[12.5px] leading-snug text-cq-on-surface shadow-cq-popover`}
        >
          {active.warning && <ShieldAlert size={13} className={`mr-1.5 -mt-0.5 inline ${tone === "critical" ? "text-rose-300" : "text-amber-300"}`} />}
          {active.message}
          {active.hold && (
            <span className="qira-dots ml-1 inline-flex gap-0.5 align-middle" aria-hidden="true"><i /><i /><i /></span>
          )}
          <button
            type="button"
            onClick={onDismiss}
            aria-label="Dismiss message"
            className="absolute right-1.5 top-1.5 rounded p-0.5 text-cq-on-surface-variant hover:text-cq-on-surface cq-focusable"
          >
            <X size={12} />
          </button>
        </motion.div>
      )}
    </AnimatePresence>
  );
}

const isTextInput = (el) =>
  el instanceof HTMLElement &&
  ((el.tagName === "INPUT" && !["password", "checkbox", "radio", "button", "submit", "file", "range", "color"].includes(el.type)) ||
    el.tagName === "TEXTAREA");
const isPasswordInput = (el) => el instanceof HTMLInputElement && el.type === "password";

/**
 * Cosmetic playfulness: cursor-following, petting, password-field eye cover,
 * dozing. Never touches the reaction engine or any security state; it is
 * switched off (`allowed=false`) whenever a reaction or warning is showing.
 */
function usePlayful({ enabled, allowed, stageRef, onSay }) {
  const socialRef = useRef(null);
  if (!socialRef.current) socialRef.current = createSocial({ reducedMotion: !enabled });
  const [sleeping, setSleeping] = useState(false);
  const [hearts, setHearts] = useState([]);
  const [flustered, setFlustered] = useState(0);
  const idRef = useRef(0);
  const timers = useRef(new Set());

  // re-create when reduced-motion changes
  useEffect(() => {
    socialRef.current = createSocial({ reducedMotion: !enabled });
    if (import.meta.env?.DEV) window.__QIRA_SOCIAL__ = socialRef.current; // dev-only QA handle (stripped from production)
    const off = socialRef.current.on((type, v) => {
      if (type === "sleep") {
        setSleeping(!!v);
        onSay?.(v ? "Zzz... I'll be here when you need me." : "Oh! You're back!", v ? 4200 : 2800);
      }
    });
    return () => { off(); socialRef.current?.dispose(); };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [enabled]);

  useEffect(() => { socialRef.current?.setAllowed(enabled && allowed); }, [enabled, allowed]);

  useEffect(() => {
    if (!enabled) return undefined;
    const S = () => socialRef.current;
    const center = () => {
      const r = stageRef.current?.getBoundingClientRect();
      return r ? { cx: r.left + r.width / 2, cy: r.top + r.height * 0.4 } : { cx: window.innerWidth - 100, cy: window.innerHeight - 100 };
    };
    const norm = (px, py) => {
      const { cx, cy } = center();
      return [(px - cx) / 480, (py - cy) / 360];
    };
    const onMove = (e) => { const [x, y] = norm(e.clientX, e.clientY); S()?.pointerMove(x, y); };
    const onAwake = () => S()?.activity();
    const onFocusIn = (e) => {
      const el = e.target;
      S()?.activity();
      if (isPasswordInput(el)) return; // handled by the priority-aware password reaction (see QiraDock)
      if (isTextInput(el)) {
        const r = el.getBoundingClientRect();
        const [x, y] = norm(r.left + Math.min(r.width, 220) / 2, r.top + r.height / 2);
        S()?.typingAt(x, y);
      }
    };
    const onFocusOut = () => { S()?.clearFocusTarget(); };
    const onLeave = (e) => { if (!e.relatedTarget) S()?.pointerLeave(); };
    const onInput = (e) => {
      if (isTextInput(e.target)) {
        const r = e.target.getBoundingClientRect();
        const [x, y] = norm(r.left + Math.min(r.width, 220) / 2, r.top + r.height / 2);
        S()?.typingAt(x, y);
      } else S()?.activity();
    };
    const onVis = () => { if (!document.hidden) S()?.greet(); };
    window.addEventListener("pointermove", onMove, { passive: true });
    window.addEventListener("pointerdown", onAwake, { passive: true });
    window.addEventListener("keydown", onAwake, { passive: true });
    document.addEventListener("focusin", onFocusIn);
    document.addEventListener("focusout", onFocusOut);
    document.addEventListener("input", onInput, true);
    document.addEventListener("visibilitychange", onVis);
    document.documentElement.addEventListener("mouseleave", onLeave);
    return () => {
      document.documentElement.removeEventListener("mouseleave", onLeave);
      window.removeEventListener("pointermove", onMove);
      window.removeEventListener("pointerdown", onAwake);
      window.removeEventListener("keydown", onAwake);
      document.removeEventListener("focusin", onFocusIn);
      document.removeEventListener("focusout", onFocusOut);
      document.removeEventListener("input", onInput, true);
      document.removeEventListener("visibilitychange", onVis);
    };
  }, [enabled, stageRef]);

  useEffect(() => () => { timers.current.forEach((id) => clearTimeout(id)); timers.current.clear(); }, []);

  const later = useCallback((fn, ms) => {
    const id = setTimeout(() => { timers.current.delete(id); fn(); }, ms);
    timers.current.add(id);
  }, []);

  const clickAt = useRef(-Infinity);
  const pet = useCallback(() => {
    const r = socialRef.current?.poke();
    if (!r?.accepted) return;
    if (r.combo >= 3 && !r.ticklish) onSay?.("Hehe! That tickles!", 2600); // repeated petting, not an accidental click
    else if (r.combo === 1 && Date.now() - clickAt.current > 9000 && Math.random() < 0.4) {
      clickAt.current = Date.now();
      onSay?.(CLICK_LINES[Math.floor(Math.random() * CLICK_LINES.length)], 2400);
    }
    if (r.ticklish) {
      setFlustered((n) => n + 1);
      later(() => setFlustered(0), 1100);
      return;
    }
    const born = Array.from({ length: r.hearts }, (_, i) => {
      idRef.current += 1;
      return { id: idRef.current, dx: (i - (r.hearts - 1) / 2) * 16 + (Math.random() - 0.5) * 10, delay: i * 0.08, size: 12 + Math.random() * 6 };
    });
    setHearts((h) => [...h, ...born].slice(-12));
    later(() => setHearts((h) => h.filter((x) => !born.includes(x))), 1700);
  }, [later, onSay]);

  return { socialRef, sleeping, hearts, flustered, pet, setHover: (v) => socialRef.current?.setHover(v) };
}

/**
 * The single QIRA presence (the sprite mascot), mounted at the app root so it
 * is the same character on the login page and inside the authenticated app. Presentation only — it can never grant or deny access.
 */
export default function QiraDock() {
  const { snapshot, dismiss, chat, toggleChat, setSlot, emit: emitQira, release: releaseQira } = useQiraReactions();
  const [minimized, setMinimized] = useState(() => readFlag(MIN_KEY));
  const [quiet, setQuiet] = useState(() => readFlag(QUIET_KEY));
  const [status, setStatus] = useState("loading"); // loading | ready | error
  const [attempt, setAttempt] = useState(0);
  const reducedMotion = usePrefersReducedMotion();

  // Social one-liners (sleep / wake / petting / click). Shown only while no QIRA reaction is showing.
  const [say, setSay] = useState(null);
  const sayTimer = useRef(null);
  const onSay = useCallback((text, ms = 2800) => {
    setSay({ key: Date.now(), text });
    clearTimeout(sayTimer.current);
    sayTimer.current = setTimeout(() => setSay(null), ms);
  }, []);
  useEffect(() => () => clearTimeout(sayTimer.current), []);

  const planRef = useRef(IDLE_PLAN);
  planRef.current = planFor(snapshot.active, snapshot.ambient, snapshot.context);

  const showCanvas = !minimized && status !== "error";
  const stageRef = useRef(null);
  // playfulness only where the avatar is shown, never under a reaction/warning
  const playful = usePlayful({
    enabled: showCanvas && !reducedMotion,
    allowed: !snapshot.active && !snapshot.warning,
    stageRef,
    onSay,
  });
  const showPlay = showCanvas && !reducedMotion && !snapshot.active && !snapshot.warning;
  const tone = snapshot.active?.visual?.tone || "neutral";

  // Password fields: QIRA closes its eyes and covers them with both wings for as long as the field
  // has focus. Focus events ONLY: the value is never read, stored or displayed. It runs whether or
  // not the avatar is minimised / motion is reduced (the bubble + static wings still show).
  useEffect(() => {
    let id = null;
    let poll = null;
    const stop = () => {
      if (poll) { clearInterval(poll); poll = null; }
      if (id) { releaseQira(id); id = null; }
    };
    const onIn = (e) => {
      if (!isPasswordInput(e.target)) return;
      const mode = e.target.form?.dataset?.qiraMode;
      const next = mode === "login" ? "password.hide.login" : "password.hide.register";
      if (id && id !== next) releaseQira(id);
      id = next;
      emitQira(id);
      if (!poll) {
        // safety net: if the field is removed while focused the browser may not send focusout
        poll = setInterval(() => { if (!isPasswordInput(document.activeElement)) stop(); }, 800);
      }
    };
    const onOut = (e) => { if (id && !isPasswordInput(e.relatedTarget)) stop(); };
    document.addEventListener("focusin", onIn);
    document.addEventListener("focusout", onOut);
    return () => {
      document.removeEventListener("focusin", onIn);
      document.removeEventListener("focusout", onOut);
      stop();
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const toggleQuiet = useCallback(() => {
    setQuiet((q) => { writeFlag(QUIET_KEY, !q); return !q; });
  }, []);
  // Quiet mode hides friendly chatter; security warnings / critical alerts are always shown.
  const important = !!(snapshot.active && (snapshot.active.warning || snapshot.active.priority >= 5));
  const bubbleVisible = snapshot.bubbleVisible && (!quiet || important);
  const sayVisible = !quiet && !snapshot.active && !!say;

  // keep page content clear of the dock
  useEffect(() => {
    const root = document.documentElement;
    root.style.setProperty("--qira-clearance", minimized ? "76px" : "200px");
    return () => root.style.removeProperty("--qira-clearance");
  }, [minimized]);

  const toggleMin = useCallback(() => {
    setMinimized((m) => {
      writeFlag(MIN_KEY, !m);
      return !m;
    });
    setStatus("loading");
    setAttempt((a) => a + 1); // a re-expand retries a previously failed load
  }, []);

  const onReady = useCallback(() => setStatus("ready"), []);
  const onError = useCallback(() => setStatus("error"), []);

  const label = chat.available
    ? `Open QIRA assistant${chat.label ? ` — ${chat.label}` : ""}`
    : "QIRA";
  const message = !snapshot.active?.message || (quiet && !important) ? "" : snapshot.active.message;

  return (
    <motion.div
      initial={reducedMotion ? false : { opacity: 0, y: 36 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.55, ease: "easeOut" }}
      className="pointer-events-none fixed bottom-3 right-3 z-40 flex flex-col items-end gap-2 sm:bottom-5 sm:right-5"
      data-testid="qira-dock"
      data-status={minimized ? "minimized" : status}
      data-reaction={snapshot.active?.id || "idle"}
    >
      {/* the authenticated chat panel is portalled here (see QiraWidget) */}
      <div ref={setSlot} className="pointer-events-auto" />

      {/* screen-reader announcement; the visible bubble is aria-hidden to avoid double reading */}
      <div role="status" aria-live="polite" className="sr-only" data-testid="qira-live">{message}</div>

      <div className="flex items-end gap-2">
        <Bubble active={snapshot.active} visible={bubbleVisible} onDismiss={dismiss} />
        <Bubble
          active={say ? { key: `say-${say.key}`, message: say.text, visual: { tone: "neutral" }, warning: false, kind: "friendly" } : null}
          visible={sayVisible}
          onDismiss={() => setSay(null)}
        />

        {minimized ? (
          <div className="pointer-events-auto relative">
            <button
              type="button"
              onClick={chat.available ? toggleChat : toggleMin}
              aria-label={label}
              title={label}
              className="rounded-full cq-focusable"
            >
              <QiraPortrait size={52} tone={snapshot.warning ? (tone === "critical" ? "critical" : "warn") : tone} />
            </button>
            {snapshot.warning && (
              <span role="img" aria-label="Security warning" className="absolute -right-0.5 -top-0.5 flex h-4 w-4 items-center justify-center rounded-full bg-amber-400 text-black">
                <ShieldAlert size={10} />
              </span>
            )}
            <button
              type="button"
              onClick={toggleMin}
              aria-label="Show QIRA"
              title="Show QIRA"
              className="absolute -left-2 -top-2 flex h-5 w-5 items-center justify-center rounded-full border border-white/10 bg-cq-surface-container-high text-cq-on-surface-variant hover:text-cq-on-surface cq-focusable"
            >
              <ChevronUp size={12} />
            </button>
          </div>
        ) : (
          <div ref={stageRef} className="relative h-[150px] w-[132px] sm:h-[192px] sm:w-[168px]" data-testid="qira-stage">
            {showCanvas && (
              <CanvasBoundary key={attempt} onError={onError}>
                <QiraSprite planRef={planRef} socialRef={playful.socialRef} onReady={onReady} onError={onError} reducedMotion={reducedMotion} />
              </CanvasBoundary>
            )}

            {/* loading state */}
            {showCanvas && status === "loading" && (
              <div className="pointer-events-none absolute inset-0 flex items-center justify-center" aria-hidden="true" data-testid="qira-loading">
                <span className="h-9 w-9 animate-spin rounded-full border-2 border-cq-primary/25 border-t-cq-primary" />
              </div>
            )}

            {/* fallback: the sprite failed to load/render */}
            {status === "error" && (
              <div className="pointer-events-none absolute inset-0 flex items-end justify-center pb-2" data-testid="qira-fallback">
                <QiraPortrait size={96} tone={snapshot.warning ? "warn" : tone} />
              </div>
            )}

            {/* chat launcher: the character itself is the button once monitoring is available */}
            {chat.available && (
              <button
                type="button"
                onClick={() => { playful.pet(); toggleChat(); }}
                onPointerEnter={() => playful.setHover(true)}
                onPointerLeave={() => playful.setHover(false)}
                aria-label={label}
                aria-expanded={chat.open}
                title={label}
                data-testid="qira-launcher"
                className="pointer-events-auto absolute inset-x-3 bottom-0 top-8 rounded-cq-xl cq-focusable"
              />
            )}

            {/* just-for-fun: pet QIRA (only while nothing important is being shown) */}
            {showPlay && !chat.available && (
              <button
                type="button"
                onClick={playful.pet}
                onPointerEnter={() => playful.setHover(true)}
                onPointerLeave={() => playful.setHover(false)}
                aria-label="Pet QIRA"
                title="Pet QIRA"
                data-testid="qira-pet"
                className="pointer-events-auto absolute inset-x-3 bottom-0 top-8 cursor-pointer rounded-cq-xl cq-focusable"
              />
            )}

            {/* cosmetic effects: hearts, flustered puff, snoring */}
            <div className="pointer-events-none absolute inset-0 overflow-visible" aria-hidden="true" data-testid="qira-fx">
              <AnimatePresence>
                {showPlay && playful.hearts.map((h) => (
                  <motion.span
                    key={h.id}
                    initial={{ opacity: 0, y: 0, x: h.dx, scale: 0.5 }}
                    animate={{ opacity: [0, 1, 0], y: -64, x: h.dx * 1.6, scale: [0.5, 1.15, 0.9] }}
                    transition={{ duration: 1.35, delay: h.delay, ease: "easeOut" }}
                    className="absolute left-1/2 top-[22%] text-pink-300 drop-shadow"
                    data-testid="qira-heart"
                  >
                    <Heart size={h.size} fill="currentColor" strokeWidth={0} />
                  </motion.span>
                ))}
              </AnimatePresence>
              {showPlay && playful.flustered > 0 && (
                <motion.span
                  key={playful.flustered}
                  initial={{ opacity: 0, scale: 0.6, y: 4 }}
                  animate={{ opacity: [0, 1, 1, 0], scale: 1, y: -6 }}
                  transition={{ duration: 1.1 }}
                  className="absolute left-[58%] top-[10%] rounded-full bg-amber-300/90 px-1.5 text-[12px] font-extrabold leading-5 text-black"
                  data-testid="qira-flustered"
                >
                  !?
                </motion.span>
              )}
              {showPlay && playful.sleeping && (
                <span className="absolute left-[60%] top-[12%] select-none text-[13px] font-bold text-cq-primary/80" data-testid="qira-zzz">
                  <motion.span className="inline-block" animate={{ y: [0, -6, 0], opacity: [0.3, 1, 0.3] }} transition={{ duration: 2.4, repeat: Infinity }}>z</motion.span>
                  <motion.span className="inline-block text-[16px]" animate={{ y: [0, -8, 0], opacity: [0.3, 1, 0.3] }} transition={{ duration: 2.4, repeat: Infinity, delay: 0.5 }}>Z</motion.span>
                </span>
              )}
            </div>

            {snapshot.warning && (
              <span
                role="img"
                aria-label="Security warning"
                data-testid="qira-warning"
                className={`pointer-events-none absolute left-1 top-1 flex h-6 w-6 items-center justify-center rounded-full ${tone === "critical" ? "bg-rose-500 text-white" : "bg-amber-400 text-black"} shadow-lg animate-pulse`}
              >
                <ShieldAlert size={14} />
              </span>
            )}

            <button
              type="button"
              onClick={toggleQuiet}
              aria-label={quiet ? "Turn QIRA messages on" : "Quiet mode: hide QIRA's friendly messages"}
              aria-pressed={quiet}
              title={quiet ? "Messages off (alerts still show)" : "Quiet mode"}
              data-testid="qira-quiet"
              className="pointer-events-auto absolute right-0 top-7 flex h-6 w-6 items-center justify-center rounded-full border border-white/10 bg-cq-surface-container-high/80 text-cq-on-surface-variant hover:text-cq-on-surface cq-focusable"
            >
              {quiet ? <VolumeX size={12} /> : <Volume2 size={12} />}
            </button>

            <button
              type="button"
              onClick={toggleMin}
              aria-label="Minimize QIRA"
              title="Minimize QIRA"
              className="pointer-events-auto absolute right-0 top-0 flex h-6 w-6 items-center justify-center rounded-full border border-white/10 bg-cq-surface-container-high/80 text-cq-on-surface-variant hover:text-cq-on-surface cq-focusable"
            >
              <ChevronDown size={13} />
            </button>
          </div>
        )}
      </div>
    </motion.div>
  );
}
