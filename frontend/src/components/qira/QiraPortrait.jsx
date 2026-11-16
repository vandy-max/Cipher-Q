const PORTRAIT = `${import.meta.env.BASE_URL}qira/qira-portrait.webp`;

const TONE_RING = {
  neutral: "ring-white/15",
  ok: "ring-emerald-300/50",
  warn: "ring-amber-400/70",
  critical: "ring-rose-400/80",
};

/**
 * Small round QIRA portrait (a head crop of the mascot). DECORATIVE: it never
 * conveys security state on its own - callers pass text/labels for that.
 */
export default function QiraPortrait({ size = 36, tone = "neutral", pulse = false, className = "" }) {
  return (
    <span
      aria-hidden="true"
      className={`inline-block shrink-0 overflow-hidden rounded-full bg-cq-surface-container-highest ring-2 ${TONE_RING[tone] || TONE_RING.neutral} ${pulse ? "animate-pulse" : ""} ${className}`.trim()}
      style={{ width: size, height: size }}
    >
      <img
        src={PORTRAIT}
        alt=""
        width={size}
        height={size}
        draggable={false}
        decoding="async"
        style={{ width: "100%", height: "100%", objectFit: "cover" }}
      />
    </span>
  );
}
