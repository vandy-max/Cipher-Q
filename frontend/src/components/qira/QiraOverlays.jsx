/**
 * Lightweight vector overlays layered on the existing QIRA sprite poses.
 * Colours are sampled from the character sheet (navy ~#35487a body / #1b2a55 shade,
 * gold ~#e3a458 trim, cyan eyes) so the original character is kept, never replaced.
 *
 * Everything here is static SVG + CSS (see QiraOverlays.css). Visibility is driven
 * by data attributes on the sprite root, so toggling an overlay never re-renders React.
 * Overlays are decorative (aria-hidden) and never carry information.
 */

const NAVY_HI = "#3c5088";
const NAVY = "#26396f";
const NAVY_LO = "#17234b";
const GOLD = "#e3a458";
const GOLD_HI = "#f4cf8a";

/** One feathered wing, drawn pointing up (tip at the top, shoulder at the bottom). */
function WingShape({ id, flip = false }) {
  return (
    <svg viewBox="0 0 100 130" className="qira-wing-svg" style={flip ? { transform: "scaleX(-1)" } : undefined} aria-hidden="true">
      <defs>
        <linearGradient id={`${id}-g`} x1="0" y1="0" x2="1" y2="1">
          <stop offset="0" stopColor={NAVY_HI} />
          <stop offset="0.55" stopColor={NAVY} />
          <stop offset="1" stopColor={NAVY_LO} />
        </linearGradient>
      </defs>
      {/* wing body */}
      <path d="M52 127 C20 120 5 88 9 52 C12 24 31 6 55 5 C77 5 93 24 92 54 C91 92 78 119 52 127 Z" fill={`url(#${id}-g)`} stroke={NAVY_LO} strokeWidth="2" />
      {/* feather tips: scalloped lobes along the leading edge, gold-trimmed like the sheet */}
      <path d="M9 52 C4 44 6 36 12 31 M14 74 C7 68 7 58 11 52 M23 96 C14 90 13 80 16 74" fill="none" stroke={GOLD} strokeWidth="3.2" strokeLinecap="round" />
      <path d="M55 5 C66 5 76 10 83 18 M83 18 C90 27 92 38 91 49" fill="none" stroke={GOLD} strokeWidth="3.2" strokeLinecap="round" />
      {/* inner feather ribs */}
      <path d="M30 108 C26 84 28 52 40 22 M50 118 C48 88 52 52 62 18 M68 108 C70 84 74 56 80 36" fill="none" stroke={NAVY_LO} strokeOpacity="0.55" strokeWidth="2.4" strokeLinecap="round" />
      <path d="M33 40 C38 30 46 24 56 22" fill="none" stroke={GOLD_HI} strokeOpacity="0.45" strokeWidth="2" strokeLinecap="round" />
    </svg>
  );
}

/** Two wings that rise from the shoulders and cover the closed eyes (password field focused). */
export function CoverWings() {
  return (
    <div className="qira-wings" aria-hidden="true">
      <div className="qira-wing qira-wing-l"><WingShape id="qwl" /></div>
      <div className="qira-wing qira-wing-r"><WingShape id="qwr" flip /></div>
    </div>
  );
}

/** Small golden engineering helmet (hard hat) sitting between the ear tufts. */
export function Helmet() {
  return (
    <svg viewBox="0 0 120 70" className="qira-helmet" aria-hidden="true">
      <defs>
        <linearGradient id="qh-g" x1="0" y1="0" x2="0" y2="1">
          <stop offset="0" stopColor="#ffe2a0" />
          <stop offset="0.55" stopColor="#f0b84e" />
          <stop offset="1" stopColor="#c98a2a" />
        </linearGradient>
      </defs>
      {/* brim */}
      <path d="M6 54 C6 48 22 45 60 45 C98 45 114 48 114 54 C114 60 98 62 60 62 C22 62 6 60 6 54 Z" fill="#d79a33" stroke="#8c5d17" strokeWidth="2" />
      {/* dome */}
      <path d="M17 48 C15 22 34 6 60 6 C86 6 105 22 103 48 C88 44 32 44 17 48 Z" fill="url(#qh-g)" stroke="#8c5d17" strokeWidth="2" />
      {/* centre ridge + side ribs */}
      <path d="M60 6 L60 45 M42 10 C38 22 37 34 38 45 M78 10 C82 22 83 34 82 45" fill="none" stroke="#b27a22" strokeWidth="2.2" strokeLinecap="round" />
      {/* highlight */}
      <path d="M26 30 C29 20 38 13 50 10" fill="none" stroke="#fff3cf" strokeOpacity="0.8" strokeWidth="3" strokeLinecap="round" />
      {/* Q lamp badge */}
      <circle cx="60" cy="27" r="8.5" fill="#17234b" stroke="#8c5d17" strokeWidth="1.6" />
      <circle cx="60" cy="27" r="4.4" fill="none" stroke="#63f7ff" strokeWidth="1.8" />
      <path d="M62.5 29.5 L66 33" stroke="#63f7ff" strokeWidth="1.8" strokeLinecap="round" />
    </svg>
  );
}

/** Tiny quantum-circuit card: three qubit wires, gates, entangling link, pulsing cyan/violet nodes. */
export function QuantumCircuit() {
  return (
    <svg viewBox="0 0 84 58" className="qira-quantum" aria-hidden="true">
      <rect x="1" y="1" width="82" height="56" rx="9" fill="#0b1230" fillOpacity="0.78" stroke="#63f7ff" strokeOpacity="0.45" />
      {[14, 29, 44].map((y, i) => (
        <line key={y} x1="8" y1={y} x2="76" y2={y} stroke={i === 1 ? "#a98bff" : "#63f7ff"} strokeOpacity="0.55" strokeWidth="1.3" />
      ))}
      {/* gates */}
      <rect x="15" y="9" width="10" height="10" rx="2" fill="#63f7ff" fillOpacity="0.85" />
      <rect x="44" y="39" width="10" height="10" rx="2" fill="#a98bff" fillOpacity="0.9" />
      {/* entangling link (control dot -> target) */}
      <line x1="34" y1="14" x2="34" y2="44" stroke="#c9b8ff" strokeWidth="1.3" />
      <circle cx="34" cy="14" r="2.6" fill="#63f7ff" />
      <circle cx="34" cy="44" r="4.2" fill="none" stroke="#a98bff" strokeWidth="1.5" />
      <line x1="34" y1="39.8" x2="34" y2="48.2" stroke="#a98bff" strokeWidth="1.3" />
      <line x1="29.8" y1="44" x2="38.2" y2="44" stroke="#a98bff" strokeWidth="1.3" />
      {/* glowing connection nodes (pulse via CSS) */}
      <circle className="qira-node qira-node-a" cx="64" cy="14" r="3.2" fill="#63f7ff" />
      <circle className="qira-node qira-node-b" cx="64" cy="29" r="3.2" fill="#a98bff" />
      <circle className="qira-node qira-node-c" cx="64" cy="44" r="3.2" fill="#63f7ff" />
      <path d="M64 14 L64 44" stroke="#63f7ff" strokeOpacity="0.4" strokeWidth="1" strokeDasharray="2 2" />
    </svg>
  );
}

/** Small shield badge (monitoring ACTIVE confidence / encryption protection). */
export function ShieldBadge() {
  return (
    <svg viewBox="0 0 40 46" className="qira-shield" aria-hidden="true">
      <defs>
        <linearGradient id="qs-g" x1="0" y1="0" x2="0" y2="1">
          <stop offset="0" stopColor="#7cf6ff" />
          <stop offset="1" stopColor="#1fa7c9" />
        </linearGradient>
      </defs>
      <path d="M20 2 L36 8 V22 C36 33 29 41 20 44 C11 41 4 33 4 22 V8 Z" fill="url(#qs-g)" stroke="#0e5f78" strokeWidth="2" />
      <path d="M20 8 L31 12 V22 C31 30 26 36 20 39 Z" fill="#ffffff" fillOpacity="0.16" />
      <path d="M12 22.5 L18 28.5 L29 16" fill="none" stroke="#06283a" strokeWidth="3.4" strokeLinecap="round" strokeLinejoin="round" />
    </svg>
  );
}

/** Soft screen glow drawn over the laptop in the "typing" pose (monitoring OFF). */
export function LaptopGlow() {
  return <div className="qira-laptop-glow" aria-hidden="true" />;
}

/** Eight sparkles used by celebrations. */
export function Sparkles() {
  return (
    <div className="qira-sparkles" aria-hidden="true">
      {[0, 1, 2, 3, 4, 5].map((i) => (
        <span key={i} className={`qira-spark qira-spark-${i}`} />
      ))}
    </div>
  );
}

/** Scanning ring + sweep line used while a face/integrity check is running. */
export function ScanRing() {
  return (
    <div className="qira-scan" aria-hidden="true">
      <span className="qira-scan-ring" />
      <span className="qira-scan-line" />
    </div>
  );
}
