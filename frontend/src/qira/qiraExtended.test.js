import { describe, it, expect } from "vitest";
import { createQiraEngine } from "./qiraEngine";
import { EXTENDED_REACTIONS, EXT_PRIORITY, MONITORING_STICKY_IDS } from "./qiraReactionsExtended";
import { SPRITE_KEYS, spriteForReaction, restingSprite } from "./qiraSprites";
import { planFor } from "./qiraAnimator";

describe("extended QIRA catalogue", () => {
  const entries = Object.entries(EXTENDED_REACTIONS);
  it("every reaction maps to a real character-sheet pose", () => {
    for (const [id, d] of entries) {
      expect(SPRITE_KEYS, id).toContain(d.sprite);
      expect(spriteForReaction(id), id).toBe(d.sprite);
    }
  });
  it("messages are short, fixed strings with no sensitive wording", () => {
    for (const [id, d] of entries) {
      if (!d.message) continue;
      expect(d.message.length, id).toBeLessThan(110);
      expect(d.message, id).not.toMatch(/token|jwt|secret key|hash|exception|traceback|descriptor|embedding/i);
    }
  });
  it("the required spec messages exist verbatim", () => {
    const m = (id) => EXTENDED_REACTIONS[id].message;
    expect(m("landing.welcome")).toBe("Welcome to CipherQ! I'm QIRA, your security companion!");
    expect(m("face.analyzing.enroll")).toBe("I'm analyzing your face for registration.");
    expect(m("face.analyzing.verify")).toBe("Your face is being analyzed. Please hold still.");
    expect(m("monitoring.off")).toMatch(/^Monitoring is currently OFF\. I'm keeping busy here\./);
    expect(m("monitoring.on")).toBe("Monitoring is active! Don't worry, I'm keeping an eye on your session.");
    expect(m("monitoring.warning")).toBe("Hey! Something unusual needs our attention. Please review the monitoring panel.");
    expect(m("monitoring.highrisk")).toBe("High-risk activity detected! Please review immediately.");
    expect(m("encrypt.done")).toBe("Your file is securely encrypted! Nice work!");
    expect(m("decrypt.done")).toBe("Decryption complete! Your file is ready.");
  });
  it("monitoring warnings are sticky + flagged; success states are not", () => {
    for (const id of MONITORING_STICKY_IDS) { expect(EXTENDED_REACTIONS[id].sticky, id).toBe(true); expect(EXTENDED_REACTIONS[id].warning, id).toBe(true); }
    expect(EXTENDED_REACTIONS["encrypt.done"].sticky).toBeFalsy();
  });
  it("hold reactions have a safety cap so a missed release can never wedge QIRA", () => {
    for (const [id, d] of entries) if (d.hold) expect(d.maxHoldMs, id).toBeGreaterThan(0);
  });
});

describe("priorities (spec phase 13)", () => {
  it("high risk preempts everything below it", () => {
    const e = createQiraEngine();
    e.trigger("monitoring.highrisk");
    e.trigger("encrypt.done"); e.trigger("nav.page"); e.trigger("landing.welcome");
    expect(e.getSnapshot().active.id).toBe("monitoring.highrisk");
  });
  it("password hiding preempts a normal/failed expression immediately", () => {
    const e = createQiraEngine();
    e.trigger("login.invalid");
    e.trigger("password.hide.login");
    expect(e.getSnapshot().active.id).toBe("password.hide.login");
  });
  it("authentication results outrank a monitoring warning, which then returns", () => {
    const e = createQiraEngine();
    e.trigger("monitoring.warning");
    e.trigger("face.verified");
    expect(e.getSnapshot().active.id).toBe("face.verified");
    expect(e.hasSticky("monitoring.warning")).toBe(true);
  });
  it("quantum / intent workflow events cannot hide an unresolved warning", () => {
    const e = createQiraEngine();
    e.trigger("monitoring.warning");
    e.trigger("intent.pending");
    expect(e.getSnapshot().active.id).toBe("monitoring.warning");
  });
  it("ordering constants follow the spec", () => {
    const P = EXT_PRIORITY;
    expect(P.CRITICAL > P.AUTH && P.AUTH > P.OPERATION && P.OPERATION > P.MONITOR && P.MONITOR > P.WORKFLOW && P.WORKFLOW > P.USER && P.USER > P.WELCOME && P.WELCOME > P.IDLE).toBe(true);
  });
  it("the same reaction is not repeated back-to-back (dedupe)", () => {
    const e = createQiraEngine();
    e.trigger("landing.welcome"); e.trigger("landing.welcome");
    const h = e.getHistory().filter((x) => x.id === "landing.welcome");
    expect(h[h.length - 1].outcome).toBe("deduped");
  });
});

describe("resting pose + accessories", () => {
  it("monitoring OFF -> laptop pose; Quantum Lab -> laptop + helmet + quantum circuit", () => {
    expect(restingSprite("off", null)).toBe("typing");
    expect(planFor(null, "off", null).fx).toContain("laptopGlow");
    const q = planFor(null, "idle", "quantum");
    expect(q.base).toBe("typing");
    expect(q.fx).toEqual(expect.arrayContaining(["helmet", "quantum"]));
  });
  it("monitoring ACTIVE -> cyan glow + shield", () => {
    const p = planFor(null, "active", null);
    expect(p.fx).toContain("shield");
    expect(p.tone).toBe("ok");
  });
  it("password hiding plan uses the existing eyes-closed pose without wing overlays", () => {
    const e = createQiraEngine();
    e.trigger("password.hide.register");
    const p = planFor(e.getSnapshot().active, "idle", null);
    expect(p.sprite).toBe("processing");
    expect(p.fx).not.toContain("cover");
  });
  it("a warning never carries the ACTIVE shield", () => {
    const e = createQiraEngine();
    e.trigger("monitoring.warning");
    expect(planFor(e.getSnapshot().active, "idle", null).fx).not.toContain("shield");
  });
});
