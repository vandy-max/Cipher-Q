import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { createQiraEngine } from "./qiraEngine";
import { REACTIONS, SCENARIO_COUNT } from "./qiraReactions";

// A manual clock so display durations are tested deterministically. These
// timers are DISPLAY timers only — they never stand in for a security event.
function makeEngine(opts = {}) {
  let t = 1_000_000;
  const timers = new Map();
  let id = 0;
  const engine = createQiraEngine({
    now: () => t,
    setTimer: (fn, ms) => { const h = ++id; timers.set(h, { at: t + ms, fn }); return h; },
    clearTimer: (h) => timers.delete(h),
    ...opts,
  });
  const advance = (ms) => {
    const target = t + ms;
    for (;;) {
      const due = [...timers.entries()].filter(([, v]) => v.at <= target).sort((a, b) => a[1].at - b[1].at)[0];
      if (!due) break;
      t = Math.max(t, due[1].at);
      timers.delete(due[0]);
      due[1].fn();
    }
    t = target;
  };
  return { engine, advance, timers };
}

describe("reaction catalogue", () => {
  it("has exactly the 29 scenarios, numbered 1..29 once each", () => {
    expect(SCENARIO_COUNT).toBe(29);
    const ns = Object.values(REACTIONS).map((r) => r.n).sort((a, b) => a - b);
    expect(ns).toEqual(Array.from({ length: 29 }, (_, i) => i + 1));
  });

  it("keeps the specified messages exactly", () => {
    const expected = {
      1: "Welcome to CipherQ.",
      2: "Identity verified. Welcome back.",
      3: "Authentication failed. Please try again.",
      4: "Please position your face in the camera.",
      5: "Face verification successful.",
      6: "Verification failed. Access has not been granted.",
      7: "I'm checking your declared intent.",
      8: "The request is consistent with the declared intent.",
      9: "The requested action differs from the declared intent.",
      10: "Your role permits this operation.",
      11: "Your role does not permit this operation.",
      12: "Evaluating risk and contextual signals.",
      13: "Risk is within the acceptable range.",
      14: "Elevated risk detected. Additional checks may be required.",
      15: "High-risk activity detected.",
      16: "Quantum key distribution simulation in progress.",
      17: "Data encrypted successfully.",
      18: "Decryption and integrity checks completed.",
      19: "Security monitoring is starting.",
      20: "Monitoring is active.",
      21: "Your current activity may have drifted from the original intent.",
      22: "Suspicious activity requires review.",
      23: "Your session has been revoked.",
      24: "Audit integrity verified.",
      25: "Audit integrity verification failed.",
      26: "Security policy updated. Reviewing the new state.",
      27: "Security status is temporarily unavailable.",
      28: null,
      29: null,
    };
    for (const r of Object.values(REACTIONS)) expect(r.message).toBe(expected[r.n]);
  });

  it("never puts secrets or backend text in a message", () => {
    for (const r of Object.values(REACTIONS)) {
      expect(String(r.message ?? "")).not.toMatch(/token|descriptor|embedding|key[:=]|hash|password|secret/i);
    }
  });
});

describe("engine: priority, queue, sticky, hold", () => {
  let h;
  beforeEach(() => { h = makeEngine(); });
  afterEach(() => h.engine.dispose());

  it("shows a transient reaction and returns to idle after its duration", () => {
    h.engine.trigger("login.success");
    expect(h.engine.getSnapshot().active.id).toBe("login.success");
    expect(h.engine.getSnapshot().bubbleVisible).toBe(true);
    h.advance(REACTIONS["login.success"].durationMs + 5);
    expect(h.engine.getSnapshot().active).toBeNull();
    expect(h.engine.getSnapshot().bubbleVisible).toBe(false);
  });

  it("ignores unknown ids without throwing", () => {
    expect(h.engine.trigger("nope")).toBe(false);
    expect(h.engine.getSnapshot().active).toBeNull();
  });

  it("higher priority preempts lower priority", () => {
    h.engine.trigger("login.page");
    h.engine.trigger("login.failed");
    expect(h.engine.getSnapshot().active.id).toBe("login.failed");
  });

  it("lower priority is queued behind, not shown over, a higher one", () => {
    h.engine.trigger("login.failed");
    h.engine.trigger("face.success");
    expect(h.engine.getSnapshot().active.id).toBe("login.failed");
    h.advance(REACTIONS["login.failed"].durationMs + 5);
    expect(h.engine.getSnapshot().active.id).toBe("face.success");
  });

  it("collapses duplicate rapid events", () => {
    for (let i = 0; i < 20; i++) h.engine.trigger("login.success");
    h.advance(REACTIONS["login.success"].durationMs + 5);
    expect(h.engine.getSnapshot().active).toBeNull();
  });

  it("bounds the queue under a rapid burst", () => {
    h.engine.trigger("login.failed");
    ["face.success", "intent.match", "encrypt.success", "decrypt.success", "audit.verified", "rbac.pass", "risk.low"].forEach((id) => h.engine.trigger(id));
    let shown = 0;
    for (let i = 0; i < 40 && h.engine.getSnapshot().active; i++) { shown++; h.advance(6000); }
    expect(shown).toBeLessThanOrEqual(6); // 1 current + max 4 queued (+ slack)
  });

  it("a sticky warning is NEVER cleared by a timer", () => {
    h.engine.trigger("session.revoked");
    h.advance(10 * 60 * 1000);
    expect(h.engine.getSnapshot().active.id).toBe("session.revoked");
    expect(h.engine.getSnapshot().warning).toBe(true);
  });

  it("low-priority events cannot hide an unresolved critical alert", () => {
    h.engine.trigger("session.revoked");
    expect(h.engine.trigger("face.success")).toBe(false);
    expect(h.engine.trigger("login.page")).toBe(false);
    expect(h.engine.getSnapshot().active.id).toBe("session.revoked");
  });

  it("a transient of equal/greater priority may show over a sticky, then falls back to it", () => {
    h.engine.trigger("suspicious.activity"); // ALERT sticky
    h.engine.trigger("login.failed"); // ALERT transient
    expect(h.engine.getSnapshot().active.id).toBe("login.failed");
    h.advance(REACTIONS["login.failed"].durationMs + 5);
    expect(h.engine.getSnapshot().active.id).toBe("suspicious.activity");
  });

  it("alert.cleared resolves ONLY the named warnings", () => {
    h.engine.trigger("suspicious.activity");
    h.engine.trigger("session.revoked");
    h.engine.trigger("alert.cleared", { clears: ["suspicious.activity"] });
    expect(h.engine.hasSticky("suspicious.activity")).toBe(false);
    expect(h.engine.hasSticky("session.revoked")).toBe(true);
    expect(h.engine.getSnapshot().active.id).toBe("session.revoked");
  });

  it("alert.cleared without a target clears no warning", () => {
    h.engine.trigger("audit.failed");
    h.engine.trigger("alert.cleared");
    expect(h.engine.hasSticky("audit.failed")).toBe(true);
  });

  it("returns to idle when the last warning is resolved", () => {
    h.engine.trigger("api.unavailable");
    h.engine.trigger("alert.cleared", { clears: ["api.unavailable"] });
    expect(h.engine.getSnapshot().active).toBeNull();
    expect(h.engine.getSnapshot().warning).toBe(false);
  });

  it("hold reactions persist until released, with a safety cap", () => {
    h.engine.trigger("qkd.running");
    h.advance(30000);
    expect(h.engine.getSnapshot().active.id).toBe("qkd.running");
    h.engine.release("qkd.running");
    h.advance(1300);
    expect(h.engine.getSnapshot().active).toBeNull();

    h.engine.trigger("risk.started", { force: true });
    h.advance(REACTIONS["risk.started"].maxHoldMs + 10);
    expect(h.engine.getSnapshot().active).toBeNull(); // cap: a lost response cannot wedge it
  });

  it("dismiss hides the bubble but never the warning", () => {
    h.engine.trigger("audit.failed");
    h.engine.dismiss();
    const s = h.engine.getSnapshot();
    expect(s.bubbleVisible).toBe(false);
    expect(s.warning).toBe(true);
    expect(s.active.id).toBe("audit.failed");
  });

  it("honours per-event cooldowns", () => {
    expect(h.engine.trigger("api.unavailable")).toBe(true);
    expect(h.engine.trigger("api.unavailable")).toBe(false);
  });

  it("reset clears every timer (no leak after unmount)", () => {
    h.engine.trigger("login.success");
    h.engine.trigger("qkd.running");
    h.engine.trigger("session.revoked");
    h.engine.reset();
    expect(h.timers.size).toBe(0);
    expect(h.engine.getSnapshot().active).toBeNull();
  });

  it("does not notify subscribers for no-op clears", () => {
    const spy = vi.fn();
    h.engine.subscribe(spy);
    h.engine.clear(["api.unavailable"]);
    h.engine.release("qkd.running");
    expect(spy).not.toHaveBeenCalled();
  });

  it("a throwing subscriber cannot break the engine", () => {
    h.engine.subscribe(() => { throw new Error("boom"); });
    expect(() => h.engine.trigger("login.success")).not.toThrow();
    expect(h.engine.getSnapshot().active.id).toBe("login.success");
  });
});
