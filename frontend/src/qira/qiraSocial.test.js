import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { createSocial, SOCIAL } from "./qiraSocial";

// deterministic randomness
const seq = (...v) => { let i = 0; return () => v[i++ % v.length]; };
const make = (opts = {}) => { const s = createSocial({ rand: seq(0.2, 0.9, 0.3), ...opts }); s.setAllowed(true); return s; };
const run = (s, seconds, step = 0.05) => { let o; for (let t = 0; t < seconds; t += step) o = s.tick(step); return o; };

describe("QIRA social layer is cosmetic and fully gated", () => {
  it("does not import or call the reaction engine / api (presentation only)", () => {
    const src = readFileSync(resolve(__dirname, "qiraSocial.js"), "utf8");
    expect(src).not.toMatch(/from\s+["'][^"']*(qiraEngine|index|report|classify|services\/api)["']/);
    expect(src).not.toMatch(/emitQira|clearQira|releaseQira|trigger\(/);
  });

  it("weight ramps up when allowed and drops to ~0 when a reaction/warning appears", () => {
    const s = make();
    expect(run(s, 2).weight).toBeGreaterThan(0.95);
    s.setAllowed(false);
    const o = run(s, 1.5);
    expect(o.weight).toBeLessThan(0.02);
    expect(o.happy).toBe(false);
    expect(o.cover).toBe(false);
    expect(o.wave).toBe(false);
  });

  it("pokes are ignored while not allowed (cannot interfere with an alert)", () => {
    const s = make();
    s.setAllowed(false);
    expect(s.poke()).toMatchObject({ accepted: false });
    expect(run(s, 1).happy).toBe(false);
  });

  it("reduced motion makes the whole layer inert", () => {
    const s = make({ reducedMotion: true });
    s.pointerMove(-1, -1);
    s.setCover(true);
    expect(s.poke().accepted).toBe(false);
    const o = run(s, 2);
    expect(o.weight).toBe(0);
    expect(o.gazeActive).toBe(false);
  });

  it("dropping allowed mid-pet clears transient happy/surprise state (nothing lingers)", () => {
    const s = make();
    run(s, 1);
    s.poke();
    s.setAllowed(false);
    run(s, 0.2);
    s.setAllowed(true);
    expect(run(s, 0.05).happy).toBe(false);
  });
});

describe("gaze", () => {
  it("follows a fresh pointer, clamped to -1..1, and lets go after it goes stale", () => {
    const s = make();
    s.pointerMove(-5, 3);
    const o = run(s, 1.5);
    expect(o.gazeActive).toBe(true);
    expect(o.gx).toBeLessThan(-0.9);
    expect(o.gx).toBeGreaterThanOrEqual(-1);
    expect(o.gy).toBeLessThanOrEqual(1);
    const later = run(s, SOCIAL.pointerFreshS + 3);
    expect(Math.abs(later.gx)).toBeLessThan(1.01); // may be glancing, but no longer pinned to the pointer
  });

  it("a field being typed in takes priority over the pointer", () => {
    const s = make();
    s.pointerMove(1, 1);
    s.typingAt(-0.6, -0.4);
    const o = run(s, 1.2);
    expect(o.gx).toBeLessThan(-0.4);
    expect(o.gy).toBeLessThan(-0.2);
  });
});

describe("petting", () => {
  it("a poke gives hearts and a happy moment that ends by itself", () => {
    const s = make();
    run(s, 1);
    const r = s.poke();
    expect(r).toMatchObject({ accepted: true, ticklish: false });
    expect(r.hearts).toBeGreaterThanOrEqual(2);
    expect(run(s, 0.1).happy).toBe(true);
    expect(run(s, SOCIAL.happyHoldS + 0.5).happy).toBe(false);
  });

  it("poking too fast gets QIRA flustered, then a cooldown stops spam", () => {
    const s = make();
    run(s, 1);
    let last;
    for (let i = 0; i < SOCIAL.ticklishAt; i++) { last = s.poke(); run(s, 0.1); }
    expect(last.ticklish).toBe(true);
    expect(last.hearts).toBe(0);
    expect(s.poke().accepted).toBe(false); // cooldown
    run(s, SOCIAL.ticklishCooldownS + 0.2);
    expect(s.poke().accepted).toBe(true);
  });
});

describe("password cover, sleep, wake", () => {
  it("covers its eyes while a password field is focused and uncovers after", () => {
    const s = make();
    s.setCover(true);
    expect(run(s, 0.3).cover).toBe(true);
    s.setCover(false);
    expect(run(s, 0.3).cover).toBe(false);
  });

  it("will not accept a poke while covering its eyes", () => {
    const s = make();
    s.setCover(true);
    expect(s.poke().accepted).toBe(false);
  });

  it("dozes off after a long idle time, emits sleep events, and waves hello when woken", () => {
    const s = make();
    const events = [];
    s.on((t, v) => events.push([t, v]));
    run(s, SOCIAL.sleepAfterS + 2);
    expect(s.isSleeping()).toBe(true);
    expect(run(s, 2).sleepy).toBeGreaterThan(0.8);
    s.pointerMove(0, 0);
    const o = run(s, 0.1);
    expect(s.isSleeping()).toBe(false);
    expect(o.wave).toBe(true);
    expect(events).toEqual([["sleep", true], ["sleep", false]]);
  });

  it("never dozes while a real reaction is showing (allowed=false)", () => {
    const s = make();
    s.setAllowed(false);
    run(s, SOCIAL.sleepAfterS * 2);
    expect(s.isSleeping()).toBe(false);
  });

  it("any activity (keys, clicks) keeps it awake", () => {
    const s = make();
    for (let i = 0; i < 4; i++) { run(s, SOCIAL.sleepAfterS * 0.6); s.activity(); }
    expect(s.isSleeping()).toBe(false);
  });
});

describe("idle fidgets", () => {
  it("fidget occasionally when nothing is happening, but not while the pointer is active", () => {
    const s = make({ rand: seq(0.1, 0.3, 0.9, 0.6, 0.5) });
    let moved = false;
    for (let t = 0; t < 30; t += 0.05) { const o = s.tick(0.05); if (o.gazeActive || o.tilt > 0.01 || o.hop > 0.01) moved = true; }
    expect(moved).toBe(true);

    const busy = make({ rand: seq(0.1, 0.3, 0.9, 0.6, 0.5) });
    let t2 = 0, hopped = false;
    for (; t2 < 30; t2 += 0.05) { busy.pointerMove(0, 0); const o = busy.tick(0.05); if (o.hop > 0.01 || o.tilt > 0.02) hopped = true; }
    expect(hopped).toBe(false);
  });
});
