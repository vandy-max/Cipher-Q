import { describe, it, expect } from "vitest";
import { existsSync, readFileSync } from "node:fs";
import { resolve } from "node:path";
import { REACTIONS, SCENARIO_COUNT } from "./qiraReactions";
import { REACTION_SPRITE, SOCIAL_SPRITE, SPRITE_KEYS, NEUTRAL, spriteForReaction, spriteMeta } from "./qiraSprites";
import { planFor, bodyMotion, TONE_COLOR } from "./qiraAnimator";

const SPRITE_DIR = resolve(__dirname, "../../public/qira/sprites");

describe("QIRA sprite mascot assets", () => {
  it("ships all sprites as real transparent WebP files that match the metadata", () => {
    expect(SPRITE_KEYS.length).toBeGreaterThanOrEqual(14);
    for (const k of SPRITE_KEYS) {
      const m = spriteMeta(k);
      const file = resolve(SPRITE_DIR, m.file);
      expect(existsSync(file), `${m.file} missing`).toBe(true);
      const buf = readFileSync(file);
      expect(buf.subarray(0, 4).toString()).toBe("RIFF");
      expect(buf.subarray(8, 12).toString()).toBe("WEBP");
      const fmt = buf.subarray(12, 16).toString();
      expect(["VP8X", "VP8L"]).toContain(fmt);          // extended / lossless => can carry alpha
      if (fmt === "VP8X") expect(buf[20] & 0x10).toBe(0x10); // alpha flag set
      expect(m.ax).toBeGreaterThan(0);
      expect(m.ax).toBeLessThan(m.w);
    }
  });

  it("has a portrait and no leftover 3D model", () => {
    expect(existsSync(resolve(__dirname, "../../public/qira/qira-portrait.webp"))).toBe(true);
    expect(existsSync(resolve(__dirname, "../../public/models/qira.glb"))).toBe(false);
  });

  it("every reaction in the catalogue has a pose, and every pose exists", () => {
    expect(SCENARIO_COUNT).toBe(29);
    expect(Object.keys(REACTIONS).length).toBe(29);
    for (const id of Object.keys(REACTIONS)) {
      expect(REACTION_SPRITE[id], `no pose for ${id}`).toBeTruthy();
      expect(SPRITE_KEYS).toContain(REACTION_SPRITE[id]);
    }
    for (const k of Object.values(SOCIAL_SPRITE)) expect(SPRITE_KEYS).toContain(k);
    expect(SPRITE_KEYS).toContain(NEUTRAL);
  });

  it("security reactions use clearly serious poses, good news uses happy ones", () => {
    for (const id of ["risk.high", "suspicious.activity", "session.revoked", "audit.failed"]) expect(spriteForReaction(id)).toBe("riskAlert");
    for (const id of ["login.failed", "face.failed", "rbac.denied"]) expect(spriteForReaction(id)).toBe("loginFailed");
    for (const id of ["login.success", "face.success"]) expect(["loginSuccess", "success"]).toContain(spriteForReaction(id));
  });

  it("planFor picks the pose and keeps the warning flag from the engine", () => {
    const plan = planFor({ key: 3, id: "audit.failed", visual: REACTIONS["audit.failed"].visual, warning: true }, "idle");
    expect(plan.sprite).toBe("riskAlert");
    expect(plan.warning).toBe(true);
    expect(planFor(null, "idle").sprite).toBe(NEUTRAL);
    expect(planFor(null, "monitoring").scan).toBe(true);
  });

  it("body motions settle back to rest", () => {
    for (const kind of ["nod", "shake"]) {
      const end = bodyMotion(kind, 5);
      expect(end).toEqual({ dy: 0, dx: 0, rot: 0, scale: 0 });
    }
    expect(bodyMotion(null, 1)).toEqual({ dy: 0, dx: 0, rot: 0, scale: 0 });
    expect(TONE_COLOR.critical).toBeTruthy();
  });
});
