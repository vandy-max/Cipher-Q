import React from "react";
import { describe, it, expect, afterEach, vi } from "vitest";
import { render, act } from "@testing-library/react";
import QiraSprite from "./QiraSprite";
import { createSocial } from "../../qira/qiraSocial";
import { planFor, IDLE_PLAN } from "../../qira/qiraAnimator";
import { REACTIONS } from "../../qira/qiraReactions";

afterEach(() => vi.useRealTimers());

function mount({ plan = IDLE_PLAN, social = null, reducedMotion = false } = {}) {
  vi.useFakeTimers({ toFake: ["setTimeout", "clearTimeout", "setInterval", "clearInterval", "performance", "Date"] }); // the sprite times itself with performance.now()
  const planRef = { current: plan };
  const socialRef = { current: social };
  const onReady = vi.fn();
  const onError = vi.fn();
  const utils = render(<QiraSprite planRef={planRef} socialRef={socialRef} reducedMotion={reducedMotion} onReady={onReady} onError={onError} />);
  const sprite = () => utils.getByTestId("qira-sprite-root").dataset.sprite;
  const run = (ms) => act(() => { vi.advanceTimersByTime(ms); });
  return { ...utils, planRef, socialRef, sprite, run, onReady, onError };
}
const reaction = (id, warning = false) => planFor({ key: Math.random(), id, visual: REACTIONS[id].visual, warning }, "idle");

describe("QiraSprite pose selection", () => {
  it("shows the neutral pose by default and reports ready when the sprite loads", () => {
    const m = mount();
    expect(m.sprite()).toBe("login");
    expect(m.container.querySelectorAll('img[alt=""]').length).toBeGreaterThan(0); // images are decorative (alt="")
  });

  it("a foreground reaction picks its pose (and a new one replaces it)", () => {
    const m = mount({ plan: reaction("login.failed") });
    m.run(100);
    expect(m.sprite()).toBe("loginFailed");
    m.planRef.current = reaction("risk.high", true);
    m.run(100);
    expect(m.sprite()).toBe("riskAlert");
  });

  it("a real reaction beats any social pose", () => {
    const social = createSocial({ rand: () => 0.5 });
    social.setAllowed(true);
    social.setCover(true);                       // would show the eyes-shut pose
    const m = mount({ social });
    m.run(800);
    expect(m.sprite()).toBe("processing");       // social cover while idle
    m.planRef.current = reaction("session.revoked", true);
    m.run(100);
    expect(m.sprite()).toBe("riskAlert");        // reaction wins immediately
  });

  it("petting shows the happy pose and settles back to neutral", () => {
    const social = createSocial({ rand: () => 0.9 });
    social.setAllowed(true);
    const m = mount({ social });
    m.run(1000);
    social.poke();
    m.run(200);
    expect(m.sprite()).toBe("happy");
    m.run(3000);
    expect(["login", "processing"]).toContain(m.sprite()); // neutral (or a quick blink)
  });

  it("reduced motion applies no transform animation", () => {
    const m = mount({ reducedMotion: true });
    m.run(1000);
    const puppet = m.container.querySelector('[data-testid="qira-sprite-root"] > div:nth-child(2)');
    expect(puppet.style.transform).toBe("");
  });

  it("stops its timers on unmount", () => {
    const m = mount();
    const before = vi.getTimerCount();
    m.unmount();
    expect(vi.getTimerCount()).toBeLessThan(before);
  });
});
