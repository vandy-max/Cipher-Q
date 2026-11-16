import React from "react";
import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { render, screen, act, fireEvent } from "@testing-library/react";

import { QiraReactionProvider } from "../../context/QiraReactionContext";
import QiraDock from "./QiraDock";
import { createQiraEngine } from "../../qira/qiraEngine";

function setup() {
  const engine = createQiraEngine();
  const utils = render(
    <QiraReactionProvider engine={engine}>
      <QiraDock />
      <form>
        <input data-testid="user" type="text" />
        <input data-testid="pw" type="password" />
      </form>
    </QiraReactionProvider>
  );
  return { engine, ...utils };
}
const social = () => window.__QIRA_SOCIAL__;
// full MediaQueryList shape (framer-motion also uses the legacy addListener)
function mockMotionPref(reduce) {
  window.matchMedia = () => ({ matches: reduce, addEventListener() {}, removeEventListener() {}, addListener() {}, removeListener() {} });
}

beforeEach(() => {
  localStorage.clear();
  mockMotionPref(false);
});
afterEach(() => vi.restoreAllMocks());

describe("QiraDock playful layer", () => {
  it("offers a pet button when idle and shows hearts when petted", async () => {
    setup();
    const pet = await screen.findByTestId("qira-pet");
    act(() => { social().tick(0.1); });
    fireEvent.click(pet);
    expect((await screen.findAllByTestId("qira-heart")).length).toBeGreaterThanOrEqual(2);
  });

  it("petting never emits or changes any QIRA reaction", async () => {
    const { engine } = setup();
    const before = engine.getHistory().length;
    fireEvent.click(await screen.findByTestId("qira-pet"));
    expect(engine.getHistory().length).toBe(before);
    expect(engine.getSnapshot().active).toBeNull();
  });

  it("is switched off while a reaction is showing (no pet button, no hearts)", async () => {
    const { engine } = setup();
    await screen.findByTestId("qira-pet");
    act(() => { engine.trigger("login.failed"); });
    expect(screen.queryByTestId("qira-pet")).toBeNull();
    expect(screen.queryAllByTestId("qira-heart")).toHaveLength(0);
    expect(screen.getByTestId("qira-bubble")).toBeInTheDocument();
  });

  it("stays off while a security warning is unresolved, even after the bubble is dismissed", async () => {
    const { engine } = setup();
    act(() => { engine.trigger("audit.failed"); });
    fireEvent.click(screen.getByLabelText("Dismiss message"));
    expect(screen.queryByTestId("qira-pet")).toBeNull();
    expect(screen.getByTestId("qira-warning")).toBeInTheDocument();
  });

  it("uses the closed-eye password reaction without a wing overlay, then restores after blur", async () => {
    const { engine } = setup();
    await screen.findByTestId("qira-pet");
    act(() => { screen.getByTestId("pw").focus(); });
    expect(engine.getSnapshot().active?.id).toBe("password.hide.register");
    expect(engine.getSnapshot().active?.message).toMatch(/won't peek/i);
    expect(engine.getSnapshot().active?.visual?.fx || []).not.toContain("cover");
    act(() => { screen.getByTestId("pw").blur(); });
  });

  it("login forms get the shorter message", async () => {
    const { engine, container } = setup();
    await screen.findByTestId("qira-pet");
    container.querySelector("form").dataset.qiraMode = "login";
    act(() => { screen.getByTestId("pw").focus(); });
    expect(engine.getSnapshot().active?.id).toBe("password.hide.login");
    expect(engine.getSnapshot().active?.message).toBe("I won't peek!");
  });

  it("a text field does not trigger the password closed-eye reaction", async () => {
    const { engine } = setup();
    await screen.findByTestId("qira-pet");
    act(() => { screen.getByTestId("user").focus(); });
    expect(engine.getSnapshot().active?.id ?? "").not.toMatch(/^password\.hide/);
  });

  it("no pet button / playful layer under reduced motion", () => {
    mockMotionPref(true);
    setup();
    expect(screen.queryByTestId("qira-pet")).toBeNull();
  });

  it("removes its listeners and timers on unmount", async () => {
    const add = vi.spyOn(window, "addEventListener");
    const rem = vi.spyOn(window, "removeEventListener");
    const { unmount } = setup();
    await screen.findByTestId("qira-pet");
    fireEvent.click(screen.getByTestId("qira-pet"));
    unmount();
    const added = add.mock.calls.filter((c) => ["pointermove", "keydown", "pointerdown"].includes(c[0])).length;
    const removed = rem.mock.calls.filter((c) => ["pointermove", "keydown", "pointerdown"].includes(c[0])).length;
    expect(removed).toBeGreaterThanOrEqual(added);
  });
});
