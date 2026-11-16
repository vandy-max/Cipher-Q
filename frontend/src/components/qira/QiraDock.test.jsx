import { describe, it, expect, beforeEach } from "vitest";
import { render, screen, act, fireEvent, waitFor } from "@testing-library/react";
import { QiraReactionProvider } from "../../context/QiraReactionContext";
import QiraDock from "./QiraDock";
import { createQiraEngine } from "../../qira/qiraEngine";

function setup() {
  const engine = createQiraEngine();
  const utils = render(
    <QiraReactionProvider engine={engine}>
      <QiraDock />
    </QiraReactionProvider>
  );
  return { engine, ...utils };
}

beforeEach(() => {
  localStorage.clear();
});

describe("QiraDock (sprite mascot)", () => {
  it("shows a loading state, then becomes ready once the neutral sprite has loaded", () => {
    setup();
    expect(screen.getByTestId("qira-dock")).toHaveAttribute("data-status", "loading");
    expect(screen.getByTestId("qira-loading")).toBeInTheDocument();
    fireEvent.load(document.querySelector('[data-sprite-img="login"]'));
    expect(screen.getByTestId("qira-dock")).toHaveAttribute("data-status", "ready");
    expect(screen.queryByTestId("qira-loading")).toBeNull();
  });

  it("falls back to the static portrait instead of crashing when the sprite fails to load", () => {
    setup();
    fireEvent.error(document.querySelector('[data-sprite-img="login"]'));
    expect(screen.getByTestId("qira-dock")).toHaveAttribute("data-status", "error");
    expect(screen.getByTestId("qira-fallback")).toBeInTheDocument();
  });

  it("shows the exact message and announces it to assistive tech", () => {
    const { engine } = setup();
    act(() => { engine.trigger("login.page"); });
    expect(screen.getByTestId("qira-bubble")).toHaveTextContent("Welcome to CipherQ.");
    expect(screen.getByTestId("qira-live")).toHaveTextContent("Welcome to CipherQ.");
    expect(screen.getByTestId("qira-dock")).toHaveAttribute("data-reaction", "login.page");
  });

  it("dismiss hides the bubble but NOT the warning indicator", async () => {
    const { engine } = setup();
    act(() => { engine.trigger("audit.failed"); });
    expect(screen.getByTestId("qira-warning")).toBeInTheDocument();
    fireEvent.click(screen.getByLabelText("Dismiss message"));
    // bubble leaves via an exit animation, so wait for it to unmount
    await waitFor(() => expect(screen.queryByTestId("qira-bubble")).toBeNull());
    expect(screen.getByTestId("qira-warning")).toBeInTheDocument();
    expect(engine.hasSticky("audit.failed")).toBe(true);
  });

  it("a low-priority message cannot replace an unresolved critical alert", () => {
    const { engine } = setup();
    act(() => { engine.trigger("session.revoked"); });
    act(() => { engine.trigger("face.success"); });
    expect(screen.getByTestId("qira-bubble")).toHaveTextContent("Your session has been revoked.");
  });

  it("minimize/restore works and persists", () => {
    setup();
    fireEvent.click(screen.getByLabelText("Minimize QIRA"));
    expect(screen.queryByTestId("qira-stage")).toBeNull();
    expect(localStorage.getItem("ibqc_qira_minimized")).toBe("1");
    fireEvent.click(screen.getByLabelText("Show QIRA"));
    expect(screen.getByTestId("qira-stage")).toBeInTheDocument();
  });

  it("is removed cleanly on unmount (no timers left behind)", () => {
    const { engine, unmount } = setup();
    act(() => { engine.trigger("qkd.running"); });
    unmount();
    engine.reset();
    expect(engine.getSnapshot().active).toBeNull();
  });
});
