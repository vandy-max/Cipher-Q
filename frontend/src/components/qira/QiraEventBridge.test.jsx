import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { render, act } from "@testing-library/react";
import { QiraReactionProvider } from "../../context/QiraReactionContext";
import { createQiraEngine } from "../../qira/qiraEngine";
import { deriveMonitoringState } from "../monitoring/monitoringState";

// The bridge OBSERVES these two contexts; we feed it the same shapes the real
// backend-driven providers expose and assert QIRA mirrors the SAME classification
// the monitoring UI uses (deriveMonitoringState). QIRA never computes risk itself.
const mon = { monitoringSessionId: null, snapshot: null, isMonitoring: false, reauthRequired: false, connectionState: "connected" };
const qira = { decision: null, assessing: false };
vi.mock("../../context/MonitoringContext", () => ({ useMonitoringContext: () => mon }));
vi.mock("../../context/QiraContext", () => ({ useQiraContext: () => qira }));

import QiraEventBridge from "./QiraEventBridge";

let engine;
let view;
const ui = () => (
  <QiraReactionProvider engine={engine}>
    <QiraEventBridge />
  </QiraReactionProvider>
);
const rerender = () => act(() => { view.rerender(ui()); });
const set = (patch) => { Object.assign(mon, patch); rerender(); };
const snap = (status, extra = {}) => ({ status, ...extra });
const live = (status, extra) => set({ monitoringSessionId: "s1", isMonitoring: true, snapshot: snap(status, extra) });
const ids = () => engine.getHistory().map((h) => h.id);
const fg = () => engine.getSnapshot().active?.id;

beforeEach(() => {
  vi.useFakeTimers();
  Object.assign(mon, { monitoringSessionId: null, snapshot: null, isMonitoring: false, reauthRequired: false, connectionState: "connected" });
  Object.assign(qira, { decision: null, assessing: false });
  engine = createQiraEngine();
  view = render(ui());
});
afterEach(() => { vi.useRealTimers(); });

describe("QiraEventBridge: mirrors the monitoring UI state", () => {
  it("OFF: laptop-working resting pose immediately, the OFF message only once it is stable", () => {
    expect(deriveMonitoringState(mon)).toBe("off");
    expect(engine.getSnapshot().ambient).toBe("off");
    expect(ids()).not.toContain("monitoring.off"); // not announced during the brief pre-session window
    act(() => { vi.advanceTimersByTime(1600); });
    expect(ids()).toContain("monitoring.off");
    expect(engine.getSnapshot().active.message).toMatch(/Monitoring is currently OFF/);
  });

  it("does not announce OFF if monitoring starts right after login", () => {
    set({ isMonitoring: true }); // verification pending
    act(() => { vi.advanceTimersByTime(3000); });
    expect(ids()).not.toContain("monitoring.off");
  });

  it("ACTIVE: confident pose (ambient active) + one message per transition, never repeated", () => {
    live("active");
    set({ snapshot: snap("active", { n: 2 }) });
    set({ snapshot: snap("active", { n: 3 }) });
    expect(engine.getSnapshot().ambient).toBe("active");
    expect(ids().filter((i) => i === "monitoring.on")).toHaveLength(1);
  });

  it("does not claim ACTIVE before the backend confirms (verification pending)", () => {
    set({ isMonitoring: true });
    expect(ids()).not.toContain("monitoring.on");
    expect(engine.getSnapshot().ambient).toBe("idle");
  });

  it("WARNING: sticky orange concerned reaction; the normal secure pose is not shown", () => {
    live("active");
    set({ snapshot: snap("warning", { reason_code: "camera_unavailable", current_risk: "medium" }) });
    expect(deriveMonitoringState(mon)).toBe("warning");
    expect(engine.hasSticky("monitoring.warning")).toBe(true);
    expect(fg()).toBe("monitoring.warning");
    expect(engine.getSnapshot().ambient).toBe("idle");
  });

  it("aggregate HIGH risk cannot jump ahead of the backend 3/6/8 failure thresholds", () => {
    live("active");
    set({ snapshot: snap("warning", { current_risk: "high", consecutive_face_failures: 5 }) });
    expect(deriveMonitoringState(mon)).toBe("warning");
    expect(engine.hasSticky("monitoring.warning")).toBe(true);
    expect(engine.hasSticky("monitoring.highrisk")).toBe(false);
    expect(fg()).toBe("monitoring.warning");
    expect(engine.getSnapshot().ambient).not.toBe("active");
  });

  it("recovery warning -> active clears the monitoring warning and restores the ACTIVE pose; unrelated alerts survive", () => {
    live("active");
    set({ snapshot: snap("warning", { current_risk: "medium" }) });
    engine.trigger("audit.failed"); // unrelated critical alert
    set({ snapshot: snap("active") });
    expect(engine.hasSticky("monitoring.warning")).toBe(false);
    expect(engine.hasSticky("audit.failed")).toBe(true);
    expect(engine.getSnapshot().ambient).toBe("active");
  });

  it("warning remains warning until the backend changes status to reauth_required", () => {
    live("active");
    set({ snapshot: snap("warning", { current_risk: "critical", consecutive_face_failures: 5 }) });
    expect(engine.hasSticky("monitoring.warning")).toBe(true);
    expect(engine.hasSticky("monitoring.highrisk")).toBe(false);
    set({ snapshot: snap("reauth_required", { consecutive_face_failures: 6 }) });
    expect(engine.hasSticky("monitoring.warning")).toBe(false);
    expect(engine.hasSticky("monitoring.reauth")).toBe(true);
  });

  it("monitoring disabled mid-session: back to the laptop pose, warnings cleared", () => {
    live("warning", { current_risk: "medium" });
    expect(engine.hasSticky("monitoring.warning")).toBe(true);
    set({ monitoringSessionId: null, isMonitoring: false, snapshot: null });
    expect(deriveMonitoringState(mon)).toBe("off");
    expect(engine.hasSticky("monitoring.warning")).toBe(false);
    expect(engine.getSnapshot().ambient).toBe("off");
  });

  it("stale snapshot / lost connection: the UI shows WARNING, so QIRA shows an orange state (and says the link is lost)", () => {
    live("active");
    set({ connectionState: "lost" });
    expect(deriveMonitoringState(mon)).toBe("warning");
    expect(engine.getSnapshot().ambient).toBe("idle"); // never the confident pose on a stale snapshot
    expect(engine.hasSticky("api.unavailable")).toBe(true);
  });

  it("reconnection: connectionState back to connected + active snapshot restores ACTIVE", () => {
    live("active");
    set({ connectionState: "lost" });
    set({ connectionState: "connected" });
    expect(engine.hasSticky("api.unavailable")).toBe(false);
    expect(engine.getSnapshot().ambient).toBe("active");
  });

  it("a lost link preserves the backend warning even when aggregate risk is high", () => {
    live("warning", { current_risk: "high" });
    set({ connectionState: "lost" });
    expect(deriveMonitoringState(mon)).toBe("warning"); // UI rule: lost -> warning
    expect(engine.getSnapshot().ambient).toBe("idle");
  });

  it("revoked -> session.revoked (sticky, critical)", () => {
    live("active");
    set({ snapshot: snap("revoked") });
    expect(engine.hasSticky("session.revoked")).toBe(true);
  });

  it("reauth_required / reauthRequired flag -> sticky re-authentication warning, not 'revoked'", () => {
    live("active");
    set({ snapshot: snap("reauth_required") });
    expect(engine.hasSticky("monitoring.reauth")).toBe(true);
    expect(engine.hasSticky("session.revoked")).toBe(false);
  });

  it("the new active session after re-authentication clears session.revoked", () => {
    live("active");
    set({ snapshot: snap("revoked") });
    set({ monitoringSessionId: "s2", snapshot: snap("active") });
    expect(engine.hasSticky("session.revoked")).toBe(false);
    expect(engine.getSnapshot().ambient).toBe("active");
  });

  it("sleep/idle personality can never hide a monitoring warning (sticky outranks lower priorities)", () => {
    live("warning", { current_risk: "medium" });
    engine.trigger("nav.page"); // low priority, must not take the foreground
    expect(fg()).toBe("monitoring.warning");
  });

  it("assessment activity shows risk.started and releases it", () => {
    live("active");
    Object.assign(qira, { assessing: true }); rerender();
    expect(ids()).toContain("risk.started");
    Object.assign(qira, { assessing: false }); rerender();
  });
});
