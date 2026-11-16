// Behavioural tests for the Live Monitoring provider (React hooks, timers, retries, tabs).
// Not part of `npm test` (which uses node:test). Run with test-only tooling that is intentionally NOT a
// project dependency:
//   npm i --no-save vitest@2 jsdom@24 @testing-library/react@14
//   npx vitest run --environment jsdom tests/monitoring-context.spec.jsx
import React from "react";
import { act, render } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const api = vi.hoisted(() => ({
  startMonitoring: vi.fn(), monitoringHeartbeat: vi.fn(), stopMonitoring: vi.fn(), getMonitoringStatus: vi.fn(),
  getMonitoringForSession: vi.fn(), getDeviceStatus: vi.fn(), getSessionStatus: vi.fn(), reauthenticateSession: vi.fn(),
  issueStepUpChallenge: vi.fn(), stepUp: vi.fn(),
}));
vi.mock("../src/services/api", () => api);
vi.mock("../src/services/faceIdentity", () => ({
  loadModels: async () => {}, detectFaceLite: async () => ({ ok: true }), assessQuality: () => ({ ok: true }),
  extractDescriptor: async () => Array.from({ length: 128 }, () => Math.random()),
}));
vi.mock("react-webcam", async () => {
  const R = await import("react");
  return { default: R.forwardRef(({ onUserMedia }, ref) => {
    R.useImperativeHandle(ref, () => ({ video: { readyState: 4 } }));
    R.useEffect(() => { onUserMedia?.(); }, []); // eslint-disable-line
    return null;
  }) };
});

const { MonitoringProvider, useMonitoringContext } = await import("../src/context/MonitoringContext");

const user = { userId: 1, role: "USER_LEVEL_1" };
const snap = (rev, extra = {}) => ({
  monitoring_session_id: "m1", snapshot_revision: rev, heartbeat_nonce: `n${rev}`, status: "active",
  current_authorization_state: "valid", ...extra,
});
const err = (status, detail = "x") => Object.assign(new Error(detail), { status, detail });
let ctx;
function Probe() { ctx = useMonitoringContext(); return null; }
const mount = () => render(<MonitoringProvider user={user} deviceId="dev_1" sessionId="sess_1"><Probe /></MonitoringProvider>);
const advance = (ms) => act(async () => { await vi.advanceTimersByTimeAsync(ms); });

beforeEach(() => {
  vi.useFakeTimers();
  sessionStorage.clear();
  Object.values(api).forEach((f) => f.mockReset());
  let rev = 0;
  api.getMonitoringForSession.mockResolvedValue(snap(1));
  api.getMonitoringStatus.mockImplementation(async () => snap(++rev));
  api.getDeviceStatus.mockResolvedValue({ device_id: "dev_1", revoked: false });
  api.getSessionStatus.mockResolvedValue({ session_id: "sess_1", revoked: false, version: 1 });
  api.monitoringHeartbeat.mockImplementation(async () => snap(++rev + 100));
  api.stopMonitoring.mockResolvedValue(null);
  Object.defineProperty(navigator, "onLine", { value: true, configurable: true });
});
afterEach(() => { vi.useRealTimers(); delete navigator.locks; });

describe("Live Monitoring provider", () => {
  it("recovers an existing session after refresh and heartbeats at the configured cadence (single loop)", async () => {
    mount(); await advance(100);
    expect(ctx.isMonitoring).toBe(true);
    expect(api.startMonitoring).not.toHaveBeenCalled();
    await advance(10_000);
    const n = api.monitoringHeartbeat.mock.calls.length;
    expect(n).toBeGreaterThanOrEqual(3); expect(n).toBeLessThanOrEqual(5);
  });

  it("nonce conflict (409) re-syncs without raising 'connection lost' or an error", async () => {
    api.monitoringHeartbeat.mockRejectedValueOnce(err(409, "nonce mismatch")).mockImplementation(async () => snap(200));
    mount(); await advance(100);
    await advance(2600);
    expect(ctx.connectionState).toBe("connected"); expect(ctx.error).toBe("");
    await advance(2600);
    expect(ctx.snapshot.snapshot_revision).toBe(200);
  });

  it("network failures back off, show connection lost, never end monitoring, and recover", async () => {
    api.monitoringHeartbeat.mockRejectedValue(new TypeError("Failed to fetch"));
    mount(); await advance(100);
    await advance(30_000);
    expect(ctx.isMonitoring).toBe(true); expect(ctx.connectionState).toBe("lost");
    expect(api.monitoringHeartbeat.mock.calls.length).toBeLessThan(8);   // 12 without backoff
    api.monitoringHeartbeat.mockImplementation(async () => snap(300));
    await advance(16_000);
    expect(ctx.connectionState).toBe("connected"); expect(ctx.snapshot.snapshot_revision).toBe(300);
  });

  it("server 5xx is temporary (keeps monitoring); 401 ends it", async () => {
    api.monitoringHeartbeat.mockRejectedValue(err(503, "boom internals"));
    mount(); await advance(100); await advance(6000);
    expect(ctx.isMonitoring).toBe(true); expect(ctx.error).not.toContain("internals");
    api.monitoringHeartbeat.mockRejectedValue(err(401, "authentication required"));
    // a real expired login fails every authenticated call, including the re-attach lookup
    api.getMonitoringForSession.mockRejectedValue(err(401, "authentication required"));
    api.getMonitoringStatus.mockRejectedValue(err(401, "authentication required"));
    await advance(45_000);   // loop may be sitting in a capped backoff delay from the 5xx run
    expect(ctx.isMonitoring).toBe(false);
  });

  it("404 re-attaches to a newer live session instead of ending monitoring", async () => {
    api.monitoringHeartbeat.mockRejectedValueOnce(err(404, "monitoring session not found")).mockImplementation(async () => snap(1, { monitoring_session_id: "m2" }));
    api.getMonitoringForSession.mockResolvedValueOnce(snap(1)).mockResolvedValue(snap(5, { monitoring_session_id: "m2" }));
    mount(); await advance(100); await advance(3000);
    expect(ctx.isMonitoring).toBe(true); expect(ctx.monitoringSessionId).toBe("m2");
  });

  it("offline: sends no heartbeats, reports lost, resumes on 'online'", async () => {
    mount(); await advance(100);
    Object.defineProperty(navigator, "onLine", { value: false, configurable: true });
    const before = api.monitoringHeartbeat.mock.calls.length;
    await advance(10_000);
    expect(api.monitoringHeartbeat.mock.calls.length).toBe(before); expect(ctx.connectionState).toBe("lost");
    Object.defineProperty(navigator, "onLine", { value: true, configurable: true });
    await act(async () => { window.dispatchEvent(new Event("online")); await vi.advanceTimersByTimeAsync(200); });
    expect(ctx.connectionState).toBe("connected");
  });

  it("hiding the tab does not inject a failed identity tick", async () => {
    mount(); await advance(100);
    Object.defineProperty(document, "hidden", { value: true, configurable: true });
    document.dispatchEvent(new Event("visibilitychange"));
    await advance(6000);
    expect(api.monitoringHeartbeat.mock.calls.every((c) => c[2].facePresent === true)).toBe(true);
    Object.defineProperty(document, "hidden", { value: false, configurable: true });
  });

  it("a missing step-up grant is NOT shown as a revoked session / admin approval", async () => {
    api.getMonitoringForSession.mockRejectedValue(err(404));
    sessionStorage.setItem("ibqc_pending_monitoring_face_confidence", "1");
    api.startMonitoring.mockRejectedValue(err(403, "a fresh step-up verification is required to start monitoring"));
    mount(); await advance(300);
    expect(ctx.reauthRequired).toBe(false);
  });

  it("an expired session is reported as face-only recovery, a revoked one as approval-required", async () => {
    api.getMonitoringForSession.mockRejectedValue(err(404));
    sessionStorage.setItem("ibqc_pending_monitoring_face_confidence", "1");
    api.startMonitoring.mockRejectedValue(err(403, "session is expired; re-authentication is required before monitoring can start"));
    mount(); await advance(300);
    expect(ctx.reauthRequired).toBe(true); expect(ctx.reauthKind).toBe("session_expired");
  });

  it("two tabs: only the leader sends heartbeats; the follower takes over when the leader closes", async () => {
    const held = new Map(); const queue = [];
    const grant = () => { if (held.get("l") || !queue.length) return; const q = queue.shift(); held.set("l", true);
      Promise.resolve(q.cb()).finally(() => { held.set("l", false); grant(); }); };
    Object.defineProperty(navigator, "locks", { configurable: true, value: { request: (_n, _o, cb) => new Promise((res) => { queue.push({ cb: async () => { await cb(); res(); } }); grant(); }) } });
    const a = mount(); await advance(100);
    const b = mount(); await advance(100);
    api.monitoringHeartbeat.mockClear();
    await advance(10_000);
    const both = api.monitoringHeartbeat.mock.calls.length;
    expect(both).toBeLessThanOrEqual(5);                   // one loop, not two
    a.unmount(); await advance(100);
    api.monitoringHeartbeat.mockClear();
    await advance(10_000);
    expect(api.monitoringHeartbeat.mock.calls.length).toBeGreaterThanOrEqual(3);   // follower took over
    b.unmount();
  });
});
