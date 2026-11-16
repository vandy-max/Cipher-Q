import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { qiraEngine } from "./index";
import { reportAuditVerification, resetAuditMemory } from "./report";
import { login, verifyAuditChain } from "../services/api";

const json = (status, body) => ({ ok: status >= 200 && status < 300, status, text: async () => JSON.stringify(body) });

beforeEach(() => { qiraEngine.reset(); resetAuditMemory(); });
afterEach(() => vi.restoreAllMocks());

describe("api layer -> QIRA connectivity signals", () => {
  it("a network error raises 'unavailable' and never a security denial", async () => {
    vi.stubGlobal("fetch", vi.fn().mockRejectedValue(new TypeError("Failed to fetch")));
    await expect(login("a", "b")).rejects.toBeInstanceOf(TypeError); // caller still sees the real error
    const s = qiraEngine.getSnapshot();
    expect(s.active.id).toBe("api.unavailable");
    expect(s.warning).toBe(true);
    expect(qiraEngine.getHistory().some((h) => /rbac|login\.failed|face/.test(h.id))).toBe(false);
  });

  it("a 503 is 'unavailable'; a 401 is NOT (backend answered)", async () => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(json(503, { detail: "down" })));
    await expect(login("a", "b")).rejects.toMatchObject({ status: 503 });
    expect(qiraEngine.hasSticky("api.unavailable")).toBe(true);

    qiraEngine.reset();
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(json(401, { detail: "Invalid credentials" })));
    await expect(login("a", "b")).rejects.toMatchObject({ status: 401 });
    expect(qiraEngine.hasSticky("api.unavailable")).toBe(false);
  });

  it("the warning resolves only after a real successful response", async () => {
    vi.stubGlobal("fetch", vi.fn().mockRejectedValue(new TypeError("Failed to fetch")));
    await expect(login("a", "b")).rejects.toThrow();
    expect(qiraEngine.hasSticky("api.unavailable")).toBe(true);
    // still failing => still shown
    await expect(login("a", "b")).rejects.toThrow();
    expect(qiraEngine.hasSticky("api.unavailable")).toBe(true);
    // backend back (even a 4xx proves reachability)
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(json(200, { token: "t" })));
    await login("a", "b");
    expect(qiraEngine.hasSticky("api.unavailable")).toBe(false);
  });

  it("does not alter the request/response contract", async () => {
    const f = vi.fn().mockResolvedValue(json(200, { user_id: 1 }));
    vi.stubGlobal("fetch", f);
    const out = await login("alice", "pw");
    expect(out).toEqual({ user_id: 1 });
    expect(f).toHaveBeenCalledWith("/api/auth/login", expect.objectContaining({ method: "POST", body: JSON.stringify({ username: "alice", password: "pw" }) }));
  });
});

describe("audit verification reactions", () => {
  it("reacts to real state changes, not to every poll", () => {
    reportAuditVerification({ valid: true });
    expect(qiraEngine.getSnapshot().active.id).toBe("audit.verified");
    qiraEngine.reset();
    reportAuditVerification({ valid: true }); // same state, background poll
    expect(qiraEngine.getSnapshot().active).toBeNull();
  });

  it("a failed verification is sticky and only a later VALID result resolves it", () => {
    reportAuditVerification({ valid: false });
    expect(qiraEngine.getSnapshot().active.id).toBe("audit.failed");
    reportAuditVerification({ valid: false });
    expect(qiraEngine.hasSticky("audit.failed")).toBe(true);
    reportAuditVerification({ valid: true });
    expect(qiraEngine.hasSticky("audit.failed")).toBe(false);
    expect(qiraEngine.getSnapshot().active.id).toBe("audit.verified");
  });

  it("ignores malformed results", () => {
    reportAuditVerification(null);
    reportAuditVerification({});
    expect(qiraEngine.getSnapshot().active).toBeNull();
  });
});
