import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import {
  classifyApiError, isUnavailableError, isNetworkError, riskEventForLevel,
  RBAC_DENIED_RE, INTENT_MISMATCH_RE, RISK_REJECTED_RE, FACE_FAILED_RE,
} from "./classify";

const err = (status, detail) => Object.assign(new Error(typeof detail === "string" ? detail : JSON.stringify(detail)), { status, detail });

describe("classifyApiError", () => {
  it("network failures and 5xx are 'unavailable', never a denial", () => {
    expect(isNetworkError(new TypeError("Failed to fetch"))).toBe(true);
    expect(isUnavailableError(new TypeError("Failed to fetch"))).toBe(true);
    expect(isUnavailableError(err(503, "x"))).toBe(true);
    expect(isUnavailableError(err(502, "bad gateway"))).toBe(true);
    expect(classifyApiError(new TypeError("Failed to fetch"))).toBeNull();
    expect(classifyApiError(err(500, "boom"))).toBeNull();
  });

  it("a 4xx is a real answer from a reachable backend", () => {
    expect(isUnavailableError(err(403, "no"))).toBe(false);
    expect(isNetworkError(err(401, "Invalid credentials"))).toBe(false);
  });

  it("maps real backend denials to the right reaction", () => {
    expect(classifyApiError(err(403, "this operation requires one of the following roles: ['ADMIN']"))).toBe("rbac.denied");
    expect(classifyApiError(err(403, "not authorized to decrypt this resource"))).toBe("rbac.denied");
    expect(classifyApiError(err(403, "Intent hash mismatch: stored=abc, recreated=def"))).toBe("intent.mismatch");
    expect(classifyApiError(err(409, "submitted intent does not match the approved intent's canonical hash"))).toBe("intent.mismatch");
    expect(classifyApiError(err(403, "request rejected: high risk assessment"))).toBe("risk.high");
    expect(classifyApiError(err(428, "face re-verification required"))).toBe("risk.elevated");
    expect(classifyApiError(err(403, "face verification failed"))).toBe("face.failed");
    expect(classifyApiError(err(401, "face verification required"))).toBe("face.failed");
  });

  it("does not guess: unrecognised denials produce no reaction", () => {
    expect(classifyApiError(err(403, "some policy rule rejected this"))).toBeNull();
    expect(classifyApiError(err(409, "intent 5 is not eligible for encryption in lifecycle state 'draft'"))).toBeNull();
    expect(classifyApiError(err(400, "malformed input"))).toBeNull();
    expect(classifyApiError(null)).toBeNull();
  });

  it("maps the existing risk vocabulary", () => {
    expect(riskEventForLevel("low")).toBe("risk.low");
    expect(riskEventForLevel("medium")).toBe("risk.elevated");
    expect(riskEventForLevel("HIGH")).toBe("risk.high");
    expect(riskEventForLevel("critical")).toBe("risk.high");
    expect(riskEventForLevel("???")).toBeNull();
    expect(riskEventForLevel(undefined)).toBeNull();
  });
});

// Contract test: the patterns we match must still correspond to messages that
// exist in the backend source. If someone rewords a backend message, this fails
// loudly instead of QIRA silently going quiet.
describe("backend message contract", () => {
  const read = (p) => readFileSync(resolve(__dirname, "../../../backend", p), "utf8");
  it("rbac messages", () => {
    const s = read("api/rbac.py");
    expect(s).toMatch(/requires one of the following roles/);
    expect(s).toMatch(/not authorized to \{action\} this resource/);
    expect(RBAC_DENIED_RE.test("this operation requires one of the following roles: []")).toBe(true);
  });
  it("intent mismatch messages", () => {
    expect(read("crypto/service.py")).toMatch(/Intent hash mismatch/);
    expect(read("api/routers/encryption.py")).toMatch(/submitted intent does not match the approved intent's canonical hash/);
    expect(INTENT_MISMATCH_RE.test("Intent hash mismatch: stored=a, recreated=b")).toBe(true);
  });
  it("risk + face messages", () => {
    const d = read("api/routers/decryption.py");
    expect(d).toMatch(/request rejected: high risk assessment/);
    expect(d).toMatch(/face verification failed/);
    expect(d).toMatch(/face re-verification required/);
    expect(RISK_REJECTED_RE.test("request rejected: high risk assessment")).toBe(true);
    expect(FACE_FAILED_RE.test("face verification required")).toBe(true);
  });
});

describe("responses captured from the running backend (real FastAPI app, mongomock)", () => {
  // Verbatim 403/401 bodies recorded from the real app during E2E (USER_LEVEL_1 token).
  it("recognises the real RBAC denial (403) and not the missing-token 401", () => {
    const rbac = err(403, "this operation requires one of the following roles: ['ADMIN']");
    expect(classifyApiError(rbac)).toBe("rbac.denied");
    expect(isUnavailableError(rbac)).toBe(false);
    expect(classifyApiError(err(401, "Missing Authorization header"))).not.toBe("rbac.denied");
  });
});
