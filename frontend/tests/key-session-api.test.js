import assert from "node:assert/strict";
import { afterEach, beforeEach, test } from "node:test";

const api = await import("../src/services/api.js");
const originalFetch = globalThis.fetch;
const originalSetTimeout = globalThis.setTimeout;
const storage = new Map([["ibqc_token", "test-token"]]);

beforeEach(() => {
  globalThis.localStorage = { getItem: (key) => storage.get(key) ?? null };
});

afterEach(() => {
  globalThis.fetch = originalFetch;
  globalThis.setTimeout = originalSetTimeout;
});

test("createKeySession sends its authorized request and returns the server result", async () => {
  const result = { key_session_id: "ks_test_12345678", status: "ACTIVE" };
  let request;
  globalThis.fetch = async (url, options) => {
    request = { url, options };
    return new Response(JSON.stringify(result), { status: 201 });
  };

  assert.deepEqual(await api.createKeySession(1024, 0), result);
  assert.equal(request.url, "/api/key-sessions");
  assert.equal(request.options.method, "POST");
  assert.equal(request.options.headers.Authorization, "Bearer test-token");
  assert.deepEqual(JSON.parse(request.options.body), {
    n_qubits: 1024,
    simulate_eavesdropper_prob: 0,
  });
});

for (const [status, payload] of [
  [401, { detail: "authentication required" }],
  [403, { detail: "attack simulation is disabled in this deployment" }],
  [422, { detail: [{ loc: ["body", "n_qubits"], msg: "Input should be greater than or equal to 64" }] }],
]) {
  test(`createKeySession preserves HTTP ${status} error details`, async () => {
    globalThis.fetch = async () => new Response(JSON.stringify(payload), { status });

    await assert.rejects(api.createKeySession(1024, 0), (error) => {
      assert.equal(error.status, status);
      assert.deepEqual(error.detail, payload.detail);
      assert.deepEqual(error.body, payload);
      return true;
    });
  });
}

test("createKeySession converts an abort into a safe timeout error", async () => {
  globalThis.setTimeout = (callback, delay, ...args) =>
    originalSetTimeout(callback, delay === 120_000 ? 0 : delay, ...args);
  globalThis.fetch = async (_url, { signal }) =>
    new Promise((resolve, reject) => {
      signal.addEventListener("abort", () => reject(new DOMException("Aborted", "AbortError")), { once: true });
    });

  await assert.rejects(api.createKeySession(1024, 0), (error) => {
    assert.equal(error.status, 0);
    assert.equal(error.body.code, "REQUEST_TIMEOUT");
    assert.match(error.message, /Check your key-session list before trying again/);
    return true;
  });
});

test("createKeySession does not turn network failures into success", async () => {
  globalThis.fetch = async () => {
    throw new TypeError("Failed to fetch");
  };

  await assert.rejects(api.createKeySession(1024, 0), {
    name: "TypeError",
    message: "Failed to fetch",
  });
});
