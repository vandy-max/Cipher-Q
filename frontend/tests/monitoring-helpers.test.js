import assert from "node:assert/strict";
import { test } from "node:test";
import {
  backoffDelay, classifyMonitoringError, isTemporary, isTerminal, needsFaceOnly,
} from "../src/components/monitoring/monitoringErrors.js";
import { createLeaderElection } from "../src/components/monitoring/monitoringLeader.js";

const e = (status, detail) => ({ status, detail, message: detail });

test("classifies temporary vs security failures", () => {
  assert.equal(classifyMonitoringError(new TypeError("Failed to fetch")), "network");
  assert.equal(classifyMonitoringError(e(0, "x")), "network");
  assert.equal(classifyMonitoringError(e(503, "x")), "transient");
  assert.equal(classifyMonitoringError(e(429, "x")), "transient");
  assert.equal(classifyMonitoringError(e(409, "nonce")), "nonce");
  assert.equal(classifyMonitoringError(e(401, "x")), "auth");
  assert.equal(classifyMonitoringError(e(404, "x")), "gone");
  assert.ok(isTemporary("network") && isTemporary("transient") && !isTemporary("auth"));
});

test("403 reasons map to distinct recovery paths", () => {
  const k = (d) => classifyMonitoringError(e(403, d));
  assert.equal(k("a fresh step-up verification is required to start monitoring"), "stepup_required");
  assert.equal(k("device is revoked; re-authentication is required before monitoring can start"), "device_revoked");
  assert.equal(k("session is expired; re-authentication is required before monitoring can start"), "session_expired");
  assert.equal(k("session is invalid; re-authentication is required before monitoring can start"), "session_revoked");
  assert.equal(k("not authorized"), "forbidden");
  assert.ok(needsFaceOnly("session_expired") && needsFaceOnly("stepup_required"));
  assert.ok(!needsFaceOnly("session_revoked") && !needsFaceOnly("device_revoked"));
  assert.ok(isTerminal("session_revoked") && !isTerminal("stepup_required"));
});

test("backoff is capped exponential", () => {
  assert.equal(backoffDelay(0, 2500, 15000), 2500);
  assert.equal(backoffDelay(1, 2500, 15000), 2500);
  assert.equal(backoffDelay(2, 2500, 15000), 5000);
  assert.equal(backoffDelay(3, 2500, 15000), 10000);
  assert.equal(backoffDelay(9, 2500, 15000), 15000);
});

function fakeLocks() {
  const held = new Map();
  const queue = new Map();
  const grant = (name) => {
    const q = queue.get(name) || [];
    if (held.get(name) || !q.length) return;
    const { cb, resolve, reject } = q.shift();
    held.set(name, true);
    Promise.resolve(cb()).then(resolve, reject).finally(() => { held.set(name, false); grant(name); });
  };
  return {
    request(name, _opts, cb) {
      return new Promise((resolve, reject) => {
        (queue.get(name) || queue.set(name, []).get(name)).push({ cb, resolve, reject });
        grant(name);
      });
    },
  };
}
const tick = () => new Promise((r) => setTimeout(r, 5));

test("only one tab leads; a follower takes over when the leader leaves", async () => {
  const locks = fakeLocks();
  const a = [], b = [];
  const A = createLeaderElection("s1", (v) => a.push(v), locks);
  await tick();
  const B = createLeaderElection("s1", (v) => b.push(v), locks);
  await tick();
  assert.ok(A.isLeader() && !B.isLeader());
  A.release();
  await tick();
  assert.ok(!A.isLeader() && B.isLeader());
  assert.deepEqual(b, [true]);
  B.release();
});

test("without Web Locks the tab leads (legacy behaviour)", () => {
  const seen = [];
  const L = createLeaderElection("s1", (v) => seen.push(v), null);
  assert.ok(L.isLeader());
  assert.deepEqual(seen, [true]);
});
