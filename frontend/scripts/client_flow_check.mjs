// Drives the REAL frontend API client (src/services/api.js) against a live backend (no browser, no mocks).
// Usage: CQ_ADMIN_USER=admin CQ_ADMIN_PW_FILE=pw.txt node scripts/client_flow_check.mjs
import fs from "node:fs";
const BASE = process.env.CQ_BASE || "http://127.0.0.1:8000";
const ADMIN_USER = process.env.CQ_ADMIN_USER || "admin";
const ADMIN_PW_FILE = process.env.CQ_ADMIN_PW_FILE; // 0600 file holding the admin password
if (!ADMIN_PW_FILE) { console.error("set CQ_ADMIN_PW_FILE"); process.exit(2); }
const store = new Map();
globalThis.localStorage = { getItem: (k) => store.get(k) ?? null, setItem: (k, v) => store.set(k, String(v)), removeItem: (k) => store.delete(k) };
const realFetch = globalThis.fetch;
globalThis.fetch = (u, o) => realFetch(BASE + u, o);
const api = await import("../src/services/api.js");
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
let fails = 0;
const ok = (n, c, d = "") => { console.log((c ? "PASS " : "FAIL ") + n + (c ? "" : " " + d)); if (!c) fails++; };
const rnd = (() => { let s = (Date.now() % 2147483646) + 1; return () => (s = (s * 16807) % 2147483647) / 2147483647; })();
const face = Array.from({ length: 128 }, () => +(rnd() * 2 - 1).toFixed(4));
const jit = () => face.map((x) => +(x + (rnd() - 0.5) * 0.004).toFixed(6));
const b64 = (s) => Buffer.from(s).toString("base64");

const adminPw = fs.readFileSync(ADMIN_PW_FILE, "utf8").trim();
const name = "cl" + Math.random().toString(16).slice(2, 8), pw = "Cl-" + Math.random().toString(36).slice(2) + "Zz9!";
const reg = await api.register(name, name + "@example.test", pw);
const userTok = reg.token;
// === user session bootstrap exactly as useAuth.saveAuth does ===
localStorage.setItem("ibqc_token", userTok);
const deviceId = (await api.registerDevice()).device_id;
const sessionId = (await api.createAuthSession(deviceId)).session_id;
ok("server-issued device/session", deviceId.startsWith("dev_") && sessionId.startsWith("sess_"));
// admin
const adm = await api.login(ADMIN_USER, adminPw);
const ref = "CASE-" + (100000 + Math.floor(Math.random() * 899999));
const resource = "vault:client-flow";
localStorage.setItem("ibqc_token", adm.token);
await api.putCase(ref, { title: "Client flow", classification_cap: "RESTRICTED", allowed_resources: [resource], assigned_user_ids: [reg.user_id], status: "OPEN" });
localStorage.setItem("ibqc_token", userTok);
// identity
ok("face status not enrolled", (await api.faceStatus()).enrolled === false);
await api.enrollFace(face, pw);
const g = await api.stepUp(sessionId, jit());
ok("stepUp via client", g.verified === true && g.liveness === "NOT_ESTABLISHED", JSON.stringify(g));
// key session
const ks = await api.createKeySession(1024, 0);
ok("key session, no key returned", ks.status === "ACTIVE" && !JSON.stringify(ks).match(/key_hex|quantum_key/), JSON.stringify(ks).slice(0, 200));
// monitoring
let mon = await api.startMonitoring(deviceId, sessionId);
let nonce = mon.heartbeat_nonce;
for (let i = 0; i < 2; i++) {
  mon = await api.monitoringHeartbeat(mon.monitoring_session_id, nonce, { facePresent: true, probeDescriptor: jit(), cameraAvailable: true });
  nonce = mon.heartbeat_nonce;
}
ok("heartbeats with nonce chain", mon.status === "active" || mon.status === "ACTIVE", mon.status);
// intent exactly like CreateIntentPage.payload
const now = new Date();
const payload = {
  purpose_code: "CASE_INVESTIGATION", purpose_statement: "Investigate suspected card testing fraud", business_reference: ref, resource,
  operations: ["encrypt", "decrypt"], data_scope: { classification: "CONFIDENTIAL", max_bytes: 4096, max_uses: 3 },
  session_id: sessionId, device_id: deviceId, valid_from: new Date(now - 60000).toISOString(), valid_until: new Date(+now + 3600e3).toISOString(),
  evidence_refs: [{ kind: "CASE", ref }], reason: "initial creation",
};
const created = await api.createIntent(payload);
const iid = created.intent_id;
await api.validateIntent(iid);
let view = await api.getIntent(iid);
ok("intent pending approval", view.status === "PENDING_APPROVAL", view.status);
// operation before approval -> REQUIRE_APPROVAL (useSecureOperation payload)
const common = { intent_id: iid, resource, purpose_code: "CASE_INVESTIGATION", session_id: sessionId, device_id: deviceId };
let d = await api.requestDecision({ ...common, operation: "encrypt", key_session_id: ks.key_session_id, requested_bytes: 11 });
ok("REQUIRE_APPROVAL before approval", d.outcome === "REQUIRE_APPROVAL", d.outcome);
localStorage.setItem("ibqc_token", adm.token);
await api.approveIntent(iid, view.version, "APPROVE", "ok");
localStorage.setItem("ibqc_token", userTok);
view = await api.getIntent(iid);
ok("intent approved", view.status === "APPROVED", view.status);
const pt = "client-flow-secret";
d = await api.requestDecision({ ...common, operation: "encrypt", key_session_id: ks.key_session_id, requested_bytes: pt.length });
ok("PERMIT", d.outcome === "PERMIT", JSON.stringify(d));
const enc = await api.encryptWithContext({ ...common, context_id: d.context_id, key_session_id: ks.key_session_id, plaintext_base64: b64(pt) });
ok("encrypt", !!enc.record_id && enc.ciphertext_preview_b64 !== b64(pt));
let replay = null; try { await api.encryptWithContext({ ...common, context_id: d.context_id, key_session_id: ks.key_session_id, plaintext_base64: b64(pt) }); } catch (e) { replay = e.status; }
ok("context replay rejected (409)", replay === 409, String(replay));
const d2 = await api.requestDecision({ ...common, operation: "decrypt", record_id: enc.record_id });
const dec = await api.decryptWithContext({ ...common, context_id: d2.context_id, record_id: enc.record_id });
ok("decrypt round trip", JSON.stringify(dec).includes(b64(pt)) || JSON.stringify(dec).includes(pt), JSON.stringify(dec).slice(0, 160));
// state change -> stale
const d3 = await api.requestDecision({ ...common, operation: "decrypt", record_id: enc.record_id });
localStorage.setItem("ibqc_token", adm.token);
await api.closeCase(ref);
localStorage.setItem("ibqc_token", userTok);
let stale = null; try { await api.decryptWithContext({ ...common, context_id: d3.context_id, record_id: enc.record_id }); } catch (e) { stale = e.status + " " + JSON.stringify(e.detail); }
ok("context stale after case closed", stale && /^40[39]/.test(stale), String(stale));
const d4 = await api.requestDecision({ ...common, operation: "decrypt", record_id: enc.record_id });
ok("new decision denied (case closed)", d4.outcome === "DENY", d4.outcome);
ok("records list / key sessions list / intents list", (await api.listRecords()).length >= 1 && (await api.listKeySessions()).length >= 1 && (await api.listIntents()).length >= 1);
await api.revokeKeySession(ks.key_session_id);
await api.stopMonitoring(mon.monitoring_session_id);
localStorage.setItem("ibqc_token", adm.token);
const v = await api.verifyAuditChain();
ok("audit verify via client", v.valid === true, JSON.stringify(v));
console.log(fails ? `${fails} FAILED` : "ALL CLIENT FLOW CHECKS PASSED");
process.exit(fails ? 1 : 0);
