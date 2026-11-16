import test from "node:test";
import assert from "node:assert/strict";
import { buildTextEnvelope, buildFileEnvelope, parseShareEnvelope, checkFile, statusLabel, verifyShareIntegrity,
  fileExtension, MAX_FILE_BYTES, sha256Hex } from "../src/utils/sharePayload.js";

test("text envelope round-trips exactly (unicode, newlines)", () => {
  const msg = "Wire €1,250,000 ✓\nline 2 \"quoted\" \\ backslash 😀";
  const env = parseShareEnvelope(buildTextEnvelope({ subject: " S ", description: " d ", text: msg }));
  assert.equal(env.kind, "text"); assert.equal(env.text, msg); assert.equal(env.subject, "S"); assert.equal(env.description, "d");
});

test("file envelope round-trips byte-identically and the digest verifies", async () => {
  const bytes = Uint8Array.from({ length: 1000 }, (_, i) => (i * 7) % 256);
  const env = parseShareEnvelope(await buildFileEnvelope({ filename: "a.pdf", bytes }));
  assert.equal(env.kind, "attachment"); assert.deepEqual([...env.data], [...bytes]);
  assert.equal(await verifyShareIntegrity(env), true);
  env.data[3] ^= 1;
  assert.equal(await verifyShareIntegrity(env), false);
  assert.equal(await sha256Hex(new Uint8Array()), "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
});

test("non-share and malformed plaintext is not treated as a share", () => {
  for (const t of ["hello", "{}", '{"format":"CIPHERQ_ATTACHMENT_V1"}', '{"format":"CIPHERQ_SHARE_V1","kind":"x"}', "{bad"]) assert.equal(parseShareEnvelope(t), null);
});

test("client-side file checks", () => {
  assert.match(checkFile({ name: "x.exe", size: 5 }), /Unsupported/);
  assert.match(checkFile({ name: "x.pdf", size: 0 }), /empty/);
  assert.match(checkFile({ name: "x.pdf", size: MAX_FILE_BYTES + 1 }), /limit/);
  assert.equal(checkFile({ name: "x.PDF", size: 10 }), "");
  assert.equal(fileExtension("noext"), "");
});

test("status labels never claim delivery before approval", () => {
  assert.match(statusLabel({ status: "PENDING_ADMIN" }, true), /Pending approval/);
  assert.match(statusLabel({ status: "PENDING" }, true), /awaiting/);
  assert.equal(statusLabel({ status: "APPROVED", access_count: 0 }, true), "Delivered / available");
  assert.equal(statusLabel({ status: "APPROVED", access_count: 0, opened_ts: 1 }, true), "Opened by recipient");
  assert.equal(statusLabel({ status: "APPROVED", access_count: 2, opened_ts: 1 }, false), "Decrypted");
  for (const s of ["REVOKED", "REJECTED", "EXPIRED"]) assert.equal(statusLabel({ status: s }, true), s[0] + s.slice(1).toLowerCase());
});
