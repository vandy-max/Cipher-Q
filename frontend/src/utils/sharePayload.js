// Secure Sharing payload helpers. The envelope built here is what the backend encrypts; the backend re-validates
// and rebuilds it (filename, MIME type, size, digest, magic bytes), so nothing here is trusted by the server.
export const SHARE_FORMAT = "CIPHERQ_SHARE_V1";

// Keep in sync with backend/crypto/share_payload.py ALLOWED_TYPES (the backend is authoritative).
export const ALLOWED_TYPES = {
  pdf: "application/pdf",
  jpg: "image/jpeg",
  jpeg: "image/jpeg",
  png: "image/png",
  doc: "application/msword",
  docx: "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
  xls: "application/vnd.ms-excel",
  xlsx: "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
};
export const ACCEPT_ATTR = Object.keys(ALLOWED_TYPES).map((e) => `.${e}`).join(",");
// Secure Sharing direct-message attachment cap: 1 MiB.
export const MAX_FILE_BYTES = 1 * 1024 * 1024;
export const MAX_TEXT_CHARS = 200000;

export function fileExtension(name) {
  const i = String(name || "").lastIndexOf(".");
  return i < 0 ? "" : name.slice(i + 1).toLowerCase();
}

export function checkFile(file) {
  if (!file) return "Choose a file.";
  if (!ALLOWED_TYPES[fileExtension(file.name)]) return `Unsupported file type. Allowed: ${Object.keys(ALLOWED_TYPES).join(", ")}.`;
  if (file.size === 0) return "The file is empty.";
  if (file.size > MAX_FILE_BYTES) return `File is ${file.size.toLocaleString()} bytes; the current limit is ${MAX_FILE_BYTES.toLocaleString()} bytes.`;
  return "";
}

export function bytesToBase64(bytes) {
  let bin = "";
  const CH = 0x8000;
  for (let i = 0; i < bytes.length; i += CH) bin += String.fromCharCode.apply(null, bytes.subarray(i, i + CH));
  return btoa(bin);
}
export function base64ToBytes(b64) {
  const bin = atob(b64);
  return Uint8Array.from(bin, (c) => c.charCodeAt(0));
}
export function utf8Bytes(s) { return new TextEncoder().encode(s); }

export async function sha256Hex(bytes) {
  const d = await crypto.subtle.digest("SHA-256", bytes);
  return [...new Uint8Array(d)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

/** Field order and compact JSON match the backend's canonical form so the authorised byte count stays exact. */
export function buildTextEnvelope({ subject = "", description = "", text }) {
  return JSON.stringify({ format: SHARE_FORMAT, kind: "text", subject: subject.trim(), description: description.trim(), text });
}
export async function buildFileEnvelope({ subject = "", description = "", filename, bytes }) {
  const ext = fileExtension(filename);
  return JSON.stringify({
    format: SHARE_FORMAT, kind: "file", subject: subject.trim(), description: description.trim(),
    filename, mime_type: ALLOWED_TYPES[ext] || "application/octet-stream", size: bytes.length,
    sha256: await sha256Hex(bytes), data_base64: bytesToBase64(bytes),
  });
}

/** Returns a decoded share, or null when the plaintext is not a Secure Sharing envelope. */
export function parseShareEnvelope(text) {
  let p;
  try { p = JSON.parse(text); } catch { return null; }
  if (!p || p.format !== SHARE_FORMAT) return null;
  const base = { subject: String(p.subject || ""), description: String(p.description || "") };
  if (p.kind === "text" && typeof p.text === "string") return { ...base, kind: "text", text: p.text };
  if (p.kind === "file" && typeof p.data_base64 === "string") {
    const data = base64ToBytes(p.data_base64);
    return { ...base, kind: "attachment", filename: String(p.filename || "shared-file.bin"),
      mimeType: String(p.mime_type || "application/octet-stream"), size: data.length, data,
      text: String(p.text || ""), sha256: String(p.sha256 || "") };
  }
  return null;
}

/** Re-computes the digest of what was decrypted and compares it to the sender-declared one. */
export async function verifyShareIntegrity(decoded) {
  if (!decoded || decoded.kind !== "attachment" || !decoded.sha256) return null;
  return (await sha256Hex(decoded.data)) === decoded.sha256;
}

export function statusLabel(share, meOwner) {
  const s = share.status;
  if (s === "PENDING") return "Sent · awaiting sender authorization";
  if (s === "PENDING_ADMIN") return "Pending approval";
  if (s === "APPROVED") {
    if (share.access_count > 0) return meOwner ? "Decrypted by recipient" : "Decrypted";
    if (share.opened_ts) return meOwner ? "Opened by recipient" : "Opened";
    return meOwner ? "Delivered / available" : "Available";
  }
  return { REJECTED: "Rejected", REVOKED: "Revoked", EXPIRED: "Expired" }[s] || s;
}

export function downloadBytes(data, filename, mimeType) {
  const url = URL.createObjectURL(new Blob([data], { type: mimeType || "application/octet-stream" }));
  const a = document.createElement("a");
  a.href = url; a.download = filename;
  document.body.appendChild(a); a.click(); a.remove(); URL.revokeObjectURL(url);
}
