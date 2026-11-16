import { useEffect, useMemo, useState } from "react";
import { emitQira } from "../qira";
import { useQiraOperationPhase } from "../qira/useQira";
import { Lock, ArrowRight, CheckCircle2, KeyRound, Paperclip } from "lucide-react";
import CopyBox from "../components/CopyBox";
import LifecyclePill from "../components/ui/LifecyclePill";
import { WorkflowStepper } from "../components/ui/WorkflowStepper";
import { Field, TextAreaField, SelectField } from "../components/ui/Field";
import Button from "../components/ui/Button";
import Alert from "../components/ui/Alert";
import PageHeader from "../components/ui/PageHeader";
import DecisionPanel from "../components/crypto/DecisionPanel";
import FaceAuthPanel from "../components/face/FaceAuthPanel";
import MonitoringBlockedBanner from "../components/monitoring/MonitoringBlockedBanner";
import { listIntents, listKeySessions } from "../services/api";
import { useMonitoringContext } from "../context/MonitoringContext";
import { useSecureOperation } from "../hooks/useSecureOperation";
import { formatTimestamp } from "../utils/formatTimestamp";

const STEPS = ["Approved intent", "Key session", "Authorize + encrypt"];
const MIME_BY_EXT = {
  pdf: "application/pdf", jpg: "image/jpeg", jpeg: "image/jpeg", png: "image/png",
  doc: "application/msword",
  docx: "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
  xls: "application/vnd.ms-excel",
  xlsx: "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
};

function bytesToBase64(bytes) {
  let binary = "";
  for (let i = 0; i < bytes.length; i += 0x8000) {
    binary += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
  }
  return btoa(binary);
}
function base64ToBytes(value) {
  const binary = atob(value);
  return Uint8Array.from(binary, (char) => char.charCodeAt(0));
}
async function sha256Hex(bytes) {
  const digest = await crypto.subtle.digest("SHA-256", bytes);
  return Array.from(new Uint8Array(digest), (byte) => byte.toString(16).padStart(2, "0")).join("");
}
function validateFileSignature(ext, bytes) {
  const starts = (...values) => values.every((value, index) => bytes[index] === value);
  if (ext === "pdf") return new TextDecoder().decode(bytes.slice(0, 5)) === "%PDF-";
  if (["jpg", "jpeg"].includes(ext)) return starts(0xff, 0xd8, 0xff);
  if (ext === "png") return starts(0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a);
  if (["doc", "xls"].includes(ext)) return starts(0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1);
  if (["docx", "xlsx"].includes(ext)) return starts(0x50, 0x4b, 0x03, 0x04);
  return false;
}
async function buildAttachmentPayload(file, preloaded) {
  let filename, mimeType, bytes;
  if (preloaded) {
    filename = preloaded.filename;
    mimeType = preloaded.content_type;
    bytes = base64ToBytes(preloaded.content_base64);
  } else {
    filename = file.name;
    bytes = new Uint8Array(await file.arrayBuffer());
  }
  const ext = filename.split(".").pop()?.toLowerCase();
  if (!MIME_BY_EXT[ext]) throw new Error("Supported files: PDF, JPG, JPEG, PNG, DOC, DOCX, XLS and XLSX.");
  if (bytes.length === 0 || bytes.length > 1024 * 1024) throw new Error("Files must be between 1 byte and 1 MB.");
  if (!validateFileSignature(ext, bytes)) throw new Error("The file content does not match its extension.");
  mimeType = MIME_BY_EXT[ext];
  const envelope = JSON.stringify({
    format: "CIPHERQ_ATTACHMENT_V1",
    filename,
    mime_type: mimeType,
    original_size: bytes.length,
    sha256: await sha256Hex(bytes),
    data_base64: bytesToBase64(bytes),
  });
  const payloadBytes = new TextEncoder().encode(envelope);
  return { plaintextBase64: bytesToBase64(payloadBytes), requestedBytes: payloadBytes.length, filename };
}

export default function EncryptionPage({ navigate, shared }) {
  const { deviceId, sessionId, reauthRequired } = useMonitoringContext();
  const [intents, setIntents] = useState([]);
  const [keySessions, setKeySessions] = useState([]);
  const [intentId, setIntentId] = useState(shared?.intentId ? String(shared.intentId) : "");
  const [keySessionId, setKeySessionId] = useState(shared?.keySessionId || "");
  const [plaintext, setPlaintext] = useState("");
  const [attachment, setAttachment] = useState(null);
  const [initialAttachment, setInitialAttachment] = useState(shared?.initialAttachment || null);
  const [attachmentError, setAttachmentError] = useState("");
  const [loadError, setLoadError] = useState("");
  const [payloadKind, setPayloadKind] = useState("text");

  useEffect(() => {
    if (shared?.intentId && intentId !== String(shared.intentId)) setInitialAttachment(null);
  }, [intentId, shared?.intentId]);

  useEffect(() => {
    Promise.all([listIntents(), listKeySessions()])
      .then(([i, k]) => {
        setIntents(i.filter((x) => x.status === "APPROVED" && x.body.operations.includes("encrypt")));
        const active = k.filter((x) => x.status === "ACTIVE");
        setKeySessions(active);
        setKeySessionId((cur) => cur || active[0]?.key_session_id || "");
      })
      .catch((e) => setLoadError(e.message));
  }, []);

  const intent = useMemo(() => intents.find((i) => String(i.intent_id) === intentId) || null, [intents, intentId]);
  const op = useSecureOperation({ operation: "encrypt", intent, sessionId, deviceId });
  useQiraOperationPhase("encrypt", op.phase); // QIRA mirrors the real operation phase (presentation only)
  const hasAttachment = Boolean(attachment || initialAttachment);
  const step = op.phase === "done" ? 3 : !intent ? 0 : !keySessionId ? 1 : 2;

  async function submit(e) {
    e?.preventDefault?.();
    setAttachmentError("");
    try {
      if (hasAttachment) {
        const payload = await buildAttachmentPayload(attachment, initialAttachment);
        setPayloadKind("file");
        op.run({ keySessionId, plaintextBase64: payload.plaintextBase64, requestedBytes: payload.requestedBytes });
      } else {
        if (!plaintext.trim()) { setAttachmentError("Enter text or attach a file to encrypt."); return; }
        const bytes = new TextEncoder().encode(plaintext);
        setPayloadKind("text");
        op.run({ keySessionId, plaintextBase64: bytesToBase64(bytes), requestedBytes: bytes.length });
      }
    } catch (err) {
      setAttachmentError(err?.message || "Could not prepare the selected file.");
    }
  }

  return (
    <div>
      <PageHeader icon="lock" eyebrow="Encryption Pipeline" title="Encryption"
        description="Every encryption is authorized first. Attach a file to encrypt that file as the actual payload; otherwise the text entered below is encrypted." />
      <MonitoringBlockedBanner />
      <div className="bg-cq-surface-container rounded-cq-xl p-cq-stack-lg">
        <WorkflowStepper steps={STEPS} activeIndex={step} />
        <Alert type="error">{loadError}</Alert>
        <form onSubmit={submit}>
          <Field label="Approved intent" hint="Only approved intents that allow encryption are listed.">
            <SelectField value={intentId} onChange={(e) => { setIntentId(e.target.value); op.reset(); }} required>
              <option value="">Select an intent…</option>
              {intents.map((i) => (
                <option key={i.intent_id} value={i.intent_id}>
                  #{i.intent_id} v{i.version} · {i.body.purpose_code} · {i.body.resource}
                </option>
              ))}
            </SelectField>
          </Field>
          {intent && (
            <div className="rounded-cq-lg border border-cq-outline-variant/25 bg-cq-surface-container-lowest px-4 py-3 mb-4 text-[13px]">
              <div className="flex items-center gap-2 mb-2"><LifecyclePill state={intent.status.toLowerCase()} />
                <span className="text-cq-on-surface-variant">scope: {intent.body.data_scope.classification} · ≤{intent.body.data_scope.max_bytes} B · uses {intent.uses}/{intent.body.data_scope.max_uses}</span></div>
              <div className="text-cq-on-surface-variant">Valid {formatTimestamp(intent.body.valid_from)} → {formatTimestamp(intent.body.valid_until)} · case {intent.body.business_reference}</div>
            </div>
          )}
          <Field label="Key session" hint="Simulated BB84 exchange; the raw key is never shown.">
            <SelectField value={keySessionId} onChange={(e) => setKeySessionId(e.target.value)} required>
              <option value="">Select a key session…</option>
              {keySessions.map((k) => (
                <option key={k.key_session_id} value={k.key_session_id}>
                  {k.key_session_id.slice(0, 14)}… · QBER {k.qber} · gen {k.generation}
                </option>
              ))}
            </SelectField>
          </Field>
          {keySessions.length === 0 && (
            <p className="text-[13px] text-cq-on-surface-variant mb-4">
              No active key session.{" "}
              <button type="button" className="underline text-cq-primary" onClick={() => navigate("bb84")}>Establish one</button>.
            </p>
          )}
          <Field label="Text payload" hint={hasAttachment ? "A selected attachment takes priority and becomes the encrypted payload." : "Enter text, or attach a file below."}>
            <TextAreaField rows={4} value={plaintext} onChange={(e) => setPlaintext(e.target.value)} />
          </Field>
          <Field label="File attachment (optional)" hint="PDF, JPG, JPEG, PNG, DOC, DOCX, XLS or XLSX · maximum 1 MB.">
            <input type="file" accept=".pdf,.jpg,.jpeg,.png,.doc,.docx,.xls,.xlsx"
              className="block w-full text-sm text-cq-on-surface"
              onChange={(e) => { if (e.target.files?.[0]) emitQira("op.file.select"); setAttachment(e.target.files?.[0] || null); setInitialAttachment(null); setAttachmentError(""); op.reset(); }} />
            {(attachment || initialAttachment) && <div className="mt-2 text-xs text-cq-on-surface-variant flex items-center gap-2">
              <Paperclip size={13}/>{attachment?.name || initialAttachment?.filename}
              {attachment && ` · ${attachment.size.toLocaleString()} bytes`}
              {initialAttachment && ` · ${Math.round((initialAttachment.content_base64?.length || 0) * 0.75).toLocaleString()} bytes`}
              <Button type="button" size="sm" variant="ghost" onClick={() => {
                setAttachment(null); setInitialAttachment(null); setAttachmentError("");
                const input = document.querySelector('input[type="file"]'); if (input) input.value = "";
              }}>Remove</Button>
            </div>}
          </Field>
          <Alert type="error">{attachmentError}</Alert>
          <DecisionPanel decision={op.decision} />
          <Alert type="error">{op.error || (reauthRequired ? "Re-authentication is required before cryptographic operations." : "")}</Alert>
          {op.phase === "needs_stepup" ? (
            <FaceAuthPanel mode="verify" sessionId={sessionId} title="Step-up verification"
              subtitle="This operation needs a fresh, challenge-bound identity check (similarity only; liveness is not established)."
              onSuccess={() => submit()} onCancel={() => op.reset()} />
          ) : (
            <Button type="submit" variant="accent" accent="mint" full icon={Lock}
              loading={op.phase === "deciding" || op.phase === "operating"}
              disabled={!intent || !keySessionId || (!hasAttachment && !plaintext.trim()) || reauthRequired}>
              Authorize and encrypt
            </Button>
          )}
        </form>
      </div>

      {op.phase === "done" && op.result && (
        <div className="bg-cq-surface-container rounded-cq-xl p-cq-stack-lg mt-6">
          <div className="flex items-center gap-2 mb-1">
            <CheckCircle2 size={18} className="text-cq-secondary" />
            <h2 className="text-[16px] font-bold text-cq-on-surface">{payloadKind === "file" ? "Attachment encrypted" : "Record sealed"}</h2>
          </div>
          <p className="text-[13px] text-cq-on-surface-variant mb-4">
            Stored under a per-record key wrapped by a key derived from this key session. Only ciphertext and metadata are kept.
          </p>
          <CopyBox label="Record ID" value={op.result.record_id} />
          <CopyBox label="Decision ID" value={op.result.decision_id} />
          <CopyBox label="Ciphertext preview (first 32 bytes, base64)" value={op.result.ciphertext_preview_b64} />
          <div className="text-[12.5px] text-cq-on-surface-variant mt-2 flex items-center gap-2">
            <KeyRound size={14} /> {op.result.classification} · {op.result.size} B · schema {op.result.schema}
          </div>
          <Button variant="accent" accent="peach" full iconRight={ArrowRight} className="mt-4"
            onClick={() => navigate("decrypt", { recordId: op.result.record_id, intentId: Number(intentId) })}>
            Decrypt this record
          </Button>
        </div>
      )}
    </div>
  );
}
