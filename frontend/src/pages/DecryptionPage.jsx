import { useCallback, useEffect, useMemo, useState } from "react";
import { Unlock, CheckCircle2, EyeOff } from "lucide-react";
import { Field, SelectField } from "../components/ui/Field";
import Button from "../components/ui/Button";
import Alert from "../components/ui/Alert";
import PageHeader from "../components/ui/PageHeader";
import DecisionPanel from "../components/crypto/DecisionPanel";
import FaceAuthPanel from "../components/face/FaceAuthPanel";
import MonitoringBlockedBanner from "../components/monitoring/MonitoringBlockedBanner";
import { listIntents, listRecords, listShares } from "../services/api";
import { useMonitoringContext } from "../context/MonitoringContext";
import { emitQira, releaseQira } from "../qira";
import { useQiraOperationPhase } from "../qira/useQira";
import { useSecureOperation } from "../hooks/useSecureOperation";
import { parseShareEnvelope, verifyShareIntegrity } from "../utils/sharePayload";
import { formatTimestamp } from "../utils/formatTimestamp";

function base64ToBytes(b64) {
  const bin = atob(b64);
  return Uint8Array.from(bin, (c) => c.charCodeAt(0));
}

function decodePlaintext(b64) {
  const bytes = base64ToBytes(b64);

  // First, check whether the decrypted bytes contain a supported
  // CipherQ attachment envelope.
  let decodedText = null;

  try {
    decodedText = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  } catch {
    // Non-UTF-8 content is treated as binary data below.
  }

  if (decodedText !== null) {
    const shareEnvelope = parseShareEnvelope(decodedText);
    if (shareEnvelope) return shareEnvelope;
    try {
      const parsed = JSON.parse(decodedText);

      if (
        parsed?.format === "CIPHERQ_ATTACHMENT_V1" &&
        typeof parsed.data_base64 === "string"
      ) {
        const data = base64ToBytes(parsed.data_base64);

        return {
          kind: "attachment",
          filename: String(parsed.filename || "decrypted-file.bin"),
          mimeType: String(
            parsed.mime_type || "application/octet-stream"
          ),
          size: data.length,
          data,
          sha256: String(parsed.sha256 || ""),
        };
      }
    } catch {
      // Valid text that is not an attachment envelope remains text.
    }

    // Preserve the exact readable text, including JSON text that
    // does not use the CipherQ attachment envelope.
    return { kind: "text", text: decodedText };
  }

  // Do not pretend arbitrary binary bytes are readable text.
  return {
    kind: "binary",
    size: bytes.length,
    data: bytes,
  };
}


export default function DecryptionPage({ shared, user }) {
  const { deviceId, sessionId, reauthRequired } = useMonitoringContext();
  const [intents, setIntents] = useState([]);
  const [records, setRecords] = useState([]);
  const [shares, setShares] = useState([]);
  const [intentId, setIntentId] = useState(shared?.intentId ? String(shared.intentId) : "");
  const [recordId, setRecordId] = useState(shared?.recordId || "");
  const [loadError, setLoadError] = useState("");
  const [plain, setPlain] = useState(null);

  const refreshAvailableRecords = useCallback(async () => {
    try {
      const [i, r, s] = await Promise.all([listIntents(), listRecords(), listShares()]);
      setIntents(i.filter((x) => x.status === "APPROVED" && x.body.operations.includes("decrypt")));
      setRecords(r);
      // The API already scopes shares to the authenticated user. Keep an explicit recipient
      // check as defence-in-depth, and normalize numeric IDs to avoid string/number mismatches.
      const currentUserId = Number(user?.userId ?? user?.user_id ?? user?.id);
      setShares(s.filter((x) => x.status === "APPROVED" && Number(x.recipient_user_id) === currentUserId));
      setLoadError("");
    } catch (e) {
      setLoadError(e.message || "Could not refresh available records.");
    }
  }, [user?.userId, user?.user_id, user?.id]);

  useEffect(() => {
    let active = true;
    const refresh = async () => { if (active && document.visibilityState !== "hidden") await refreshAvailableRecords(); };
    refresh();
    const timer = window.setInterval(refresh, 4000);
    const onFocus = () => refresh();
    window.addEventListener("focus", onFocus);
    return () => { active = false; window.clearInterval(timer); window.removeEventListener("focus", onFocus); };
  }, [refreshAvailableRecords]);

  const sharedIntents = shares.map((s) => ({ intent_id: s.intent_id, status: "APPROVED", version: 1,
    body: { resource: s.resource, purpose_code: s.purpose_code, operations: ["decrypt"],
      data_scope: { classification: s.classification, max_bytes: s.size, max_uses: 1 } }, __shared: true }));
  const availableIntents = [...intents, ...sharedIntents.filter((si) => !intents.some((i) => i.intent_id === si.intent_id))];
  const availableRecords = [...records, ...shares.map((s) => ({ record_id: s.share_id, intent_id: s.intent_id,
    resource: s.resource, classification: s.classification, created_ts: s.created_ts, expires_ts: s.expires_ts,
    size: s.size, __shared: true }))];
  const intent = useMemo(() => availableIntents.find((i) => String(i.intent_id) === intentId) || null, [availableIntents, intentId]);
  const record = availableRecords.find((r) => r.record_id === recordId) || null;
  const op = useSecureOperation({ operation: "decrypt", intent, sessionId, deviceId });
  useQiraOperationPhase("decrypt", op.phase); // QIRA mirrors the real operation phase (presentation only)

  // Never keep decrypted data around: clear it when the selection changes or the page unmounts.
  useEffect(() => () => setPlain(null), []);
  useEffect(() => {
    let active = true;
    async function decode() {
      if (op.phase !== "done" || !op.result) return;
      emitQira("decrypt.verify"); // QIRA: integrity verification in progress (presentation only)
      const decoded = decodePlaintext(op.result.plaintext_base64);
      if (decoded.kind === "attachment" && decoded.sha256) {
        const valid = await verifyShareIntegrity(decoded);
        if (!active) return;
        if (!valid) {
          setPlain(null);
          setLoadError("Decrypted attachment integrity verification failed. The file will not be offered for download.");
          releaseQira("decrypt.verify");
          emitQira("decrypt.integrityFailed");
          return;
        }
      }
      if (active) {
        setLoadError(""); setPlain(decoded);
        releaseQira("decrypt.verify");
        emitQira("decrypt.done"); // announced only after the operation AND the integrity check succeeded
      }
    }
    decode().catch(() => { releaseQira("decrypt.verify"); if (active) { setLoadError("Could not validate the decrypted payload."); emitQira("decrypt.failed"); } });
    return () => { active = false; releaseQira("decrypt.verify"); };
  }, [op.phase, op.result]);

  function submit(e) {
    e?.preventDefault?.();
    setPlain(null);
    op.run({ recordId });
  }

  return (
    <div>
      <PageHeader icon="lock_open" eyebrow="Decryption Pipeline" title="Decryption"
        description="Decrypt your own encrypted records or files securely shared with your account. Approved recipient shares refresh automatically and remain subject to their validity period." />
      <MonitoringBlockedBanner />
      <div className="bg-cq-surface-container rounded-cq-xl p-cq-stack-lg">
        <Alert type="error">{loadError}</Alert>
        <form onSubmit={submit}>
          <Field label="Record">
            <SelectField value={recordId} onChange={(e) => { if (e.target.value) emitQira("op.record.select"); setRecordId(e.target.value); op.reset(); setPlain(null); }} required>
              <option value="">Select a record…</option>
              {availableRecords.map((r) => (
                <option key={r.record_id} value={r.record_id}>
                  {r.__shared ? "SHARED · " : ""}{r.record_id.slice(0, 14)}… · {r.resource} · {r.classification} · {formatTimestamp(r.created_ts * 1000)}
                </option>
              ))}
            </SelectField>
          </Field>
          <Field label="Approved intent" hint="must allow decryption for this resource">
            <SelectField value={intentId} onChange={(e) => { setIntentId(e.target.value); op.reset(); }} required>
              <option value="">Select an intent…</option>
              {availableIntents.filter((i) => !record || i.body.resource === record.resource).map((i) => (
                <option key={i.intent_id} value={i.intent_id}>{i.__shared ? "Shared authorization · " : ""}#{i.intent_id} v{i.version} · {i.body.purpose_code} · {i.body.resource}</option>
              ))}
            </SelectField>
          </Field>

          <DecisionPanel decision={op.decision} />
          <Alert type="error">{op.error || (reauthRequired ? "Re-authentication is required before cryptographic operations." : "")}</Alert>

          {op.phase === "needs_stepup" ? (
            <FaceAuthPanel mode="verify" sessionId={sessionId} title="Step-up verification"
              subtitle="Fresh, challenge-bound identity check (similarity only; liveness is not established)."
              onSuccess={() => submit()} onCancel={() => op.reset()} />
          ) : (
            <Button type="submit" variant="accent" accent="peach" full icon={Unlock}
              loading={op.phase === "deciding" || op.phase === "operating"}
              disabled={!intent || !recordId || reauthRequired}>
              Authorize and decrypt
            </Button>
          )}
        </form>
      </div>

      {plain !== null && (
        <div className="bg-cq-surface-container rounded-cq-xl p-cq-stack-lg mt-6">
          <div className="flex items-center gap-2 mb-3">
            <CheckCircle2 size={18} className="text-cq-secondary" />
            <h2 className="text-[16px] font-bold text-cq-on-surface">{plain.kind === "attachment" ? "Attachment decrypted" : "Decrypted"}{plain.subject ? ` · ${plain.subject}` : ""}</h2>
          </div>
          {plain.kind === "attachment" || plain.kind === "binary" ? (
            <div className="rounded-cq-md bg-cq-surface-container-lowest p-4 text-sm text-cq-on-surface">
              {plain.text && <p className="whitespace-pre-wrap break-words mb-3">{plain.text}</p>}
              <p className="font-semibold break-all">{plain.filename}</p>
              <p className="text-cq-on-surface-variant mt-1">{plain.size.toLocaleString()} bytes · {plain.mimeType}</p>
              <Button variant="accent" accent="mint" full className="mt-4" onClick={() => {
                const blob = new Blob([plain.data], { type: plain.mimeType });
                const url = URL.createObjectURL(blob);
                const a = document.createElement("a"); a.href = url; a.download = plain.filename;
                document.body.appendChild(a); a.click(); a.remove(); URL.revokeObjectURL(url);
              }}>Download decrypted file</Button>
            </div>
          ) : (
            <pre className="whitespace-pre-wrap break-words rounded-cq-md bg-cq-surface-container-lowest p-4 text-[13px] text-cq-on-surface" data-testid="plaintext">{plain.text}</pre>
          )}
          <Button variant="ghost" icon={EyeOff} className="mt-3" onClick={() => { setPlain(null); op.reset(); }}>Clear from screen</Button>
        </div>
      )}
    </div>
  );
}
