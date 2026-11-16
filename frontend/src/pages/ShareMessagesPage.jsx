import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { Inbox, Send, RefreshCw, LockKeyhole, XCircle } from "lucide-react";
import PageHeader from "../components/ui/PageHeader";
import Alert from "../components/ui/Alert";
import Button from "../components/ui/Button";
import { Field, SelectField, TextField } from "../components/ui/Field";
import FaceAuthPanel from "../components/face/FaceAuthPanel";
import DecisionPanel from "../components/crypto/DecisionPanel";
import { useMonitoringContext } from "../context/MonitoringContext";
import { useSecureOperation } from "../hooks/useSecureOperation";
import { formatTimestamp } from "../utils/formatTimestamp";
import {
  listShareRecipients, listShares, listIntents, listKeySessions,
  createShare, activateShare, revokeShare, rejectShare,
} from "../services/api";

function bytesToBase64(bytes) {
  let binary = "";
  for (let i = 0; i < bytes.length; i += 0x8000) binary += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
  return btoa(binary);
}
async function digestHex(bytes) {
  const digest = await crypto.subtle.digest("SHA-256", bytes);
  return Array.from(new Uint8Array(digest), (v) => v.toString(16).padStart(2, "0")).join("");
}
function fmt(value) {
  // Share metadata timestamps are Unix seconds; the shared formatter expects
  // milliseconds for numeric timestamps. ISO strings are passed through.
  const normalized = typeof value === "number" ? value * 1000 : value;
  return formatTimestamp(normalized);
}

function statusLabel(status) {
  return ({
    PENDING: "Pending authorization", PENDING_ADMIN: "Awaiting administrator approval",
    APPROVED: "Delivered", REJECTED: "Rejected", REVOKED: "Revoked", EXPIRED: "Expired",
  })[status] || status;
}

function ShareCard({ item, folder, onDecrypt, onRevoke, onReject }) {
  const sender = folder === "sent";
  const name = sender ? item.recipient_username || `User #${item.recipient_user_id}` :
    item.owner_username || `User #${item.owner_user_id}`;
  const canDecrypt = item.status === "APPROVED";
  return (
    <article className="rounded-cq-lg border border-cq-outline-variant/30 bg-cq-surface-container p-4 space-y-3">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div className="min-w-0">
          <div className="font-semibold text-sm">{sender ? `To ${name}` : `From ${name}`}</div>
          <div className="text-xs text-cq-on-surface-variant mt-1">
            {item.kind === "file" ? "Encrypted file attachment" : "Legacy encrypted text share"} · {Number(item.size || 0).toLocaleString()} bytes
          </div>
          <div className="text-xs text-cq-on-surface-variant">Intent #{item.intent_id} · Sent {fmt(item.created_ts)} · Expires {fmt(item.expires_ts)}</div>
        </div>
        <span className={`text-xs font-semibold ${item.status === "APPROVED" ? "text-emerald-300" : item.status === "REVOKED" || item.status === "REJECTED" ? "text-cq-error" : "text-amber-300"}`}>
          {statusLabel(item.status)}
        </span>
      </div>
      <div className="flex flex-wrap gap-2">
        {canDecrypt && <Button size="sm" variant="accent" accent="mint" icon={LockKeyhole}
          onClick={() => onDecrypt(sender ? item.record_id : item.share_id, item.intent_id)}>
          {sender ? "Decrypt my sent file" : "Decrypt received file"}
        </Button>}
        {sender && ["PENDING", "PENDING_ADMIN", "APPROVED"].includes(item.status) &&
          <Button size="sm" variant="ghost" icon={XCircle} onClick={() => onRevoke(item.share_id)}>Revoke</Button>}
        {!sender && ["PENDING", "PENDING_ADMIN", "APPROVED"].includes(item.status) && item.access_count === 0 &&
          <Button size="sm" variant="ghost" icon={XCircle} onClick={() => onReject(item.share_id)}>Decline</Button>}
      </div>
    </article>
  );
}

export default function ShareMessagesPage({ shared, navigate, user }) {
  const { deviceId, sessionId, reauthRequired, reauthenticate, deviceRevoked } = useMonitoringContext();
  const [tab, setTab] = useState("compose");
  const [intents, setIntents] = useState([]);
  const [keySessions, setKeySessions] = useState([]);
  const [people, setPeople] = useState([]);
  const [shares, setShares] = useState([]);
  const [intentId, setIntentId] = useState(shared?.intentId ? String(shared.intentId) : "");
  const [keySessionId, setKeySessionId] = useState("");
  const [recipientId, setRecipientId] = useState("");
  const [recipientQuery, setRecipientQuery] = useState("");
  const [attachmentInfo, setAttachmentInfo] = useState(null);
  const [busy, setBusy] = useState(false);
  const [showReauth, setShowReauth] = useState(false);
  const [reauthBusy, setReauthBusy] = useState(false);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const [pendingShare, setPendingShare] = useState(null);
  const processedRecord = useRef(null);

  const refresh = useCallback(async () => {
    const [intentRows, keys, recipients, shareRows] = await Promise.all([
      listIntents(), listKeySessions(), listShareRecipients(), listShares(),
    ]);
    setIntents(intentRows.filter((item) => item.status === "APPROVED" &&
      item.body.operations.includes("share") && item.body.operations.includes("encrypt")));
    setKeySessions(keys.filter((item) => item.status === "ACTIVE"));
    setPeople(recipients);
    setShares(shareRows);
  }, []);

  useEffect(() => {
    refresh().catch((e) => setError(e.message || "Could not load Secure Share data."));
  }, [refresh]);

  useEffect(() => {
    let active = true;
    const timer = window.setTimeout(() => {
      listShareRecipients(recipientQuery).then((rows) => { if (active) setPeople(rows); })
        .catch(() => { if (active) setPeople([]); });
    }, 200);
    return () => { active = false; window.clearTimeout(timer); };
  }, [recipientQuery]);

  const intent = useMemo(() => intents.find((item) => String(item.intent_id) === intentId) || null, [intents, intentId]);
  const boundRecipient = intent?.body?.recipient_user_id;
  const availablePeople = boundRecipient ? people.filter((person) => Number(person.user_id) === Number(boundRecipient)) : people;
  const op = useSecureOperation({ operation: "encrypt", intent, sessionId, deviceId });
  const currentUserId = Number(user?.userId ?? user?.user_id ?? user?.id);
  const inbox = useMemo(() => shares.filter((item) => Number(item.recipient_user_id) === currentUserId), [shares, currentUserId]);
  const sent = useMemo(() => shares.filter((item) => Number(item.owner_user_id) === currentUserId), [shares, currentUserId]);

  useEffect(() => {
    if (!intent) return;
    setRecipientId(boundRecipient ? String(boundRecipient) : "");
  }, [intentId, boundRecipient]);

  useEffect(() => {
    setAttachmentInfo(intent?.body?.attachment || null);
  }, [intentId, intent?.body?.attachment?.filename, intent?.body?.attachment?.size]);

  async function submit(e, afterReauthentication = false) {
    e?.preventDefault?.();
    if (busy || !intent || !keySessionId || !recipientId) return;
    if (reauthRequired && !afterReauthentication) {
      setShowReauth(true);
      setError("");
      return;
    }
    setError(""); setNotice("");
    try {
      const remainingUses = Number(intent.body.data_scope.max_uses) - Number(intent.uses || 0);
      if (remainingUses < 4) {
        throw new Error("This intent needs at least 4 remaining uses for authorized CID attachment retrieval, encryption, share authorization and recipient decryption. Create a new approved version with a higher Max uses value.");
      }
      if (!attachmentInfo) {
        throw new Error("This approved intent has no CID attachment. Upload the file during Create Intent, submit it for approval, then share that intent.");
      }
      const attachmentResponse = await fetch(
        `/api/intents/${encodeURIComponent(intent.intent_id)}/attachment?session_id=${encodeURIComponent(sessionId)}&device_id=${encodeURIComponent(deviceId)}&key_session_id=${encodeURIComponent(keySessionId)}`,
        { headers: { Authorization: `Bearer ${localStorage.getItem("ibqc_token") || ""}` }, cache: "no-store" }
      );
      if (!attachmentResponse.ok) {
        const raw = await attachmentResponse.text();
        let detail = raw;
        try {
          const parsed = JSON.parse(raw);
          detail = typeof parsed?.detail === "string" ? parsed.detail : raw;
        } catch { /* response was plain text */ }
        throw new Error(detail || `Could not retrieve the CID attachment (${attachmentResponse.status}).`);
      }
      const fileBytes = new Uint8Array(await attachmentResponse.arrayBuffer());
      if (!fileBytes.length || fileBytes.length !== Number(attachmentInfo.size)) {
        throw new Error("The CID attachment size does not match its approved metadata.");
      }
      const envelope = {
        format: "CIPHERQ_ATTACHMENT_V1",
        filename: attachmentInfo.filename,
        mime_type: attachmentInfo.content_type,
        original_size: fileBytes.length,
        sha256: await digestHex(fileBytes),
        data_base64: bytesToBase64(fileBytes),
      };
      const encoded = new TextEncoder().encode(JSON.stringify(envelope));
      if (encoded.length > Number(intent.body.data_scope.max_bytes)) {
        throw new Error(`Encrypted attachment payload is ${encoded.length} bytes, exceeding this intent's ${intent.body.data_scope.max_bytes}-byte operation limit.`);
      }
      const bytesBase64 = bytesToBase64(encoded);
      setPendingShare({
        intentId: intent.intent_id, resource: intent.body.resource, purposeCode: intent.body.purpose_code,
        sessionId, deviceId, recipientId: Number(recipientId), kind: "file",
      });
      op.run({ keySessionId, plaintextBase64: bytesBase64, requestedBytes: encoded.length });
    } catch (e2) {
      setError(e2.message || "Could not prepare the CID attachment.");
    }
  }

  const finishShare = useCallback(async (record) => {
    if (!pendingShare || !record?.record_id || processedRecord.current === record.record_id) return;
    processedRecord.current = record.record_id;
    setBusy(true); setError(""); setNotice("");
    try {
      let created = await createShare({
        intent_id: pendingShare.intentId,
        resource: pendingShare.resource,
        purpose_code: pendingShare.purposeCode,
        session_id: pendingShare.sessionId,
        device_id: pendingShare.deviceId,
        record_id: record.record_id,
        recipient_user_id: pendingShare.recipientId,
        kind: pendingShare.kind,
      });
      if (created.status === "PENDING") {
        created = await activateShare(created.share_id, pendingShare.sessionId, pendingShare.deviceId);
      }
      const message = created.status === "APPROVED"
        ? "Encrypted share delivered. The recipient must authenticate and complete the required face verification before decryption."
        : created.status === "PENDING_ADMIN"
          ? "Sender authorization completed. The share is waiting for administrator approval."
          : "Share request recorded. Refresh the page to check its authorization status.";
      setNotice(message);
      setRecipientQuery(""); setPendingShare(null);
      await refresh();
      setTab("sent");
    } catch (e) {
      processedRecord.current = null;
      setError(e?.detail || e.message || "Secure Share could not be completed.");
    } finally {
      setBusy(false);
    }
  }, [pendingShare, refresh]);

  useEffect(() => {
    if (op.phase === "done" && op.result?.record_id) finishShare(op.result).catch(() => {});
  }, [op.phase, op.result, finishShare]);

  async function completeShareReauthentication({ descriptor }) {
    if (deviceRevoked) {
      setError("This device is revoked. Request administrator approval before sharing; face reauthentication alone cannot restore a revoked device.");
      setShowReauth(false);
      return;
    }
    setReauthBusy(true);
    setError("");
    try {
      await reauthenticate(descriptor);
      setShowReauth(false);
      await submit(null, true);
    } catch (e) {
      setError(e?.detail || e?.message || "Re-authentication failed. Sharing remains blocked until the session is restored.");
    } finally {
      setReauthBusy(false);
    }
  }

  async function doRevoke(shareId) {
    if (!window.confirm("Revoke this encrypted share?")) return;
    try { await revokeShare(shareId, "Sender revoked access"); await refresh(); }
    catch (e) { setError(e.message || "Could not revoke share."); }
  }
  async function doReject(shareId) {
    try { await rejectShare(shareId, "Recipient declined"); await refresh(); }
    catch (e) { setError(e.message || "Could not decline share."); }
  }

  return (
    <div>
      <PageHeader icon="share" eyebrow="Intent-bound encrypted sharing" title="Secure Share"
        description="Share the original file attached to an approved Create Intent. Secure Share does not accept separate text or file uploads; use Direct Messages for text conversations." />
      <div className="flex flex-wrap gap-2 mb-4" role="tablist">
        {[
          ["compose", "New secure share"], ["inbox", `Received (${inbox.length})`], ["sent", `Sent (${sent.length})`],
        ].map(([key, label]) => (
          <button key={key} role="tab" aria-selected={tab === key} onClick={() => setTab(key)}
            className={`px-4 py-2 rounded-full text-sm font-semibold ${tab === key ? "bg-cq-primary/20 text-cq-primary" : "bg-cq-surface-container-high text-cq-on-surface-variant"}`}>
            {label}
          </button>
        ))}
        <Button variant="ghost" icon={RefreshCw} onClick={() => refresh().catch((e) => setError(e.message))}>Refresh</Button>
      </div>
      {error && <Alert type="error">{error}</Alert>}
      {notice && <Alert type="success">{notice}</Alert>}

      {tab === "compose" && (
        <section className="bg-cq-surface-container rounded-cq-xl p-cq-stack-lg max-w-3xl">
          <h2 className="font-bold mb-4">Share CID attachment</h2>
          <form onSubmit={submit} className="space-y-2">
            <Field label="Approved intent" hint="Only approved intents that explicitly permit sharing are listed.">
              <SelectField value={intentId} disabled={busy || op.phase === "deciding" || op.phase === "operating"}
                onChange={(e) => { setIntentId(e.target.value); op.reset(); }} required>
                <option value="">Select an approved intent…</option>
                {intents.map((item) => <option key={item.intent_id} value={item.intent_id}>
                  #{item.intent_id} v{item.version} · {item.body.resource} · {item.body.purpose_code}
                </option>)}
              </SelectField>
            </Field>
            <Field label="Sender key session" hint="Select one of your active sender key sessions. Recipient key provisioning is handled securely by the backend.">
              <SelectField value={keySessionId} disabled={busy || op.phase === "deciding" || op.phase === "operating"}
                onChange={(e) => setKeySessionId(e.target.value)} required>
                <option value="">Select an active key session…</option>
                {keySessions.map((key) => <option key={key.key_session_id} value={key.key_session_id}>
                  {key.key_session_id.slice(0, 14)}… · QBER {key.qber} · generation {key.generation}
                </option>)}
              </SelectField>
            </Field>
            {!boundRecipient && <Field label="Find recipient">
              <TextField value={recipientQuery} disabled={busy || op.phase === "deciding" || op.phase === "operating"}
                onChange={(e) => setRecipientQuery(e.target.value)} placeholder="Search enabled users…" />
            </Field>}
            <Field label="Recipient" hint={boundRecipient ? "This legacy intent is bound to the selected recipient." : "The backend validates the selected recipient again before delivery."}>
              <SelectField value={recipientId} disabled={busy || op.phase === "deciding" || op.phase === "operating"}
                onChange={(e) => setRecipientId(e.target.value)} required>
                <option value="">Select a recipient…</option>
                {availablePeople.map((person) => <option key={person.user_id} value={person.user_id}>
                  {person.username} · {person.role}
                </option>)}
              </SelectField>
            </Field>
            <Field label="CID attachment" hint="Secure Share uses only the file uploaded and sealed during Create Intent. Files cannot be uploaded or replaced here.">
              {attachmentInfo ? (
                <div className="rounded-cq-md border border-cq-outline-variant/30 bg-cq-surface-container-lowest p-3 text-sm">
                  <div className="font-semibold text-cq-on-surface break-all">{attachmentInfo.filename}</div>
                  <div className="text-xs text-cq-on-surface-variant mt-1">
                    {Number(attachmentInfo.size || 0).toLocaleString()} bytes · {attachmentInfo.content_type}
                  </div>
                  <div className="text-xs text-cq-secondary mt-2">Source: approved Create Intent attachment</div>
                </div>
              ) : (
                <Alert type="warning">No file is attached to this intent. Upload the file in Create Intent and obtain approval before sharing.</Alert>
              )}
            </Field>
            <Button type="submit" icon={Send} variant="accent" accent="mint"
                  loading={busy || op.phase === "deciding" || op.phase === "operating"}
                  disabled={busy || reauthBusy || !intent || !attachmentInfo || !keySessionId || !recipientId || op.phase === "deciding" || op.phase === "operating"}>
              Encrypt and Send
            </Button>
          </form>
          {showReauth && (
            <div className="mt-4 space-y-3">
              {deviceRevoked ? (
                <Alert type="error">This device is revoked. Request administrator approval before sharing.</Alert>
              ) : (
                <FaceAuthPanel mode="verify" title="Re-authenticate to share"
                  subtitle="Monitoring requires a fresh identity check before the CID attachment can be accessed and encrypted."
                  onSuccess={completeShareReauthentication}
                  onCancel={() => setShowReauth(false)} />
              )}
              {reauthBusy && <Alert type="info">Restoring the monitored session…</Alert>}
            </div>
          )}
          {op.phase === "done" && error && op.result?.record_id && (
            <div className="mt-3 flex justify-end">
              <Button size="sm" variant="outline" loading={busy} disabled={busy}
                onClick={() => finishShare(op.result)}>Retry Secure Share delivery</Button>
            </div>
          )}
        </section>
      )}

      {tab === "inbox" && (
        <section className="bg-cq-surface-container rounded-cq-xl p-cq-stack-lg">
          <h2 className="font-bold mb-4 flex items-center gap-2"><Inbox size={17}/> Received encrypted shares</h2>
          {inbox.length
            ? <div className="space-y-3">{inbox.map((item) =>
              <ShareCard key={item.share_id} item={item} folder="inbox"
                onDecrypt={(recordId, id) => navigate("decrypt", { recordId, intentId: id })}
                onReject={doReject} onRevoke={doRevoke} />)}</div>
            : <p className="text-sm text-cq-on-surface-variant">No shares have been received.</p>}
        </section>
      )}

      {tab === "sent" && (
        <section className="bg-cq-surface-container rounded-cq-xl p-cq-stack-lg">
          <h2 className="font-bold mb-4 flex items-center gap-2"><Send size={17}/> Sent encrypted shares</h2>
          {sent.length
            ? <div className="space-y-3">{sent.map((item) =>
              <ShareCard key={item.share_id} item={item} folder="sent"
                onDecrypt={(recordId, id) => navigate("decrypt", { recordId, intentId: id })}
                onReject={doReject} onRevoke={doRevoke} />)}</div>
            : <p className="text-sm text-cq-on-surface-variant">No shares have been sent.</p>}
        </section>
      )}
    </div>
  );
}
