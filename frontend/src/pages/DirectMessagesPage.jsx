import { useCallback, useEffect, useMemo, useState } from "react";
import { Inbox, Send, Paperclip, RefreshCw, LockKeyhole, Download, ShieldCheck, XCircle } from "lucide-react";
import PageHeader from "../components/ui/PageHeader";
import Alert from "../components/ui/Alert";
import Button from "../components/ui/Button";
import { Field, SelectField, TextField, TextAreaField } from "../components/ui/Field";
import { listDirectMessageRecipients, listDirectMessages, createDirectMessage, decryptDirectMessage, revokeDirectMessage } from "../services/api";

const MAX_FILE_BYTES = 1024 * 1024;
const fmt = (ts) => ts ? new Date(ts * 1000).toLocaleString() : "—";

function toBase64(bytes) {
  let binary = "";
  const chunk = 0x8000;
  for (let i = 0; i < bytes.length; i += chunk) binary += String.fromCharCode(...bytes.subarray(i, i + chunk));
  return btoa(binary);
}
function fromBase64(value) {
  const binary = atob(value);
  return Uint8Array.from(binary, (c) => c.charCodeAt(0));
}
function downloadFile(bytes, filename, mime) {
  const url = URL.createObjectURL(new Blob([bytes], { type: mime || "application/octet-stream" }));
  const link = document.createElement("a");
  link.href = url; link.download = filename || "attachment.bin";
  document.body.appendChild(link); link.click(); link.remove();
  window.setTimeout(() => URL.revokeObjectURL(url), 1000);
}
function errorText(error) {
  const detail = error?.detail;
  return (typeof detail === "string" && detail) || error?.message || "Something went wrong.";
}

function MessageCard({ item, folder, onRefresh }) {
  const [plain, setPlain] = useState(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const isSender = folder === "sent";
  const person = isSender ? item.recipient_username : item.sender_username;
  const unavailable = ["REVOKED", "EXPIRED"].includes(item.status) || item.expires_ts * 1000 <= Date.now();

  async function decrypt() {
    setBusy(true); setError("");
    try {
      const result = await decryptDirectMessage(item.message_id);
      const raw = new TextDecoder().decode(fromBase64(result.payload_base64));
      const parsed = JSON.parse(raw);
      setPlain(parsed);
      await onRefresh();
    } catch (e) { setError(errorText(e)); }
    finally { setBusy(false); }
  }

  async function revoke() {
    if (!window.confirm("Revoke access to this message? The recipient will no longer be able to decrypt it through CipherQ.")) return;
    setBusy(true); setError("");
    try { await revokeDirectMessage(item.message_id); setPlain(null); await onRefresh(); }
    catch (e) { setError(errorText(e)); }
    finally { setBusy(false); }
  }

  return <article className="rounded-cq-lg border border-cq-outline-variant/30 bg-cq-surface-container p-4 space-y-3">
    <div className="flex flex-wrap items-start justify-between gap-3">
      <div className="min-w-0">
        <div className="font-semibold text-sm">{isSender ? `To ${person}` : `From ${person}`}</div>
        <div className="text-xs text-cq-on-surface-variant mt-1">{item.kind === "file" ? "Encrypted attachment" : "Encrypted text message"} · {item.size.toLocaleString()} bytes</div>
        <div className="text-xs text-cq-on-surface-variant">Sent {fmt(item.created_ts)} · Expires {fmt(item.expires_ts)}</div>
      </div>
      <div className="flex items-center gap-2 text-xs font-semibold">
        {item.status === "DELIVERED" && <span className="text-cq-secondary">Delivered</span>}
        {item.status === "READ" && <span className="text-emerald-300">Received / opened</span>}
        {item.status === "REVOKED" && <span className="text-cq-error">Revoked</span>}
        {item.status === "EXPIRED" && <span className="text-cq-on-surface-variant">Expired</span>}
        {item.is_unread && <span className="rounded-full bg-cq-primary/20 px-2 py-1 text-cq-primary">New</span>}
      </div>
    </div>
    {error && <Alert type="error">{error}</Alert>}
    {!plain && <div className="flex flex-wrap gap-2">
      <Button size="sm" variant="accent" accent="mint" icon={LockKeyhole} loading={busy} disabled={busy || unavailable} onClick={decrypt}>
        {isSender ? "Decrypt my copy" : "Decrypt and read"}
      </Button>
      {isSender && !unavailable && <Button size="sm" variant="ghost" icon={XCircle} disabled={busy} onClick={revoke}>Revoke</Button>}
    </div>}
    {plain && <div className="rounded-cq-md bg-cq-surface-container-lowest p-3 space-y-2" data-testid="direct-message-plaintext">
      {plain.subject && <div className="font-semibold">{plain.subject}</div>}
      {plain.text && <p className="text-sm whitespace-pre-wrap break-words">{plain.text}</p>}
      {plain.kind === "file" && <>
        <div className="text-sm font-semibold break-all">{plain.filename}</div>
        <div className="text-xs text-cq-on-surface-variant">{Number(plain.size || 0).toLocaleString()} bytes · {plain.mime_type || "file"}</div>
        <Button size="sm" variant="secondary" icon={Download} onClick={() => downloadFile(fromBase64(plain.data_base64), plain.filename, plain.mime_type)}>Download decrypted file</Button>
      </>}
      <div className="text-xs text-emerald-300 flex items-center gap-1"><ShieldCheck size={13}/> AES-GCM authentication passed</div>
      <Button size="sm" variant="ghost" onClick={() => setPlain(null)}>Hide decrypted content</Button>
    </div>}
  </article>;
}

export default function DirectMessagesPage() {
  const [tab, setTab] = useState("inbox");
  const [inbox, setInbox] = useState([]);
  const [sent, setSent] = useState([]);
  const [people, setPeople] = useState([]);
  const [query, setQuery] = useState("");
  const [recipient, setRecipient] = useState("");
  const [subject, setSubject] = useState("");
  const [text, setText] = useState("");
  const [file, setFile] = useState(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");

  const refresh = useCallback(async () => {
    const [i, s] = await Promise.all([listDirectMessages("inbox"), listDirectMessages("sent")]);
    setInbox(i); setSent(s);
  }, []);

  useEffect(() => {
    let alive = true;
    const load = async () => { try { const [i, s] = await Promise.all([listDirectMessages("inbox"), listDirectMessages("sent")]); if (alive) { setInbox(i); setSent(s); } } catch (e) { if (alive) setError(errorText(e)); } };
    load();
    const timer = window.setInterval(() => { if (document.visibilityState === "visible") load(); }, 5000);
    window.addEventListener("focus", load);
    return () => { alive = false; window.clearInterval(timer); window.removeEventListener("focus", load); };
  }, []);

  useEffect(() => {
    const timer = window.setTimeout(() => listDirectMessageRecipients(query).then(setPeople).catch(() => setPeople([])), 200);
    return () => window.clearTimeout(timer);
  }, [query]);

  const unread = useMemo(() => inbox.filter((m) => m.is_unread).length, [inbox]);

  async function send() {
    if (!recipient || busy) return;
    if (!file && !text.trim()) { setError("Write a message or attach a file."); return; }
    if (file && file.size > MAX_FILE_BYTES) { setError("Attachments are limited to 1 MB."); return; }
    setBusy(true); setError(""); setNotice("");
    try {
      let payload;
      if (file) {
        payload = { recipient_user_id: Number(recipient), kind: "file", subject, text, filename: file.name,
          mime_type: file.type || "application/octet-stream", file_base64: toBase64(new Uint8Array(await file.arrayBuffer())) };
      } else {
        payload = { recipient_user_id: Number(recipient), kind: "text", subject, text };
      }
      await createDirectMessage(payload);
      setSubject(""); setText(""); setFile(null); setRecipient(""); setQuery("");
      const picker = document.getElementById("direct-message-file"); if (picker) picker.value = "";
      setNotice("Encrypted and sent. The message is now available in the recipient's Inbox.");
      await refresh(); setTab("sent");
    } catch (e) { setError(errorText(e)); }
    finally { setBusy(false); }
  }

  return <div>
    <PageHeader icon="share" eyebrow="Private messaging" title="Direct Messages"
      description="Send an encrypted message or attachment to another CipherQ user. Both sender and recipient can decrypt it until it expires." />
    <div className="flex flex-wrap gap-2 mb-4" role="tablist">
      <button role="tab" aria-selected={tab === "inbox"} onClick={() => setTab("inbox")} className={`px-4 py-2 rounded-full text-sm font-semibold ${tab === "inbox" ? "bg-cq-primary/20 text-cq-primary" : "bg-cq-surface-container-high text-cq-on-surface-variant"}`}><Inbox size={14} className="inline mr-2"/>Inbox ({unread} new)</button>
      <button role="tab" aria-selected={tab === "compose"} onClick={() => setTab("compose")} className={`px-4 py-2 rounded-full text-sm font-semibold ${tab === "compose" ? "bg-cq-primary/20 text-cq-primary" : "bg-cq-surface-container-high text-cq-on-surface-variant"}`}><Send size={14} className="inline mr-2"/>New message</button>
      <button role="tab" aria-selected={tab === "sent"} onClick={() => setTab("sent")} className={`px-4 py-2 rounded-full text-sm font-semibold ${tab === "sent" ? "bg-cq-primary/20 text-cq-primary" : "bg-cq-surface-container-high text-cq-on-surface-variant"}`}>Sent ({sent.length})</button>
      <Button variant="ghost" icon={RefreshCw} onClick={() => refresh().catch((e) => setError(errorText(e)))}>Refresh</Button>
    </div>
    {error && <Alert type="error">{error}</Alert>}
    {notice && <Alert type="success">{notice}</Alert>}

    {tab === "compose" && <section className="bg-cq-surface-container rounded-cq-xl p-cq-stack-lg max-w-3xl">
      <h2 className="font-bold mb-4">New encrypted message</h2>
      <Field label="Find user"><TextField value={query} onChange={(e) => setQuery(e.target.value)} placeholder="Search by username…"/></Field>
      <Field label="Recipient"><SelectField value={recipient} onChange={(e) => setRecipient(e.target.value)}><option value="">Choose a user…</option>{people.map((p) => <option key={p.user_id} value={p.user_id}>{p.username}</option>)}</SelectField></Field>
      <Field label="Subject (optional)"><TextField maxLength={120} value={subject} onChange={(e) => setSubject(e.target.value)} placeholder="Subject"/></Field>
      <Field label="Message"><TextAreaField rows={5} maxLength={20000} value={text} onChange={(e) => setText(e.target.value)} placeholder="Write your message (optional when attaching a file)…"/></Field>
      <Field label="Attachment (optional)" hint="Maximum 1 MB; any file type"><input id="direct-message-file" type="file" className="block w-full text-sm" onChange={(e) => { const f = e.target.files?.[0] || null; setFile(f); setError(f && f.size > MAX_FILE_BYTES ? "Attachments are limited to 1 MB." : ""); }}/>{file && <div className="mt-2 text-xs text-cq-on-surface-variant flex items-center gap-2"><Paperclip size={13}/>{file.name} · {file.size.toLocaleString()} bytes<Button size="sm" variant="ghost" onClick={() => {setFile(null); const el=document.getElementById("direct-message-file"); if(el) el.value="";}}>Remove</Button></div>}</Field>
      <div className="text-xs text-cq-on-surface-variant mb-3">Encrypted automatically · Available for 24 hours · Sender and recipient can both decrypt · No face verification or per-message approval.</div>
      <div className="flex justify-end"><Button icon={Send} variant="accent" accent="mint" loading={busy} disabled={busy || !recipient || (!text.trim() && !file) || (!!file && file.size > MAX_FILE_BYTES)} onClick={send}>Encrypt and send</Button></div>
    </section>}

    {tab === "inbox" && <section className="bg-cq-surface-container rounded-cq-xl p-cq-stack-lg"><h2 className="font-bold mb-4">Inbox</h2>{inbox.length ? <div className="space-y-3">{inbox.map((m) => <MessageCard key={m.message_id} item={m} folder="inbox" onRefresh={refresh}/>)}</div> : <p className="text-sm text-cq-on-surface-variant">Your inbox is empty.</p>}</section>}
    {tab === "sent" && <section className="bg-cq-surface-container rounded-cq-xl p-cq-stack-lg"><h2 className="font-bold mb-4">Sent messages</h2>{sent.length ? <div className="space-y-3">{sent.map((m) => <MessageCard key={m.message_id} item={m} folder="sent" onRefresh={refresh}/>)}</div> : <p className="text-sm text-cq-on-surface-variant">You have not sent any messages yet.</p>}</section>}
  </div>;
}
