import { useEffect, useMemo, useState } from "react";
import { ShieldCheck, ArrowRight, Info } from "lucide-react";
import { Field, TextField, TextAreaField, SelectField } from "../components/ui/Field";
import Button from "../components/ui/Button";
import Alert from "../components/ui/Alert";
import PageHeader from "../components/ui/PageHeader";
import { createIntent, createIntentVersion, validateIntent, getIntent } from "../services/api";
import { useMonitoringContext } from "../context/MonitoringContext";
import { emitQira, releaseQira } from "../qira";
import { isUnavailableError } from "../qira/classify";
import { useQiraOnce } from "../qira/useQira";

// Must mirror backend/intent_engine/schema.py (the server is authoritative; it re-validates everything).
const PURPOSES = [
  ["CASE_INVESTIGATION", "Case investigation"],
  ["AUDIT_REVIEW", "Audit review"],
  ["REGULATORY_REPORTING", "Regulatory reporting"],
  ["INCIDENT_RESPONSE", "Incident response"],
  ["CUSTOMER_SERVICE", "Customer service"],
];
const CLASSIFICATIONS = ["PUBLIC", "INTERNAL", "CONFIDENTIAL", "RESTRICTED"];
const REQUIRED_APPROVALS = { PUBLIC: 0, INTERNAL: 1, CONFIDENTIAL: 1, RESTRICTED: 2 };

function toLocalInput(d) {
  const p = (n) => String(n).padStart(2, "0");
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())}T${p(d.getHours())}:${p(d.getMinutes())}`;
}

function defaultForm() {
  const now = new Date();
  return {
    purpose_code: "CASE_INVESTIGATION",
    purpose_statement: "",
    business_reference: "",
    resource: "",
    encrypt: true,
    decrypt: true,
    share: false,
    classification: "CONFIDENTIAL",
    max_bytes: 2000000,
    max_uses: 10,
    valid_from: toLocalInput(now),
    valid_until: toLocalInput(new Date(now.getTime() + 2 * 3600 * 1000)),
    evidence_ref: "",
    reason: "initial creation",
  };
}

function formFromBody(body) {
  return {
    purpose_code: body.purpose_code,
    purpose_statement: body.purpose_statement,
    business_reference: body.business_reference,
    resource: body.resource,
    encrypt: body.operations.includes("encrypt"),
    decrypt: body.operations.includes("decrypt"),
    share: body.operations.includes("share"),
    classification: body.data_scope.classification,
    max_bytes: body.data_scope.max_bytes,
    max_uses: body.data_scope.max_uses,
    valid_from: toLocalInput(new Date(body.valid_from)),
    valid_until: toLocalInput(new Date(body.valid_until)),
    evidence_ref: body.evidence_refs?.[0]?.ref || "",
    reason: "scope change",
  };
}

export default function CreateIntentPage({ navigate, shared }) {
  const { deviceId, sessionId, reauthRequired, isMonitoring } = useMonitoringContext();
  const editId = shared?.editIntentId || null;
  const [form, setForm] = useState(defaultForm);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);
  const [created, setCreated] = useState(null);
  const [attachment, setAttachment] = useState(null);
  const [attachmentSize, setAttachmentSize] = useState(0);
  const [attachmentPayloadSize, setAttachmentPayloadSize] = useState(0);
  const [attachmentError, setAttachmentError] = useState("");

  async function handleAttachmentChange(e) {
    setAttachmentError("");
    const file = e.target.files?.[0];
    if (!file) { setAttachment(null); setAttachmentSize(0); setAttachmentPayloadSize(0); return; }
    if (file.size > 1024 * 1024) {
      e.target.value = "";
      setAttachment(null);
      setAttachmentSize(0); setAttachmentPayloadSize(0);
      setAttachmentError("Attachments are limited to 1 MB.");
      return;
    }
    const ext = file.name.split(".").pop()?.toLowerCase();
    const mimeByExt = {
      pdf: "application/pdf", jpg: "image/jpeg", jpeg: "image/jpeg", png: "image/png",
      doc: "application/msword",
      docx: "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
      xls: "application/vnd.ms-excel",
      xlsx: "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    };
    if (!mimeByExt[ext]) {
      e.target.value = ""; setAttachment(null); setAttachmentSize(0); setAttachmentPayloadSize(0);
      setAttachmentError("Supported formats: PDF, JPG, JPEG, PNG, DOC, DOCX, XLS and XLSX.");
      return;
    }
    try {
      const raw = new Uint8Array(await file.arrayBuffer());
      const starts = (...bytes) => bytes.every((value, index) => raw[index] === value);
      const ole = starts(0xd0,0xcf,0x11,0xe0,0xa1,0xb1,0x1a,0xe1);
      const zip = starts(0x50,0x4b,0x03,0x04);
      const valid = ext === "pdf" ? new TextDecoder().decode(raw.slice(0,5)) === "%PDF-"
        : ["jpg","jpeg"].includes(ext) ? starts(0xff,0xd8,0xff)
        : ext === "png" ? starts(0x89,0x50,0x4e,0x47,0x0d,0x0a,0x1a,0x0a)
        : ["doc","xls"].includes(ext) ? ole : ["docx","xlsx"].includes(ext) ? zip : false;
      if (!valid) throw new Error("The file content does not match its extension.");
      const contentBase64 = btoa(Array.from(raw, (byte) => String.fromCharCode(byte)).join(""));
      const nextAttachment = { filename: file.name, content_type: mimeByExt[ext], content_base64: contentBase64 };
      setAttachment(nextAttachment);
      setAttachmentSize(file.size);
      setAttachmentPayloadSize(new TextEncoder().encode(JSON.stringify({
        format: "CIPHERQ_ATTACHMENT_V1", filename: file.name, mime_type: mimeByExt[ext],
        original_size: file.size, sha256: "0".repeat(64), data_base64: contentBase64,
      })).length);
    } catch (err) {
      setAttachmentError(err.message || "Could not read attachment.");
      setAttachment(null);
      setAttachmentSize(0);
      setAttachmentPayloadSize(0);
    }
  }

  const qiraStarted = useQiraOnce("intent.start"); // first real edit: QIRA starts thinking along
  const set = (k) => (e) => setForm((f) => ({ ...f, [k]: e.target.type === "checkbox" ? e.target.checked : e.target.value }));

  useEffect(() => {
    if (!editId) return;
    getIntent(editId)
      .then((v) => setForm(formFromBody(v.body)))
      .catch((e) => setError(e.message));
  }, [editId]);

  useEffect(() => {
    const businessReference = form.business_reference.trim().toUpperCase();
    if (!businessReference || form.evidence_ref.trim()) return;
    setForm((current) => (current.evidence_ref.trim() ? current : { ...current, evidence_ref: businessReference }));
  }, [form.business_reference, form.evidence_ref]);

  const approvalsNeeded = REQUIRED_APPROVALS[form.classification];
  const blocked = reauthRequired;

  const payload = useMemo(() => {
    const operations = [form.encrypt && "encrypt", form.decrypt && "decrypt", form.share && "share"].filter(Boolean);
    const evidenceRef = (form.evidence_ref.trim() || form.business_reference.trim()).toUpperCase();
    return {
      purpose_code: form.purpose_code,
      purpose_statement: form.purpose_statement.trim(),
      business_reference: form.business_reference.trim().toUpperCase(),
      resource: form.resource.trim(),
      operations,
      data_scope: {
        classification: form.classification,
        max_bytes: Number(form.max_bytes),
        max_uses: Number(form.max_uses),
      },
      // bound to the SERVER-issued session/device of this login; not user-editable
      session_id: sessionId,
      device_id: deviceId,
      valid_from: new Date(form.valid_from).toISOString(),
      valid_until: new Date(form.valid_until).toISOString(),
      evidence_refs: evidenceRef ? [{ kind: "CASE", ref: evidenceRef }] : [],
      attachment,
      reason: form.reason || "initial creation",
    };
  }, [form, sessionId, deviceId, attachment]);

  async function handleSubmit(e) {
    e.preventDefault();
    setError("");
    if (!payload.operations.length) return setError("Select at least one operation.");
    if (attachment && attachmentPayloadSize > Number(form.max_bytes)) {
      return setError(`The encrypted file payload requires ${attachmentPayloadSize} bytes, above this intent's ${Number(form.max_bytes)}-byte operation limit. Increase Maximum Bytes Per Operation or choose a smaller file.`);
    }
    setLoading(true);
    emitQira("intent.processing"); // QIRA: a real create/validate request is in flight
    try {
      const res = editId ? await createIntentVersion(editId, payload) : await createIntent(payload);
      const intentId = res.intent_id ?? editId;
      // Submit for approval straight away (DRAFT -> PENDING_APPROVAL/APPROVED per policy).
      const validation = await validateIntent(intentId);
      const latest = validation?.intent || await getIntent(intentId);
      if (validation && validation.evidence_ok === false) {
        const notAssigned = (validation.findings || []).some((f) => f.code === "USER_NOT_ASSIGNED");
        const findings = (validation.findings || []).map((f) => f.detail || f.message || f.reason || f.code).filter(Boolean);
        setError(
          `Intent saved as DRAFT because evidence validation failed: ${validation.evidence_summary || "evidence requirements were not met."}` +
          (findings.length ? ` Details: ${findings.join("; ")}` : "") +
          (notAssigned
            ? " Ask an administrator to assign your account to this case (Admin → Evidence Cases), then use “Validate / submit” in Intent History."
            : " Correct the case reference/evidence and submit a new version or retry validation.")
        );
      }
      setCreated(latest);
      // Real outcome from the server: it decides the status, never the client.
      releaseQira("intent.processing");
      if (latest?.status === "APPROVED") emitQira("intent.approved");
      else if (latest?.status === "PENDING_APPROVAL") emitQira("intent.pending");
      else if (latest?.status === "REJECTED") emitQira("intent.rejected");
      else emitQira("op.failed"); // saved as DRAFT: evidence validation did not pass
    } catch (err) {
      releaseQira("intent.processing");
      if (err?.status === 403) emitQira("auth.unauthorized");
      else if (!isUnavailableError(err)) emitQira("op.failed");
      const validationErrors = err.body?.errors;
      setError(Array.isArray(validationErrors)
        ? validationErrors.map((x) => `${(x.loc || []).slice(1).join(".")}: ${x.msg}`).join("; ")
        : err.message);
    } finally {
      setLoading(false);
    }
  }

  if (created) {
    return (
      <div>
        <PageHeader icon="verified_user" eyebrow="Intent" title={`Intent #${created.intent_id} · v${created.version}`}
          description="Submitted. The server decides whether it is approved; nothing here is client-asserted." />
        <div className="bg-cq-surface-container rounded-cq-xl p-cq-stack-lg max-w-2xl">
          {error && <Alert type="error">{error}</Alert>}
          <div className="text-[14px] text-cq-on-surface">
            Status: <b>{created.status}</b> · approvals {created.approvals.filter((a) => a.verdict === "APPROVE").length}/{created.required_approvals}
          </div>
          {created.status === "DRAFT" && (
            <Alert type="error">This intent is saved as a draft, not sent to the approval queue. Evidence validation must succeed before an administrator can approve it.</Alert>
          )}
          {created.status === "PENDING_APPROVAL" && (
            <p className="mt-2 text-[13px] text-cq-on-surface-variant">
              An administrator other than you must approve this version before any key operation is permitted.
              Changing the scope later creates a new version that needs approval again.
            </p>
          )}
          {!created.integrity_ok && <Alert type="error">Integrity check of this record failed.</Alert>}
          <div className="mt-4 flex gap-2.5">
            <Button variant="brand" iconRight={ArrowRight}
              onClick={() => navigate("intent-history", { intentId: created.intent_id, initialAttachment: attachment })}>Intent history</Button>
            {created.status === "APPROVED" && (
              <Button variant="ghost" onClick={() => navigate("encrypt", {
                intentId: created.intent_id, initialAttachment: attachment,
              })}>{attachment ? "Encrypt attached file" : "Go to encrypt"}</Button>
            )}
          </div>
        </div>
      </div>
    );
  }

  return (
    <div>
      <PageHeader icon="assignment" eyebrow="Intent"
        title={editId ? `New version of intent #${editId}` : "Declare an intent"}
        description="A structured, reviewable statement of why privileged access is needed. Scope is bounded and any change needs fresh approval." />
      <form onSubmit={handleSubmit} onChange={qiraStarted} className="bg-cq-surface-container rounded-cq-xl p-cq-stack-lg max-w-3xl">
        <Alert type="error">{error}</Alert>
        {blocked && <Alert type="error">Your session needs reauthentication before an intent can be created.</Alert>}
        {!isMonitoring && <Alert type="info">Monitoring is not active yet; decisions made later will require it.</Alert>}

        <div className="grid sm:grid-cols-2 gap-x-4">
          <Field label="Purpose">
            <SelectField value={form.purpose_code} onChange={set("purpose_code")}>
              {PURPOSES.map(([v, l]) => <option key={v} value={v}>{l}</option>)}
            </SelectField>
          </Field>
          <Field label="Business reference" hint="e.g. CASE-100234">
            <TextField mono value={form.business_reference} onChange={set("business_reference")} required pattern="[A-Za-z]{2,8}-[0-9]{3,10}" />
          </Field>
        </div>
        <Field label="Purpose statement" hint="10–500 characters">
          <TextAreaField rows={3} value={form.purpose_statement} onChange={set("purpose_statement")} onFocus={() => emitQira("intent.justification")} required minLength={10} maxLength={500} />
        </Field>
        <Field label="Resource" hint="e.g. vault:customer-records">
          <TextField mono value={form.resource} onChange={set("resource")} required pattern="[a-z0-9][a-z0-9:/._\-]{2,127}" />
        </Field>
        <Field label="Operations">
          <label className="mr-5 text-[14px] text-cq-on-surface"><input type="checkbox" checked={form.encrypt}
            onChange={(e) => setForm((f) => ({ ...f, encrypt: e.target.checked, share: e.target.checked ? f.share : false }))} /> encrypt</label>
          <label className="text-[14px] text-cq-on-surface"><input type="checkbox" checked={form.decrypt} onChange={set("decrypt")} /> decrypt</label>
          <label className="ml-5 text-[14px] text-cq-on-surface"><input type="checkbox" checked={form.share}
            disabled={!form.encrypt} onChange={set("share")} /> share</label>
        </Field>
        <div className="grid sm:grid-cols-3 gap-x-4">
          <Field label="Classification">
            <SelectField value={form.classification} onChange={set("classification")}>
              {CLASSIFICATIONS.map((c) => <option key={c}>{c}</option>)}
            </SelectField>
          </Field>
          <Field label="Maximum Bytes Per Operation">
            <TextField type="number" min={1} max={12582912} value={form.max_bytes} onChange={set("max_bytes")} required />
          </Field>
          <Field label="Max uses">
            <TextField type="number" min={1} max={100} value={form.max_uses} onChange={set("max_uses")} required />
          </Field>
        </div>
        <div className="grid sm:grid-cols-2 gap-x-4">
          <Field label="Valid from"><TextField type="datetime-local" value={form.valid_from} onChange={set("valid_from")} required /></Field>
          <Field label="Valid until" hint="max 24 h"><TextField type="datetime-local" value={form.valid_until} onChange={set("valid_until")} required /></Field>
        </div>
        <Field label="Evidence: case reference" hint="verified against the administrator-maintained case table (local provider, not an external system)">
          <TextField mono value={form.evidence_ref} onChange={set("evidence_ref")} placeholder="CASE-100234" />
        </Field>
        <Field label="Attach supporting file (optional)" hint="PDF, JPG, JPEG, PNG, DOC, DOCX, XLS or XLSX · maximum 1 MB. The selected file can be sent to the encryption workflow as the actual payload.">
          <input type="file" accept=".pdf,.jpg,.jpeg,.png,.doc,.docx,.xls,.xlsx"
            onChange={handleAttachmentChange}
            className="block w-full text-sm text-cq-on-surface file:mr-3 file:rounded-lg file:border-0 file:px-3 file:py-2 file:bg-cq-surface-container-high" />
          {attachment && <p className="mt-1 text-xs text-cq-on-surface-variant">Attached: {attachment.filename} · {attachmentSize} bytes</p>}
          {attachmentError && <Alert type="error">{attachmentError}</Alert>}
        </Field>
        {editId && (
          <Field label="Reason for change"><TextField value={form.reason} onChange={set("reason")} minLength={3} maxLength={200} /></Field>
        )}

        <div className="rounded-cq-md bg-cq-surface-container-high px-4 py-3 text-[12.5px] text-cq-on-surface-variant mb-4 flex gap-2">
          <Info size={15} className="shrink-0 mt-0.5" />
          <span>
            {form.classification} requires <b>{approvalsNeeded}</b> administrator approval{approvalsNeeded === 1 ? "" : "s"}
            {form.classification === "RESTRICTED" ? " and a fresh identity step-up per operation" : ""}.
            This intent is bound to your current session and device; it cannot be used from any other.
          </span>
        </div>

        <Button type="submit" variant="brand" icon={ShieldCheck} loading={loading} disabled={blocked || !sessionId}>
          {editId ? "Submit new version" : "Create and submit"}
        </Button>
      </form>
    </div>
  );
}
