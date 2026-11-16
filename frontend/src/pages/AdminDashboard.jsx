import { emitQira } from "../qira";
import { reportApiError } from "../qira/report";
import { useEffect, useState, useRef, useCallback } from "react";
import { motion } from "framer-motion";
import {
  ShieldCheck,
  Users,
  ClipboardCheck,
  ShieldAlert,
  RefreshCcw,
  CheckCircle2,
  XCircle,
  Bot,
  Activity,
  UserCheck,
  ChevronDown,
  ChevronUp,
} from "lucide-react";
import PageHeader from "../components/ui/PageHeader";
import Button from "../components/ui/Button";
import Alert from "../components/ui/Alert";
import { Field, SelectField, TextField } from "../components/ui/Field";
import LifecyclePill from "../components/ui/LifecyclePill";
import { formatTimestamp } from "../utils/formatTimestamp";
import { useMonitoringContext } from "../context/MonitoringContext";
import FaceAuthPanel from "../components/face/FaceAuthPanel";
import AdminMonitoringSessionsPanel from "../components/monitoring/AdminMonitoringSessionsPanel";
import { deriveMonitoringState, monitoringReason, MONITORING_UI_META } from "../components/monitoring/monitoringState";
import {
  listUsers,
  updateUserRole,
  listIntents,
  approveIntent,
  revokeIntent,
  getCase,
  listCases,
  putCase,
  revokeDevice,
  unrevokeDevice,
  revokeSession,
  listSecurityIncidents,
  resolveSecurityIncident,
  listReauthRequests,
  approveReauthRequest,
  rejectReauthRequest,
  getDeviceStatus,
  getSessionStatus,
} from "../services/api";

// Server-side enforced role model (see backend/api/rbac.py) — this is
// just the display list, never a source of authorization truth.
const USER_ROLES = ["USER_LEVEL_1", "USER_LEVEL_2"];

const TABS = [
  { id: "users", label: "Users & Roles", icon: Users },
  { id: "intents", label: "Intent Approval", icon: ClipboardCheck },
  { id: "cases", label: "Evidence Cases", icon: ClipboardCheck },
  { id: "access-requests", label: "Access Requests", icon: UserCheck },
  { id: "devices", label: "Devices & Sessions", icon: ShieldAlert },
  { id: "risk", label: "Admin Live Monitoring", icon: Activity },
  { id: "sessions", label: "Monitoring Sessions", icon: Activity },
  { id: "incidents", label: "Security Incidents", icon: Bot },
];

function Loading({ label }) {
  return (
    <div className="bg-cq-surface-container rounded-cq-xl p-14 flex flex-col items-center justify-center gap-4 text-center">
      <div className="relative w-11 h-11">
        <motion.div className="absolute inset-0 rounded-full border-[3px] border-cq-primary/20" />
        <motion.div
          className="absolute inset-0 rounded-full border-[3px] border-transparent border-t-cq-primary border-r-cq-secondary"
          animate={{ rotate: 360 }}
          transition={{ repeat: Infinity, duration: 0.9, ease: "linear" }}
        />
      </div>
      <p className="text-cq-body-md text-cq-on-surface-variant">{label}</p>
    </div>
  );
}

function EmptyState({ title, desc }) {
  return (
    <div className="bg-cq-surface-container rounded-cq-xl p-14 flex flex-col items-center justify-center text-center">
      <div className="text-[14.5px] font-semibold text-cq-on-surface">{title}</div>
      {desc && <div className="mt-1 text-[13.5px] text-cq-on-surface-variant max-w-sm">{desc}</div>}
    </div>
  );
}

// ---------------------------------------------------------------------
// Users & Roles
// ---------------------------------------------------------------------

function UsersPanel({ user }) {
  const [users, setUsers] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [savingId, setSavingId] = useState(null);

  async function load() {
    setLoading(true);
    setError("");
    try {
      setUsers(await listUsers());
    } catch (err) {
      setError(err.detail?.toString?.() || err.message || "Failed to load users");
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    load();
  }, []);

  async function handleRoleChange(id, role) {
    setSavingId(id);
    setError("");
    try {
      await updateUserRole(id, role);
      await load();
    } catch (err) {
      setError(err.detail?.toString?.() || err.message || "Failed to update role");
    } finally {
      setSavingId(null);
    }
  }

  if (loading) return <Loading label="Loading users…" />;

  return (
    <div className="bg-cq-surface-container rounded-cq-xl p-cq-stack-lg">
      <div className="flex items-center justify-between mb-4">
        <h2 className="text-[16px] font-bold text-cq-on-surface">Users & Roles</h2>
        <Button variant="outline" size="sm" icon={RefreshCcw} onClick={load}>
          Refresh
        </Button>
      </div>
      <Alert type="error">{error}</Alert>
      {users.length === 0 ? (
        <EmptyState title="No users found" />
      ) : (
        <div className="overflow-x-auto -mx-2 sm:mx-0">
          <table className="w-full text-left border-collapse min-w-[520px]">
            <thead>
              <tr className="border-b border-cq-outline-variant/25">
                <th className="py-2.5 px-3 text-[11.5px] font-bold uppercase tracking-wide text-cq-on-surface-variant">
                  Username
                </th>
                <th className="py-2.5 px-3 text-[11.5px] font-bold uppercase tracking-wide text-cq-on-surface-variant">
                  Email
                </th>
                <th className="py-2.5 px-3 text-[11.5px] font-bold uppercase tracking-wide text-cq-on-surface-variant">
                  Role
                </th>
              </tr>
            </thead>
            <tbody>
              {users.map((u) => (
                <tr key={u.id} className="hover:bg-cq-surface-container-high transition-colors">
                  <td className="py-3 px-3 text-[13.5px] text-cq-on-surface border-b border-cq-outline-variant/15">
                    {u.username}
                    {u.id === user?.userId && (
                      <span className="ml-2 text-[11px] uppercase tracking-wide text-cq-primary">you</span>
                    )}
                  </td>
                  <td className="py-3 px-3 text-[13px] text-cq-on-surface-variant border-b border-cq-outline-variant/15">
                    {u.email}
                  </td>
                  <td className="py-3 px-3 border-b border-cq-outline-variant/15">
                    {u.role === "ADMIN" ? (
                      <span className="inline-flex items-center rounded-cq-md bg-cq-secondary-container/15 px-2.5 py-1.5 text-[13px] font-semibold text-cq-secondary">
                        ADMIN
                      </span>
                    ) : (
                      <SelectField
                        value={u.role}
                        disabled={savingId === u.id}
                        onChange={(e) => handleRoleChange(u.id, e.target.value)}
                        className="!py-1.5 !text-[13px] max-w-[220px]"
                      >
                        {USER_ROLES.map((r) => (
                          <option key={r} value={r}>
                            {r}
                          </option>
                        ))}
                      </SelectField>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}

// ---------------------------------------------------------------------
// Intent Approval queue
// ---------------------------------------------------------------------

function IntentsPanel() {
  const [intents, setIntents] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [message, setMessage] = useState("");
  const [busyId, setBusyId] = useState(null);
  const [filter, setFilter] = useState("PENDING_APPROVAL");
  const loadInFlightRef = useRef(false);

  async function load(showLoading = true) {
    // A slow API response must not accumulate overlapping 4-second polls.
    if (loadInFlightRef.current) return;
    loadInFlightRef.current = true;
    if (showLoading) setLoading(true);
    setError("");
    try {
      const all = await listIntents();
      setIntents(all.filter((i) => !filter || i.status === filter).sort((a, b) => b.intent_id - a.intent_id));
    } catch (err) {
      setError(err.detail?.toString?.() || err.message || "Failed to load intents");
    } finally {
      loadInFlightRef.current = false;
      if (showLoading) setLoading(false);
    }
  }

  useEffect(() => {
    load();
    const id = window.setInterval(() => load(false), 4000);
    return () => window.clearInterval(id);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [filter]);

  async function act(intent, kind) {
    setBusyId(intent.intent_id);
    setError("");
    setMessage("");
    try {
      let outcome = null;
      if (kind === "revoke") await revokeIntent(intent.intent_id, "revoked from admin dashboard");
      else outcome = await approveIntent(intent.intent_id, intent.version, kind === "approve" ? "APPROVE" : "REJECT");
      setMessage(`Intent #${intent.intent_id} v${intent.version}: ${kind} recorded.`);
      // QIRA: the real, server-confirmed outcome of this decision (presentation only)
      if (kind === "reject") emitQira("intent.rejected");
      else if (kind === "approve") emitQira(outcome?.status === "APPROVED" ? "intent.approved" : "intent.recorded");
      await load();
    } catch (err) {
      setError(err.detail?.toString?.() || err.message || "Action failed");
      reportApiError(err); // QIRA: only a recognised real denial/outage produces a reaction
    } finally {
      setBusyId(null);
    }
  }

  return (
    <div className="bg-cq-surface-container rounded-cq-xl p-cq-stack-lg">
      <div className="flex items-center justify-between flex-wrap gap-3 mb-4">
        <h2 className="text-[16px] font-bold text-cq-on-surface">Intent Approval</h2>
        <div className="flex items-center gap-2">
          <SelectField value={filter} onChange={(e) => setFilter(e.target.value)} className="!py-1.5 !text-[13px]">
            <option value="PENDING_APPROVAL">Pending approval</option>
            <option value="DRAFT">Draft / needs validation</option>
            <option value="APPROVED">Approved</option>
            <option value="REJECTED">Rejected</option>
            <option value="REVOKED">Revoked</option>
            <option value="">All</option>
          </SelectField>
          <Button variant="outline" size="sm" icon={RefreshCcw} onClick={() => load()}>Refresh</Button>
        </div>
      </div>
      <Alert type="error">{error}</Alert>
      {message && <Alert type="success">{message}</Alert>}
      <p className="text-[13px] text-cq-on-surface-variant mb-4">
        Approval is bound to a specific version. Separation of duties is enforced server-side: a requester cannot approve
        their own intent, and any scope change creates a new version that must be approved again.
      </p>
      {loading ? (
        <Loading label="Loading intents…" />
      ) : intents.length === 0 ? (
        <EmptyState title="Nothing here" desc="No intents match this filter." />
      ) : (
        <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
          {intents.map((i) => (
            <div key={i.intent_id} className="rounded-cq-xl p-cq-stack-md bg-cq-surface-container-high border-l-2 border-cq-outline-variant/30">
              <div className="flex items-center justify-between mb-2">
                <span className="text-[13.5px] font-bold text-cq-on-surface">Intent #{i.intent_id} · v{i.version}</span>
                <LifecyclePill state={i.status.toLowerCase()} />
              </div>
              <div className="text-[12.5px] text-cq-on-surface mb-1">
                {i.body.purpose_code} · {i.body.operations.join("/")} · {i.body.resource}
              </div>
              <div className="text-[12.5px] text-cq-on-surface-variant mb-1">
                User #{i.owner_user_id} · case {i.body.business_reference} · {i.body.data_scope.classification} · ≤{i.body.data_scope.max_bytes} B × {i.body.data_scope.max_uses}
              </div>
              <div className="text-[12.5px] text-cq-on-surface-variant mb-1">
                Window {formatTimestamp(i.body.valid_from)} → {formatTimestamp(i.body.valid_until)}
              </div>
              <div className="text-[12.5px] text-cq-on-surface-variant italic mb-2">"{i.body.purpose_statement}"</div>
              {i.body.attachment?.content_base64 && (
                <div className="text-[12px] mb-2">
                  <a className="text-cq-primary underline" download={i.body.attachment.filename}
                    href={`data:${i.body.attachment.content_type};base64,${i.body.attachment.content_base64}`}>
                    View attachment: {i.body.attachment.filename}
                  </a>
                </div>
              )}
              <div className="text-[12px] text-cq-on-surface-variant mb-2">
                Approvals {i.approvals.filter((a) => a.verdict === "APPROVE").length}/{i.required_approvals}
                {!i.integrity_ok && <span className="text-cq-error"> · INTEGRITY CHECK FAILED</span>}
              </div>
              {i.status === "DRAFT" && (
                <p className="text-[12px] text-amber-300 mb-2">
                  Not ready for approval: the requester must complete evidence validation. Approve/reject controls appear only after validation succeeds.
                </p>
              )}
              <div className="flex gap-2 mt-2">
                {i.status === "PENDING_APPROVAL" && (
                  <>
                    <Button variant="brand" size="sm" icon={CheckCircle2} loading={busyId === i.intent_id} onClick={() => act(i, "approve")}>Approve</Button>
                    <Button variant="danger" size="sm" icon={XCircle} loading={busyId === i.intent_id} onClick={() => act(i, "reject")}>Reject</Button>
                  </>
                )}
                {(i.status === "APPROVED" || i.status === "PENDING_APPROVAL") && (
                  <Button variant="outline" size="sm" loading={busyId === i.intent_id} onClick={() => act(i, "revoke")}>Revoke</Button>
                )}
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

// ---------------------------------------------------------------------
// Evidence cases (local, administrator-maintained evidence provider)
// ---------------------------------------------------------------------
const CASE_TEMPLATES = [
  { id: "investigation", label: "Investigation", title: "Case investigation", cap: "CONFIDENTIAL", resources: "vault:customer-records" },
  { id: "incident", label: "Security incident", title: "Security incident response", cap: "RESTRICTED", resources: "vault:security-incidents" },
  { id: "audit", label: "Audit review", title: "Audit evidence review", cap: "CONFIDENTIAL", resources: "vault:audit-records" },
  { id: "regulatory", label: "Regulatory review", title: "Regulatory reporting review", cap: "RESTRICTED", resources: "vault:regulatory-reports" },
  { id: "service", label: "Service request", title: "Internal service request", cap: "INTERNAL", resources: "vault:service-requests" },
];

function CasesPanel() {
  const [ref, setRef] = useState("");
  const [loaded, setLoaded] = useState(null);
  const [form, setForm] = useState({ title: "", cap: "CONFIDENTIAL", resources: "", users: "" });
  const [cases, setCases] = useState([]);
  const [offset, setOffset] = useState(0);
  const [hasMore, setHasMore] = useState(false);
  const [casesLoading, setCasesLoading] = useState(true);
  const [error, setError] = useState("");
  const [message, setMessage] = useState("");
  const [busy, setBusy] = useState(false);
  const [roster, setRoster] = useState([]);
  const set = (k) => (e) => setForm((f) => ({ ...f, [k]: e.target.value }));
  const ids = (t) => t.split(",").map((x) => x.trim()).filter(Boolean).map(Number);
  // Requesters are picked by name from the real user list, so an assignment can never be a typo or a
  // user ID that does not exist (the server rejects unknown IDs as well).
  useEffect(() => { listUsers().then(setRoster).catch(() => setRoster([])); }, []);
  const toggleUser = (id) => setForm((f) => {
    const cur = ids(f.users);
    const next = cur.includes(id) ? cur.filter((x) => x !== id) : [...cur, id].sort((a, b) => a - b);
    return { ...f, users: next.join(", ") };
  });
  const normalizedRef = ref.trim().toUpperCase();
  const loadedIds = loaded?.assigned_user_ids || [];
  const draftIds = ids(form.users);
  const hasUnsavedChanges = loaded
    ? loaded.ref !== normalizedRef || loaded.title !== form.title || loaded.classification_cap !== form.cap
      || JSON.stringify(loaded.allowed_resources) !== JSON.stringify(form.resources.split(",").map((x) => x.trim()).filter(Boolean))
      || JSON.stringify(loadedIds) !== JSON.stringify(draftIds)
    : Boolean(normalizedRef || form.title || form.resources || form.users);

  async function refreshCases(nextOffset = 0) {
    setCasesLoading(true);
    setError("");
    try {
      const page = await listCases(20, nextOffset);
      setCases(page.cases);
      setOffset(page.offset);
      setHasMore(page.has_more);
    } catch (err) {
      setError(err.detail?.toString?.() || err.message || "Failed to load saved cases");
    } finally {
      setCasesLoading(false);
    }
  }

  useEffect(() => { refreshCases(0); }, []);

  function selectSavedCase(c) {
    setRef(c.ref);
    setLoaded(c);
    setForm({ title: c.title, cap: c.classification_cap, resources: c.allowed_resources.join(", "),
      users: c.assigned_user_ids.join(", ") });
    setError("");
    setMessage(`Loaded saved case ${c.ref}. Changes remain unsaved until you save.`);
  }

  function applyTemplate(templateId) {
    const template = CASE_TEMPLATES.find((item) => item.id === templateId);
    if (!template) return;
    setForm((current) => ({ ...current, title: template.title, cap: template.cap, resources: template.resources }));
    setMessage(`${template.label} suggestions applied to this draft only; nothing has been saved.`);
    setError("");
  }

  async function load() {
    setError(""); setMessage(""); setLoaded(null);
    try {
      const c = await getCase(normalizedRef);
      setLoaded(c);
      setForm({ title: c.title, cap: c.classification_cap, resources: c.allowed_resources.join(", "), users: c.assigned_user_ids.join(", ") });
    } catch (err) {
      setError(err.status === 404 ? "No saved case with this reference. Choose a template or enter case details, then save to create it." : err.message);
    }
  }
  async function save(status = "OPEN") {
    setBusy(true); setError(""); setMessage("");
    try {
      const c = await putCase(normalizedRef, {
        title: form.title.trim(), classification_cap: form.cap, status,
        allowed_resources: form.resources.split(",").map((x) => x.trim()).filter(Boolean),
        assigned_user_ids: draftIds,
      });
      setLoaded(c);
      setForm({ title: c.title, cap: c.classification_cap, resources: c.allowed_resources.join(", "),
        users: c.assigned_user_ids.join(", ") });
      setMessage(`Case ${c.ref} saved as revision ${c.revision} (${c.status}).`);
      await refreshCases(0);
    } catch (err) {
      const d = err.detail;
      setError(Array.isArray(d) ? d.map((x) => `${(x.loc || []).slice(1).join(".")}: ${x.msg}`).join("; ") : err.message);
    } finally { setBusy(false); }
  }

  return (
    <div className="grid gap-5 xl:grid-cols-[minmax(0,0.9fr)_minmax(0,1.1fr)]">
      <div className="bg-cq-surface-container rounded-cq-xl p-cq-stack-lg">
        <h2 className="text-[16px] font-bold text-cq-on-surface mb-1">Evidence cases</h2>
        <p className="text-[13px] text-cq-on-surface-variant mb-4">
          For INTERNAL and higher classifications, the backend requires a matching OPEN case, recently updated,
          assigned to the requester, within the allowed resource and classification cap. This is a local admin-maintained
          table, not an external case-management integration.
        </p>
        <Alert type="error">{error}</Alert>
        {message && <Alert type="success">{message}</Alert>}
        <div className="mb-4 rounded-cq-lg border border-cq-outline-variant/25 bg-cq-surface-container-low p-4">
          <div className="font-semibold text-[13px] text-cq-on-surface mb-1">What is saved</div>
          <p className="text-[12.5px] text-cq-on-surface-variant">
            Saving writes the reference, title, status, classification cap, allowed resources, assigned user IDs,
            server update time, and revision to the encrypted <code>evidence_cases</code> database collection.
            Each save creates or updates a revision and an audit event. Changing a case can invalidate an existing
            authorization context; the backend checks the current case again before protected operations.
          </p>
          <p className="text-[12.5px] text-cq-on-surface-variant mt-2">
            A template is only a suggestion until saved. This form does not save attachments, intent bodies,
            ciphertext, encryption keys, or user profile data. Assigned IDs must refer to real users.
          </p>
        </div>
        <div className="flex gap-2 items-end mb-4">
          <div className="flex-1"><Field label="Case reference" hint="format: CASE-100200"><TextField value={ref} onChange={(e) => setRef(e.target.value)} placeholder="CASE-100200" /></Field></div>
          <Button variant="outline" onClick={load} disabled={!normalizedRef || busy}>Load</Button>
        </div>
        <Field label="Starter template" hint="suggestions only; does not create a case">
          <SelectField defaultValue="" onChange={(e) => applyTemplate(e.target.value)}>
            <option value="">Choose a template…</option>
            {CASE_TEMPLATES.map((template) => <option key={template.id} value={template.id}>{template.label}</option>)}
          </SelectField>
        </Field>
        <Field label="Title"><TextField value={form.title} onChange={set("title")} placeholder="Short case title" /></Field>
        <Field label="Highest classification allowed">
          <SelectField value={form.cap} onChange={set("cap")}>
            {["PUBLIC", "INTERNAL", "CONFIDENTIAL", "RESTRICTED"].map((c) => <option key={c}>{c}</option>)}
          </SelectField>
        </Field>
        <Field label="Allowed resources" hint="comma separated, e.g. vault:customer-records">
          <TextField value={form.resources} onChange={set("resources")} placeholder="vault:customer-records" />
        </Field>
        <Field label="Assigned requesters" hint="Only assigned users can use this case as evidence in Create Intent">
          {roster.length > 0 ? (
            <div className="max-h-44 overflow-auto rounded-cq-lg border border-cq-outline-variant/25 divide-y divide-cq-outline-variant/15">
              {roster.filter((u) => !u.disabled || draftIds.includes(u.id)).map((u) => (
                <label key={u.id} className="flex items-center gap-2 px-3 py-1.5 text-[13px] text-cq-on-surface cursor-pointer">
                  <input type="checkbox" checked={draftIds.includes(u.id)} onChange={() => toggleUser(u.id)} />
                  <span className="font-semibold">{u.username}</span>
                  <span className="text-cq-on-surface-variant">ID {u.id} · {u.role}{u.disabled ? " · disabled" : ""}</span>
                </label>
              ))}
            </div>
          ) : (
            <TextField value={form.users} onChange={set("users")} placeholder="12, 18" />
          )}
          {draftIds.length === 0 && (
            <p className="mt-1 text-[12px] text-amber-300">No requester assigned: every intent that cites this case will fail with USER_NOT_ASSIGNED.</p>
          )}
        </Field>
        <div className="flex flex-wrap gap-2 items-center">
          <Button variant="brand" loading={busy} onClick={() => save("OPEN")} disabled={!normalizedRef || !form.title.trim()}>Save as open</Button>
          {loaded && <Button variant="danger" loading={busy} onClick={() => save("CLOSED")}>Save and close</Button>}
          <span className="text-[12px] text-cq-on-surface-variant">
            {hasUnsavedChanges ? "Draft has unsaved changes" : `Saved revision ${loaded?.revision} · ${loaded?.status}`}
          </span>
        </div>
      </div>

      <div className="bg-cq-surface-container rounded-cq-xl p-cq-stack-lg">
        <div className="flex items-center justify-between mb-4">
          <div>
            <h2 className="text-[16px] font-bold text-cq-on-surface">Saved cases</h2>
            <p className="text-[12.5px] text-cq-on-surface-variant">Select a case to load it into the editor. Latest updates first.</p>
          </div>
          <Button variant="outline" size="sm" onClick={() => refreshCases(offset)} loading={casesLoading}>Refresh</Button>
        </div>
        {casesLoading ? <p className="text-sm text-cq-on-surface-variant">Loading saved cases…</p>
          : cases.length === 0 ? <EmptyState title="No saved evidence cases" desc="Choose a template or enter a reference and save a case to begin." />
            : <div className="space-y-2">
              {cases.map((c) => (
                <button key={c.ref} type="button" onClick={() => selectSavedCase(c)}
                  className={`w-full rounded-cq-lg border p-3 text-left transition-colors ${loaded?.ref === c.ref ? "border-cq-primary/60 bg-cq-primary/10" : "border-cq-outline-variant/25 bg-cq-surface-container-low hover:bg-cq-surface-container-high"}`}>
                  <span className="flex items-start justify-between gap-2">
                    <span className="min-w-0">
                      <span className="block font-mono text-[12px] text-cq-primary">{c.ref}</span>
                      <span className="block truncate text-[13.5px] font-semibold text-cq-on-surface">{c.title}</span>
                    </span>
                    <span className={`shrink-0 rounded px-2 py-0.5 text-[10px] font-bold ${c.status === "OPEN" ? "bg-emerald-500/10 text-emerald-300" : "bg-cq-error-container/20 text-cq-error"}`}>{c.status}</span>
                  </span>
                  <span className="mt-2 block text-[11.5px] text-cq-on-surface-variant">
                    {c.classification_cap} cap · {c.allowed_resources.length} resources · {c.assigned_user_ids.length} assigned · rev {c.revision}
                  </span>
                  <span className="mt-1 block text-[11px] text-cq-outline">Updated {formatTimestamp(c.updated_at)}</span>
                </button>
              ))}
            </div>}
        <div className="mt-4 flex items-center justify-between">
          <Button variant="outline" size="sm" disabled={offset === 0 || casesLoading} onClick={() => refreshCases(Math.max(0, offset - 20))}>Previous</Button>
          <span className="text-[11px] text-cq-on-surface-variant">
            {cases.length ? `Cases ${offset + 1}–${offset + cases.length}` : "No cases on this page"}
          </span>
          <Button variant="outline" size="sm" disabled={!hasMore || casesLoading} onClick={() => refreshCases(offset + 20)}>Next</Button>
        </div>
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------
// Devices & Sessions quick actions
// ---------------------------------------------------------------------

// Part 13/14 — Qira's automatic CRITICAL-severity revocations show up
// here for admin review/recovery. Qira itself can never call the
// resolve endpoint (server-enforced: `POST /api/security/incidents/
// {id}/resolve` requires ADMIN role) — this panel is the ONLY path
// back to restored access after an automatic revoke.
const SEVERITY_META = {
  LOW: { tone: "text-cq-on-surface-variant", bg: "bg-white/[0.03]" },
  MEDIUM: { tone: "text-amber-400", bg: "bg-amber-400/10" },
  HIGH: { tone: "text-orange-400", bg: "bg-orange-400/10" },
  CRITICAL: { tone: "text-cq-error", bg: "bg-cq-error-container/15" },
};

// ---------------------------------------------------------------------
// Access Requests (device reauthorization approvals)
// ---------------------------------------------------------------------

function ReauthRequestsPanel() {
  const [requests, setRequests] = useState(null);
  const [error, setError] = useState("");
  const [message, setMessage] = useState("");
  const [filter, setFilter] = useState("pending"); // "pending" | "all"
  const [busyId, setBusyId] = useState(null);
  const [notes, setNotes] = useState({});
  // Per-request expand/collapse + fetched detail cache, so admins can
  // review who they're approving before they click. Details are
  // fetched lazily (only when a row is expanded) from the same
  // admin-accessible endpoints the Admin's own live-monitoring panel
  // already uses — GET /devices/{id}/trust and GET /sessions/{id} both
  // allow an ADMIN caller regardless of ownership (see rbac.py's
  // require_owner_or_admin) — plus the roster from `listUsers()` for
  // email/role, since the request itself only carries username/user_id.
  const [expandedId, setExpandedId] = useState(null);
  const [details, setDetails] = useState({}); // requestId -> { loading, error, deviceTrust, sessionStatus, profile }
  const [users, setUsers] = useState(null);

  async function load(nextFilter = filter) {
    setError("");
    try {
      const rows = await listReauthRequests(nextFilter === "pending" ? "pending" : undefined);
      setRequests(rows);
    } catch (err) {
      setError(err.detail?.toString?.() || err.message || "Failed to load access requests");
    }
  }

  useEffect(() => {
    load(filter);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [filter]);

  async function toggleDetails(req) {
    if (expandedId === req.request_id) {
      setExpandedId(null);
      return;
    }
    setExpandedId(req.request_id);
    if (details[req.request_id]) return; // already fetched
    setDetails((prev) => ({ ...prev, [req.request_id]: { loading: true } }));
    try {
      let roster = users;
      if (!roster) {
        roster = await listUsers();
        setUsers(roster);
      }
      const profile = roster?.find((u) => u.id === req.user_id) || null;
      const [deviceStatus, sessionStatus] = await Promise.all([
        getDeviceStatus(req.device_id).catch(() => null),
        getSessionStatus(req.session_id).catch(() => null),
      ]);
      setDetails((prev) => ({
        ...prev,
        [req.request_id]: { loading: false, profile, deviceStatus, sessionStatus },
      }));
    } catch (err) {
      setDetails((prev) => ({
        ...prev,
        [req.request_id]: {
          loading: false,
          error: err.detail?.toString?.() || err.message || "Failed to load user details",
        },
      }));
    }
  }

  async function handleDecision(requestId, decision) {
    setBusyId(requestId);
    setError("");
    setMessage("");
    try {
      const note = (notes[requestId] || "").trim() || null;
      if (decision === "approve") {
        await approveReauthRequest(requestId, note);
        setMessage(`Request #${requestId} approved — the user must complete one fresh face verification before the device/session are restored.`);
      } else {
        await rejectReauthRequest(requestId, note);
        setMessage(`Request #${requestId} rejected — access remains blocked.`);
      }
      await load(filter);
    } catch (err) {
      setError(err.detail?.toString?.() || err.message || "Failed to record decision");
    } finally {
      setBusyId(null);
    }
  }

  if (requests === null && !error) return <Loading label="Loading access requests…" />;

  const STATUS_META = {
    pending: { label: "Pending", tone: "text-amber-400", icon: ShieldAlert },
    approved: { label: "Approved", tone: "text-cq-secondary", icon: CheckCircle2 },
    rejected: { label: "Rejected", tone: "text-cq-error", icon: XCircle },
  };

  return (
    <div className="bg-cq-surface-container rounded-cq-xl p-cq-stack-lg">
      <div className="flex items-center justify-between mb-1">
        <h2 className="text-[16px] font-bold text-cq-on-surface">Access Requests</h2>
        <div className="flex items-center gap-1.5">
          <Button variant="outline" size="sm" icon={RefreshCcw} onClick={() => load(filter)}>
            Refresh
          </Button>
          <div className="inline-flex rounded-cq-md overflow-hidden border border-white/10">
            {[
              { id: "pending", label: "Pending" },
              { id: "all", label: "All" },
            ].map((f) => (
              <button
                key={f.id}
                onClick={() => setFilter(f.id)}
                className={`px-3 py-1.5 text-[12px] font-semibold ${
                  filter === f.id ? "bg-cq-primary-container/20 text-cq-primary" : "text-cq-on-surface-variant"
                }`}
              >
                {f.label}
              </button>
            ))}
          </div>
        </div>
      </div>
      <p className="text-[13px] text-cq-on-surface-variant mb-4">
        A user's device or session was revoked by continuous monitoring, and only an
        administrator can restore it. Approving restores the device and session immediately; the
        user still needs one fresh face verification to resume monitoring. Rejecting leaves
        intent creation, encryption, and decryption blocked for that user.
      </p>
      <Alert type="error">{error}</Alert>
      {message && <Alert type="success">{message}</Alert>}

      {requests?.length === 0 && (
        <div className="text-[13px] text-cq-on-surface-variant py-6 text-center">
          No {filter === "pending" ? "pending" : ""} access requests.
        </div>
      )}

      <div className="space-y-3">
        {requests?.map((req) => {
          const meta = STATUS_META[req.status] || STATUS_META.pending;
          const StatusIcon = meta.icon;
          return (
            <div key={req.request_id} className="rounded-cq-lg border border-white/10 p-3.5 bg-cq-surface-container-high/50">
              <div className="flex items-start justify-between gap-3 mb-1.5">
                <div>
                  <div className="text-[13px] font-bold text-cq-on-surface">
                    {req.username}{" "}
                    <span className="text-[11px] font-normal text-cq-on-surface-variant">
                      (user #{req.user_id})
                    </span>
                  </div>
                  <div className="text-[11px] text-cq-on-surface-variant">
                    {formatTimestamp(req.created_at)}
                  </div>
                </div>
                <span className={`inline-flex items-center gap-1 text-[11px] font-semibold ${meta.tone}`}>
                  <StatusIcon size={12} /> {meta.label}
                </span>
              </div>

              <div className="grid grid-cols-2 gap-x-3 gap-y-1 text-[11.5px] text-cq-on-surface-variant mb-2">
                <div><span className="text-cq-on-surface font-medium">Device:</span> {req.device_id}</div>
                <div><span className="text-cq-on-surface font-medium">Session:</span> {req.session_id}</div>
              </div>

              <div className="text-[12px] text-cq-on-surface mb-2 bg-cq-surface-container rounded-cq-sm px-2.5 py-2">
                <span className="font-semibold">Message: </span>
                {req.message}
              </div>

              <button
                type="button"
                onClick={() => toggleDetails(req)}
                className="mb-2 inline-flex items-center gap-1 text-[11.5px] font-semibold text-cq-primary hover:underline"
              >
                {expandedId === req.request_id ? (
                  <>
                    <ChevronUp size={13} /> Hide user details
                  </>
                ) : (
                  <>
                    <ChevronDown size={13} /> View user details
                  </>
                )}
              </button>

              {expandedId === req.request_id && (
                <div className="mb-3 rounded-cq-md border border-cq-outline-variant/15 bg-cq-surface-container/60 p-3">
                  {details[req.request_id]?.loading && (
                    <div className="text-[11.5px] text-cq-on-surface-variant">Loading user details…</div>
                  )}
                  {details[req.request_id]?.error && (
                    <div className="text-[11.5px] text-cq-error">{details[req.request_id].error}</div>
                  )}
                  {details[req.request_id] && !details[req.request_id].loading && !details[req.request_id].error && (
                    <div className="grid grid-cols-1 sm:grid-cols-2 gap-x-4 gap-y-1 text-[11.5px]">
                      <div className="flex items-center justify-between py-0.5">
                        <span className="text-cq-on-surface-variant">Email</span>
                        <span className="font-semibold text-cq-on-surface">
                          {details[req.request_id].profile?.email || "—"}
                        </span>
                      </div>
                      <div className="flex items-center justify-between py-0.5">
                        <span className="text-cq-on-surface-variant">Role</span>
                        <span className="font-semibold text-cq-on-surface">
                          {details[req.request_id].profile?.role || "—"}
                        </span>
                      </div>
                      <div className="flex items-center justify-between py-0.5">
                        <span className="text-cq-on-surface-variant">Device Revoked</span>
                        <span
                          className={`font-semibold ${
                            details[req.request_id].deviceStatus?.revoked ? "text-cq-error" : "text-cq-primary"
                          }`}
                        >
                          {details[req.request_id].deviceStatus
                            ? details[req.request_id].deviceStatus.revoked
                              ? "YES"
                              : "NO"
                            : "—"}
                        </span>
                      </div>
                      <div className="flex items-center justify-between py-0.5">
                        <span className="text-cq-on-surface-variant">Session Valid</span>
                        <span
                          className={`font-semibold ${
                            details[req.request_id].sessionStatus?.revoked ? "text-cq-error" : "text-cq-primary"
                          }`}
                        >
                          {details[req.request_id].sessionStatus?.revoked ? "REVOKED" : "ACTIVE"}
                        </span>
                      </div>
                      <div className="flex items-center justify-between py-0.5">
                        <span className="text-cq-on-surface-variant">Session Expires</span>
                        <span className="font-semibold text-cq-on-surface">
                          {details[req.request_id].sessionStatus?.expires_at
                            ? new Date(details[req.request_id].sessionStatus.expires_at).toLocaleString()
                            : "—"}
                        </span>
                      </div>
                      <div className="flex items-center justify-between py-0.5">
                        <span className="text-cq-on-surface-variant">Renewals</span>
                        <span className="font-semibold text-cq-on-surface">
                          {details[req.request_id].sessionStatus?.version != null
                            ? `v${details[req.request_id].sessionStatus.version}`
                            : "—"}
                        </span>
                      </div>
                    </div>
                  )}
                </div>
              )}

              {req.status !== "pending" ? (
                <div className={`text-[11.5px] rounded-cq-sm px-2.5 py-2 ${req.status === "approved" ? "text-cq-secondary bg-cq-secondary-container/10" : "text-cq-error bg-cq-error-container/10"}`}>
                  {meta.label} by {req.resolved_by_username || `admin #${req.resolved_by}`} at{" "}
                  {formatTimestamp(req.resolved_at)}
                  {req.resolution_note && (
                    <>
                      {" — "}
                      {req.resolution_note}
                    </>
                  )}
                </div>
              ) : (
                <div className="flex items-center gap-2 mt-1">
                  <TextField
                    value={notes[req.request_id] || ""}
                    onChange={(e) => setNotes((prev) => ({ ...prev, [req.request_id]: e.target.value }))}
                    placeholder="Note (optional)"
                    className="flex-1"
                  />
                  <Button
                    variant="primary"
                    size="sm"
                    icon={CheckCircle2}
                    loading={busyId === req.request_id}
                    onClick={() => handleDecision(req.request_id, "approve")}
                  >
                    Approve
                  </Button>
                  <Button
                    variant="outline"
                    size="sm"
                    icon={XCircle}
                    loading={busyId === req.request_id}
                    onClick={() => handleDecision(req.request_id, "reject")}
                  >
                    Reject
                  </Button>
                </div>
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
}

function SecurityIncidentsPanel() {
  const [incidents, setIncidents] = useState(null);
  const [error, setError] = useState("");
  const [filter, setFilter] = useState("unresolved"); // "unresolved" | "all"
  const [busyId, setBusyId] = useState(null);
  const [notes, setNotes] = useState({});
  const [message, setMessage] = useState("");

  async function load(nextFilter = filter) {
    setError("");
    try {
      const resolved = nextFilter === "unresolved" ? false : undefined;
      const rows = await listSecurityIncidents(resolved);
      setIncidents(rows);
    } catch (err) {
      setError(err.detail?.toString?.() || err.message || "Failed to load security incidents");
    }
  }

  useEffect(() => {
    load(filter);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [filter]);

  async function handleResolve(incidentId) {
    const note = (notes[incidentId] || "").trim();
    if (!note) {
      setError("A resolution note is required before restoring access.");
      return;
    }
    setBusyId(incidentId);
    setError("");
    setMessage("");
    try {
      await resolveSecurityIncident(incidentId, note);
      setMessage(`Incident #${incidentId} resolved — device access restored.`);
      await load(filter);
    } catch (err) {
      setError(err.detail?.toString?.() || err.message || "Failed to resolve incident");
    } finally {
      setBusyId(null);
    }
  }

  if (incidents === null && !error) return <Loading label="Loading security incidents…" />;

  return (
    <div className="bg-cq-surface-container rounded-cq-xl p-cq-stack-lg">
      <div className="flex items-center justify-between mb-1">
        <h2 className="text-[16px] font-bold text-cq-on-surface">Security Incidents</h2>
        <div className="flex items-center gap-1.5">
          <Button variant="outline" size="sm" icon={RefreshCcw} onClick={() => load(filter)}>
            Refresh
          </Button>
          <div className="inline-flex rounded-cq-md overflow-hidden border border-white/10">
            {[
              { id: "unresolved", label: "Open" },
              { id: "all", label: "All" },
            ].map((f) => (
              <button
                key={f.id}
                onClick={() => setFilter(f.id)}
                className={`px-3 py-1.5 text-[12px] font-semibold ${
                  filter === f.id ? "bg-cq-primary-container/20 text-cq-primary" : "text-cq-on-surface-variant"
                }`}
              >
                {f.label}
              </button>
            ))}
          </div>
        </div>
      </div>
      <p className="text-[13px] text-cq-on-surface-variant mb-4">
        Every automatic CRITICAL-severity revocation triggered by Qira is recorded here.
        Qira can revoke access — it can never restore it; only an authorized administrator
        can, and doing so requires a resolution note (recorded to the audit trail).
      </p>
      <Alert type="error">{error}</Alert>
      {message && <Alert type="success">{message}</Alert>}

      {incidents?.length === 0 && (
        <div className="text-[13px] text-cq-on-surface-variant py-6 text-center">
          No {filter === "unresolved" ? "open" : ""} security incidents.
        </div>
      )}

      <div className="space-y-3">
        {incidents?.map((incident) => {
          const sevMeta = SEVERITY_META[incident.severity] || SEVERITY_META.LOW;
          return (
            <div
              key={incident.incident_id}
              className={`rounded-cq-lg border border-white/10 p-3.5 ${sevMeta.bg}`}
            >
              <div className="flex items-start justify-between gap-3 mb-1.5">
                <div>
                  <div className={`text-[12.5px] font-bold ${sevMeta.tone}`}>
                    {incident.severity} · {incident.security_state}
                  </div>
                  <div className="text-[11px] text-cq-on-surface-variant">
                    {formatTimestamp(incident.detected_at)}
                  </div>
                </div>
                {incident.resolved ? (
                  <span className="inline-flex items-center gap-1 text-[11px] font-semibold text-cq-secondary">
                    <CheckCircle2 size={12} /> Resolved
                  </span>
                ) : (
                  <span className="inline-flex items-center gap-1 text-[11px] font-semibold text-cq-error">
                    <ShieldAlert size={12} /> Open
                  </span>
                )}
              </div>

              <div className="grid grid-cols-2 sm:grid-cols-4 gap-x-3 gap-y-1 text-[11.5px] text-cq-on-surface-variant mb-2">
                <div><span className="text-cq-on-surface font-medium">User:</span> {incident.user_id}</div>
                <div><span className="text-cq-on-surface font-medium">Device:</span> {incident.device_id}</div>
                <div><span className="text-cq-on-surface font-medium">Session:</span> {incident.session_id}</div>
                <div><span className="text-cq-on-surface font-medium">Action:</span> {incident.action_taken}</div>
              </div>

              <div className="text-[12px] text-cq-on-surface mb-1">
                <span className="font-semibold">Reason: </span>
                {incident.reason}
              </div>
              {incident.signals?.length > 0 && (
                <div className="text-[11px] text-cq-on-surface-variant mb-2">
                  Signals: {incident.signals.join(", ")}
                </div>
              )}
              {incident.qira_assessment && (
                <div className="text-[10.5px] text-cq-on-surface-variant mb-2 flex items-center gap-1">
                  <Bot size={11} /> Qira assessment: confidence{" "}
                  {Math.round((incident.qira_assessment.confidence || 0) * 100)}%
                </div>
              )}

              {incident.resolved ? (
                <div className="text-[11.5px] text-cq-secondary bg-cq-secondary-container/10 rounded-cq-sm px-2.5 py-2">
                  Resolved by admin #{incident.resolved_by} at {formatTimestamp(incident.resolved_at)}
                  {incident.resolution_note && (
                    <>
                      {" — "}
                      {incident.resolution_note}
                    </>
                  )}
                </div>
              ) : (
                <div className="flex items-center gap-2 mt-1">
                  <TextField
                    value={notes[incident.incident_id] || ""}
                    onChange={(e) =>
                      setNotes((prev) => ({ ...prev, [incident.incident_id]: e.target.value }))
                    }
                    placeholder="Resolution note (required)"
                    className="flex-1"
                  />
                  <Button
                    variant="primary"
                    size="sm"
                    icon={CheckCircle2}
                    disabled={busyId === incident.incident_id}
                    onClick={() => handleResolve(incident.incident_id)}
                  >
                    Restore Access
                  </Button>
                </div>
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
}

function DevicesPanel({ user }) {
  const ownDeviceId = localStorage.getItem(`ibqc_device_id_${user?.userId}`);
  const ownSessionId = localStorage.getItem("ibqc_session_id");
  const [deviceId, setDeviceId] = useState("");
  const [sessionId, setSessionId] = useState("");
  const [message, setMessage] = useState("");
  const [error, setError] = useState("");
  const [deviceStatus, setDeviceStatus] = useState(null);
  const [sessionStatus, setSessionStatus] = useState(null);
  const [checking, setChecking] = useState(false);

  async function run(action, label, targetType = null, targetId = null) {
    if (targetType === "session" && targetId && targetId === ownSessionId) {
      setError("An administrator cannot revoke the current administrator session.");
      return;
    }
    if (targetType === "device" && targetId && targetId === ownDeviceId) {
      setError("An administrator cannot revoke the current administrator device.");
      return;
    }
    setError("");
    setMessage("");
    try {
      await action();
      setMessage(label);
      // Refresh whichever status card is currently showing this entity,
      // using the same real lookup endpoints — never assumed locally.
      if (targetType === "device" && targetId === deviceId) checkDevice();
      if (targetType === "session" && targetId === sessionId) checkSession();
    } catch (err) {
      setError(err.detail?.toString?.() || err.message || "Action failed");
    }
  }

  async function checkDevice() {
    if (!deviceId) return;
    setChecking(true);
    try {
      setDeviceStatus(await getDeviceStatus(deviceId));
    } catch (err) {
      setDeviceStatus(null);
      setError(err.detail?.toString?.() || err.message || "Device lookup failed");
    } finally {
      setChecking(false);
    }
  }

  async function checkSession() {
    if (!sessionId) return;
    setChecking(true);
    try {
      setSessionStatus(await getSessionStatus(sessionId));
    } catch (err) {
      setSessionStatus(null);
      setError(err.detail?.toString?.() || err.message || "Session lookup failed");
    } finally {
      setChecking(false);
    }
  }

  return (
    <div className="bg-cq-surface-container rounded-cq-xl p-cq-stack-lg">
      <h2 className="text-[16px] font-bold text-cq-on-surface mb-1">Devices & Sessions</h2>
      <p className="text-[13px] text-cq-on-surface-variant mb-4">
        Revoking a device or session immediately invalidates the current cryptographic
        authorization state for it — any in-flight encrypt/decrypt request against it is
        rejected, and a fresh authentication is required to establish a new authorization state.
      </p>
      <Alert type="error">{error}</Alert>
      {message && <Alert type="success">{message}</Alert>}

      <div className="grid grid-cols-1 sm:grid-cols-2 gap-x-5">
        <Field label="Device ID">
          <div className="flex gap-2">
            <TextField value={deviceId} onChange={(e) => setDeviceId(e.target.value)} placeholder="device-001" />
            <Button variant="outline" size="sm" onClick={checkDevice} disabled={!deviceId || checking}>
              Check
            </Button>
          </div>
        </Field>
        <Field label="Session ID">
          <div className="flex gap-2">
            <TextField value={sessionId} onChange={(e) => setSessionId(e.target.value)} placeholder="session-abc" />
            <Button variant="outline" size="sm" onClick={checkSession} disabled={!sessionId || checking}>
              Check
            </Button>
          </div>
        </Field>
      </div>

      {/* Security-entity status cards — populated only from real
          getDeviceStatus/getSessionStatus responses, never inferred. */}
      {(deviceStatus || sessionStatus) && (
        <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 mt-3 mb-1">
          {deviceStatus && <EntityStatusCard kind="Device" id={deviceStatus.device_id} revoked={deviceStatus.revoked} extra={[
            { label: "Trust", value: deviceStatus.status },
            { label: "Own device", value: deviceStatus.is_own_device ? "yes" : "no" },
            { label: "Claimed", value: deviceStatus.has_any_owner ? "yes" : "no" },
          ]} />}
          {sessionStatus && <EntityStatusCard kind="Session" id={sessionStatus.session_id} revoked={sessionStatus.revoked} extra={[
            { label: "Device", value: sessionStatus.device_id },
            { label: "Expires", value: formatTimestamp(sessionStatus.expires_at) },
            { label: "Version", value: sessionStatus.version },
          ]} />}
        </div>
      )}

      <div className="flex flex-wrap gap-2 mt-2">
        <Button
          variant="danger"
          size="sm"
          icon={XCircle}
          disabled={!deviceId}
          onClick={() => run(() => revokeDevice(deviceId), `Device ${deviceId} revoked`, "device", deviceId)}
        >
          Revoke Device
        </Button>
        <Button
          variant="outline"
          size="sm"
          icon={CheckCircle2}
          disabled={!deviceId}
          onClick={() => run(() => unrevokeDevice(deviceId), `Device ${deviceId} unrevoked`)}
        >
          Unrevoke Device
        </Button>
        <Button
          variant="danger"
          size="sm"
          icon={XCircle}
          disabled={!sessionId}
          onClick={() => run(() => revokeSession(sessionId), `Session ${sessionId} revoked`, "session", sessionId)}
        >
          Revoke Session
        </Button>
      </div>
    </div>
  );
}

function EntityStatusCard({ kind, id, revoked, extra }) {
  const tone = revoked ? "#ffb4ab" : "#63f7ff";
  return (
    <div className="relative rounded-cq-lg bg-cq-surface-container-high border border-cq-outline-variant/15 p-4 overflow-hidden">
      <div className="absolute inset-y-0 left-0 w-[2px]" style={{ background: tone }} />
      <div className="flex items-center justify-between mb-2">
        <span className="text-[10px] font-bold tracking-[0.16em] text-cq-on-surface-variant uppercase">{kind}</span>
        <span className="flex items-center gap-1.5">
          <span className="w-1.5 h-1.5 rounded-full cq-telemetry-dot" style={{ background: tone }} />
          <span className="text-[10.5px] font-bold uppercase tracking-wide" style={{ color: tone }}>
            {revoked ? "revoked" : "active"}
          </span>
        </span>
      </div>
      <div className="text-[12.5px] font-mono text-cq-on-surface break-all">{id}</div>
      <div className="mt-2.5 space-y-1">
        {extra.map((row) => (
          <div key={row.label} className="flex items-center justify-between text-[11.5px]">
            <span className="text-cq-on-surface-variant">{row.label}</span>
            <span className="text-cq-on-surface font-medium font-mono">{String(row.value)}</span>
          </div>
        ))}
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------
// Admin's own live monitoring
// ---------------------------------------------------------------------
// IMPORTANT: This is intentionally NOT an all-users risk overview.
// The Admin Dashboard already runs inside the same MonitoringProvider as
// every authenticated page. Therefore the Admin tab must use that exact
// context: the admin's own authenticated user/device/session, their own
// enrolled face, and their own continuous camera heartbeat.

function AdminOwnLiveMonitoringPanel({ user }) {
  /*
   * ADMIN-ONLY LIVE MONITORING
   *
   * This panel is deliberately a READ-ONLY view of the same authoritative
   * MonitoringContext heartbeat that is already running for the currently
   * authenticated administrator.
   *
   * Do NOT run a second face-analysis loop here. MonitoringContext already:
   *   camera -> face detection -> fresh descriptor -> /face/verify
   *           -> /api/monitoring/heartbeat -> authoritative snapshot
   *
   * That keeps Admin Live Monitoring tied to THIS admin's enrolled face,
   * rather than to an all-user aggregate or a separate local state machine.
   */
  const {
    snapshot,
    isMonitoring,
    cameraState,
    connectionState,
    webcamRef,
    deviceId,
    sessionId,
    sessionStatus,
    reauthRequired,
    deviceRevoked,
    reauthenticate,
  } = useMonitoringContext();

  const [open, setOpen] = useState(false);
  const [reauthPanelOpen, setReauthPanelOpen] = useState(false);
  const [reauthError, setReauthError] = useState("");
  const videoRef = useRef(null);
  const [attached, setAttached] = useState(false);

  // Attach the SAME camera stream used by MonitoringContext. Never request
  // a second webcam and never create a competing face-monitoring loop.
  useEffect(() => {
    if (!open) {
      setAttached(false);
      return undefined;
    }

    let cancelled = false;
    let raf = 0;

    const attach = () => {
      if (cancelled) return;
      const stream = webcamRef?.current?.video?.srcObject;
      if (stream && videoRef.current) {
        if (videoRef.current.srcObject !== stream) {
          videoRef.current.srcObject = stream;
        }
        setAttached(true);
        return;
      }
      raf = requestAnimationFrame(attach);
    };

    attach();

    return () => {
      cancelled = true;
      if (raf) cancelAnimationFrame(raf);
    };
  }, [open, webcamRef, cameraState]);

  /*
   * Hard scope check: the Admin Live Monitoring panel may consume a
   * snapshot only when it belongs to the currently authenticated admin.
   * It must never display another user's monitoring state.
   */
  const snapshotBelongsToAdmin =
    snapshot && user?.userId != null
      ? String(snapshot.current_user) === String(user.userId)
      : false;

  const adminSnapshot = snapshotBelongsToAdmin ? snapshot : null;

  const identityState = adminSnapshot?.identity_state || "no_face";
  const identityVerified = identityState === "identity_confirmed";
  const faceDetected =
    identityState === "identity_confirmed" ||
    identityState === "identity_mismatch" ||
    identityState === "liveness_uncertain";

  const cameraActive = cameraState === "ready" && (attached || !open);

  /*
   * Monitoring state is driven by the SAME backend heartbeat that performs
   * the administrator-specific face verification.
   *
   * A matched enrolled face is SECURE.
   * Identity details are displayed separately. The monitoring status label
   * mirrors the backend's configured 3/6/8 consecutive-failure thresholds;
   * one or two failed frames do not independently force a WARNING label.
   */
  let monitorLabel = "STARTING";
  let monitorTone = "text-cq-on-surface-variant";
  let monitorDot = "bg-cq-outline";

  // When no monitoring session has been established AND the backend
  // has flagged that re-authentication is required (session revoked,
  // or — for a device revocation — restorable by this same admin via
  // reauthenticate(), see MonitoringContext), the camera is never even
  // opened (see cameraState fix above) and `adminSnapshot` never
  // arrives. Surface that explicitly instead of showing "STARTING"
  // forever, which looked like a hang.
  const needsReauth = (!isMonitoring || !adminSnapshot) && reauthRequired;

  if (needsReauth) {
    monitorLabel = "RE-AUTHENTICATION REQUIRED";
    monitorTone = "text-amber-500";
    monitorDot = "bg-amber-500";
  } else if (adminSnapshot?.status === "revoked") {
    monitorLabel = "REVOKED";
    monitorTone = "text-cq-error";
    monitorDot = "bg-cq-error";
  } else if (adminSnapshot?.status === "reauth_required") {
    monitorLabel = "RE-AUTHENTICATION REQUIRED";
    monitorTone = "text-amber-500";
    monitorDot = "bg-amber-500";
  } else if (adminSnapshot?.status === "warning") {
    monitorLabel = "WARNING";
    monitorTone = "text-amber-500";
    monitorDot = "bg-amber-500";
  } else if (adminSnapshot?.status === "active") {
    // The backend owns the 3/6/8 escalation policy. An individual
    // non-matching frame remains visible in the Identity row but must
    // not make this status panel warn before the third consecutive failure.
    monitorLabel = identityVerified && adminSnapshot?.liveness ? "SECURE" : "ACTIVE";
    monitorTone = "text-cq-secondary";
    monitorDot = "bg-cq-secondary";
  }

  const identityLabel =
    identityState === "identity_confirmed"
      ? "IDENTITY CONFIRMED"
      : identityState === "identity_mismatch"
        ? "IDENTITY MISMATCH"
        : identityState === "no_face"
          ? "NO FACE DETECTED"
          : identityState === "liveness_uncertain"
            ? "LIVENESS UNCERTAIN"
            : identityState === "camera_unavailable"
              ? "CAMERA UNAVAILABLE"
              : "WAITING";

  const identityReason = needsReauth
    ? deviceRevoked
      ? "Your device was revoked. As the administrator, you can restore it yourself with a fresh face verification below — there is no higher authority to approve this for you."
      : "Your session was revoked. Verify your face against your enrolled identity below to restore monitoring."
    : adminSnapshot?.reason ||
    (identityState === "identity_confirmed"
      ? "Administrator face matches the enrolled identity."
      : identityState === "identity_mismatch"
        ? "The detected face does not match the enrolled administrator."
        : identityState === "no_face"
          ? "No face was detected in the administrator's current monitoring frame."
          : "Waiting for the next administrator-specific monitoring heartbeat.");

  const confidence = adminSnapshot?.face_match_confidence;
  const liveness = !!adminSnapshot?.liveness;
  const consecutiveFailures = adminSnapshot?.consecutive_face_failures ?? 0;
  const authLabel =
    adminSnapshot?.current_authorization_state === "valid" && !sessionStatus?.revoked
      ? "VALID"
      : "INVALID / REAUTH REQUIRED";

  return (
    <>
      <div className="bg-cq-surface-container rounded-cq-xl p-cq-stack-lg">
        <div className="flex items-start justify-between gap-4">
          <div>
            <h2 className="text-[16px] font-bold text-cq-on-surface">Admin Live Monitoring</h2>
            <p className="text-[13px] text-cq-on-surface-variant mt-1 max-w-3xl">
              Continuous identity monitoring for{" "}
              <span className="font-semibold text-cq-on-surface">
                {user?.username || "the administrator"}
              </span>{" "}
              only. The state below comes from this admin's enrolled-face
              verification and monitoring heartbeat — never from other users.
            </p>
          </div>

          <button
            type="button"
            onClick={() => setOpen(true)}
            className="shrink-0 inline-flex items-center gap-2 rounded-cq-md bg-cq-primary-container/20 text-cq-primary px-3 py-2 text-[12px] font-semibold hover:bg-cq-primary-container/30"
          >
            Open Live Monitor
          </button>
        </div>

        <div className="mt-5 grid grid-cols-1 md:grid-cols-2 xl:grid-cols-4 gap-3">
          <div className="rounded-cq-md bg-cq-surface-container-high p-3">
            <div className="text-[10px] uppercase tracking-wide text-cq-on-surface-variant">
              Monitoring
            </div>
            <div className={`mt-1 text-[14px] font-bold ${monitorTone}`}>
              {monitorLabel}
            </div>
          </div>

          <div className="rounded-cq-md bg-cq-surface-container-high p-3">
            <div className="text-[10px] uppercase tracking-wide text-cq-on-surface-variant">
              Camera
            </div>
            <div className={`mt-1 text-[14px] font-bold ${cameraState === "ready" ? "text-cq-secondary" : cameraState === "requesting" ? "text-amber-500" : "text-cq-error"}`}>
              {cameraState === "ready"
                ? "ACTIVE"
                : cameraState === "unavailable"
                  ? "UNAVAILABLE"
                  : cameraState === "requesting"
                    ? "OPENING…"
                    : /* 'idle': no monitoring session is running yet, so the
                         camera has not even been asked to open — most
                         commonly because re-authentication is required
                         first. Never label this "OPENING", which falsely
                         implies a permission prompt is pending. */
                      "NOT STARTED"}
            </div>
          </div>

          <div className="rounded-cq-md bg-cq-surface-container-high p-3">
            <div className="text-[10px] uppercase tracking-wide text-cq-on-surface-variant">
              Identity
            </div>
            <div className={`mt-1 text-[14px] font-bold ${identityVerified ? "text-cq-secondary" : "text-amber-400"}`}>
              {identityLabel}
            </div>
          </div>

          <div className="rounded-cq-md bg-cq-surface-container-high p-3">
            <div className="text-[10px] uppercase tracking-wide text-cq-on-surface-variant">
              Face Match
            </div>
            <div className={`mt-1 text-[14px] font-bold ${identityVerified ? "text-cq-secondary" : "text-cq-on-surface"}`}>
              {confidence != null ? `${(confidence * 100).toFixed(1)}%` : "—"}
            </div>
          </div>
        </div>

        <div className="mt-4 rounded-cq-md border border-cq-outline-variant/15 bg-cq-surface-container-high/50 p-3">
          <div className={`text-[12px] font-semibold ${monitorTone}`}>
            {identityReason}
          </div>

          {needsReauth && (
            <div className="mt-3">
              {!reauthPanelOpen ? (
                <button
                  type="button"
                  onClick={() => setReauthPanelOpen(true)}
                  className="inline-flex items-center gap-2 rounded-cq-md bg-cq-primary-container/20 text-cq-primary px-3 py-2 text-[12px] font-semibold hover:bg-cq-primary-container/30"
                >
                  Re-authenticate now
                </button>
              ) : (
                <div className="max-w-sm">
                  {reauthError && (
                    <div className="mb-2 rounded-cq-sm bg-cq-error-container/15 px-2.5 py-2 text-[11.5px] text-cq-error">
                      {reauthError}
                    </div>
                  )}
                  <FaceAuthPanel
                    mode="verify"
                    title="Reauthenticate"
                    subtitle={
                      deviceRevoked
                        ? "Verify your enrolled face to restore this device and resume monitoring."
                        : "Verify your enrolled face to restore your session and resume monitoring."
                    }
                    onSuccess={async ({ descriptor }) => {
                      try {
                        setReauthError("");
                        await reauthenticate(descriptor);
                        setReauthPanelOpen(false);
                      } catch (err) {
                        setReauthError(err.message || "Reauthentication failed");
                      }
                    }}
                    onCancel={() => setReauthPanelOpen(false)}
                  />
                </div>
              )}
            </div>
          )}

          <div className="mt-2 grid grid-cols-1 sm:grid-cols-2 gap-1.5 text-[11px] text-cq-on-surface-variant">
            <div>
              Admin:{" "}
              <span className="text-cq-on-surface font-semibold">
                {user?.username || "—"}
              </span>
            </div>
            <div>
              User ID:{" "}
              <span className="text-cq-on-surface font-semibold">
                {user?.userId || "—"}
              </span>
            </div>
            <div>
              Face:{" "}
              <span className="text-cq-on-surface font-semibold">
                {faceDetected ? "DETECTED" : "NOT DETECTED"}
              </span>
            </div>
            <div>
              Identity:{" "}
              <span className="text-cq-on-surface font-semibold">
                {identityLabel}
              </span>
            </div>
            <div>
              Liveness:{" "}
              <span className="text-cq-on-surface font-semibold">
                {liveness ? "CONFIRMED" : "NOT CONFIRMED"}
              </span>
            </div>
            <div>
              Confidence:{" "}
              <span className="text-cq-on-surface font-semibold">
                {confidence != null ? `${(confidence * 100).toFixed(1)}%` : "—"}
              </span>
            </div>
            <div>
              Authorization:{" "}
              <span className={`font-semibold ${authLabel === "VALID" ? "text-cq-secondary" : "text-cq-error"}`}>
                {authLabel}
              </span>
            </div>
            <div>
              Consecutive failures:{" "}
              <span className="text-cq-on-surface font-semibold">
                {consecutiveFailures}
              </span>
            </div>
            <div>
              Device:{" "}
              <span className="text-cq-on-surface font-semibold">
                {deviceId || "—"}
              </span>
            </div>
            <div>
              Session:{" "}
              <span className="text-cq-on-surface font-semibold">
                {sessionId || "—"}
              </span>
            </div>
            <div className="sm:col-span-2">
              Last monitoring check:{" "}
              <span className="text-cq-on-surface font-semibold">
                {adminSnapshot?.timestamp ? formatTimestamp(adminSnapshot.timestamp) : "—"}
              </span>
            </div>
          </div>

          {connectionState === "lost" && (
            <div className="mt-3 rounded-cq-sm bg-amber-400/10 border border-amber-400/20 px-3 py-2 text-[11px] text-amber-300">
              Monitoring backend connection is temporarily lost. The displayed result is the last confirmed administrator-specific state.
            </div>
          )}

          {sessionStatus?.revoked && (
            <div className="mt-3 rounded-cq-sm bg-amber-400/10 border border-amber-400/20 px-3 py-2 text-[11px] text-amber-300">
              The administrator's authorization session is revoked. This is separate from the face identity result.
            </div>
          )}
        </div>
      </div>

      {open && (
        <div
          className="fixed inset-0 z-[110] flex items-center justify-center bg-black/60 backdrop-blur-sm px-4"
          onClick={() => setOpen(false)}
        >
          <div
            className="w-full max-w-md rounded-cq-xl bg-cq-surface-container-low border border-cq-outline-variant/20 shadow-cq-popover overflow-hidden"
            onClick={(e) => e.stopPropagation()}
          >
            <div className="flex items-center justify-between px-4 py-3 border-b border-cq-outline-variant/10">
              <div>
                <div className="text-[13px] font-bold uppercase tracking-wide text-cq-on-surface">
                  Admin Live Security Monitoring
                </div>
                <div className="text-[10.5px] text-cq-on-surface-variant mt-0.5">
                  {user?.username || "admin"} · own enrolled identity
                </div>
              </div>
              <button
                onClick={() => setOpen(false)}
                className="text-cq-on-surface-variant hover:text-cq-on-surface text-xl"
              >
                ×
              </button>
            </div>

            <div className="relative bg-black aspect-video flex items-center justify-center">
              {cameraState === "ready" && attached ? (
                <video
                  ref={videoRef}
                  autoPlay
                  playsInline
                  muted
                  className="w-full h-full object-cover scale-x-[-1]"
                />
              ) : (
                <div className="flex flex-col items-center gap-2 text-cq-on-surface-variant py-10">
                  <div className="text-[12px]">
                    {cameraState === "unavailable" ? "Camera unavailable" : "Opening camera…"}
                  </div>
                </div>
              )}

              <div className="absolute top-2.5 left-2.5 flex items-center gap-1.5 rounded-full bg-black/55 px-2.5 py-1 text-[11px] font-semibold text-white">
                <span className={`w-1.5 h-1.5 rounded-full ${cameraState === "ready" ? "bg-emerald-400 animate-pulse" : "bg-rose-400"}`} />
                {cameraState === "ready" ? "Camera live" : "Camera off"}
              </div>

              <div className="absolute bottom-2 right-2 inline-flex items-center gap-1 rounded-full bg-black/60 px-2 py-0.5 text-[10px] text-white">
                <Activity size={10} className={isMonitoring ? "text-cq-secondary animate-pulse" : "text-cq-on-surface-variant"} />
                {isMonitoring ? "Monitoring continuously" : "Monitoring not established"}
              </div>
            </div>

            <div className="p-4">
              <div className="flex items-center gap-2">
                <div className={`text-[14px] font-bold ${monitorTone}`}>
                  {monitorLabel}
                </div>
                <span className={`ml-auto w-2 h-2 rounded-full ${monitorDot}`} />
              </div>

              <div className={`mt-1 text-[12px] leading-relaxed ${monitorTone}`}>
                {identityReason}
              </div>

              <div className="mt-4 space-y-1.5 text-[12px]">
                <div className="flex justify-between">
                  <span className="text-cq-on-surface-variant">Face</span>
                  <span className={faceDetected ? "text-cq-secondary font-semibold" : "text-amber-400 font-semibold"}>
                    {faceDetected ? "DETECTED" : "NOT DETECTED"}
                  </span>
                </div>
                <div className="flex justify-between">
                  <span className="text-cq-on-surface-variant">Identity</span>
                  <span className={identityVerified ? "text-cq-secondary font-semibold" : "text-amber-400 font-semibold"}>
                    {identityLabel}
                  </span>
                </div>
                <div className="flex justify-between">
                  <span className="text-cq-on-surface-variant">Confidence</span>
                  <span className="text-cq-on-surface font-semibold">
                    {confidence != null ? `${(confidence * 100).toFixed(1)}%` : "—"}
                  </span>
                </div>
                <div className="flex justify-between">
                  <span className="text-cq-on-surface-variant">Liveness</span>
                  <span className={liveness ? "text-cq-secondary font-semibold" : "text-amber-400 font-semibold"}>
                    {liveness ? "CONFIRMED" : "NOT CONFIRMED"}
                  </span>
                </div>
                <div className="flex justify-between">
                  <span className="text-cq-on-surface-variant">Authorization</span>
                  <span className={authLabel === "VALID" ? "text-cq-secondary font-semibold" : "text-cq-error font-semibold"}>
                    {authLabel}
                  </span>
                </div>
                <div className="flex justify-between">
                  <span className="text-cq-on-surface-variant">Consecutive failures</span>
                  <span className="text-cq-on-surface font-semibold">
                    {consecutiveFailures}
                  </span>
                </div>
              </div>

              <div className="mt-4 pt-3 border-t border-cq-outline-variant/10 text-[10.5px] text-cq-on-surface-variant">
                This panel displays only the authenticated administrator's
                enrolled-face monitoring result. It does not aggregate,
                average, or inspect other users.
              </div>
            </div>
          </div>
        </div>
      )}
    </>
  );
}

// ---------------------------------------------------------------------
// Root
// ---------------------------------------------------------------------

export default function AdminDashboard({ user }) {
  const [tab, setTab] = useState("users");

  return (
    <div>
      <PageHeader
        icon="admin_panel_settings"
        eyebrow="Administration"
        title="Admin Dashboard"
        description="Server-enforced role hierarchy: ADMIN, USER_LEVEL_2 (security officer/manager), USER_LEVEL_1 (user). Every action here is re-checked against the caller's role on the backend — this page only surfaces what the API already permits."
        right={
          <div className="inline-flex items-center gap-1.5 rounded-cq-md bg-cq-secondary-container/15 text-cq-secondary px-3 py-1.5 text-[12.5px] font-semibold">
            <ShieldCheck size={14} /> {user?.role || "—"}
          </div>
        }
      />

      <div className="flex flex-wrap items-center gap-2 mb-5 border-b border-cq-outline-variant/15 pb-3 overflow-visible" role="tablist" aria-label="Administrator sections">
        {TABS.map((t) => {
          const Icon = t.icon;
          const active = tab === t.id;
          return (
            <button
              key={t.id}
              onClick={() => setTab(t.id)}
              role="tab"
              aria-selected={active}
              className={
                "relative inline-flex items-center gap-1.5 px-3.5 py-2 rounded-cq-md text-[13px] font-semibold whitespace-nowrap transition-colors " +
                (active
                  ? "bg-cq-primary-container/20 text-cq-primary"
                  : "text-cq-on-surface-variant hover:bg-cq-surface-container-highest hover:text-cq-on-surface")
              }
            >
              <Icon size={15} /> {t.label}
              {active && (
                <motion.span
                  layoutId="admin-tab-indicator"
                  className="absolute left-2 right-2 -bottom-[5px] h-[2px] rounded-full bg-cq-primary"
                  transition={{ type: "spring", stiffness: 500, damping: 40 }}
                />
              )}
            </button>
          );
        })}
      </div>

      {tab === "users" && <UsersPanel user={user} />}
      {tab === "intents" && <IntentsPanel />}
      {tab === "cases" && <CasesPanel />}
      {tab === "access-requests" && <ReauthRequestsPanel />}
      {tab === "devices" && <DevicesPanel user={user} />}
      {tab === "risk" && <AdminOwnLiveMonitoringPanel user={user} />}
      {tab === "sessions" && <AdminMonitoringSessionsPanel />}
      {tab === "incidents" && <SecurityIncidentsPanel />}
    </div>
  );
}