import { useEffect, useRef, useState } from "react";
import { RefreshCcw } from "lucide-react";
import Button from "../components/ui/Button";
import Alert from "../components/ui/Alert";
import PageHeader from "../components/ui/PageHeader";
import Loading from "../components/ui/Loading";
import EmptyState from "../components/ui/EmptyState";
import { listIntents, validateIntent, approveIntent, revokeIntent } from "../services/api";
import { emitQira } from "../qira";
import { reportApiError } from "../qira/report";
import { formatTimestamp } from "../utils/formatTimestamp";

const POLL_MS = 5000;
const TONE = {
  APPROVED: "#63f7ff", PENDING_APPROVAL: "#b8c3ff", DRAFT: "#c4c5d9",
  REJECTED: "#ffb4ab", REVOKED: "#ffb4ab", EXPIRED: "#fbbf24", EXHAUSTED: "#fbbf24",
};

function StatusPill({ status }) {
  const c = TONE[status] || "#c4c5d9";
  return (
    <span className="inline-flex rounded-full px-2.5 py-1 text-[12px] font-semibold" style={{ background: `${c}22`, color: c }}>
      {status}
    </span>
  );
}

export default function IntentHistoryPage({ navigate, user, shared }) {
  const isAdmin = user?.role === "ADMIN";
  const seenStatus = useRef(new Map());
  const [intents, setIntents] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [info, setInfo] = useState("");
  const [busy, setBusy] = useState(null);
  const [validationMessages, setValidationMessages] = useState({});

  async function load(showLoading = true) {
    if (showLoading) setLoading(true);
    try {
      const rows = await listIntents();
      rows.sort((a, b) => b.intent_id - a.intent_id);
      setIntents(rows);
      // QIRA: react to a REAL status change of one of MY intents (as reported by the backend list)
      const seen = seenStatus.current;
      for (const it of rows) {
        const before = seen.get(it.intent_id);
        if (before === "PENDING_APPROVAL" && it.owner_user_id === user?.userId) {
          if (it.status === "APPROVED") emitQira("intent.approved");
          else if (it.status === "REJECTED") emitQira("intent.rejected");
        }
        seen.set(it.intent_id, it.status);
      }
      setError("");
    } catch (e) {
      setError(e.message);
      reportApiError(e);
    } finally {
      setLoading(false);
    }
  }
  useEffect(() => {
    load();
    const t = setInterval(() => load(false), POLL_MS);
    return () => clearInterval(t);
  }, []);

  async function act(id, fn, ok) {
    setBusy(id);
    setError("");
    setInfo("");
    try {
      const result = await fn();
      await load(false);
      // QIRA: the action's real outcome (the API call succeeded)
      if (ok === "Rejected.") emitQira("intent.rejected");
      else if (ok === "Approval recorded.") emitQira(result?.status === "APPROVED" ? "intent.approved" : "intent.recorded");
      if (result?.evidence_ok === false) {
        const details = (result.findings || [])
          .filter((finding) => !finding.ok)
          .map((finding) => `${finding.code}: ${finding.detail}`)
          .join("; ");
        setValidationMessages((current) => ({
          ...current,
          [id]: `${result.outcome || "EVIDENCE_INVALID"}: ${result.evidence_summary || "Evidence requirements were not met."}${details ? ` Details: ${details}` : ""}`,
        }));
        return;
      }
      setValidationMessages((current) => {
        const next = { ...current };
        delete next[id];
        return next;
      });
      setInfo(result?.evidence_ok === true ? "Evidence verified. Intent is ready for approval." : ok);
    } catch (e) {
      setError(e.message);
      reportApiError(e);
      if (e?.status === 403 && !/requires one of the following roles|not authorized/i.test(String(e.detail || ""))) emitQira("auth.unauthorized");
    } finally {
      setBusy(null);
    }
  }

  return (
    <div>
      <PageHeader icon="history" eyebrow="Intent" title="Intent history"
        description="Every intent is versioned. A scope change creates a new version that must be approved again; approving or revoking invalidates outstanding crypto contexts."
        right={<Button variant="ghost" icon={RefreshCcw} onClick={() => load()}>Refresh</Button>} />
      <Alert type="error">{error}</Alert>
      <Alert type="success">{info}</Alert>
      {loading ? <Loading /> : intents.length === 0 ? (
        <EmptyState title="No intents yet" description="Declare an intent to request privileged access." />
      ) : (
        <div className="space-y-3">
          {intents.map((it) => {
            const b = it.body;
            const approved = it.approvals.filter((a) => a.verdict === "APPROVE").length;
            const mine = it.owner_user_id === user?.userId;
            const live = !["REJECTED", "REVOKED", "EXPIRED", "EXHAUSTED"].includes(it.status);
            return (
              <div key={it.intent_id} className="bg-cq-surface-container rounded-cq-xl p-cq-stack-lg">
                <div className="flex flex-wrap items-center gap-3">
                  <span className="font-bold text-cq-on-surface">#{it.intent_id} · v{it.version}</span>
                  <StatusPill status={it.status} />
                  <span className="text-[12.5px] text-cq-on-surface-variant">
                    approvals {approved}/{it.required_approvals} · uses {it.uses}/{b.data_scope.max_uses}
                  </span>
                  {!it.integrity_ok && <span className="text-cq-error text-[12.5px] font-semibold">INTEGRITY CHECK FAILED</span>}
                </div>
                <dl className="mt-3 grid sm:grid-cols-2 gap-x-6 gap-y-1 text-[13px] text-cq-on-surface-variant">
                  <div><b>Purpose</b> {b.purpose_code} — {b.purpose_statement}</div>
                  <div><b>Reference</b> {b.business_reference}</div>
                  <div><b>Resource</b> <span className="font-mono">{b.resource}</span></div>
                  <div><b>Operations</b> {b.operations.join(", ")}</div>
                  <div><b>Scope</b> {b.data_scope.classification}, ≤{b.data_scope.max_bytes} B/op</div>
                  <div><b>Valid</b> {formatTimestamp(b.valid_from)} → {formatTimestamp(b.valid_until)}</div>
                  {isAdmin && <div><b>Owner</b> user {it.owner_user_id}</div>}
                </dl>
                {validationMessages[it.intent_id] && (
                  <Alert type="error">{validationMessages[it.intent_id]} Correct the case evidence, then validate this draft again.</Alert>
                )}
                <div className="mt-4 flex flex-wrap gap-2">
                  {mine && it.status === "DRAFT" && (
                    <Button size="sm" variant="brand" loading={busy === it.intent_id}
                      onClick={() => act(it.intent_id, () => validateIntent(it.intent_id), "Submitted for approval.")}>Validate / submit</Button>
                  )}
                  {isAdmin && it.status === "PENDING_APPROVAL" && !mine && (
                    <>
                      <Button size="sm" variant="brand" loading={busy === it.intent_id}
                        onClick={() => act(it.intent_id, () => approveIntent(it.intent_id, it.version, "APPROVE"), "Approval recorded.")}>Approve v{it.version}</Button>
                      <Button size="sm" variant="danger"
                        onClick={() => act(it.intent_id, () => approveIntent(it.intent_id, it.version, "REJECT"), "Rejected.")}>Reject</Button>
                    </>
                  )}
                  {mine && live && (
                    <Button size="sm" variant="ghost" onClick={() => navigate("create-intent", { editIntentId: it.intent_id })}>New version</Button>
                  )}
                  {mine && it.status === "APPROVED" && (
                    <>
                      <Button size="sm" variant="ghost" onClick={() => navigate("encrypt", {
                        intentId: it.intent_id,
                        ...(shared?.intentId === it.intent_id && shared?.initialAttachment
                          ? { initialAttachment: shared.initialAttachment } : {}),
                      })}>Encryption</Button>
                      <Button size="sm" variant="ghost" onClick={() => navigate("decrypt", { intentId: it.intent_id })}>Decryption</Button>
                      {b.operations.includes("share") && b.operations.includes("encrypt") && (
                        <Button size="sm" variant="ghost" onClick={() => navigate("sharing", { intentId: it.intent_id })}>Secure Share</Button>
                      )}
                    </>
                  )}
                  {(mine || isAdmin) && live && (
                    <Button size="sm" variant="danger" loading={busy === it.intent_id}
                      onClick={() => act(it.intent_id, () => revokeIntent(it.intent_id, "revoked from intent history"), "Revoked; outstanding contexts invalidated.")}>Revoke</Button>
                  )}
                </div>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}
