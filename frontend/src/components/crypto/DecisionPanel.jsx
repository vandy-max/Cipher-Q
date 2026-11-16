import { ShieldCheck, ShieldAlert, ShieldQuestion } from "lucide-react";

const TONE = {
  PERMIT: { icon: ShieldCheck, cls: "text-cq-secondary border-cq-secondary/25 bg-cq-secondary/5", label: "Permitted" },
  DENY: { icon: ShieldAlert, cls: "text-cq-error border-cq-error/25 bg-cq-error-container/10", label: "Denied" },
  REQUIRE_STEP_UP: { icon: ShieldQuestion, cls: "text-cq-primary border-cq-primary/25 bg-cq-primary-container/10", label: "Step-up required" },
  REQUIRE_APPROVAL: { icon: ShieldQuestion, cls: "text-cq-primary border-cq-primary/25 bg-cq-primary-container/10", label: "Approval required" },
};

/** Shows the server's authorization decision and the machine-readable reasons behind it. */
export default function DecisionPanel({ decision }) {
  if (!decision) return null;
  const t = TONE[decision.outcome] || TONE.DENY;
  const Icon = t.icon;
  return (
    <div className={`rounded-cq-lg border px-4 py-3 mb-4 ${t.cls}`} data-testid="decision-panel">
      <div className="flex items-center gap-2 text-[13.5px] font-semibold">
        <Icon size={16} /> {t.label}
        <span className="ml-auto text-[11.5px] font-mono opacity-70">decision {decision.decision_id?.slice(0, 12)} · policy v{decision.policy_version}</span>
      </div>
      {decision.reasons?.length > 0 && (
        <ul className="mt-2 text-[12.5px] text-cq-on-surface-variant space-y-1">
          {decision.reasons.map((r, i) => (
            <li key={i}>
              <code className="font-mono text-[12px] text-cq-on-surface">{r.code}</code>
              {r.detail ? <span> — {String(r.detail)}</span> : null}
            </li>
          ))}
        </ul>
      )}
      {decision.next && <p className="mt-2 text-[12.5px] text-cq-on-surface-variant">{decision.next}</p>}
    </div>
  );
}
