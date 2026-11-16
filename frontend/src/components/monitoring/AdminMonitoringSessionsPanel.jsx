import { Fragment, useCallback, useEffect, useRef, useState } from "react";
import { RefreshCcw, ChevronDown, ChevronUp } from "lucide-react";
import Button from "../ui/Button";
import Alert from "../ui/Alert";
import { SelectField } from "../ui/Field";
import { formatTimestamp } from "../../utils/formatTimestamp";
import { listMonitoringEvents, listMonitoringSessions } from "../../services/api";
import { backoffDelay, classifyMonitoringError, isTemporary } from "./monitoringErrors";

const POLL_MS = 5000;
const MAX_POLL_MS = 30000;

const TONE = {
  active: "text-cq-primary",
  warning: "text-amber-500",
  reauth_required: "text-amber-500",
  revoked: "text-cq-error",
};
const CONNECTION = {
  live: { label: "LIVE", tone: "text-cq-primary" },
  lapsed: { label: "NO HEARTBEAT", tone: "text-amber-500" },
  ended: { label: "ENDED", tone: "text-cq-on-surface-variant" },
};

function fmtDuration(sec) {
  if (sec == null) return "—";
  const s = Math.round(sec);
  const h = Math.floor(s / 3600), m = Math.floor((s % 3600) / 60);
  return h ? `${h}h ${m}m` : m ? `${m}m ${s % 60}s` : `${s}s`;
}

/**
 * ADMIN: monitoring summaries + session history + saved evidence (events).
 * Read-only. Refreshes itself (no manual refresh needed), pauses while the tab is hidden and backs off
 * while the backend is unavailable. Evidence for an open row reloads only when that session changed.
 */
export default function AdminMonitoringSessionsPanel() {
  const [rows, setRows] = useState(null);
  const [error, setError] = useState("");
  const [activeOnly, setActiveOnly] = useState(false);
  const [openId, setOpenId] = useState(null);
  const [events, setEvents] = useState({});
  const failuresRef = useRef(0);
  const inFlightRef = useRef(false);
  const timerRef = useRef(null);
  const eventsStampRef = useRef({});

  const loadEvents = useCallback(async (row) => {
    const stamp = `${row.updated_at}|${row.status}|${row.warning_occurrences}|${row.ended_at}`;
    if (eventsStampRef.current[row.monitoring_session_id] === stamp) return;
    try {
      const ev = await listMonitoringEvents(row.monitoring_session_id);
      eventsStampRef.current[row.monitoring_session_id] = stamp;
      setEvents((prev) => ({ ...prev, [row.monitoring_session_id]: ev }));
    } catch (err) {
      setEvents((prev) => ({ ...prev, [row.monitoring_session_id]: { error: err.message || "Could not load evidence" } }));
    }
  }, []);

  const load = useCallback(async () => {
    if (inFlightRef.current) return;
    inFlightRef.current = true;
    try {
      const data = await listMonitoringSessions({ limit: 100, activeOnly });
      failuresRef.current = 0;
      setError("");
      setRows(data);
    } catch (err) {
      failuresRef.current += 1;
      setError(isTemporary(classifyMonitoringError(err)) ? "Monitoring backend unreachable — retrying…" : err.message || "Failed to load sessions");
    } finally {
      inFlightRef.current = false;
    }
  }, [activeOnly]);

  useEffect(() => {
    let cancelled = false;
    const loop = async () => {
      if (!document.hidden) await load();
      if (!cancelled) timerRef.current = setTimeout(loop, backoffDelay(failuresRef.current, POLL_MS, MAX_POLL_MS));
    };
    loop();
    const onVisible = () => { if (!document.hidden) load(); };
    document.addEventListener("visibilitychange", onVisible);
    return () => {
      cancelled = true;
      clearTimeout(timerRef.current);
      document.removeEventListener("visibilitychange", onVisible);
    };
  }, [load]);

  // Keep the open row's evidence in sync as new data arrives.
  useEffect(() => {
    const row = rows?.find((r) => r.monitoring_session_id === openId);
    if (row) loadEvents(row);
  }, [rows, openId, loadEvents]);

  return (
    <div className="bg-cq-surface-container rounded-cq-xl p-cq-stack-lg">
      <div className="flex items-center justify-between flex-wrap gap-3 mb-2">
        <h2 className="text-[16px] font-bold text-cq-on-surface">Monitoring Sessions</h2>
        <div className="flex items-center gap-2">
          <SelectField value={activeOnly ? "active" : "all"} onChange={(e) => setActiveOnly(e.target.value === "active")} className="!py-1.5 !text-[13px]">
            <option value="all">Active + history</option>
            <option value="active">Active only</option>
          </SelectField>
          <Button variant="outline" size="sm" icon={RefreshCcw} onClick={load}>Refresh</Button>
        </div>
      </div>
      <p className="text-[13px] text-cq-on-surface-variant mb-3">
        Session-level summaries recorded by continuous monitoring. Updates automatically. Counters come from
        saved aggregates and the last real heartbeat; nothing here re-runs face checks.
      </p>
      <Alert type="error">{error}</Alert>
      {rows === null ? (
        <div className="text-[13px] text-cq-on-surface-variant py-4">Loading monitoring sessions…</div>
      ) : rows.length === 0 ? (
        <div className="text-[13px] text-cq-on-surface-variant py-4">No monitoring sessions recorded yet.</div>
      ) : (
        <div className="overflow-x-auto">
          <table className="w-full text-left text-[12.5px]">
            <thead>
              <tr className="text-cq-on-surface-variant">
                {["User", "Status", "Connection", "Risk", "Checks", "Warnings", "Started", "Duration", ""].map((h) => (
                  <th key={h} className="py-2 px-2 font-semibold uppercase text-[11px] tracking-wide">{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {rows.map((r) => {
                const open = openId === r.monitoring_session_id;
                const conn = CONNECTION[r.connection] || CONNECTION.ended;
                const ev = events[r.monitoring_session_id];
                return (
                  <Fragment key={r.monitoring_session_id}>
                    <tr className="border-t border-cq-outline-variant/15 hover:bg-cq-surface-container-high cursor-pointer"
                        onClick={() => setOpenId(open ? null : r.monitoring_session_id)}>
                      <td className="py-2 px-2 text-cq-on-surface">{r.username || `#${r.user_id}`}</td>
                      <td className={`py-2 px-2 font-bold uppercase ${TONE[r.status] || ""}`}>{r.status.replace("_", " ")}</td>
                      <td className={`py-2 px-2 font-semibold ${conn.tone}`}>{conn.label}</td>
                      <td className="py-2 px-2 text-cq-on-surface uppercase">{r.last_risk_level} ({Math.round(r.last_risk_score)})</td>
                      <td className="py-2 px-2 text-cq-on-surface">{r.successful_face_verifications}/{r.check_count}</td>
                      <td className="py-2 px-2 text-cq-on-surface">{r.warning_occurrences}</td>
                      <td className="py-2 px-2 text-cq-on-surface-variant">{formatTimestamp(r.started_at)}</td>
                      <td className="py-2 px-2 text-cq-on-surface-variant">{fmtDuration(r.duration_seconds)}</td>
                      <td className="py-2 px-2">{open ? <ChevronUp size={14} /> : <ChevronDown size={14} />}</td>
                    </tr>
                    {open && (
                      <tr className="bg-cq-surface-container-high">
                        <td colSpan={9} className="px-3 py-3 text-[12px] text-cq-on-surface-variant">
                          <div className="grid grid-cols-2 md:grid-cols-4 gap-x-4 gap-y-1 mb-2">
                            <span>Identity: <b className="text-cq-on-surface">{r.last_identity_state}</b></span>
                            <span>Highest state: <b className="text-cq-on-surface">{r.highest_security_state}</b></span>
                            <span>Outcome: <b className="text-cq-on-surface">{r.overall_security_outcome || "in progress"}</b></span>
                            <span>Recoveries: <b className="text-cq-on-surface">{r.recovery_count}</b></span>
                            <span>Failed checks: <b className="text-cq-on-surface">{r.face_liveness_failures}</b></span>
                            <span>Camera interruptions: <b className="text-cq-on-surface">{r.camera_interruptions}</b></span>
                            <span>Re-auth latched: <b className="text-cq-on-surface">{r.reauth_latched ? "yes" : "no"}</b></span>
                            <span>Last heartbeat: <b className="text-cq-on-surface">{r.last_heartbeat_ts ? formatTimestamp(r.last_heartbeat_ts) : "—"}</b></span>
                          </div>
                          {r.last_reason && <div className="mb-2">Reason: <span className="text-cq-on-surface">{r.last_reason}</span></div>}
                          <div className="font-semibold text-cq-on-surface mb-1">Saved evidence (events)</div>
                          {!ev ? "Loading…" : ev.error ? <span className="text-cq-error">{ev.error}</span> : ev.length === 0 ? "No events." : (
                            <ul className="space-y-0.5 max-h-56 overflow-y-auto">
                              {ev.slice().reverse().map((e, i) => (
                                <li key={i}>
                                  <span className="text-cq-on-surface-variant">{formatTimestamp(e.snapshot.timestamp)}</span>{" "}
                                  <b className="text-cq-on-surface">{e.event_type}</b>{" "}
                                  — {e.snapshot.reason || e.snapshot.status} (risk {e.snapshot.current_risk})
                                </li>
                              ))}
                            </ul>
                          )}
                        </td>
                      </tr>
                    )}
                  </Fragment>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
