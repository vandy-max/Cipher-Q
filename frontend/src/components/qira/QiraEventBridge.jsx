import { useEffect, useRef } from "react";
import { useMonitoringContext } from "../../context/MonitoringContext";
import { useQiraContext } from "../../context/QiraContext";
import { useQiraReactions } from "../../context/QiraReactionContext";
import { deriveMonitoringState } from "../monitoring/monitoringState";
import { MONITORING_STICKY_IDS } from "../../qira/qiraReactionsExtended";

// Warnings that a return to a healthy monitoring state may resolve (monitoring-derived only).
const MONITORING_WARNINGS = [...MONITORING_STICKY_IDS, "session.revoked", "suspicious.activity", "intent.drift"];
const OFF_MESSAGE_DELAY_MS = 1500; // OFF is announced only once it is stable (the session is created right after login)

/**
 * Presentation-only bridge. QIRA mirrors EXACTLY the state the monitoring UI shows:
 * it calls the same `deriveMonitoringState()` (monitoringState.js) that the badge, the
 * Live Monitoring panel and the security card use, fed by the same shared monitoring
 * context. It never calculates a risk score, never creates a parallel monitoring state,
 * never writes security state and never calls a protected API. An exception here cannot
 * affect monitoring.
 *
 *   UI state                       QIRA
 *   OFF                            laptop-working pose (ambient "off") + one OFF message
 *   VERIFICATION PENDING           neutral (nothing is claimed yet)
 *   SECURE (active)                confident pose: cyan glow + shield (ambient "active")
 *   WARNING (incl. lost link)      orange concerned, sticky until the UI state changes
 *   RISK DETECTED (high risk)      red serious/protective, sticky until the UI state changes
 *   RE-AUTHENTICATION REQUIRED     orange, sticky
 *   ACCESS REVOKED                 red critical, sticky
 *
 * Must render inside <MonitoringProvider> and <QiraProvider>.
 */
export default function QiraEventBridge() {
  const { monitoringSessionId, snapshot, isMonitoring, reauthRequired, connectionState } = useMonitoringContext();
  const { assessing } = useQiraContext();
  const { emit, release, clear, setAmbient } = useQiraReactions();

  const prev = useRef({ state: null, session: null, offTimer: null });

  useEffect(() => () => { clearTimeout(prev.current.offTimer); }, []);

  // --- ONE state, the same one the monitoring UI shows ---------------------------------
  const uiState = deriveMonitoringState({ isMonitoring, snapshot, connectionState, reauthRequired });

  useEffect(() => {
    try {
      const p = prev.current;
      const state = uiState;
      const newSession = !!monitoringSessionId && p.session !== monitoringSessionId;
      if (monitoringSessionId) p.session = monitoringSessionId;
      else if (!isMonitoring) p.session = null;

      // resting pose follows the UI immediately (never delayed)
      setAmbient(state === "active" ? "active" : state === "off" ? "off" : "idle");

      if (state === p.state && !newSession) return; // same UI state: nothing to announce (no repeated messages)
      const before = p.state;
      p.state = state;

      clearTimeout(p.offTimer);
      p.offTimer = null;

      // A real change of UI state resolves the previous monitoring-derived warnings, then re-asserts
      // the sticky warning that matches the new state (so warning -> active restores the normal pose).
      clear(MONITORING_WARNINGS);

      switch (state) {
        case "revoked":
          emit("session.revoked");
          break;
        case "reauth_required":
          emit("monitoring.reauth");
          break;
        case "risk_detected":
          emit("monitoring.highrisk");
          break;
        case "warning":
          // A lost link is shown by the UI as WARNING too; say what is true about it.
          if (connectionState === "lost" && snapshot?.status !== "warning") emit("api.unavailable", { source: "monitoring_connection" });
          else emit("monitoring.warning");
          break;
        case "active":
          clear(["api.unavailable"]);
          release("monitoring.starting");
          emit("monitoring.on", { force: true });
          break;
        case "off":
          p.offTimer = setTimeout(() => {
            if (prev.current.state === "off") emit("monitoring.off");
          }, before === null ? OFF_MESSAGE_DELAY_MS : 0);
          break;
        default: // verification_pending: nothing is claimed until the backend confirms
          break;
      }
    } catch { /* presentation only */ }
  }, [uiState, monitoringSessionId, isMonitoring, connectionState, snapshot?.status, emit, release, clear, setAmbient]);

  // A healthy backend connection resolves the connectivity warning (same signal the badge uses).
  useEffect(() => {
    try { if (connectionState === "connected") clear(["api.unavailable"]); } catch { /* presentation only */ }
  }, [connectionState, clear]);

  // --- Qira assessment activity indicator ----------------------------------
  useEffect(() => {
    try {
      if (assessing) emit("risk.started");
      else release("risk.started");
    } catch { /* presentation only */ }
  }, [assessing, emit, release]);

  return null;
}
