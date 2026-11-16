import { useCallback, useState } from "react";
import { requestDecision, encryptWithContext, decryptWithContext } from "../services/api";

function errText(err) {
  const d = err?.detail;
  if (Array.isArray(d)) return d.map((x) => `${(x.loc || []).slice(1).join(".")}: ${x.msg}`).join("; ");
  return (typeof d === "string" && d) || err?.message || "Request failed";
}

/**
 * Drives: authorization decision -> single-use crypto context -> operation.
 * The browser never sees key material; every request is re-checked by the server against the
 * current authorization state, so a stale context is rejected (CONTEXT_STALE / AUTHORIZATION_CHANGED).
 *
 * phase: idle | deciding | operating | done | denied | needs_stepup | needs_approval | error
 */
export function useSecureOperation({ operation, intent, sessionId, deviceId }) {
  const [phase, setPhase] = useState("idle");
  const [decision, setDecision] = useState(null);
  const [result, setResult] = useState(null);
  const [error, setError] = useState("");

  const reset = useCallback(() => {
    setPhase("idle"); setDecision(null); setResult(null); setError("");
  }, []);

  const run = useCallback(
    async ({ keySessionId, recordId, plaintextBase64, requestedBytes }) => {
      setError(""); setResult(null); setDecision(null);
      if (!intent) { setError("Select an approved intent first."); setPhase("error"); return; }
      const body = intent.body;
      const common = {
        intent_id: intent.intent_id,
        resource: body.resource,
        purpose_code: body.purpose_code,
        session_id: sessionId,
        device_id: deviceId,
      };
      setPhase("deciding");
      try {
        const d = await requestDecision({
          ...common,
          operation,
          ...(operation === "encrypt"
            ? { key_session_id: keySessionId, requested_bytes: requestedBytes }
            : { record_id: recordId }),
        });
        setDecision(d);
        if (d.outcome === "REQUIRE_STEP_UP") return setPhase("needs_stepup");
        if (d.outcome === "REQUIRE_APPROVAL") return setPhase("needs_approval");
        if (d.outcome !== "PERMIT") return setPhase("denied");
        setPhase("operating");
        const res =
          operation === "encrypt"
            ? await encryptWithContext({ ...common, context_id: d.context_id, key_session_id: keySessionId, plaintext_base64: plaintextBase64 })
            : await decryptWithContext({ ...common, context_id: d.context_id, record_id: recordId });
        setResult(res);
        setPhase("done");
      } catch (err) {
        setError(errText(err));
        setPhase("error");
      }
    },
    [operation, intent, sessionId, deviceId]
  );

  return { phase, decision, result, error, run, reset };
}
