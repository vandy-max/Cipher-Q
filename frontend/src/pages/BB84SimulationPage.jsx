import { useEffect, useRef, useState } from "react";
import { emitQira, releaseQira } from "../qira";
import { Atom, TrendingDown, Binary, CheckCircle2, XCircle, ArrowRight, Gauge, History } from "lucide-react";
import { motion } from "framer-motion";
import CopyBox from "../components/CopyBox";
import { Field, TextField } from "../components/ui/Field";
import Button from "../components/ui/Button";
import Alert from "../components/ui/Alert";
import BentoCard from "../components/ui/BentoCard";
import PageHeader from "../components/ui/PageHeader";
import QuantumField from "../components/quantum/QuantumField";
import QuantumChannel from "../components/quantum/QuantumChannel";
import { createKeySession, listKeySessions, revokeKeySession, quantumBackendInfo } from "../services/api";

function describeKeySessionError(error) {
  if (error.status === 401) return "Your sign-in has expired. Sign in again before establishing a key session.";
  if (error.status === 422 && Array.isArray(error.detail)) {
    const issues = error.detail.map((item) => {
      const field = Array.isArray(item.loc) ? item.loc.filter((part) => part !== "body").join(".") : "";
      return [field, item.msg].filter(Boolean).join(": ");
    }).filter(Boolean);
    if (issues.length) return `Check the session parameters: ${issues.join("; ")}`;
  }
  if (error.status === 0) return error.message;
  if (error.status === 403) {
    return typeof error.detail === "string" ? error.detail : "This key-session request is not allowed.";
  }
  if (error.status === 422) return "The key-session parameters are invalid. Check the values and try again.";
  if (error.status) {
    return typeof error.detail === "string" ? error.detail : `The server could not establish the key session (HTTP ${error.status}).`;
  }
  return "Unable to reach the server. Check the backend connection and retry.";
}

function Pill({ ok, children }) {
  return (
    <span
      className={
        "inline-flex items-center gap-1.5 rounded-full px-2.5 py-1 text-[12.5px] font-semibold whitespace-nowrap " +
        (ok ? "bg-cq-secondary-container/15 text-cq-secondary" : "bg-cq-error-container/20 text-cq-error")
      }
    >
      {ok ? <CheckCircle2 size={13} strokeWidth={2.5} /> : <XCircle size={13} strokeWidth={2.5} />}
      {children}
    </span>
  );
}

export default function BB84SimulationPage({ navigate }) {
  const [nQubits, setNQubits] = useState(1024);
  const [eavesdropProb, setEavesdropProb] = useState(0);
  const [result, setResult] = useState(null);
  const [backendInfo, setBackendInfo] = useState(null);
  const [error, setError] = useState("");
  const [authExpired, setAuthExpired] = useState(false);
  const [loading, setLoading] = useState(false);
  const [sessions, setSessions] = useState([]);
  const requestInFlight = useRef(false);

  useEffect(() => {
    quantumBackendInfo()
      .then(setBackendInfo)
      .catch(() => setBackendInfo({ qiskit_available: false }));
  }, []);

  const refresh = async () => {
    try {
      setSessions(await listKeySessions());
    } catch (err) {
      setError(describeKeySessionError(err));
      setAuthExpired(err.status === 401);
    }
  };
  useEffect(() => { refresh(); }, []);

  async function runSimulation() {
    if (requestInFlight.current) return;
    requestInFlight.current = true;
    setError("");
    setAuthExpired(false);
    setLoading(true);
    setResult(null);
    const startedAt = performance.now();
    emitQira("quantum.connecting"); // QIRA (presentation only): a real request is in flight
    try {
      const response = await createKeySession(Number(nQubits), Number(eavesdropProb));
      setResult({ ...response, session_aborted: false, elapsedMs: Math.round(performance.now() - startedAt) });
      releaseQira("quantum.connecting");
      emitQira("quantum.ready"); // only after the API confirmed the session
    } catch (err) {
      releaseQira("quantum.connecting");
      if (err.status === 409 && err.body?.key_session_id) {
        // Eavesdropper detected: the server aborted the exchange and established NO key.
        setResult({ ...err.body, session_aborted: true });
      } else {
        setError(describeKeySessionError(err));
        setAuthExpired(err.status === 401);
      }
      emitQira("quantum.failed");
    } finally {
      requestInFlight.current = false;
      setLoading(false);
      refresh();
    }
  }

  async function endSession(id) {
    try { await revokeKeySession(id); } catch (e) { setError(e.message); }
    refresh();
  }

  const keyBits = result?.effective_entropy_bits || 0;
  const efficiency = result && nQubits ? ((result.sifted_bits / Number(nQubits)) * 100).toFixed(1) : null;

  return (
    <div className="relative">
      <QuantumField density="low" tone="violet" className="opacity-30 -z-10" />
      <PageHeader
        icon="hub"
        eyebrow="Quantum Key Distribution"
        title="Quantum Lab"
        description="BB84 is SIMULATED on a classical computer with Qiskit Aer. It is not physical quantum key distribution and is not a claim of quantum-proof security. The resulting key stays on the server; you only receive an opaque key-session handle."
      />

      {/* Alice -> Quantum Channel -> Bob visualization, reflecting the
          actual run parameters and results below (never fabricated
          per-qubit detail — see QuantumChannel.jsx). */}
      <div className="mb-5">
        <QuantumChannel
          phase={loading ? "running" : result ? "result" : "idle"}
          nQubits={nQubits}
          eavesdropProb={eavesdropProb}
          result={result}
        />
      </div>

      <div className="grid grid-cols-1 xl:grid-cols-[1fr_320px] gap-5 items-start">
        <div className="bg-cq-surface-container rounded-cq-xl p-cq-stack-lg">
          {backendInfo?.qiskit_available ? (
            <Pill ok>{`Qiskit ${backendInfo.qiskit_version} · ${backendInfo.simulator}`}</Pill>
          ) : (
            <Pill>Qiskit backend not detected</Pill>
          )}

          <h2 className="text-[16px] font-bold text-cq-on-surface mt-4 mb-4">Session Parameters</h2>
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-x-5">
            <Field label="Number of qubits" hint="~1000+ recommended; fewer than ~500 usually cannot yield 128 bits of entropy and is refused">
              <TextField type="number" min={64} max={2048} value={nQubits} onChange={(e) => setNQubits(e.target.value)} />
            </Field>
            <Field label="Eavesdrop probability (0–1)">
              <TextField
                type="number"
                min={0}
                max={1}
                step={0.05}
                value={eavesdropProb}
                onChange={(e) => setEavesdropProb(e.target.value)}
              />
            </Field>
          </div>

          <Alert type="error">{error}</Alert>
          {authExpired && (
            <button type="button" className="underline text-cq-primary mb-4" onClick={() => navigate("login")}>
              Sign in again
            </button>
          )}

          <Button variant="accent" accent="violet" full onClick={runSimulation} loading={loading} icon={Atom}>
            Establish key session (simulated BB84)
          </Button>

          {loading && (
            <div className="mt-6 flex flex-col items-center justify-center gap-4 py-10 text-center">
              <div className="relative w-11 h-11">
                <motion.div className="absolute inset-0 rounded-full border-[3px] border-cq-primary/20" />
                <motion.div
                  className="absolute inset-0 rounded-full border-[3px] border-transparent border-t-cq-primary border-r-cq-secondary"
                  animate={{ rotate: 360 }}
                  transition={{ repeat: Infinity, duration: 0.9, ease: "linear" }}
                />
              </div>
              <p className="text-cq-body-md text-cq-on-surface-variant">Executing batched 6-qubit circuits on Qiskit Aer…</p>
            </div>
          )}

          {result && !loading && (
            <div
              className={
                "mt-6 rounded-cq-lg border p-5 " +
                (result.session_aborted
                  ? "border-cq-error/25 bg-cq-error-container/10"
                  : "border-cq-secondary/25 bg-cq-secondary-container/10")
              }
            >
              <div className="flex items-center gap-2 mb-4">
                {result.session_aborted ? (
                  <XCircle size={18} className="text-cq-error" />
                ) : (
                  <CheckCircle2 size={18} className="text-cq-secondary" />
                )}
                <h2 className="text-[15px] font-bold text-cq-on-surface">
                  {result.session_aborted ? (result.status === "INSUFFICIENT_KEY" ? "No key established — not enough entropy after sifting (use more qubits)" : "Session aborted — error rate too high (possible eavesdropper)") : "Key established"}
                </h2>
              </div>

              <div className="grid grid-cols-2 sm:grid-cols-3 gap-3 mb-5">
                <BentoCard icon={TrendingDown} label="QBER" value={`${(result.qber * 100).toFixed(1)}%`} />
                <BentoCard icon={Binary} label="Sifted Bits" value={result.sifted_bits} />
                {!result.session_aborted && (
                  <BentoCard icon={Gauge} label="Sifting Efficiency" value={`${efficiency}%`} />
                )}
              </div>

              {result.qubits_per_circuit > 0 && (
                <div className="mb-5 rounded-cq-md bg-cq-surface-container-high/60 px-4 py-3 text-[12.5px] text-cq-on-surface-variant">
                  <span className="font-semibold text-cq-on-surface">{result.total_exchanges}</span> BB84 exchanges,
                  batched into{" "}
                  <span className="font-semibold text-cq-on-surface">{result.qubits_per_circuit}-qubit</span> circuits
                  {" — "}
                  {result.full_circuits} × {result.qubits_per_circuit}-qubit
                  {result.remainder_qubits > 0 ? ` + 1 × ${result.remainder_qubits}-qubit remainder` : ""} circuit
                  {result.full_circuits + (result.remainder_qubits > 0 ? 1 : 0) === 1 ? "" : "s"}.
                </div>
              )}

              {!result.session_aborted && (
                <>
                  <CopyBox label="Key session ID" value={result.key_session_id} />
                  <div className="mt-4 rounded-cq-md bg-cq-primary-container/10 px-4 py-3 text-[13px] leading-relaxed text-cq-on-surface-variant">
                    <strong className="text-cq-on-surface">Simulation notice:</strong> ~{keyBits} bits of effective entropy after
                    privacy amplification. The raw key is never sent to the browser; it is wrapped under the server keyring, and
                    each record gets its own key derived through HKDF and bound to an authorization decision.
                  </div>
                  <Button
                    variant="accent"
                    accent="mint"
                    full
                    iconRight={ArrowRight}
                    className="mt-4"
                    onClick={() => navigate("encrypt", { keySessionId: result.key_session_id })}
                  >
                    Use this key session to encrypt
                  </Button>
                </>
              )}
            </div>
          )}
        </div>

        <div className="bg-cq-surface-container rounded-cq-xl p-cq-stack-lg">
          <div className="flex items-center gap-2 mb-1">
            <History size={16} className="text-cq-primary" />
            <h2 className="text-[15px] font-bold text-cq-on-surface">Your key sessions</h2>
          </div>
          <p className="text-[12.5px] text-cq-on-surface-variant mb-4">Server-side sessions; revoking destroys the wrapped key.</p>
          {sessions.length === 0 ? (
            <div className="text-[13.5px] text-cq-on-surface-variant py-10 text-center">No key sessions yet.</div>
          ) : (
            <div className="space-y-2.5">
              {sessions.map((s) => (
                <div key={s.key_session_id} className="rounded-cq-md border border-cq-outline-variant/25 px-3.5 py-2.5">
                  <div className="flex items-center justify-between gap-2">
                    <span className="text-[12px] font-mono text-cq-on-surface">{s.key_session_id.slice(0, 16)}…</span>
                    <Pill ok={s.status === "ACTIVE"}>{s.status.toLowerCase()}</Pill>
                  </div>
                  <div className="mt-1 flex items-center gap-3 text-[11.5px] text-cq-on-surface-variant">
                    <span>QBER {(s.qber * 100).toFixed(1)}%</span>
                    <span>gen {s.generation}</span>
                    {s.status === "ACTIVE" && (
                      <button type="button" className="ml-auto underline text-cq-error" onClick={() => endSession(s.key_session_id)}>revoke</button>
                    )}
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
