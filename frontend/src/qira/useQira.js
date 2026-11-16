import { useEffect, useRef } from "react";
import { emitQira, releaseQira } from "./index";

/**
 * Observe a secure operation's real phase (useSecureOperation) and mirror it in QIRA.
 * Presentation only: it reads `phase`, never data, and never changes the operation.
 *
 *   deciding | operating  -> "<kind>.processing" hold (released when the phase ends)
 *   done (encrypt)        -> "encrypt.done"  (the server has finished the operation)
 *   done (decrypt)        -> nothing here: the page announces success only AFTER the integrity check
 *   denied                -> "auth.unauthorized"
 *   error                 -> "<kind>.failed"
 */
export function useQiraOperationPhase(kind, phase) {
  const prev = useRef("idle");
  useEffect(() => {
    const was = prev.current;
    prev.current = phase;
    if (was === phase) return;
    const processing = `${kind}.processing`;
    if (phase === "deciding" || phase === "operating") {
      emitQira(processing);
      return;
    }
    releaseQira(processing);
    if (phase === "done" && kind === "encrypt") emitQira("encrypt.done");
    else if (phase === "denied") emitQira("auth.unauthorized");
    else if (phase === "error") emitQira(`${kind}.failed`);
  }, [kind, phase]);
  useEffect(() => () => releaseQira(`${kind}.processing`), [kind]);
}

/** Emit `id` once per mount, the first time `flag` becomes true (e.g. "user started editing"). */
export function useQiraOnce(id) {
  const done = useRef(false);
  return () => {
    if (done.current) return;
    done.current = true;
    emitQira(id);
  };
}
