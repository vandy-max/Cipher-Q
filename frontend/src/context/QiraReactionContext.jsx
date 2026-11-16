import { createContext, useCallback, useContext, useEffect, useMemo, useState, useSyncExternalStore } from "react";
import { qiraEngine } from "../qira";

const Ctx = createContext(null);

/**
 * Presentation-layer provider. Lives at the very ROOT of the app so QIRA is
 * present on public pages (login/landing) as well as authenticated ones.
 *
 * It owns no security state. It only mirrors the QIRA engine's foreground
 * reaction and the small amount of dock UI state (chat panel open/available).
 */
export function QiraReactionProvider({ children, engine = qiraEngine }) {
  const snapshot = useSyncExternalStore(engine.subscribe, engine.getSnapshot, engine.getSnapshot);
  const [chat, setChat] = useState({ available: false, open: false, label: "" });
  const [slot, setSlot] = useState(null); // DOM node (in the dock) the chat panel is portalled into

  const emit = useCallback((id, detail) => engine.trigger(id, detail), [engine]);
  const release = useCallback((id) => engine.release(id), [engine]);
  const clear = useCallback((ids) => engine.clear(ids), [engine]);
  const dismiss = useCallback(() => engine.dismiss(), [engine]);
  const setAmbient = useCallback((mode) => engine.setAmbient(mode), [engine]);
  const reset = useCallback(() => engine.reset(), [engine]);

  const registerChat = useCallback((available, label = "") => {
    setChat((c) => (c.available === available && c.label === label ? c : { ...c, available, label, open: available ? c.open : false }));
  }, []);
  const toggleChat = useCallback(() => setChat((c) => (c.available ? { ...c, open: !c.open } : c)), []);
  const closeChat = useCallback(() => setChat((c) => (c.open ? { ...c, open: false } : c)), []);

  const value = useMemo(
    () => ({ snapshot, emit, release, clear, dismiss, setAmbient, reset, chat, registerChat, toggleChat, closeChat, slot, setSlot }),
    [snapshot, emit, release, clear, dismiss, setAmbient, reset, chat, registerChat, toggleChat, closeChat, slot]
  );
  return <Ctx.Provider value={value}>{children}</Ctx.Provider>;
}

export function useQiraReactions() {
  const v = useContext(Ctx);
  if (!v) throw new Error("useQiraReactions must be used within a QiraReactionProvider");
  return v;
}

/** Non-throwing variant for components that may render outside the provider (tests/storybook). */
export function useOptionalQiraReactions() {
  return useContext(Ctx);
}

/** Registers the authenticated chat panel with the dock for as long as the caller is mounted. */
export function useQiraChatRegistration(available, label) {
  const ctx = useContext(Ctx);
  const register = ctx?.registerChat;
  useEffect(() => {
    if (!register) return undefined;
    register(!!available, label || "");
    return () => register(false, "");
  }, [register, available, label]);
}
