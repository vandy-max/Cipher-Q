import { REACTIONS as CORE_REACTIONS } from "./qiraReactions";
import { EXTENDED_REACTIONS } from "./qiraReactionsExtended";

/** Core (original 29) + extended (page/workflow/monitoring-state) catalogues. */
const REACTIONS = { ...CORE_REACTIONS, ...EXTENDED_REACTIONS };

/**
 * QIRA reaction engine — a tiny, framework-free state machine.
 *
 * Responsibilities
 *  - priority: a higher-priority reaction preempts a lower one; a
 *    lower-priority transient can NEVER hide an unresolved (sticky)
 *    higher-priority warning.
 *  - queueing: equal/lower-priority reactions wait their turn (bounded),
 *    duplicates are collapsed, rapid sequences cannot pile up.
 *  - sticky warnings: stay until a real recovery event resolves them via
 *    `alert.cleared` + `detail.clears` — nothing else clears them, and no
 *    timer ever does.
 *  - hold reactions: stay while a real operation is in flight until
 *    `release(id)`, with a safety cap so a lost response cannot wedge the UI.
 *  - cleanup: every timer is tracked; `reset()` / `dispose()` clear them all.
 *
 * It is a PRESENTATION state machine. It has no authority over access and
 * never throws into callers: `trigger` swallows its own errors.
 */
const QUEUE_STALE_MS = 6000; // a queued reaction older than this no longer describes "now"

export function createQiraEngine(options = {}) {
  const {
    now = () => Date.now(),
    setTimer = (fn, ms) => setTimeout(fn, ms),
    clearTimer = (h) => clearTimeout(h),
    minDisplayMs = 1200,
    maxQueue = 4,
    dedupeMs = 800,
    reactions = REACTIONS,
    historyLimit = 60,
  } = options;

  let seq = 0;
  let current = null; // { id, def, detail, key, startedAt, timer, minTimer }
  let queue = []; // [{ id, detail }]
  const sticky = new Map(); // id -> { id, def, detail, key, since }
  const lastAt = new Map();
  let ambient = "idle"; // "idle" | "off" | "active" (mirrors the monitoring UI state)
  let context = null; // page context, e.g. "quantum" (engineering mode)
  let dismissedKey = null;
  const listeners = new Set();
  let snapshot = null;
  const history = [];

  const log = (id, outcome) => {
    history.push({ id, outcome, at: now() });
    if (history.length > historyLimit) history.shift();
  };

  const topSticky = () => {
    let best = null;
    for (const s of sticky.values()) {
      if (!best || s.def.priority > best.def.priority || (s.def.priority === best.def.priority && s.since > best.since)) best = s;
    }
    return best;
  };

  const view = (entry, source) => ({
    id: entry.id,
    n: entry.def.n,
    message: entry.def.message,
    visual: entry.def.visual || {},
    warning: !!entry.def.warning,
    priority: entry.def.priority,
    sticky: !!entry.def.sticky,
    hold: !!entry.def.hold,
    key: entry.key,
    source, // "transient" | "sticky"
  });

  function build() {
    const top = topSticky();
    let fg = null;
    if (current && (!top || current.def.priority >= top.def.priority)) fg = view(current, "transient");
    else if (top) fg = view(top, "sticky");
    const warning = !!top || !!(current && current.def.warning);
    return {
      active: fg,
      warning,
      stickyIds: [...sticky.keys()],
      bubbleVisible: !!(fg && fg.message && fg.key !== dismissedKey),
      ambient,
      context,
    };
  }

  function emit() {
    snapshot = build();
    for (const l of [...listeners]) {
      try { l(); } catch { /* a listener must never break the engine */ }
    }
  }

  function clearTimers(entry) {
    if (!entry) return;
    if (entry.timer) clearTimer(entry.timer);
    if (entry.minTimer) clearTimer(entry.minTimer);
    entry.timer = null;
    entry.minTimer = null;
  }

  function start(id, def, detail) {
    const entry = { id, def, detail, key: ++seq, startedAt: now(), timer: null, minTimer: null };
    current = entry;
    dismissedKey = null;
    const key = entry.key;
    if (def.hold) {
      entry.timer = setTimer(() => expire(key), def.maxHoldMs || 30000);
    } else if (def.durationMs > 0) {
      entry.timer = setTimer(() => expire(key), def.durationMs);
    }
  }

  function nextFromQueue() {
    const top = topSticky();
    const t = now();
    // A queued reaction describes a real event; if it waited too long it is stale and dropped.
    queue = queue.filter((q) => t - (q.at ?? t) <= QUEUE_STALE_MS && reactions[q.id]);
    while (queue.length) {
      // most important first; first-in-first-out among equals
      let idx = 0;
      for (let i = 1; i < queue.length; i++) {
        if (reactions[queue[i].id].priority > reactions[queue[idx].id].priority) idx = i;
      }
      const [q] = queue.splice(idx, 1);
      const def = reactions[q.id];
      if (top && def.priority < top.def.priority) continue; // stale vs. an unresolved warning
      start(q.id, def, q.detail);
      return;
    }
  }

  function expire(key) {
    if (!current || current.key !== key) return;
    clearTimers(current);
    current = null;
    nextFromQueue();
    emit();
  }

  function enqueue(id, detail, def) {
    queue = queue.filter((q) => q.id !== id);
    queue.push({ id, detail, at: now() });
    while (queue.length > maxQueue) {
      // drop the lowest-priority (oldest on ties) entry
      let idx = 0;
      for (let i = 1; i < queue.length; i++) {
        if ((reactions[queue[i].id]?.priority ?? 0) < (reactions[queue[idx].id]?.priority ?? 0)) idx = i;
      }
      queue.splice(idx, 1);
    }
    // an equal-priority newcomer may take over once the minimum display time passed
    if (current && def.priority >= current.def.priority && !current.def.hold && !current.minTimer) {
      const wait = Math.max(0, minDisplayMs - (now() - current.startedAt));
      const key = current.key;
      current.minTimer = setTimer(() => {
        if (current && current.key === key && queue.length) {
          // only preempt for something at least as important
          const idxBest = queue.findIndex((q) => (reactions[q.id]?.priority ?? 0) >= current.def.priority);
          if (idxBest >= 0) {
            clearTimers(current);
            current = null;
            const [q] = queue.splice(idxBest, 1);
            start(q.id, reactions[q.id], q.detail);
            emit();
          }
        }
      }, wait);
    }
  }

  const api = {
    /** Trigger a reaction by event id. Returns true when it was accepted. */
    trigger(id, detail) {
      try {
        const def = reactions[id];
        if (!def) { log(id, "unknown"); return false; }

        if (id === "alert.cleared") return api.clear(detail?.clears);
        if (id === "idle") return false;

        const t = now();
        const last = lastAt.get(id);
        if (def.cooldownMs && last !== undefined && t - last < def.cooldownMs && !detail?.force) {
          log(id, "cooldown");
          return false;
        }
        if (last !== undefined && t - last < dedupeMs && (current?.id === id || queue.some((q) => q.id === id) || sticky.has(id))) {
          log(id, "deduped");
          return false;
        }
        lastAt.set(id, t);

        if (def.sticky) {
          const existing = sticky.get(id);
          if (existing) {
            existing.detail = detail;
            log(id, "refreshed");
            emit();
            return true;
          }
          sticky.set(id, { id, def, detail, key: ++seq, since: t });
          // a new unresolved warning outranks / replaces lower transient noise
          if (current && def.priority >= current.def.priority) {
            clearTimers(current);
            current = null;
          }
          queue = queue.filter((q) => (reactions[q.id]?.priority ?? 0) >= def.priority);
          dismissedKey = null;
          log(id, "sticky");
          emit();
          return true;
        }

        const top = topSticky();
        if (top && def.priority < top.def.priority) {
          log(id, "suppressed");
          return false;
        }

        if (!current) {
          start(id, def, detail);
          log(id, "shown");
        } else if (current.id === id) {
          clearTimers(current);
          start(id, def, detail);
          log(id, "refreshed");
        } else if (def.priority > current.def.priority) {
          clearTimers(current);
          current = null;
          queue = queue.filter((q) => q.id !== id);
          start(id, def, detail);
          log(id, "preempted");
        } else {
          enqueue(id, detail, def);
          log(id, "queued");
        }
        emit();
        return true;
      } catch {
        return false; // presentation must never break callers
      }
    },

    /** Release a `hold` reaction when the real operation has finished. */
    release(id) {
      try {
        const before = queue.length;
        queue = queue.filter((q) => q.id !== id);
        const queuedRemoved = queue.length !== before;
        if (current && current.id === id && current.def.hold) {
          const key = current.key;
          const wait = Math.max(0, minDisplayMs - (now() - current.startedAt));
          if (wait === 0) expire(key); // emits
          else {
            if (current.timer) clearTimer(current.timer);
            current.timer = setTimer(() => expire(key), wait);
          }
        } else if (queuedRemoved) {
          emit();
        }
      } catch { /* ignore */ }
    },

    /**
     * Resolve specific reactions after a real recovery. `ids` may name sticky
     * warnings and/or transients. Unnamed warnings are never touched.
     */
    clear(ids) {
      try {
        const list = Array.isArray(ids) ? ids : [];
        let changed = false;
        for (const id of list) {
          if (sticky.delete(id)) changed = true;
          const before = queue.length;
          queue = queue.filter((q) => q.id !== id);
          if (queue.length !== before) changed = true;
          if (current && current.id === id) {
            clearTimers(current);
            current = null;
            changed = true;
          }
        }
        if (!changed) return false; // nothing to resolve: no log, no re-render
        if (!current) nextFromQueue();
        log("alert.cleared", "cleared");
        emit();
        return true;
      } catch {
        return false;
      }
    },

    setAmbient(mode) {
      if (ambient === mode) return;
      ambient = mode;
      emit();
    },

    /** Page context (e.g. "quantum" = engineering mode). Cosmetic accessory/pose only. */
    setContext(name) {
      const next = name || null;
      if (context === next) return;
      context = next;
      emit();
    },

    /** Hide the bubble for the current reaction (visual only; warnings persist). */
    dismiss() {
      const s = api.getSnapshot();
      if (s.active) {
        dismissedKey = s.active.key;
        emit();
      }
    },

    subscribe(listener) {
      listeners.add(listener);
      return () => listeners.delete(listener);
    },

    getSnapshot() {
      if (!snapshot) snapshot = build();
      return snapshot;
    },

    getHistory: () => history.slice(),
    hasSticky: (id) => sticky.has(id),

    reset() {
      clearTimers(current);
      current = null;
      queue = [];
      sticky.clear();
      lastAt.clear();
      dismissedKey = null;
      ambient = "idle";
      context = null;
      emit();
    },

    dispose() {
      api.reset();
      listeners.clear();
    },
  };

  snapshot = build();
  return api;
}
