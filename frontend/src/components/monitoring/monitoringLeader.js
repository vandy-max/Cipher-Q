// Single-instance guard for the monitoring loop across browser tabs.
//
// Two tabs of the same login used to both run the camera + heartbeat loop against ONE monitoring
// session: each heartbeat rotates the replay nonce, so the tabs invalidated each other (409 storms)
// and doubled every request. Exactly one tab per authorization session may be the "leader" (owns the
// camera and posts heartbeats); other tabs only display the leader's snapshots and take over the
// moment the leader goes away. Uses the Web Locks API; where it is unavailable the tab is simply the
// leader (previous behaviour).

export function createLeaderElection(sessionId, onChange, locks = globalThis.navigator?.locks) {
  let released = false;
  let leader = false;
  let releaseLock = null;

  const set = (v) => {
    if (leader !== v) {
      leader = v;
      onChange(v);
    }
  };

  if (!locks || !sessionId) {
    set(true);
    return { release() {}, isLeader: () => true };
  }

  const name = `cipherq-monitoring:${sessionId}`;
  const hold = () =>
    new Promise((resolve) => {
      releaseLock = resolve;
    });

  // Not leader until the lock is actually granted (immediately if nobody holds it).
  locks
    .request(name, { mode: "exclusive" }, async () => {
      if (released) return;
      set(true);
      await hold();
    })
    .catch(() => {
      if (!released) set(true); // locks misbehaving: fail open to single-tab behaviour
    });

  return {
    release() {
      released = true;
      set(false);
      if (releaseLock) releaseLock();
    },
    isLeader: () => leader,
  };
}
