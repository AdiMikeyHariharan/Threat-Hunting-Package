// One dashboard session per browser, shared by every open tab.
//
// Each tab keeps its copy in sessionStorage (gone when the tab closes), and the
// tabs keep each other in sync over a BroadcastChannel:
//   "session"     a tab signed in or rotated tokens; others adopt it
//   "hello"       a new tab asks whether anyone is signed in
//   "signed-out"  sign out everywhere (button, idle, revoked, expired)
//   "activity"    the user is active in some tab (idle timer)
//
// Only the leader tab (held through the Web Locks API) refreshes tokens and
// polls the server. Two tabs refreshing the same refresh token would look like
// token theft to the gateway and revoke every session.

export const IDLE_LIMIT_MS = 15 * 60 * 1000;
const ACTIVITY_SHARE_MS = 30 * 1000;

export function createSessionSync({
  Channel = globalThis.BroadcastChannel,
  locks = globalThis.navigator?.locks,
  now = () => Date.now(),
} = {}) {
  const channel = Channel ? new Channel("siem:auth") : null;
  const handlers = { session: [], "signed-out": [], hello: [] };
  let lastActivity = now();
  let lastShared = 0;

  channel?.addEventListener("message", ({ data }) => {
    if (data?.type === "activity") {
      lastActivity = Math.max(lastActivity, data.at);
      return;
    }
    for (const handler of handlers[data?.type] || []) handler(data);
  });

  function post(message) {
    channel?.postMessage(message);
  }

  return {
    publishSession: (session) => post({ type: "session", session }),
    announceSignOut: (reason, sessionId) => post({ type: "signed-out", reason, sessionId }),
    requestSession: () => post({ type: "hello" }),

    on(type, handler) {
      handlers[type].push(handler);
      return () => { handlers[type] = handlers[type].filter((h) => h !== handler); };
    },

    recordActivity() {
      lastActivity = now();
      if (lastActivity - lastShared >= ACTIVITY_SHARE_MS) {
        lastShared = lastActivity;
        post({ type: "activity", at: lastActivity });
      }
    },

    isIdle: () => now() - lastActivity >= IDLE_LIMIT_MS,

    // Calls onLead() once this tab becomes the leader. Without the Web Locks
    // API every tab leads (each refreshes on its own, as before).
    lead(onLead) {
      if (!locks) {
        onLead();
        return () => {};
      }
      let release;
      let cancelled = false;
      const held = new Promise((resolve) => { release = resolve; });
      locks.request("siem:session-leader", () => {
        // Released before the lock was granted (e.g. React StrictMode's
        // mount/unmount/mount): don't act as leader without holding the lock.
        if (cancelled) return undefined;
        onLead();
        return held;
      });
      return () => {
        cancelled = true;
        release();
      };
    },

    close: () => channel?.close(),
  };
}
