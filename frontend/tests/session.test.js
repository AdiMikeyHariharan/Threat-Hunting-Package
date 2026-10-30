import assert from "node:assert/strict";
import test from "node:test";

import { IDLE_LIMIT_MS, createSessionSync } from "../src/session.js";

// Node's BroadcastChannel crosses instances the way it crosses browser tabs.
// unref() so open channels don't keep the test process alive.
class Channel extends BroadcastChannel {
  constructor(name) { super(name); this.unref(); }
}
const tick = () => new Promise((resolve) => setTimeout(resolve, 30));

test("a sign-in in one tab is shared with the others, but not echoed back", async () => {
  const a = createSessionSync({ Channel, locks: null });
  const b = createSessionSync({ Channel, locks: null });
  const seenA = [], seenB = [];
  a.on("session", (m) => seenA.push(m.session));
  b.on("session", (m) => seenB.push(m.session));
  a.publishSession({ subject: "alice", session_id: "s1" });
  await tick();
  assert.deepEqual(seenB, [{ subject: "alice", session_id: "s1" }]);
  assert.deepEqual(seenA, []);
  a.close(); b.close();
});

test("sign-out is broadcast with its reason and session id", async () => {
  const a = createSessionSync({ Channel, locks: null });
  const b = createSessionSync({ Channel, locks: null });
  const seen = [];
  const stop = b.on("signed-out", (m) => seen.push([m.reason, m.sessionId]));
  a.announceSignOut("idle", "s1");
  await tick();
  assert.deepEqual(seen, [["idle", "s1"]]);
  stop();
  a.announceSignOut("user", "s1");
  await tick();
  assert.equal(seen.length, 1);
  a.close(); b.close();
});

test("a new tab's hello reaches tabs that can answer it", async () => {
  const existing = createSessionSync({ Channel, locks: null });
  const fresh = createSessionSync({ Channel, locks: null });
  let asked = 0;
  existing.on("hello", () => { asked += 1; });
  fresh.requestSession();
  await tick();
  assert.equal(asked, 1);
  existing.close(); fresh.close();
});

test("activity in any tab keeps every tab from going idle", async () => {
  let clock = 1_000_000;
  const now = () => clock;
  const a = createSessionSync({ Channel, locks: null, now });
  const b = createSessionSync({ Channel, locks: null, now });
  clock += IDLE_LIMIT_MS - 60_000;
  a.recordActivity();                       // user is working in tab A
  await tick();
  clock += 2 * 60_000;                      // 16 min after B last saw its own activity
  assert.equal(b.isIdle(), false);
  clock += IDLE_LIMIT_MS;                   // then nobody touches anything for 15 min
  assert.equal(b.isIdle(), true);
  assert.equal(a.isIdle(), true);
  a.close(); b.close();
});

test("only one tab leads; the next takes over when it goes away", async () => {
  // Minimal Web Locks stand-in: one holder at a time, queued in order.
  const queue = [];
  let held = false;
  const locks = {
    request(_name, callback) {
      queue.push(callback);
      const next = () => {
        if (held || !queue.length) return;
        held = true;
        Promise.resolve(queue.shift()()).then(() => { held = false; next(); });
      };
      next();
    },
  };
  const leaders = [];
  const releaseA = createSessionSync({ Channel: null, locks }).lead(() => leaders.push("A"));
  createSessionSync({ Channel: null, locks }).lead(() => leaders.push("B"));
  await tick();
  assert.deepEqual(leaders, ["A"]);
  releaseA();                               // tab A closes
  await tick();
  assert.deepEqual(leaders, ["A", "B"]);
});

test("works without BroadcastChannel or Web Locks", () => {
  const sync = createSessionSync({ Channel: null, locks: null });
  assert.doesNotThrow(() => { sync.publishSession({}); sync.announceSignOut("user"); sync.requestSession(); });
  let led = false;
  sync.lead(() => { led = true; });
  assert.equal(led, true);
});

test("a lead request cancelled before it is granted never acts as leader", async () => {
  // React StrictMode mounts, unmounts and remounts effects: the first request is
  // released before the lock is granted. Acting on that late grant made two tabs
  // refresh the same token and the gateway revoked every session.
  const queue = [];
  let held = false;
  const locks = {
    request(_name, callback) {
      queue.push(callback);
      setTimeout(function next() {
        if (held || !queue.length) return;
        held = true;
        Promise.resolve(queue.shift()()).then(() => { held = false; setTimeout(next); });
      });
    },
  };
  const leaders = [];
  const tabA = createSessionSync({ Channel: null, locks });
  tabA.lead(() => leaders.push("A-first"))();    // StrictMode: released immediately
  tabA.lead(() => leaders.push("A"));
  createSessionSync({ Channel: null, locks }).lead(() => leaders.push("B"));
  await tick();
  assert.deepEqual(leaders, ["A"]);
});
