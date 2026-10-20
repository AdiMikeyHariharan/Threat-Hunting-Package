import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import vm from "node:vm";

const source = await readFile(new URL("../src/api.js", import.meta.url), "utf8");

async function api({ fetch, env = {}, assign = () => {} } = {}) {
  const context = vm.createContext({
    fetch, URL,
    window: { location: { origin: "https://dashboard.example", assign } },
  });
  const module = new vm.SourceTextModule(source, {
    context,
    initializeImportMeta: (meta) => { meta.env = env; },
  });
  await module.link(() => {});
  await module.evaluate();
  return module.namespace;
}

test("SSO availability comes from the backend at runtime", async () => {
  const client = await api({
    fetch: async (url, options) => {
      assert.equal(url, "/api/gateway/auth/sso/config");
      assert.equal(options.cache, "no-store");
      return { ok: true, json: async () => ({ configured: true }) };
    },
  });
  assert.equal((await client.getSsoConfiguration()).configured, true);
});

test("SSO configuration failures cannot enable sign-in", async () => {
  const client = await api({ fetch: async () => ({ ok: false }) });
  await assert.rejects(client.getSsoConfiguration(), /Unable to check SSO/);
});

test("login defaults to the gateway and rejects cross-origin overrides", async () => {
  let redirected;
  const client = await api({ assign: (url) => { redirected = url; } });
  client.beginSsoLogin();
  assert.equal(redirected, "https://dashboard.example/api/gateway/auth/sso/login");
  const invalid = await api({ env: { VITE_SSO_LOGIN_URL: "https://other.example/login" } });
  assert.throws(() => invalid.beginSsoLogin(), /dashboard's origin/);
});

test("concurrent handoff completion performs one cookie exchange", async () => {
  let requests = 0;
  let finish;
  const response = new Promise((resolve) => { finish = resolve; });
  const tokens = { subject: "alice", access_token: "access", refresh_token: "refresh" };
  const client = await api({
    fetch: (url, options) => {
      requests++;
      assert.equal(url, "/api/gateway/auth/sso/session");
      assert.equal(options.method, "POST");
      assert.equal(options.credentials, "same-origin");
      assert.equal(options.headers["Content-Type"], "application/json");
      assert.equal(options.body, "{}");
      return response;
    },
  });
  const first = client.completeSsoLogin();
  const second = client.completeSsoLogin();
  assert.equal(first, second);
  finish({ ok: true, json: async () => tokens });
  assert.equal(await first, tokens);
  assert.equal(await second, tokens);
  assert.equal(requests, 1);
});

test("failed handoffs surface errors and allow a new login attempt", async () => {
  let requests = 0;
  const client = await api({
    fetch: async () => {
      requests++;
      return { ok: false, json: async () => ({ detail: "SSO session expired" }) };
    },
  });
  await assert.rejects(client.completeSsoLogin(), /SSO session expired/);
  await assert.rejects(client.completeSsoLogin(), /SSO session expired/);
  assert.equal(requests, 2);
});
