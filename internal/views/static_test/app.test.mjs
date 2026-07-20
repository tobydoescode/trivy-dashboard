import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import vm from "node:vm";

async function loadApp(options = {}) {
  const script = await readFile(new URL("../static/app.js", import.meta.url), "utf8");
  const elements = new Map();
  const eventSourceURLs = [];
  const fetchCalls = [];

  function element(id) {
    if (!elements.has(id)) {
      elements.set(id, {
        id,
        dataset: {},
        innerHTML: "",
        textContent: "",
        value: "",
        hidden: false,
        addEventListener() {},
        querySelectorAll() {
          return [];
        }
      });
    }
    return elements.get(id);
  }

  let authorized = !options.unauthorized;

  const context = {
    document: {
      getElementById: element
    },
    EventSource: class {
      constructor(url) {
        this.url = url;
        eventSourceURLs.push(url);
      }
      addEventListener() {}
      close() {}
    },
    fetch: async (path, init = {}) => {
      fetchCalls.push({ path, init });
      if (path === "/api/session" && init.method === "POST") {
        if (options.sessionUnauthorized) {
          return { status: 401, ok: false, text: async () => "" };
        }
        authorized = true;
        return { status: 204, ok: true, text: async () => "" };
      }
      if (path === "/api/session" && init.method === "DELETE") {
        authorized = false;
        return { status: 204, ok: true, text: async () => "" };
      }
      if (!authorized) {
        return { status: 401, ok: false, text: async () => "" };
      }
      return { status: 200, ok: true, text: async () => "<div></div>" };
    },
    window: {
      __TRIVY_DASHBOARD_TEST__: true
    }
  };
  element("auth-required").dataset.required = options.authRequired === false ? "false" : "true";
  context.window.document = context.document;
  context.window.EventSource = context.EventSource;
  context.window.fetch = context.fetch;

  vm.runInNewContext(script, context);
  await new Promise((resolve) => setImmediate(resolve));

  return { context, elements, eventSourceURLs, fetchCalls, script };
}

test("token is never persisted to browser storage", async () => {
  const { script } = await loadApp();

  assert.doesNotMatch(script, /sessionStorage|localStorage/);
});

test("buildWorkloadPath encodes namespace and name", async () => {
  const { context } = await loadApp();

  assert.equal(
    context.window.TrivyDashboardTest.buildWorkloadPath("team/a", "api v1"),
    "/workload/team%2Fa/api%20v1"
  );
});

test("valid session cookie loads dashboard and connects SSE without credentials", async () => {
  const { eventSourceURLs, fetchCalls } = await loadApp();

  const dashboardCall = fetchCalls.find((call) => call.path === "/api/dashboard");
  assert.ok(dashboardCall, "dashboard should be fetched on start");
  assert.equal(dashboardCall.init.headers, undefined);
  assert.deepEqual(eventSourceURLs, ["/api/events"]);
  assert.equal(fetchCalls.some((call) => call.path === "/api/session"), false);
});

test("401 on dashboard shows login form and skips SSE", async () => {
  const { elements, eventSourceURLs } = await loadApp({ unauthorized: true });

  assert.equal(elements.get("login").hidden, false);
  assert.equal(elements.get("content").innerHTML, "");
  assert.deepEqual(eventSourceURLs, []);
});

test("submitToken exchanges bearer token once then uses cookie", async () => {
  const { context, elements, eventSourceURLs, fetchCalls } = await loadApp({ unauthorized: true });

  const ok = await context.window.TrivyDashboardTest.submitToken("secret");

  assert.equal(ok, true);
  const sessionCall = fetchCalls.find((call) => call.path === "/api/session");
  assert.equal(sessionCall.init.method, "POST");
  assert.equal(sessionCall.init.headers.Authorization, "Bearer secret");

  const dashboardCall = fetchCalls.findLast((call) => call.path === "/api/dashboard");
  assert.equal(dashboardCall.init.headers, undefined);
  assert.deepEqual(eventSourceURLs, ["/api/events"]);
  assert.equal(elements.get("login").hidden, true);
});

test("submitToken with bad token shows error and no SSE", async () => {
  const { context, elements, eventSourceURLs } = await loadApp({
    unauthorized: true,
    sessionUnauthorized: true
  });

  const ok = await context.window.TrivyDashboardTest.submitToken("wrong");

  assert.equal(ok, false);
  assert.equal(elements.get("login").hidden, false);
  assert.equal(elements.get("login-error").hidden, false);
  assert.match(elements.get("login-error").textContent, /Invalid token/);
  assert.deepEqual(eventSourceURLs, []);
});

test("tokenless mode never calls the session endpoint", async () => {
  const { eventSourceURLs, fetchCalls } = await loadApp({ authRequired: false });

  assert.equal(fetchCalls.some((call) => call.path === "/api/session"), false);
  const dashboardCall = fetchCalls.find((call) => call.path === "/api/dashboard");
  assert.equal(dashboardCall.init.headers, undefined);
  assert.deepEqual(eventSourceURLs, ["/api/events"]);
});
