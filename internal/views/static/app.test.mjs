import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import vm from "node:vm";

async function loadApp(options = {}) {
  const script = await readFile(new URL("./app.js", import.meta.url), "utf8");
  const store = new Map();
  const elements = new Map();
  const eventSourceURLs = [];
  const fetchCalls = [];

  function element(id) {
    if (!elements.has(id)) {
      elements.set(id, {
        id,
        innerHTML: "",
        textContent: "",
        addEventListener() {}
      });
    }
    return elements.get(id);
  }

  const context = {
    document: {
      getElementById: element,
      querySelectorAll() {
        return [];
      }
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
      if (options.unauthorized) {
        return { status: 401, ok: false, text: async () => "" };
      }
      if (path === "/api/session") {
        return { status: 204, ok: true, text: async () => "" };
      }
      return { status: 200, ok: true, text: async () => "<div></div>" };
    },
    sessionStorage: {
      getItem(key) {
        return store.get(key) || null;
      },
      setItem(key, value) {
        store.set(key, value);
      },
      removeItem(key) {
        store.delete(key);
      }
    },
    window: {
      __TRIVY_DASHBOARD_TEST__: true,
      prompt() {
        return options.promptToken || "secret";
      }
    }
  };
  context.window.document = context.document;
  context.window.EventSource = context.EventSource;
  context.window.fetch = context.fetch;
  context.window.sessionStorage = context.sessionStorage;

  vm.runInNewContext(script, context);
  await new Promise((resolve) => setImmediate(resolve));

  return { context, elements, eventSourceURLs, fetchCalls, store };
}

test("buildWorkloadPath encodes namespace and name", async () => {
  const { context } = await loadApp();

  assert.equal(
    context.window.TrivyDashboardTest.buildWorkloadPath("team/a", "api v1"),
    "/workload/team%2Fa/api%20v1"
  );
});

test("EventSource URL does not contain token", async () => {
  const { eventSourceURLs } = await loadApp();

  assert.deepEqual(eventSourceURLs, ["/api/events"]);
});

test("session setup sends bearer header without query credentials", async () => {
  const { fetchCalls } = await loadApp();
  const sessionCall = fetchCalls.find((call) => call.path === "/api/session");

  assert.equal(sessionCall.init.method, "POST");
  assert.equal(sessionCall.init.headers.Authorization, "Bearer secret");
});

test("401 clears stored token and shows unauthorized message", async () => {
  const { context, elements, store } = await loadApp({ unauthorized: true });

  context.sessionStorage.setItem("trivy-dashboard.token", "secret");
  await context.window.TrivyDashboardTest.authedFetch("/api/dashboard");

  assert.equal(store.has("trivy-dashboard.token"), false);
  assert.match(elements.get("content").innerHTML, /Unauthorized/);
});
