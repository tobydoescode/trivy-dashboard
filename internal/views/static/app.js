(() => {
  const content = document.getElementById("content");
  const refreshTime = document.getElementById("refresh-time");
  const refreshBtn = document.getElementById("refresh");
  const signoutBtn = document.getElementById("signout");
  const filterInput = document.getElementById("filter");
  const login = document.getElementById("login");
  const loginForm = document.getElementById("login-form");
  const tokenInput = document.getElementById("token-input");
  const loginError = document.getElementById("login-error");
  const authRequired = document.getElementById("auth-required")?.dataset.required !== "false";

  let eventSource = null;

  function closeSSE() {
    if (eventSource) {
      eventSource.close();
      eventSource = null;
    }
  }

  function showLogin(message) {
    closeSSE();
    content.innerHTML = "";
    login.hidden = false;
    loginError.textContent = message || "";
    loginError.hidden = !message;
  }

  function hideLogin() {
    login.hidden = true;
    loginError.hidden = true;
  }

  // Exchanges the token for an HTTP-only session cookie. The token is used
  // for this one request and never stored client-side.
  async function submitToken(token) {
    const res = await fetch("/api/session", {
      method: "POST",
      headers: { "Authorization": "Bearer " + token }
    });
    if (res.status === 401) {
      showLogin("Invalid token.");
      return false;
    }
    if (!res.ok) {
      showLogin("Error: " + res.status);
      return false;
    }
    hideLogin();
    await start();
    return true;
  }

  async function authedFetch(path) {
    const res = await fetch(path);
    if (res.status === 401) {
      showLogin();
      return null;
    }
    if (!res.ok) {
      content.innerHTML = '<p class="error">Error: ' + res.status + '</p>';
      return null;
    }
    return res.text();
  }

  function buildWorkloadPath(ns, name) {
    return "/workload/" + encodeURIComponent(ns) + "/" + encodeURIComponent(name);
  }

  function rowKey(row) {
    return row.dataset.ns + "/" + row.dataset.name;
  }

  async function expandRow(row) {
    row.classList.add("expanded");
    const detail = row.nextElementSibling.querySelector("td");
    const html = await authedFetch(buildWorkloadPath(row.dataset.ns, row.dataset.name));
    if (html !== null) detail.innerHTML = html;
  }

  function collapseRow(row) {
    row.classList.remove("expanded");
    row.nextElementSibling.querySelector("td").innerHTML = "";
  }

  function attachRowHandlers() {
    content.querySelectorAll(".workload-row").forEach(function(row) {
      row.addEventListener("click", function() {
        if (row.classList.contains("expanded")) {
          collapseRow(row);
        } else {
          expandRow(row);
        }
      });
    });
  }

  function applyFilter() {
    const query = filterInput.value.trim().toLowerCase();
    content.querySelectorAll(".workload-row").forEach(function(row) {
      const match = !query || row.textContent.toLowerCase().includes(query);
      row.hidden = !match;
      row.nextElementSibling.hidden = !match;
    });
  }

  async function loadDashboard() {
    const html = await authedFetch("/api/dashboard");
    if (html === null) return false;

    const expanded = new Set();
    content.querySelectorAll(".workload-row.expanded").forEach(function(row) {
      expanded.add(rowKey(row));
    });

    content.innerHTML = html;
    refreshTime.textContent = new Date().toLocaleTimeString();
    attachRowHandlers();
    content.querySelectorAll(".workload-row").forEach(function(row) {
      if (expanded.has(rowKey(row))) expandRow(row);
    });
    applyFilter();
    return true;
  }

  function connectSSE() {
    closeSSE();
    eventSource = new EventSource("/api/events");
    eventSource.addEventListener("refresh", function() {
      loadDashboard();
    });
    eventSource.onerror = function() {
      // EventSource auto-reconnects
    };
  }

  async function start() {
    const ok = await loadDashboard();
    if (ok) connectSSE();
  }

  if (window.__TRIVY_DASHBOARD_TEST__) {
    window.TrivyDashboardTest = {
      applyFilter,
      authedFetch,
      buildWorkloadPath,
      start,
      submitToken
    };
  }

  loginForm.addEventListener("submit", function(e) {
    e.preventDefault();
    const token = tokenInput.value.trim();
    tokenInput.value = "";
    if (token) submitToken(token);
  });

  filterInput.addEventListener("input", applyFilter);
  refreshBtn.addEventListener("click", loadDashboard);
  signoutBtn.addEventListener("click", async function() {
    if (authRequired) await fetch("/api/session", { method: "DELETE" });
    closeSSE();
    content.innerHTML = "";
    refreshTime.textContent = "—";
    if (authRequired) showLogin();
  });

  start();
})();
