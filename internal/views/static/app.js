(() => {
  const TOKEN_KEY = "trivy-dashboard.token";
  const content = document.getElementById("content");
  const refreshTime = document.getElementById("refresh-time");
  const refreshBtn = document.getElementById("refresh");
  const signoutBtn = document.getElementById("signout");

  let eventSource = null;

  function getToken() {
    let t = sessionStorage.getItem(TOKEN_KEY);
    if (!t) {
      t = window.prompt("Enter trivy-dashboard bearer token:");
      if (t) sessionStorage.setItem(TOKEN_KEY, t);
    }
    return t;
  }

  function clearToken() {
    sessionStorage.removeItem(TOKEN_KEY);
  }

  async function authedFetch(path) {
    const token = getToken();
    if (!token) return null;
    const res = await fetch(path, {
      headers: { "Authorization": "Bearer " + token }
    });
    if (res.status === 401) {
      clearToken();
      content.innerHTML = '<p class="error">Unauthorized — token cleared. Refresh to re-enter.</p>';
      return null;
    }
    if (!res.ok) {
      content.innerHTML = '<p class="error">Error: ' + res.status + '</p>';
      return null;
    }
    return res.text();
  }

  async function loadDashboard() {
    const html = await authedFetch("/api/dashboard");
    if (html === null) return;
    content.innerHTML = html;
    refreshTime.textContent = new Date().toLocaleTimeString();
    attachRowHandlers();
  }

  function attachRowHandlers() {
    document.querySelectorAll(".workload-row").forEach(function(row) {
      row.addEventListener("click", async function() {
        var detail = this.nextElementSibling.querySelector("td");
        if (this.classList.toggle("expanded")) {
          var ns = this.dataset.ns;
          var name = this.dataset.name;
          var html = await authedFetch("/workload/" + ns + "/" + name);
          if (html !== null) detail.innerHTML = html;
        } else {
          detail.innerHTML = "";
        }
      });
    });
  }

  function connectSSE() {
    if (eventSource) eventSource.close();

    const token = getToken();
    if (!token) return;

    eventSource = new EventSource("/api/events?token=" + encodeURIComponent(token));

    eventSource.addEventListener("refresh", function() {
      loadDashboard();
    });

    eventSource.onerror = function() {
      // EventSource auto-reconnects
    };
  }

  refreshBtn.addEventListener("click", loadDashboard);
  signoutBtn.addEventListener("click", function() {
    clearToken();
    if (eventSource) eventSource.close();
    content.innerHTML = "";
    refreshTime.textContent = "—";
  });

  loadDashboard();
  connectSSE();
})();
