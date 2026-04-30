const API_BASE = "/api";

let csrfToken = "";

async function refreshCsrfToken() {
  const response = await fetch(`${API_BASE}/csrf-token`, { credentials: "include" });
  const data = await response.json();
  csrfToken = data.csrf_token || "";
  return csrfToken;
}

async function secureFetch(path, options = {}) {
  if (!csrfToken) {
    await refreshCsrfToken();
  }
  const headers = {
    "Content-Type": "application/json",
    ...(options.headers || {}),
  };
  if (["POST", "PUT", "PATCH", "DELETE"].includes((options.method || "GET").toUpperCase())) {
    headers["X-CSRF-Token"] = csrfToken;
  }
  return fetch(`${API_BASE}${path}`, {
    ...options,
    headers,
    credentials: "include",
  });
}

window.secureFetch = secureFetch;
