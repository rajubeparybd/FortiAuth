const API_BASE = "/api";

let csrfToken = "";

function getAccessToken() {
  return localStorage.getItem("access_token") || "";
}

function clearAccessToken() {
  localStorage.removeItem("access_token");
}

async function refreshCsrfToken() {
  const response = await fetch(`${API_BASE}/csrf-token`, { credentials: "include" });
  const data = await response.json();
  csrfToken = data.csrf_token || "";
  return csrfToken;
}

function withAuthHeader(headers = {}) {
  const token = getAccessToken();
  if (!token) {
    return headers;
  }
  return {
    ...headers,
    Authorization: `Bearer ${token}`,
  };
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

async function fetchCurrentUser() {
  const token = getAccessToken();
  if (!token) {
    return null;
  }
  const response = await secureFetch("/user/profile", {
    method: "GET",
    headers: withAuthHeader(),
  });
  if (!response.ok) {
    clearAccessToken();
    return null;
  }
  const data = await response.json();
  return data.user || null;
}

function redirectToLogin() {
  window.location.href = "/index.html";
}

function redirectToDashboard() {
  window.location.href = "/dashboard.html";
}

async function requireAuth() {
  const user = await fetchCurrentUser();
  if (!user) {
    redirectToLogin();
    return null;
  }
  return user;
}

async function requireGuest() {
  const user = await fetchCurrentUser();
  if (user) {
    redirectToDashboard();
    return false;
  }
  return true;
}

window.secureFetch = secureFetch;
window.withAuthHeader = withAuthHeader;
window.getAccessToken = getAccessToken;
window.clearAccessToken = clearAccessToken;
window.fetchCurrentUser = fetchCurrentUser;
window.requireAuth = requireAuth;
window.requireGuest = requireGuest;
window.redirectToDashboard = redirectToDashboard;
