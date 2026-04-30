const usernameValue = document.getElementById("usernameValue");
const emailValue = document.getElementById("emailValue");
const twoFaValue = document.getElementById("twoFaValue");
const createdAtValue = document.getElementById("createdAtValue");
const logoutLink = document.getElementById("logoutLink");
const statusNode = document.getElementById("status");

async function loadDashboardData() {
  const user = await window.requireAuth();
  if (!user) {
    return;
  }
  usernameValue.textContent = user.username || "-";
  emailValue.textContent = user.email || "-";
  twoFaValue.textContent = Number(user.is_2fa_enabled) === 1 ? "Enabled" : "Disabled";
  createdAtValue.textContent = user.created_at ? new Date(user.created_at).toLocaleString() : "-";
}

logoutLink?.addEventListener("click", async (event) => {
  event.preventDefault();
  statusNode.textContent = "Logging out...";
  const response = await window.secureFetch("/auth/logout", {
    method: "POST",
    headers: window.withAuthHeader(),
  });
  window.clearAccessToken();
  if (!response.ok) {
    statusNode.textContent = "Session ended locally. Redirecting to login...";
  }
  window.location.href = "/index.html";
});

window.addEventListener("DOMContentLoaded", loadDashboardData);
