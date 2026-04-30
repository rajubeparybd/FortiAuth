const loginForm = document.getElementById("loginForm");
const statusEl = document.getElementById("status");
const twoFactorBlock = document.getElementById("twoFactorBlock");
let pendingUserId = "";

loginForm?.addEventListener("submit", async (event) => {
  event.preventDefault();
  statusEl.textContent = "Signing in...";
  const username = document.getElementById("username").value.trim();
  const password = document.getElementById("password").value;
  const code = document.getElementById("code").value.trim();

  if (pendingUserId && code) {
    const verifyResponse = await window.secureFetch("/auth/verify-2fa", {
      method: "POST",
      body: JSON.stringify({ user_id: pendingUserId, code }),
    });
    const verifyData = await verifyResponse.json();
    if (!verifyResponse.ok) {
      statusEl.textContent = verifyData.error || verifyData.msg || "2FA verification failed.";
      return;
    }
    localStorage.setItem("access_token", verifyData.access_token);
    statusEl.textContent = "Login complete. Redirecting...";
    window.redirectToDashboard();
    return;
  }

  const response = await window.secureFetch("/auth/login", {
    method: "POST",
    body: JSON.stringify({ username, password }),
  });
  const data = await response.json();
  if (!response.ok) {
    statusEl.textContent = data.error || data.msg || "Login failed.";
    return;
  }

  if (data.requires_2fa) {
    pendingUserId = data.user_id;
    twoFactorBlock.style.display = "block";
    statusEl.textContent = "Enter your 2FA code to continue.";
    return;
  }

  localStorage.setItem("access_token", data.access_token);
  statusEl.textContent = "Login successful. Redirecting...";
  window.redirectToDashboard();
});

window.addEventListener("DOMContentLoaded", async () => {
  await window.requireGuest();
});
