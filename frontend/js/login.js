const loginForm = document.getElementById("loginForm");
const statusEl = document.getElementById("status");
const twoFactorBlock = document.getElementById("twoFactorBlock");
const linksEl = document.querySelector(".links");
let pendingUserId = "";

function renderLoggedInState(message) {
  loginForm.style.display = "none";
  if (linksEl) {
    linksEl.style.display = "none";
  }
  statusEl.textContent = message;

  let loggedInPanel = document.getElementById("loggedInPanel");
  if (!loggedInPanel) {
    loggedInPanel = document.createElement("div");
    loggedInPanel.id = "loggedInPanel";
    loggedInPanel.className = "links";
    loggedInPanel.innerHTML = `
      <a href="/2fa-setup.html">Set up 2FA</a>
      <a href="/forgot-password.html">Change password</a>
    `;
    statusEl.insertAdjacentElement("afterend", loggedInPanel);
  }
}

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
    renderLoggedInState("Login complete with 2FA.");
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
  renderLoggedInState("Login successful.");
});
