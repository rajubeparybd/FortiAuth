const loginForm = document.getElementById("loginForm");
const statusEl = document.getElementById("status");
const twoFactorBlock = document.getElementById("twoFactorBlock");
const submitButton = loginForm?.querySelector('button[type="submit"]');
const lockoutPanel = document.getElementById("lockoutPanel");
const lockoutTimerText = document.getElementById("lockoutTimerText");
let pendingUserId = "";
let lockoutTimerId = null;
let isLockedOut = false;
const LOCKOUT_UNTIL_KEY = "lockout_until_epoch_ms";

function formatDuration(totalSeconds) {
  const minutes = Math.floor(totalSeconds / 60);
  const seconds = totalSeconds % 60;
  return `${String(minutes).padStart(2, "0")}:${String(seconds).padStart(2, "0")}`;
}

function stopLockoutTimer() {
  if (lockoutTimerId) {
    window.clearInterval(lockoutTimerId);
    lockoutTimerId = null;
  }
}

function saveLockoutUntil(remainingSeconds) {
  const lockoutUntilMs = Date.now() + (remainingSeconds * 1000);
  localStorage.setItem(LOCKOUT_UNTIL_KEY, String(lockoutUntilMs));
}

function clearLockoutUntil() {
  localStorage.removeItem(LOCKOUT_UNTIL_KEY);
}

function getRemainingFromStorage() {
  const rawValue = localStorage.getItem(LOCKOUT_UNTIL_KEY);
  const lockoutUntilMs = Number(rawValue || 0);
  if (!Number.isFinite(lockoutUntilMs) || lockoutUntilMs <= 0) {
    return 0;
  }
  return Math.max(0, Math.ceil((lockoutUntilMs - Date.now()) / 1000));
}

function setLoginBlocked(blocked) {
  isLockedOut = blocked;
  if (loginForm) {
    loginForm.style.display = blocked ? "none" : "block";
  }
  if (lockoutPanel) {
    lockoutPanel.style.display = blocked ? "block" : "none";
  }
  if (submitButton) {
    submitButton.disabled = blocked;
    submitButton.textContent = blocked ? "Login blocked" : "Sign In";
  }
}

function setStatus(message, type = "info") {
  statusEl.textContent = message;
  statusEl.classList.remove("status-error", "status-success", "status-info");
  statusEl.classList.add(`status-${type}`);
  if (type === "error") {
    statusEl.style.color = "#ff4d6d";
  } else if (type === "success") {
    statusEl.style.color = "#67e8a5";
  } else {
    statusEl.style.color = "#bfd0ff";
  }
}

function startLockoutTimer(seconds) {
  stopLockoutTimer();
  let remainingSeconds = Number.isFinite(seconds) && seconds > 0 ? Math.max(0, seconds) : 600;
  setLoginBlocked(true);
  saveLockoutUntil(remainingSeconds);
  if (remainingSeconds <= 0) {
    setStatus("Account is temporarily blocked. Please try again later.", "error");
    return;
  }
  if (lockoutTimerText) {
    lockoutTimerText.textContent = `Try again in ${formatDuration(remainingSeconds)}.`;
  }
  setStatus(`Account blocked due to failed attempts. Retry in ${formatDuration(remainingSeconds)}.`, "error");
  lockoutTimerId = window.setInterval(() => {
    remainingSeconds -= 1;
    if (remainingSeconds <= 0) {
      stopLockoutTimer();
      setLoginBlocked(false);
      clearLockoutUntil();
      if (lockoutTimerText) {
        lockoutTimerText.textContent = "";
      }
      setStatus("Lockout ended. You can try logging in again.", "info");
      return;
    }
    if (lockoutTimerText) {
      lockoutTimerText.textContent = `Try again in ${formatDuration(remainingSeconds)}.`;
    }
    setStatus(`Account blocked due to failed attempts. Retry in ${formatDuration(remainingSeconds)}.`, "error");
  }, 1000);
}

loginForm?.addEventListener("submit", async (event) => {
  event.preventDefault();
  if (isLockedOut) {
    return;
  }
  stopLockoutTimer();
  setStatus("Signing in...", "info");
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
      setStatus(verifyData.error || verifyData.msg || "2FA verification failed.", "error");
      return;
    }
    localStorage.setItem("access_token", verifyData.access_token);
    loginForm?.reset();
    pendingUserId = "";
    if (twoFactorBlock) {
      twoFactorBlock.style.display = "none";
    }
    setStatus("Login complete. Redirecting...", "success");
    window.redirectToDashboard();
    return;
  }

  const response = await window.secureFetch("/auth/login", {
    method: "POST",
    body: JSON.stringify({ username, password }),
  });
  const data = await response.json();
  if (!response.ok) {
    const retryAfterSeconds = Number(data.retry_after_seconds || 0);
    if (response.status === 423 || retryAfterSeconds > 0) {
      startLockoutTimer(retryAfterSeconds);
      return;
    }
    setStatus(data.error || data.msg || "Invalid username or password.", "error");
    return;
  }

  if (data.requires_2fa) {
    pendingUserId = data.user_id;
    twoFactorBlock.style.display = "block";
    setStatus("Enter your 2FA code to continue.", "info");
    return;
  }

  localStorage.setItem("access_token", data.access_token);
  clearLockoutUntil();
  loginForm?.reset();
  pendingUserId = "";
  if (twoFactorBlock) {
    twoFactorBlock.style.display = "none";
  }
  setStatus("Login successful. Redirecting...", "success");
  window.redirectToDashboard();
});

window.addEventListener("DOMContentLoaded", async () => {
  await window.requireGuest();
  const storedRemainingSeconds = getRemainingFromStorage();
  if (storedRemainingSeconds > 0) {
    startLockoutTimer(storedRemainingSeconds);
    return;
  }

  const statusResponse = await window.secureFetch("/auth/lockout-status", { method: "GET" });
  const statusData = await statusResponse.json();
  const serverRemainingSeconds = Number(statusData.retry_after_seconds || 0);
  if (statusResponse.ok && serverRemainingSeconds > 0) {
    startLockoutTimer(serverRemainingSeconds);
    return;
  }

  setLoginBlocked(false);
  setStatus("", "info");
});
