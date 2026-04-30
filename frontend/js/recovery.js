const forgotForm = document.getElementById("forgotForm");
const resetForm = document.getElementById("resetForm");
const resetDivider = document.getElementById("resetDivider");
const statusNode = document.getElementById("status");

function setRecoveryStatus(message, type = "info") {
  statusNode.textContent = message;
  statusNode.classList.remove("status-error", "status-success", "status-info");
  statusNode.classList.add(`status-${type}`);
}

function showRequestState() {
  if (forgotForm) {
    forgotForm.style.display = "block";
  }
  if (resetDivider) {
    resetDivider.style.display = "none";
  }
  if (resetForm) {
    resetForm.style.display = "none";
  }
}

function showResetState() {
  if (forgotForm) {
    forgotForm.style.display = "none";
  }
  if (resetDivider) {
    resetDivider.style.display = "block";
  }
  if (resetForm) {
    resetForm.style.display = "block";
  }
}

forgotForm?.addEventListener("submit", async (event) => {
  event.preventDefault();
  const email = document.getElementById("email").value.trim();
  const response = await window.secureFetch("/auth/forgot-password", {
    method: "POST",
    body: JSON.stringify({ email }),
  });
  const data = await response.json();
  if (!response.ok) {
    setRecoveryStatus(data.error || "Could not request reset.", "error");
    return;
  }
  const token = data.mock_notification?.reset_token || "Check notification channel";
  console.log("[Password Recovery] Reset token:", token);
  forgotForm?.reset();
  setRecoveryStatus(`${data.message} Check browser console for debug reset token.`, "success");
  showResetState();
  const tokenInput = document.getElementById("token");
  tokenInput?.focus();
});

resetForm?.addEventListener("submit", async (event) => {
  event.preventDefault();
  const token = document.getElementById("token").value.trim();
  const newPassword = document.getElementById("newPassword").value;
  const response = await window.secureFetch("/auth/reset-password", {
    method: "POST",
    body: JSON.stringify({ token, new_password: newPassword }),
  });
  const data = await response.json();
  if (!response.ok) {
    setRecoveryStatus(data.error || "Reset failed.", "error");
    return;
  }
  resetForm?.reset();
  showRequestState();
  setRecoveryStatus(data.message || "Password reset successful.", "success");
});

window.addEventListener("DOMContentLoaded", async () => {
  showRequestState();
  await window.requireGuest();
});
