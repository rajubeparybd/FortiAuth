const forgotForm = document.getElementById("forgotForm");
const resetForm = document.getElementById("resetForm");
const statusNode = document.getElementById("status");

forgotForm?.addEventListener("submit", async (event) => {
  event.preventDefault();
  const email = document.getElementById("email").value.trim();
  const response = await window.secureFetch("/auth/forgot-password", {
    method: "POST",
    body: JSON.stringify({ email }),
  });
  const data = await response.json();
  if (!response.ok) {
    statusNode.textContent = data.error || "Could not request reset.";
    return;
  }
  const token = data.mock_notification?.reset_token || "Check notification channel";
  statusNode.textContent = `${data.message} Token: ${token}`;
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
  statusNode.textContent = response.ok ? data.message : data.error || "Reset failed.";
});
