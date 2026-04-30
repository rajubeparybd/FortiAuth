const enableBtn = document.getElementById("enableBtn");
const statusNode = document.getElementById("status");
const qrImage = document.getElementById("qrImage");
const secretText = document.getElementById("secretText");
const backupCodesNode = document.getElementById("backupCodes");
const codeInput = document.getElementById("code");
const codeLabel = document.querySelector('label[for="code"]');

let isTwoFactorEnabled = false;

function authHeaders() {
  return { Authorization: `Bearer ${localStorage.getItem("access_token") || ""}` };
}

function renderEnabledState(message) {
  isTwoFactorEnabled = true;
  qrImage.style.display = "none";
  qrImage.removeAttribute("src");
  secretText.textContent = "2FA is enabled for your account.";
  backupCodesNode.textContent = "";
  if (codeInput) {
    codeInput.value = "";
    codeInput.style.display = "none";
  }
  if (codeLabel) {
    codeLabel.style.display = "none";
  }
  enableBtn.textContent = "Disable 2FA";
  statusNode.textContent = message;
}

function renderSetupState() {
  isTwoFactorEnabled = false;
  if (codeInput) {
    codeInput.style.display = "block";
  }
  if (codeLabel) {
    codeLabel.style.display = "block";
  }
  enableBtn.textContent = "Enable 2FA";
}

async function loadTwoFactorStatus() {
  const response = await window.secureFetch("/auth/2fa-status", {
    method: "GET",
    headers: authHeaders(),
  });
  const data = await response.json();
  if (!response.ok) {
    statusNode.textContent = data.error || data.msg || "Could not load 2FA status.";
    return false;
  }
  if (data.is_2fa_enabled) {
    renderEnabledState("2FA is already enabled. You can disable it below.");
    return true;
  }
  renderSetupState();
  return false;
}

async function generateQrCode() {
  const token = localStorage.getItem("access_token") || "";
  if (!token) {
    statusNode.textContent = "You must log in first. No access token found.";
    return;
  }

  statusNode.textContent = "Generating QR code...";
  const response = await window.secureFetch("/auth/setup-2fa", {
    method: "POST",
    headers: authHeaders(),
  });
  const data = await response.json();
  if (!response.ok) {
    statusNode.textContent = data.error || data.msg || "Failed to generate QR.";
    return;
  }
  qrImage.src = `data:image/png;base64,${data.qr_code_base64}`;
  qrImage.width = 96;
  qrImage.height = 96;
  qrImage.style.width = "96px";
  qrImage.style.height = "96px";
  qrImage.style.maxWidth = "96px";
  qrImage.style.maxHeight = "96px";
  qrImage.style.display = "block";
  secretText.textContent = `Secret: ${data.totp_secret}`;
  backupCodesNode.textContent = data.backup_codes.join("\n");
  if (codeInput) {
    codeInput.style.display = "block";
  }
  if (codeLabel) {
    codeLabel.style.display = "block";
  }
  statusNode.textContent = "QR generated. Verify one code to enable.";
}

enableBtn?.addEventListener("click", async () => {
  if (isTwoFactorEnabled) {
    enableBtn.disabled = true;
    statusNode.textContent = "Disabling 2FA...";
    const disableResponse = await window.secureFetch("/auth/disable-2fa", {
      method: "POST",
      headers: authHeaders(),
    });
    const disableData = await disableResponse.json();
    enableBtn.disabled = false;
    if (!disableResponse.ok) {
      statusNode.textContent = disableData.error || disableData.msg || "2FA disable failed.";
      return;
    }
    renderSetupState();
    await generateQrCode();
    statusNode.textContent = disableData.message || "2FA disabled successfully.";
    return;
  }

  const code = document.getElementById("code").value.trim();
  if (!code) {
    statusNode.textContent = "Enter the verification code first.";
    return;
  }
  enableBtn.disabled = true;
  statusNode.textContent = "Verifying code and enabling 2FA...";
  const response = await window.secureFetch("/auth/enable-2fa", {
    method: "POST",
    headers: authHeaders(),
    body: JSON.stringify({ code }),
  });
  const data = await response.json();
  enableBtn.disabled = false;
  if (!response.ok) {
    statusNode.textContent = data.error || data.msg || "2FA enable failed.";
    return;
  }
  renderEnabledState(data.message || "2FA enabled successfully.");
});

window.addEventListener("DOMContentLoaded", () => {
  loadTwoFactorStatus().then((alreadyEnabled) => {
    if (!alreadyEnabled) {
      generateQrCode();
    }
  });
});
