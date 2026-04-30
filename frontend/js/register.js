const form = document.getElementById("registerForm");
const statusText = document.getElementById("status");
const strengthText = document.getElementById("strength");
const passwordInput = document.getElementById("password");

function calculateStrength(password) {
  let score = 0;
  if (password.length >= 8) score += 1;
  if (/[A-Z]/.test(password)) score += 1;
  if (/[a-z]/.test(password)) score += 1;
  if (/\d/.test(password)) score += 1;
  if (/[^A-Za-z0-9]/.test(password)) score += 1;
  return score;
}

passwordInput?.addEventListener("input", () => {
  const score = calculateStrength(passwordInput.value);
  const labels = ["Very weak", "Weak", "Okay", "Good", "Strong", "Excellent"];
  strengthText.textContent = `Password strength: ${labels[score]}`;
});

form?.addEventListener("submit", async (event) => {
  event.preventDefault();
  statusText.textContent = "Creating account...";
  const username = document.getElementById("username").value.trim();
  const email = document.getElementById("email").value.trim();
  const password = passwordInput.value;

  const response = await window.secureFetch("/auth/register", {
    method: "POST",
    body: JSON.stringify({ username, email, password }),
  });
  const data = await response.json();
  statusText.textContent = response.ok ? data.message : data.error || "Registration failed.";
});
