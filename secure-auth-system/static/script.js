const $ = (id) => document.getElementById(id);
const messageBox = $("message");

function showMessage(text, type) {
  messageBox.textContent = text;           // textContent (not innerHTML) -> prevents XSS
  messageBox.className = "message " + type;
}
function clearMessage() { messageBox.className = "message hidden"; }

/* ---------- token storage ---------- */
function saveTokens(data) {
  localStorage.setItem("access_token", data.access_token);
  localStorage.setItem("refresh_token", data.refresh_token);
}
function clearTokens() {
  localStorage.removeItem("access_token");
  localStorage.removeItem("refresh_token");
}

/* ---------- API helper (auto-refreshes expired access token once) ---------- */
async function refreshTokens() {
  const refresh_token = localStorage.getItem("refresh_token");
  if (!refresh_token) return false;
  const res = await fetch("/api/refresh", {
    method: "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ refresh_token }),
  });
  if (!res.ok) return false;
  saveTokens(await res.json());
  return true;
}

async function api(path, method = "GET", body = null, auth = false, retry = true) {
  const headers = { "Content-Type": "application/json" };
  if (auth) headers["Authorization"] = "Bearer " + localStorage.getItem("access_token");
  const res = await fetch(path, { method, headers, body: body ? JSON.stringify(body) : null });
  if (res.status === 401 && auth && retry && (await refreshTokens())) {
    return api(path, method, body, auth, false);
  }
  let data = {};
  try { data = await res.json(); } catch (e) { /* empty body */ }
  return { ok: res.ok, status: res.status, data };
}

/* ---------- views ---------- */
function showAuth() {
  $("dashboard-view").classList.add("hidden");
  $("auth-view").classList.remove("hidden");
}

async function showDashboard() {
  const res = await api("/api/profile", "GET", null, true);
  if (!res.ok) { clearTokens(); return showAuth(); }
  const u = res.data;
  $("p-username").textContent = u.username;
  $("p-email").textContent = u.email;
  $("p-phone").textContent = u.phone || "not set";
  $("p-created").textContent = new Date(u.created_at).toLocaleDateString();
  $("auth-view").classList.add("hidden");
  $("dashboard-view").classList.remove("hidden");
  loadHistory();
}

async function loadHistory() {
  const res = await api("/api/login-history", "GET", null, true);
  const list = $("history");
  list.innerHTML = "";
  if (!res.ok) return;
  res.data.forEach((l) => {
    const li = document.createElement("li");
    const status = document.createElement("span");
    status.className = l.success ? "ok" : "fail";
    status.textContent = l.success ? "✔ Success" : "✖ Failed";
    li.appendChild(status);
    li.appendChild(document.createTextNode(` · ${new Date(l.time).toLocaleString()} · ${l.ip || ""}`));
    list.appendChild(li);
  });
}

/* ---------- tabs ---------- */
function switchTab(login) {
  clearMessage();
  $("login-form").classList.toggle("hidden", !login);
  $("register-form").classList.toggle("hidden", login);
  $("tab-login").classList.toggle("active", login);
  $("tab-register").classList.toggle("active", !login);
}
$("tab-login").onclick = () => switchTab(true);
$("tab-register").onclick = () => switchTab(false);

const formData = (form) => Object.fromEntries(new FormData(form).entries());

/* ---------- form handlers ---------- */
$("register-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const res = await api("/api/register", "POST", formData(e.target));
  if (res.ok) {
    e.target.reset();
    switchTab(true);
    showMessage(res.data.message, "success");
  } else showMessage(res.data.error || "Registration failed.", "error");
});

$("login-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const res = await api("/api/login", "POST", formData(e.target));
  if (res.ok) {
    saveTokens(res.data);
    e.target.reset();
    clearMessage();
    showDashboard();
  } else showMessage(res.data.error || "Login failed.", "error");
});

$("phone-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const res = await api("/api/profile", "PUT", formData(e.target), true);
  if (res.ok) { $("p-phone").textContent = res.data.user.phone || "not set"; showMessage(res.data.message, "success"); }
  else showMessage(res.data.error || "Update failed.", "error");
});

$("password-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const res = await api("/api/change-password", "POST", formData(e.target), true);
  if (res.ok) {
    e.target.reset(); clearTokens(); showAuth();
    showMessage(res.data.message, "success");
  } else showMessage(res.data.error || "Could not change password.", "error");
});

$("logout-btn").onclick = async () => {
  await api("/api/logout", "POST", { refresh_token: localStorage.getItem("refresh_token") });
  clearTokens(); showAuth(); showMessage("You have been logged out.", "success");
};

$("logout-all-btn").onclick = async () => {
  await api("/api/logout-all", "POST", null, true);
  clearTokens(); showAuth(); showMessage("Logged out from all devices.", "success");
};

/* ---------- start ---------- */
if (localStorage.getItem("access_token")) showDashboard(); else showAuth();
