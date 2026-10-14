import { approvedDomains } from "./policy.mjs";
import { setupTheme } from "./theme.mjs";
const $ = (id) => document.getElementById(id);
setupTheme();

const initial = JSON.parse($("page-data").textContent || "{}");
const pageSize = 25;
let overview;
let linkState = { offset: 0, total: 0, search: "" };

function element(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined) node.textContent = text;
  return node;
}
function status(id, message, error = false) {
  $(id).textContent = message;
  $(id).classList.toggle("text-error", error);
}
async function request(path, options = {}) {
  const response = await fetch(path, { ...options, headers: { Accept: "application/json", ...(options.body ? { "Content-Type": "application/json" } : {}) } });
  if (response.status === 401) { location.reload(); throw new Error("Your session has ended. Sign in again."); }
  const data = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(data.error || "The request failed. Try again.");
  return data;
}
const formatDate = (seconds) => seconds ? new Date(seconds * 1000).toLocaleDateString(undefined, { year: "numeric", month: "short", day: "numeric" }) : "Imported";
const number = (value) => new Intl.NumberFormat().format(value);

function showLogin() {
  $("login-view").classList.remove("hidden");
  const auth = initial.auth || {};
  $("token-form").classList.toggle("hidden", !auth.token);
  $("access-help").classList.toggle("hidden", !auth.access);
  $("no-auth-help").classList.toggle("hidden", Boolean(auth.token || auth.access));
  if (initial.error) { $("login-error-text").textContent = initial.error; $("login-error").classList.remove("hidden"); }
  if (auth.token) $("token").focus();
}

function renderStats(stats) {
  $("stat-links").textContent = number(stats.links);
  $("stat-recent").textContent = `${number(stats.created_7d)} created in the last 7 days`;
  $("stat-clicks").textContent = number(stats.clicks);
  $("stat-disabled").textContent = number(stats.disabled);
}

function renderSettings(settings) {
  overview.settings = settings;
  for (const name of ["link_creation", "domain_policy"]) {
    for (const input of document.querySelectorAll(`input[name="${name}"]`)) input.checked = input.value === settings[name];
  }
  $("domain-count").textContent = String(settings.approved_domains.length);
  $("domain-source").textContent = settings.domains_customized
    ? "Managed here. These override the deployment defaults."
    : "Using the deployment defaults (APPROVED_DOMAINS or approved_domains.json). Changes here are saved as an override.";
  $("domain-reset").classList.toggle("hidden", !settings.domains_customized);
  renderDomains();
}

function renderDomains() {
  const search = $("domain-filter").value.trim().toLowerCase();
  const domains = overview.settings.approved_domains.filter((domain) => domain.includes(search));
  $("domain-list").replaceChildren(...domains.map((domain) => {
    const row = element("li", "flex items-center justify-between gap-2 rounded-field px-2 py-1 hover:bg-base-200");
    const remove = element("button", "btn btn-ghost btn-xs text-error", "Remove");
    remove.type = "button";
    remove.setAttribute("aria-label", `Remove ${domain}`);
    remove.addEventListener("click", () => updateDomains(overview.settings.approved_domains.filter((item) => item !== domain), `Removed ${domain}.`, `Remove ${domain}?`));
    row.append(element("span", "min-w-0 truncate font-mono text-sm", domain), remove);
    return row;
  }));
  if (!domains.length) $("domain-list").replaceChildren(element("li", "text-sm text-base-content/55", "No matching domains."));
}

async function saveSettings(changes, statusId, message) {
  status(statusId, "Saving…");
  try {
    renderSettings(await request("/admin/api/settings", { method: "PUT", body: JSON.stringify(changes) }));
    status(statusId, message);
    return true;
  } catch (error) { status(statusId, error.message, true); return false; }
}

async function updateDomains(domains, message, question) {
  if (!domains.length) { status("domain-status", "Keep at least one approved domain, or allow any domain instead.", true); return; }
  if (question && !confirm(`${question} Existing links to that domain stop redirecting while domains are restricted.`)) return;
  await saveSettings({ approved_domains: domains }, "domain-status", message);
}

function renderLinks(data) {
  linkState.total = data.total;
  $("link-rows").replaceChildren(...data.links.map((link) => {
    const row = element("tr", link.disabled ? "opacity-60" : "");
    const name = element("td", "whitespace-nowrap font-mono text-sm");
    const anchor = element("a", "link link-hover", link.slug);
    anchor.href = `${overview.short_origin}/${link.slug}`; anchor.target = "_blank"; anchor.rel = "noopener noreferrer";
    name.append(anchor);
    if (link.disabled) name.append(" ", element("span", "badge badge-warning badge-soft badge-xs", "Disabled"));
    const target = element("td", "max-w-xs truncate text-sm text-base-content/70", link.original);
    target.title = link.original;
    const clicks = element("td", "text-right tabular-nums", number(link.clicks));
    const created = element("td", "whitespace-nowrap text-sm text-base-content/60", formatDate(link.created_at));
    const actions = element("td", "whitespace-nowrap text-right");
    const toggle = element("button", "btn btn-ghost btn-xs", link.disabled ? "Enable" : "Disable");
    toggle.type = "button";
    toggle.addEventListener("click", async () => {
      try {
        await request(`/admin/api/links/${encodeURIComponent(link.slug)}`, { method: "PATCH", body: JSON.stringify({ disabled: !link.disabled }) });
        await refresh();
      } catch (error) { showDashboardError(error.message); }
    });
    const remove = element("button", "btn btn-ghost btn-xs text-error", "Delete");
    remove.type = "button";
    remove.addEventListener("click", async () => {
      if (!confirm(`Delete /${link.slug}? The name becomes available again and the link stops working.`)) return;
      try { await request(`/admin/api/links/${encodeURIComponent(link.slug)}`, { method: "DELETE" }); await refresh(); }
      catch (error) { showDashboardError(error.message); }
    });
    actions.append(toggle, remove);
    row.append(name, target, clicks, created, actions);
    return row;
  }));
  $("links-empty").classList.toggle("hidden", data.links.length !== 0);
  const end = linkState.offset + data.links.length;
  $("links-range").textContent = data.total ? `${number(linkState.offset + 1)}–${number(end)} of ${number(data.total)}` : "";
  $("links-prev").disabled = linkState.offset === 0;
  $("links-next").disabled = end >= data.total;
}

async function loadLinks() {
  const params = new URLSearchParams({ q: linkState.search, offset: String(linkState.offset), limit: String(pageSize) });
  renderLinks(await request(`/admin/api/links?${params}`));
}

function showDashboardError(message) {
  $("dashboard-error-text").textContent = message;
  $("dashboard-error").classList.toggle("hidden", !message);
}

async function refresh() {
  try {
    overview = await request("/admin/api/overview");
    renderStats(overview.stats);
    renderSettings(overview.settings);
    await loadLinks();
    showDashboardError("");
  } catch (error) { showDashboardError(error.message); }
}

async function showDashboard() {
  $("dashboard-view").classList.remove("hidden");
  $("logout-form").classList.remove("hidden");
  const identity = initial.identity || {};
  $("identity").textContent = identity.email || (identity.method === "access" ? "Cloudflare Access" : "Token session");
  // The badge stays hidden on phones, where the header has no room for it.
  $("identity").classList.add("sm:inline-flex");
  $("settings-form").addEventListener("submit", (event) => {
    event.preventDefault();
    const value = (name) => document.querySelector(`input[name="${name}"]:checked`)?.value;
    saveSettings({ link_creation: value("link_creation"), domain_policy: value("domain_policy") }, "settings-status", "Access settings saved.");
  });
  $("domain-form").addEventListener("submit", async (event) => {
    event.preventDefault();
    const entries = $("domain-input").value.split(/[\s,]+/).filter(Boolean);
    if (!entries.length) return;
    let added;
    try { added = approvedDomains(entries); } catch (error) { status("domain-status", error.message, true); return; }
    const domains = [...new Set([...overview.settings.approved_domains, ...added])];
    if (await saveSettings({ approved_domains: domains }, "domain-status", `Added ${added.join(", ")}.`)) $("domain-input").value = "";
  });
  $("domain-filter").addEventListener("input", () => { if (overview) renderDomains(); });
  $("domain-reset").addEventListener("click", () => {
    if (confirm("Replace the managed list with the deployment defaults?")) saveSettings({ approved_domains: null }, "domain-status", "Using the deployment defaults.");
  });
  let searchTimer;
  $("link-search").addEventListener("input", () => {
    clearTimeout(searchTimer);
    searchTimer = setTimeout(() => {
      linkState = { ...linkState, search: $("link-search").value.trim(), offset: 0 };
      loadLinks().catch((error) => showDashboardError(error.message));
    }, 250);
  });
  $("links-prev").addEventListener("click", () => { linkState.offset = Math.max(0, linkState.offset - pageSize); loadLinks().catch((error) => showDashboardError(error.message)); });
  $("links-next").addEventListener("click", () => { linkState.offset += pageSize; loadLinks().catch((error) => showDashboardError(error.message)); });
  $("create-form").addEventListener("submit", async (event) => {
    event.preventDefault();
    status("create-status", "Creating…");
    try {
      const result = await request("/admin/api/links", { method: "POST", body: JSON.stringify({ original: $("create-original").value.trim(), shortened: $("create-shortened").value.trim() }) });
      status("create-status", `Created ${result.short_url}`);
      $("create-form").reset();
      linkState.offset = 0;
      await refresh();
    } catch (error) { status("create-status", error.message, true); }
  });
  await refresh();
}

if (initial.view === "dashboard") showDashboard();
else showLogin();
