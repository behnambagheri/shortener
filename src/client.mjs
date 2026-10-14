import { destination, alias } from "./policy.mjs";
import { setupTheme } from "./theme.mjs";
const $ = (id) => document.getElementById(id);
setupTheme();
let config;
const initial = JSON.parse($("page-data").textContent || "{}");
function showError(message, field) {
  $("error-text").textContent = message;
  $("form-error").classList.remove("hidden");
  if (field === "original" || field === "shortened") { $(field).setAttribute("aria-invalid", "true"); $(field).focus(); }
}
function showResult(result) {
  $("short-url").value = result.short_url;
  $("open-link").href = result.short_url;
  $("destination-label").textContent = `To ${result.original}`;
  $("result").classList.remove("hidden");
  $("copy-button").textContent = "Copy link";
}
function domains() {
  const search = $("domain-filter").value.trim().toLowerCase();
  const matches = config.approved_domains.filter((domain) => domain.includes(search));
  $("domain-list").replaceChildren(...matches.map((domain) => {
    const label = document.createElement("span"); label.className = "badge badge-outline text-xs"; label.textContent = domain; return label;
  }));
  $("domain-empty").classList.toggle("hidden", matches.length !== 0);
}
$("domain-filter").addEventListener("input", () => { if (config) domains(); });
$("original").value = initial.original || "";
$("shortened").value = initial.shortened || "";
if (initial.error) showError(initial.error, initial.field);
if (initial.result) showResult(initial.result);
$("submit-button").disabled = true;
try {
  const response = await fetch("/api/config");
  if (!response.ok) throw new Error();
  config = await response.json();
  const any = config.domain_policy === "any";
  if (!Array.isArray(config.approved_domains) || (!any && !config.approved_domains.length)) throw new Error();
  if (any) {
    $("domain-count").textContent = "Any";
    $("domains-help").textContent = "Any HTTP or HTTPS destination is currently allowed.";
    $("destination-help").textContent = "HTTP and HTTPS links to any domain.";
    $("domain-filter").classList.add("hidden"); $("domain-list").replaceChildren();
  } else {
    $("domain-count").textContent = String(config.approved_domains.length);
    domains();
  }
  if (config.link_creation === "admin") $("creation-notice").classList.remove("hidden");
  else $("submit-button").disabled = false;
} catch {
  $("domain-list").replaceChildren(); showError("Could not load the approved domains. Refresh the page to try again.");
}
$("shorten-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  if (!config || $("submit-button").disabled) return;
  $("form-error").classList.add("hidden");
  $("original").removeAttribute("aria-invalid"); $("shortened").removeAttribute("aria-invalid");
  $("page-status").textContent = "";
  const original = $("original").value.trim(); const shortened = $("shortened").value.trim();
  try {
    destination(original, config.domain_policy === "any" ? null : config.approved_domains, [new URL(config.short_origin).hostname, location.hostname]);
    if (shortened) alias(shortened);
  } catch (error) { showError(error.message, error.field); return; }
  $("submit-button").disabled = true; $("submit-label").textContent = "Creating…";
  try {
    const response = await fetch("/api/links", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ original, shortened }) });
    const data = await response.json();
    if (!response.ok) { showError(data.error || "Could not create the link.", data.field); return; }
    showResult(data); $("page-status").textContent = "Short link created. Copy it or open it above."; $("short-url").focus();
  } catch { showError("Could not reach the shortener. Try again shortly."); }
  finally { $("submit-label").textContent = "Create short link"; $("submit-button").disabled = false; }
});
$("copy-button").addEventListener("click", async () => {
  try {
    await navigator.clipboard.writeText($("short-url").value); $("copy-button").textContent = "Copied"; $("page-status").textContent = "Short link copied to your clipboard.";
  } catch {
    $("short-url").focus(); $("short-url").select(); $("page-status").textContent = "Select and copy the link above. Clipboard access is unavailable.";
  }
});
