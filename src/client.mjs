import { destination, alias } from "./policy.mjs";
import { setupTheme } from "./theme.mjs";
const $ = (id) => document.getElementById(id);
setupTheme();
let config;
let turnstileWidget = null;
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
  $("expiry-note").textContent = result.expires_at ? `This link stops working on ${new Date(result.expires_at * 1000).toLocaleDateString(undefined, { year: "numeric", month: "long", day: "numeric" })}. Sign in to create links that do not expire.` : "";
  $("expiry-note").classList.toggle("hidden", !result.expires_at);
}

// Loads Cloudflare Turnstile only when it is configured; it stays invisible unless a visitor needs a challenge.
function loadTurnstile(siteKey) {
  const script = document.createElement("script");
  script.src = "https://challenges.cloudflare.com/turnstile/v0/api.js?render=explicit";
  script.async = true;
  script.addEventListener("load", () => {
    $("turnstile").classList.remove("hidden");
    turnstileWidget = window.turnstile.render("#turnstile", { sitekey: siteKey, appearance: "interaction-only", action: "create-link" });
  });
  document.head.append(script);
}

function account() {
  if (config.user) {
    $("account-name").textContent = config.user.name;
    $("account").classList.replace("hidden", "flex");
  } else if (config.sign_in.length && !config.any_domain && config.domain_policy === "signed_in") {
    for (const provider of config.sign_in) $(`sign-in-${provider}`).classList.remove("hidden");
    $("sign-in-hint").classList.replace("hidden", "flex");
  }
}
$("original").value = initial.original || "";
$("shortened").value = initial.shortened || "";
if (initial.error) showError(initial.error, initial.field);
if (initial.result) showResult(initial.result);
$("submit-button").disabled = true;
try {
  const response = await fetch("/api/config");
  if (!response.ok) throw new Error();
  config = await response.json();
  const any = config.any_domain;
  if (!Array.isArray(config.approved_domains) || !config.approved_domains.length) throw new Error();
  account();
  if (any && config.turnstile_site_key && config.link_creation !== "admin") loadTurnstile(config.turnstile_site_key);
  if (any) $("destination-help").textContent = "HTTP and HTTPS links to any domain. Sign-in, wallet, and newly registered sites are refused.";
  if (config.link_creation === "admin") $("creation-notice").classList.remove("hidden");
  else $("submit-button").disabled = false;
} catch {
  showError("Could not load the shortener settings. Refresh the page to try again.");
}
$("shorten-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  if (!config || $("submit-button").disabled) return;
  $("form-error").classList.add("hidden");
  $("original").removeAttribute("aria-invalid"); $("shortened").removeAttribute("aria-invalid");
  $("page-status").textContent = "";
  const original = $("original").value.trim(); const shortened = $("shortened").value.trim();
  try {
    destination(original, config.any_domain ? null : config.approved_domains, [new URL(config.short_origin).hostname, location.hostname]);
    if (shortened) alias(shortened);
  } catch (error) { showError(error.message, error.field); return; }
  $("submit-button").disabled = true; $("submit-label").textContent = "Creating…";
  try {
    const turnstile = turnstileWidget !== null ? window.turnstile.getResponse(turnstileWidget) : undefined;
    const response = await fetch("/api/links", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ original, shortened, turnstile }) });
    const data = await response.json();
    if (!response.ok) { showError(data.error || "Could not create the link.", data.field); return; }
    showResult(data); $("page-status").textContent = "Short link created. Copy it or open it above."; $("short-url").focus();
  } catch { showError("Could not reach the shortener. Try again shortly."); }
  finally {
    // Turnstile tokens are single-use.
    if (turnstileWidget !== null) window.turnstile.reset(turnstileWidget);
    $("submit-label").textContent = "Create short link"; $("submit-button").disabled = false;
  }
});
$("copy-button").addEventListener("click", async () => {
  try {
    await navigator.clipboard.writeText($("short-url").value); $("copy-button").textContent = "Copied"; $("page-status").textContent = "Short link copied to your clipboard.";
  } catch {
    $("short-url").focus(); $("short-url").select(); $("page-status").textContent = "Select and copy the link above. Clipboard access is unavailable.";
  }
});
