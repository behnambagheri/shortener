import inventory from "../approved_domains.json" with { type: "json" };
import { approvedDomains, domainPolicies, creationModes, ValidationError } from "./policy.mjs";

const upsert = "INSERT INTO settings (key, value, updated_at) VALUES (?, ?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at";

// Deployment defaults: APPROVED_DOMAINS when set, otherwise the version-controlled file.
export function defaultDomains(env) {
  return approvedDomains(env.APPROVED_DOMAINS === undefined || env.APPROVED_DOMAINS === "" ? inventory : env.APPROVED_DOMAINS);
}

// Settings saved from the admin area take precedence over deployment defaults.
export async function loadSettings(env) {
  const { results } = await env.DB.prepare("SELECT key, value FROM settings").all();
  const stored = Object.fromEntries(results.map((row) => [row.key, JSON.parse(row.value)]));
  const domainPolicy = stored.domain_policy ?? "approved";
  const linkCreation = stored.link_creation ?? "public";
  // An unknown stored value fails closed instead of silently opening the service.
  if (!domainPolicies.includes(domainPolicy) || !creationModes.includes(linkCreation)) throw new Error("Invalid stored settings.");
  const customized = stored.approved_domains !== undefined;
  const domains = customized ? approvedDomains(stored.approved_domains) : defaultDomains(env);
  return { domain_policy: domainPolicy, link_creation: linkCreation, approved_domains: domains, domains_customized: customized };
}

// The destination domains a creator may use: null means any domain. `kind` is "public", "user" or "admin".
export function allowedFor(settings, kind) {
  if (settings.domain_policy === "any" || (settings.domain_policy === "signed_in" && kind !== "public")) return null;
  return settings.approved_domains;
}

export async function saveSettings(env, input) {
  const now = Math.floor(Date.now() / 1000);
  const writes = [];
  for (const [key, options] of [["domain_policy", domainPolicies], ["link_creation", creationModes]]) {
    if (input[key] === undefined) continue;
    if (!options.includes(input[key])) throw new ValidationError(`Choose ${options.join(" or ")}.`, 400, key);
    writes.push(env.DB.prepare(upsert).bind(key, JSON.stringify(input[key]), now));
  }
  if (input.approved_domains === null) {
    writes.push(env.DB.prepare("DELETE FROM settings WHERE key = ?").bind("approved_domains"));
  } else if (input.approved_domains !== undefined) {
    if (!Array.isArray(input.approved_domains)) throw new ValidationError("Provide approved domains as a list.", 400, "approved_domains");
    let domains;
    try { domains = approvedDomains(input.approved_domains); }
    catch (error) { throw new ValidationError(error.message, 400, "approved_domains"); }
    writes.push(env.DB.prepare(upsert).bind("approved_domains", JSON.stringify(domains), now));
  }
  if (!writes.length) throw new ValidationError("Nothing to update.", 400, "settings");
  await env.DB.batch(writes);
  return loadSettings(env);
}
