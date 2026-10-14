export class ValidationError extends Error {
  constructor(message, status = 400, field = "original") {
    super(message); this.status = status; this.field = field;
  }
}

// "signed_in" allows any domain for signed-in users and administrators, and approved domains for everyone else.
export const domainPolicies = ["approved", "signed_in", "any"];
export const creationModes = ["public", "admin"];
export const reservedNames = ["admin", "api", "assets", "auth", "static", "health", "new"];

export function approvedDomains(value) {
  let values = value;
  if (typeof value === "string") {
    try { values = value.trim().startsWith("[") ? JSON.parse(value) : value.split(","); }
    catch { throw new Error("Invalid approved_domains configuration."); }
  }
  if (!Array.isArray(values) || !values.length) throw new Error("approved_domains must be a nonempty list.");
  if (values.length > 1000) throw new Error("Use at most 1,000 approved domains.");
  return [...new Set(values.map((domain) => {
    const label = typeof domain === "string" ? `Invalid approved domain: ${domain.trim().slice(0, 80)}.` : "Invalid approved domain.";
    if (typeof domain !== "string" || /[\s/@:%*?#\\]/.test(domain.trim())) throw new Error(label);
    let host;
    try { host = new URL(`https://${domain.trim()}`).hostname.toLowerCase().replace(/\.$/, ""); } catch { throw new Error(label); }
    if (host.length > 253 || !host.includes(".") || /^\d+(\.\d+){3}$/.test(host) ||
      !host.split(".").every((part) => /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(part))) {
      throw new Error(label);
    }
    return host;
  }))].sort();
}

export function onDomains(host, domains) {
  return domains.some((domain) => host === domain || host.endsWith(`.${domain}`));
}

// `domains` is the approved list, or null when any destination domain is allowed.
export function destination(value, domains, ownHosts = []) {
  if (typeof value !== "string" || value.length > 2048 || /[\x00-\x20\x7f\\]/.test(value) || !/^https?:\/\//i.test(value)) {
    throw new ValidationError("Enter a complete HTTP or HTTPS URL, up to 2,048 characters.");
  }
  let url;
  try { url = new URL(value); } catch { throw new ValidationError("Enter a valid destination URL."); }
  // Basic-auth credentials (http://user:pass@host) are allowed; the domain policy checks the real hostname.
  if (!["http:", "https:"].includes(url.protocol) || !url.hostname) {
    throw new ValidationError("Use an HTTP or HTTPS URL.");
  }
  const host = url.hostname.toLowerCase().replace(/\.$/, "");
  if (domains && !onDomains(host, domains)) {
    throw new ValidationError("That destination is not on an approved domain.", 403);
  }
  if (ownHosts.includes(host)) throw new ValidationError("Use the original destination, rather than another short link.");
  url.hostname = host;
  return url.href;
}

export function alias(value) {
  if (typeof value !== "string" || !/^[A-Za-z0-9_-]{1,63}$/.test(value)) {
    throw new ValidationError("Use 1–63 letters, numbers, hyphens, or underscores for your short name.", 400, "shortened");
  }
  if (reservedNames.includes(value.toLowerCase())) {
    throw new ValidationError("That short name is reserved. Choose another.", 400, "shortened");
  }
  return value;
}
