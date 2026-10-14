export class ValidationError extends Error {
  constructor(message, status = 400, field = "original") {
    super(message); this.status = status; this.field = field;
  }
}

export function approvedDomains(value) {
  let values = value;
  if (typeof value === "string") {
    try { values = value.trim().startsWith("[") ? JSON.parse(value) : value.split(","); }
    catch { throw new Error("Invalid approved_domains configuration."); }
  }
  if (!Array.isArray(values) || !values.length) throw new Error("approved_domains must be a nonempty list.");
  return [...new Set(values.map((domain) => {
    if (typeof domain !== "string" || /[\s/@:%*?#\\]/.test(domain)) throw new Error("Invalid approved domain.");
    const host = new URL(`https://${domain}`).hostname.toLowerCase().replace(/\.$/, "");
    if (host.length > 253 || !host.includes(".") || /^\d+(\.\d+){3}$/.test(host) ||
      !host.split(".").every((label) => /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(label))) {
      throw new Error("Invalid approved domain.");
    }
    return host;
  }))].sort();
}

export function destination(value, domains, ownHosts = []) {
  if (typeof value !== "string" || value.length > 2048 || /[\x00-\x20\x7f\\]/.test(value) || !/^https?:\/\//i.test(value)) {
    throw new ValidationError("Enter a complete HTTP or HTTPS URL, up to 2,048 characters.");
  }
  let url;
  try { url = new URL(value); } catch { throw new ValidationError("Enter a valid destination URL."); }
  if (!["http:", "https:"].includes(url.protocol) || url.username || url.password) {
    throw new ValidationError("Use an HTTP or HTTPS URL without embedded credentials.");
  }
  const host = url.hostname.toLowerCase().replace(/\.$/, "");
  if (!domains.some((domain) => host === domain || host.endsWith(`.${domain}`))) {
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
  if (["api", "assets", "static", "health", "new"].includes(value.toLowerCase())) {
    throw new ValidationError("That short name is reserved. Choose another.", 400, "shortened");
  }
  return value;
}
