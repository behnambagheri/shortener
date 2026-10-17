import { ValidationError } from "./policy.mjs";

// Turnstile loads its script and challenge frame from challenges.cloudflare.com.
export const security = {
  "Cache-Control": "no-store", "X-Content-Type-Options": "nosniff", "Referrer-Policy": "no-referrer",
  "Content-Security-Policy": "default-src 'self'; script-src 'self' https://challenges.cloudflare.com; frame-src https://challenges.cloudflare.com; style-src 'self'; font-src 'self'; img-src 'self' data:; connect-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'",
};

export function reply(body, status = 200, type = "application/json; charset=utf-8", headers = {}) {
  return new Response(type.startsWith("application/json") ? JSON.stringify(body) : body,
    { status, headers: { ...security, "Content-Type": type, ...headers } });
}

export function render(template, data = {}, status = 200, headers = {}) {
  const safe = JSON.stringify(data).replace(/</g, "\\u003c").replace(/\u2028/g, "\\u2028").replace(/\u2029/g, "\\u2029");
  return reply(template.replace("__PAGE_DATA__", safe), status, "text/html; charset=utf-8", headers);
}

export function decode(base64) {
  const data = atob(base64);
  return Uint8Array.from(data, (char) => char.charCodeAt(0));
}

export async function payload(request, limit = 8192, { json = false } = {}) {
  const type = request.headers.get("Content-Type") || "";
  if (json && !type.includes("application/json")) throw new ValidationError("Use a JSON request body.", 415, "body");
  const reader = request.body?.getReader();
  const parts = []; let length = 0;
  if (reader) while (true) {
    const { done, value } = await reader.read(); if (done) break;
    length += value.byteLength;
    if (length > limit) { await reader.cancel(); throw new ValidationError("The submitted form is too large.", 413); }
    parts.push(value);
  }
  const bytes = new Uint8Array(length); let offset = 0;
  for (const part of parts) { bytes.set(part, offset); offset += part.length; }
  const text = new TextDecoder().decode(bytes);
  if (type.includes("application/json")) {
    try {
      const data = JSON.parse(text);
      if (!data || typeof data !== "object" || Array.isArray(data)) throw new Error();
      return data;
    } catch { throw new ValidationError("Submit a valid JSON object."); }
  }
  if (type.includes("application/x-www-form-urlencoded")) return Object.fromEntries(new URLSearchParams(text));
  throw new ValidationError("Use JSON or a URL-encoded form.", 415);
}

export function publicOrigin(env, url) {
  return (env.PUBLIC_ORIGIN || url.origin).replace(/\/+$/, "");
}

// A mirror (e.g. one hosted for domestic access) names the primary site as canonical so search engines don't treat it as a duplicate.
export function canonicalOrigin(env, origin) {
  return (env.CANONICAL_ORIGIN || origin).replace(/\/+$/, "");
}

// Browser sessions rely on SameSite cookies; reject cross-site requests outright as well.
// Fetch metadata is authoritative where browsers send it; otherwise compare the Origin header.
export function sameOrigin(request, url) {
  const site = request.headers.get("Sec-Fetch-Site");
  if (site) return ["same-origin", "none"].includes(site);
  const origin = request.headers.get("Origin");
  if (!origin) return true;
  try { return new URL(origin).host === url.host; } catch { return false; }
}

export function cookie(request, name) {
  for (const part of (request.headers.get("Cookie") || "").split(";")) {
    const index = part.indexOf("=");
    if (index > 0 && part.slice(0, index).trim() === name) return part.slice(index + 1).trim();
  }
  return null;
}

const entities = { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" };
export const escapeHtml = (value) => String(value).replace(/[&<>"']/g, (char) => entities[char]);

// Fills [[name]] placeholders with HTML-escaped values.
export function fill(template, values) {
  return template.replace(/\[\[(\w+)\]\]/g, (match, name) => name in values ? escapeHtml(values[name]) : match);
}
