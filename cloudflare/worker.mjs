import inventory from "../approved_domains.json";
import { approvedDomains, destination, alias, ValidationError } from "./policy.mjs";
import { html, assets } from "./generated/ui.mjs";

const security = {
  "Cache-Control": "no-store", "X-Content-Type-Options": "nosniff", "Referrer-Policy": "no-referrer",
  "Content-Security-Policy": "default-src 'self'; script-src 'self'; style-src 'self'; font-src 'self'; img-src 'self' data:; connect-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'",
};
function reply(body, status = 200, type = "application/json; charset=utf-8", headers = {}) {
  return new Response(type.startsWith("application/json") ? JSON.stringify(body) : body,
    { status, headers: { ...security, "Content-Type": type, ...headers } });
}
function page(data = {}, status = 200) {
  const safe = JSON.stringify(data).replace(/</g, "\\u003c").replace(/\u2028/g, "\\u2028").replace(/\u2029/g, "\\u2029");
  return reply(html.replace("__PAGE_DATA__", safe), status, "text/html; charset=utf-8");
}
function decode(base64) {
  const data = atob(base64);
  return Uint8Array.from(data, (char) => char.charCodeAt(0));
}
async function payload(request) {
  const reader = request.body?.getReader();
  const parts = []; let length = 0;
  if (reader) while (true) {
    const { done, value } = await reader.read(); if (done) break;
    length += value.byteLength;
    if (length > 8192) { await reader.cancel(); throw new ValidationError("The submitted form is too large.", 413); }
    parts.push(value);
  }
  const bytes = new Uint8Array(length); let offset = 0;
  for (const part of parts) { bytes.set(part, offset); offset += part.length; }
  const text = new TextDecoder().decode(bytes);
  const type = request.headers.get("Content-Type") || "";
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
function randomAlias() {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
  const chars = [];
  // Rejection sampling avoids modulo bias in the generated names.
  while (chars.length < 8) for (const value of crypto.getRandomValues(new Uint8Array(12))) {
    if (value < 248 && chars.length < 8) chars.push(alphabet[value % 62]);
  }
  return chars.join("");
}
async function create(data, env, domains, origin, ownHost) {
  const original = destination(data.original, domains, [new URL(origin).hostname, ownHost]);
  const custom = data.shortened !== undefined && data.shortened !== "";
  if (custom) alias(data.shortened);
  for (let attempt = 0; attempt < 5; attempt++) {
    const slug = custom ? data.shortened : randomAlias();
    const result = await env.DB.prepare("INSERT INTO links (slug, original, created_at) VALUES (?, ?, ?) ON CONFLICT(slug) DO NOTHING")
      .bind(slug, original, Math.floor(Date.now() / 1000)).run();
    if (result.meta.changes === 1) return { original, shortened: slug, short_url: `${origin}/${slug}` };
    if (custom) throw new ValidationError("That short name is already taken. Choose another.", 409, "shortened");
  }
  throw new Error("Unable to allocate a short name.");
}
async function route(request, env) {
  const url = new URL(request.url);
  const domains = approvedDomains(env.APPROVED_DOMAINS === undefined ? inventory : env.APPROVED_DOMAINS);
  const origin = env.PUBLIC_ORIGIN || url.origin;
  const method = request.method;
  if (url.pathname === "/" && ["GET", "HEAD"].includes(method)) return page();
  if (url.pathname === "/api/config" && ["GET", "HEAD"].includes(method)) {
    return reply({ approved_domains: domains, include_subdomains: true, short_origin: origin });
  }
  if (url.pathname === "/.well-known/health" && ["GET", "HEAD"].includes(method)) {
    await env.DB.prepare("SELECT slug FROM links LIMIT 1").first();
    return reply({ status: "ok", release: env.DEPLOYMENT_SHA || "initial", approved_domains_count: domains.length });
  }
  if (url.pathname.startsWith("/assets/") && ["GET", "HEAD"].includes(method)) {
    const asset = assets[url.pathname];
    return asset ? reply(decode(asset.data), 200, asset.type, { "Cache-Control": "public, max-age=31536000, immutable" }) : reply({ error: "Asset not found." }, 404);
  }
  if (["/", "/api/links"].includes(url.pathname) && method === "POST") {
    const data = await payload(request);
    try {
      const result = await create(data, env, domains, origin, url.hostname);
      return url.pathname === "/api/links" || request.headers.get("Accept")?.includes("application/json")
        ? reply(result, 201) : page({ result });
    } catch (error) {
      if (error instanceof ValidationError && url.pathname === "/" && !request.headers.get("Accept")?.includes("application/json")) {
        return page({ error: error.message, field: error.field, original: data.original, shortened: data.shortened }, error.status);
      }
      throw error;
    }
  }
  if (!["GET", "HEAD"].includes(method)) return reply({ error: "Method not allowed." }, 405, undefined, { Allow: "GET, HEAD, POST" });
  const match = /^\/([A-Za-z0-9_-]{1,63})$/.exec(url.pathname);
  if (!match) return reply({ error: "Short link not found." }, 404);
  const link = await env.DB.prepare("SELECT original FROM links WHERE slug = ?").bind(match[1]).first();
  if (!link) return reply({ error: "Short link not found." }, 404);
  // Enforce the current policy on redirects too, including links made before a policy change.
  const target = destination(link.original, domains, [new URL(origin).hostname, url.hostname]);
  return new Response(null, { status: 302, headers: { ...security, Location: target } });
}
export default {
  async fetch(request, env) {
    try {
      const result = await route(request, env);
      return request.method === "HEAD" ? new Response(null, result) : result;
    } catch (error) {
      if (error instanceof ValidationError) return reply({ error: error.message, field: error.field }, error.status);
      console.error("Shortener request failed.");
      return reply({ error: "The shortener is temporarily unavailable. Try again shortly." }, 503);
    }
  },
};
