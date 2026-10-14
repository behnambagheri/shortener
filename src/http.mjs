import { ValidationError } from "./policy.mjs";

export const security = {
  "Cache-Control": "no-store", "X-Content-Type-Options": "nosniff", "Referrer-Policy": "no-referrer",
  "Content-Security-Policy": "default-src 'self'; script-src 'self'; style-src 'self'; font-src 'self'; img-src 'self' data:; connect-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'",
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
