import { createRemoteJWKSet, jwtVerify } from "jose";
import { cookie } from "./http.mjs";

export const sessionCookieName = "shortener_admin";
const sessionSeconds = 12 * 60 * 60;
const encoder = new TextEncoder();
const keySets = new Map();

// Tokens shorter than 16 characters disable token sign-in rather than weakening it.
export function adminToken(env) {
  const token = env.ADMIN_TOKEN;
  return typeof token === "string" && token.length >= 16 ? token : null;
}

function accessConfig(env) {
  const issuer = (env.ACCESS_ISSUER || "").replace(/\/+$/, "");
  const audience = env.ACCESS_AUD;
  const emails = (env.ADMIN_EMAILS || "").split(",").map((email) => email.trim().toLowerCase()).filter(Boolean);
  if (!/^https:\/\/[a-z0-9-]+\.cloudflareaccess\.com$/.test(issuer) || !audience || !emails.length) return null;
  return { issuer, audience, emails };
}

export function authMethods(env) {
  return { token: Boolean(adminToken(env)), access: Boolean(accessConfig(env)) };
}

export async function hmac(secret, message) {
  const key = await crypto.subtle.importKey("raw", encoder.encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  return new Uint8Array(await crypto.subtle.sign("HMAC", key, encoder.encode(message)));
}
export function same(a, b) {
  if (a.length !== b.length) return false;
  let difference = 0;
  for (let index = 0; index < a.length; index++) difference |= a[index] ^ b[index];
  return difference === 0;
}
export const hex = (bytes) => Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");

export async function tokenMatches(env, candidate) {
  const token = adminToken(env);
  if (!token || typeof candidate !== "string" || !candidate || candidate.length > 1024) return false;
  // Compare fixed-length digests so timing does not depend on the token contents.
  return same(await hmac("shortener-admin-token", token), await hmac("shortener-admin-token", candidate));
}

// Sessions are signed with a key derived from the token, so rotating ADMIN_TOKEN signs everyone out.
export async function sessionCookie(env, secure, now = Date.now()) {
  const expires = Math.floor(now / 1000) + sessionSeconds;
  const signature = hex(await hmac(adminToken(env), `session:v1:${expires}`));
  return `${sessionCookieName}=${expires}.${signature}; Path=/admin; Max-Age=${sessionSeconds}; HttpOnly; SameSite=Strict${secure ? "; Secure" : ""}`;
}
export function clearSessionCookie(secure) {
  return `${sessionCookieName}=; Path=/admin; Max-Age=0; HttpOnly; SameSite=Strict${secure ? "; Secure" : ""}`;
}

async function validSession(request, env, now) {
  const token = adminToken(env);
  const match = /^(\d{1,12})\.([0-9a-f]{64})$/.exec(cookie(request, sessionCookieName) || "");
  if (!token || !match) return false;
  const expires = Number(match[1]);
  if (expires * 1000 <= now || expires * 1000 > now + (sessionSeconds + 60) * 1000) return false;
  return same(encoder.encode(hex(await hmac(token, `session:v1:${expires}`))), encoder.encode(match[2]));
}

export async function accessEmail(request, env, { keySet, now = new Date() } = {}) {
  const config = accessConfig(env);
  const token = request.headers.get("Cf-Access-Jwt-Assertion");
  // Missing configuration, provider errors and forged identity headers all fail closed.
  if (!config || !token || token.length > 16384) return null;
  try {
    if (!keySet) {
      if (!keySets.has(config.issuer)) {
        if (keySets.size >= 4) keySets.clear();
        keySets.set(config.issuer, createRemoteJWKSet(new URL(`${config.issuer}/cdn-cgi/access/certs`), { timeoutDuration: 5000 }));
      }
      keySet = keySets.get(config.issuer);
    }
    const { payload } = await jwtVerify(token, keySet, { issuer: config.issuer, audience: config.audience, algorithms: ["RS256"],
      requiredClaims: ["exp", "iat", "sub", "email"], currentDate: now });
    const email = typeof payload.email === "string" ? payload.email.toLowerCase() : "";
    return config.emails.includes(email) ? email : null;
  } catch { return null; }
}

// Returns how the request authenticated, or null. Bearer tokens suit scripts; cookies suit browsers.
export async function authenticate(request, env, { keySet, now = Date.now() } = {}) {
  const bearer = /^Bearer\s+(\S+)$/i.exec(request.headers.get("Authorization") || "");
  if (bearer && await tokenMatches(env, bearer[1])) return { method: "token" };
  if (await validSession(request, env, now)) return { method: "session" };
  const email = await accessEmail(request, env, { keySet, now: new Date(now) });
  return email ? { method: "access", email } : null;
}
