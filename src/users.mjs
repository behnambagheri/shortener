import { hmac, same, hex } from "./auth.mjs";
import { cookie, publicOrigin, sameOrigin, reply } from "./http.mjs";
import { setting } from "./limits.mjs";
import { timedFetch } from "./screening.mjs";

// Optional visitor sign-in with GitHub or Google, so links to any domain can be tied to an account.
const userCookie = "shortener_user";
const stateCookie = "shortener_oauth";
const sessionSeconds = 30 * 24 * 60 * 60;
const encoder = new TextEncoder();

const providers = {
  github: {
    authorize: "https://github.com/login/oauth/authorize", scope: "read:user",
    async identify(code, redirect, env) {
      const token = await (await timedFetch("https://github.com/login/oauth/access_token", {
        method: "POST", headers: { Accept: "application/json", "Content-Type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams({ client_id: env.GITHUB_CLIENT_ID, client_secret: env.GITHUB_CLIENT_SECRET, code, redirect_uri: redirect }),
      })).json();
      if (!token.access_token) throw new Error("GitHub did not return an access token.");
      const user = await (await timedFetch("https://api.github.com/user", {
        headers: { Authorization: `Bearer ${token.access_token}`, Accept: "application/vnd.github+json", "User-Agent": "bea-shortener" },
      })).json();
      if (!Number.isInteger(user.id) || typeof user.login !== "string") throw new Error("GitHub did not return a user.");
      return { id: `github:${user.id}`, name: user.login, since: Date.parse(user.created_at) };
    },
  },
  google: {
    authorize: "https://accounts.google.com/o/oauth2/v2/auth", scope: "openid email",
    async identify(code, redirect, env) {
      const token = await (await timedFetch("https://oauth2.googleapis.com/token", {
        method: "POST", headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams({ client_id: env.GOOGLE_CLIENT_ID, client_secret: env.GOOGLE_CLIENT_SECRET, code, redirect_uri: redirect, grant_type: "authorization_code" }),
      })).json();
      if (!token.access_token) throw new Error("Google did not return an access token.");
      const user = await (await timedFetch("https://openidconnect.googleapis.com/v1/userinfo", { headers: { Authorization: `Bearer ${token.access_token}` } })).json();
      if (typeof user.sub !== "string" || typeof user.email !== "string" || user.email_verified !== true) throw new Error("Google did not return a verified email.");
      return { id: `google:${user.sub}`, name: user.email.toLowerCase(), since: null };
    },
  },
};

function secret(env) {
  return typeof env.SESSION_SECRET === "string" && env.SESSION_SECRET.length >= 32 ? env.SESSION_SECRET : null;
}

export function signInProviders(env) {
  if (!secret(env)) return [];
  return Object.keys(providers).filter((name) => env[`${name.toUpperCase()}_CLIENT_ID`] && env[`${name.toUpperCase()}_CLIENT_SECRET`]);
}

const base64url = (text) => btoa(String.fromCharCode(...encoder.encode(text))).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
const unbase64url = (value) => new TextDecoder().decode(Uint8Array.from(atob(value.replace(/-/g, "+").replace(/_/g, "/")), (char) => char.charCodeAt(0)));

async function sign(env, value) { return hex(await hmac(secret(env), `user:v1:${value}`)); }

const cookieFlags = (secure) => `Path=/; HttpOnly; SameSite=Lax${secure ? "; Secure" : ""}`;

export async function userSessionCookie(env, id, secure, now = Date.now()) {
  const value = `${base64url(id)}.${Math.floor(now / 1000) + sessionSeconds}`;
  return `${userCookie}=${value}.${await sign(env, value)}; Max-Age=${sessionSeconds}; ${cookieFlags(secure)}`;
}

// The signed-in, not banned visitor, or null.
export async function currentUser(request, env, now = Date.now()) {
  if (!secret(env)) return null;
  const match = /^([A-Za-z0-9_-]{1,200})\.(\d{1,12})\.([0-9a-f]{64})$/.exec(cookie(request, userCookie) || "");
  if (!match || Number(match[2]) * 1000 <= now) return null;
  if (!same(encoder.encode(await sign(env, `${match[1]}.${match[2]}`)), encoder.encode(match[3]))) return null;
  let id;
  try { id = unbase64url(match[1]); } catch { return null; }
  const user = await env.DB.prepare("SELECT id, name, banned FROM users WHERE id = ?").bind(id).first();
  return user && !user.banned ? { id: user.id, name: user.name } : null;
}

const redirect = (location, cookies = []) => {
  const headers = new Headers({ Location: location, "Cache-Control": "no-store", "Referrer-Policy": "no-referrer" });
  for (const value of cookies) headers.append("Set-Cookie", value);
  return new Response(null, { status: 303, headers });
};

// Handles /auth/<provider>, /auth/<provider>/callback and /auth/logout. Errors return to the home page.
export async function authResponse(request, env, url, onError) {
  if (!url.pathname.startsWith("/auth/")) return null;
  const origin = publicOrigin(env, url);
  const secure = origin.startsWith("https:");
  if (url.pathname === "/auth/logout" && request.method === "POST") {
    if (!sameOrigin(request, url)) return reply({ error: "Cross-site sign-out is not allowed." }, 403);
    return redirect("/", [`${userCookie}=; Max-Age=0; ${cookieFlags(secure)}`]);
  }
  const match = /^\/auth\/(github|google)(\/callback)?$/.exec(url.pathname);
  if (!match || request.method !== "GET") return reply({ error: "Not found." }, 404);
  const [, name, callback] = match;
  if (!signInProviders(env).includes(name)) return onError("That sign-in method is not enabled.", 404);
  const provider = providers[name];
  const redirectUri = `${origin}/auth/${name}/callback`;
  const clearState = `${stateCookie}=; Max-Age=0; Path=/auth; HttpOnly; SameSite=Lax${secure ? "; Secure" : ""}`;
  if (!callback) {
    const state = hex(crypto.getRandomValues(new Uint8Array(16)));
    const target = new URL(provider.authorize);
    target.search = new URLSearchParams({ client_id: env[`${name.toUpperCase()}_CLIENT_ID`], redirect_uri: redirectUri, scope: provider.scope, state,
      ...(name === "google" ? { response_type: "code", prompt: "select_account" } : { allow_signup: "false" }) }).toString();
    return redirect(target.href, [`${stateCookie}=${state}; Max-Age=600; Path=/auth; HttpOnly; SameSite=Lax${secure ? "; Secure" : ""}`]);
  }
  const state = url.searchParams.get("state") || "";
  const expected = cookie(request, stateCookie) || "";
  const code = url.searchParams.get("code");
  if (!code || !/^[0-9a-f]{32}$/.test(expected) || !same(encoder.encode(state), encoder.encode(expected))) {
    return onError("Sign-in could not be completed. Try again.", 400, [clearState]);
  }
  let identity;
  try { identity = await provider.identify(code, redirectUri, env); }
  catch { return onError("Sign-in could not be completed. Try again.", 502, [clearState]); }
  // Fresh throwaway accounts are the cheapest way around per-account limits.
  const minimum = setting(env, "MIN_ACCOUNT_DAYS", 30);
  if (minimum && identity.since && Date.now() - identity.since < minimum * 86400000) {
    return onError(`Accounts younger than ${minimum} days cannot sign in here yet.`, 403, [clearState]);
  }
  const now = Math.floor(Date.now() / 1000);
  const user = await env.DB.prepare(`INSERT INTO users (id, name, created_at) VALUES (?, ?, ?)
    ON CONFLICT(id) DO UPDATE SET name = excluded.name RETURNING banned`).bind(identity.id, identity.name, now).first();
  if (user.banned) return onError("This account can no longer create short links.", 403, [clearState]);
  return redirect("/", [clearState, await userSessionCookie(env, identity.id, secure)]);
}
