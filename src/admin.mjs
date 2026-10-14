import { ValidationError } from "./policy.mjs";
import { reply, render, payload, publicOrigin } from "./http.mjs";
import { loadSettings, saveSettings, defaultDomains } from "./settings.mjs";
import { authenticate, authMethods, adminToken, tokenMatches, sessionCookie, clearSessionCookie } from "./auth.mjs";
import { createLink } from "./links.mjs";
import { adminHtml } from "../generated/ui.mjs";

// same-origin referrers let browsers send a real Origin header on admin form posts.
const privateHeaders = { "Cache-Control": "private, no-store", "X-Robots-Tag": "noindex, nofollow, noarchive", "Referrer-Policy": "same-origin" };
const json = (body, status = 200, headers = {}) => reply(body, status, undefined, { ...privateHeaders, ...headers });
const page = (data, status = 200, headers = {}) => render(adminHtml, data, status, { ...privateHeaders, ...headers });
const redirect = (headers) => new Response(null, { status: 303, headers: { ...privateHeaders, Location: "/admin", ...headers } });

// Browser sessions rely on SameSite=Strict cookies; reject cross-site requests outright as well.
// Fetch metadata is authoritative where browsers send it; otherwise compare the Origin header.
function sameOrigin(request, url) {
  const site = request.headers.get("Sec-Fetch-Site");
  if (site) return ["same-origin", "none"].includes(site);
  const origin = request.headers.get("Origin");
  if (!origin) return true;
  try { return new URL(origin).host === url.host; } catch { return false; }
}

async function overview(env, url, identity) {
  const settings = await loadSettings(env);
  let defaults = null;
  try { defaults = defaultDomains(env); } catch { /* Shown as unavailable; saved domains still apply. */ }
  const stats = await env.DB.prepare(`SELECT COUNT(*) AS links, COALESCE(SUM(clicks), 0) AS clicks, COALESCE(SUM(disabled), 0) AS disabled,
    COALESCE(SUM(CASE WHEN created_at >= ? THEN 1 ELSE 0 END), 0) AS recent FROM links`).bind(Math.floor(Date.now() / 1000) - 7 * 86400).first();
  return {
    identity, auth: authMethods(env), short_origin: publicOrigin(env, url),
    settings: { domain_policy: settings.domain_policy, link_creation: settings.link_creation, approved_domains: settings.approved_domains,
      domains_customized: settings.domains_customized, default_domains: defaults },
    stats: { links: Number(stats.links), clicks: Number(stats.clicks), disabled: Number(stats.disabled), created_7d: Number(stats.recent) },
  };
}

async function listLinks(env, url) {
  const search = (url.searchParams.get("q") || "").trim().slice(0, 200);
  const limit = Math.min(Math.max(Number.parseInt(url.searchParams.get("limit"), 10) || 25, 1), 100);
  const offset = Math.min(Math.max(Number.parseInt(url.searchParams.get("offset"), 10) || 0, 0), 1_000_000);
  const pattern = `%${search.replace(/[\\%_]/g, (char) => `\\${char}`)}%`;
  const where = search ? "WHERE slug LIKE ?1 ESCAPE '\\' OR original LIKE ?1 ESCAPE '\\'" : "";
  const bind = (statement) => search ? statement.bind(pattern) : statement;
  const total = await bind(env.DB.prepare(`SELECT COUNT(*) AS total FROM links ${where}`)).first();
  const { results } = await bind(env.DB.prepare(`SELECT slug, original, created_at, clicks, last_clicked_at, disabled FROM links ${where}
    ORDER BY created_at DESC, slug LIMIT ${limit} OFFSET ${offset}`)).all();
  return { total: Number(total.total), limit, offset,
    links: results.map((link) => ({ ...link, clicks: Number(link.clicks), disabled: Boolean(link.disabled) })) };
}

async function api(request, env, url, identity) {
  const method = request.method;
  const path = url.pathname.slice("/admin/api".length);
  if (path === "/overview" && method === "GET") return json(await overview(env, url, identity));
  if (path === "/settings" && method === "PUT") {
    await saveSettings(env, await payload(request, 65536, { json: true }));
    return json((await overview(env, url, identity)).settings);
  }
  if (path === "/links" && method === "GET") return json(await listLinks(env, url));
  if (path === "/links" && method === "POST") {
    const settings = await loadSettings(env);
    return json(await createLink(await payload(request, 8192, { json: true }), env, settings, publicOrigin(env, url), url.hostname), 201);
  }
  const match = /^\/links\/([A-Za-z0-9_-]{1,63})$/.exec(path);
  if (match && method === "PATCH") {
    const data = await payload(request, 1024, { json: true });
    if (typeof data.disabled !== "boolean") throw new ValidationError("Set disabled to true or false.", 400, "disabled");
    const result = await env.DB.prepare("UPDATE links SET disabled = ? WHERE slug = ?").bind(data.disabled ? 1 : 0, match[1]).run();
    return result.meta.changes ? json({ shortened: match[1], disabled: data.disabled }) : json({ error: "Short link not found." }, 404);
  }
  if (match && method === "DELETE") {
    const result = await env.DB.prepare("DELETE FROM links WHERE slug = ?").bind(match[1]).run();
    return result.meta.changes ? json({ deleted: match[1] }) : json({ error: "Short link not found." }, 404);
  }
  return json({ error: "Not found." }, 404);
}

export async function adminResponse(request, env, url) {
  if (url.pathname !== "/admin" && !url.pathname.startsWith("/admin/")) return null;
  const method = request.method;
  const secure = publicOrigin(env, url).startsWith("https:");
  if (url.pathname === "/admin/login" && method === "POST") {
    if (!sameOrigin(request, url)) return json({ error: "Cross-site sign-in is not allowed." }, 403);
    if (!adminToken(env)) return page({ view: "login", auth: authMethods(env), error: "Token sign-in is not enabled on this deployment." }, 403);
    const data = await payload(request, 4096);
    if (!await tokenMatches(env, typeof data.token === "string" ? data.token.trim() : "")) {
      return page({ view: "login", auth: authMethods(env), error: "That admin token is not valid." }, 401);
    }
    return redirect({ "Set-Cookie": await sessionCookie(env, secure) });
  }
  if (url.pathname === "/admin/logout" && method === "POST") {
    if (!sameOrigin(request, url)) return json({ error: "Cross-site sign-out is not allowed." }, 403);
    return redirect({ "Set-Cookie": clearSessionCookie(secure) });
  }
  // Authenticate every other admin path before reading storage.
  const identity = await authenticate(request, env);
  if (url.pathname === "/admin" && ["GET", "HEAD"].includes(method)) {
    return identity ? page({ view: "dashboard", identity }) : page({ view: "login", auth: authMethods(env) });
  }
  if (!url.pathname.startsWith("/admin/api/")) return json({ error: "Not found." }, 404);
  if (!identity) return json({ error: "Admin sign-in is required." }, 401);
  if (!["GET", "HEAD"].includes(method) && identity.method === "session" && !sameOrigin(request, url)) {
    return json({ error: "Cross-site requests are not allowed." }, 403);
  }
  return api(request, env, url, identity);
}
