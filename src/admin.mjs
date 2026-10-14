import { ValidationError } from "./policy.mjs";
import { reply, render, payload, publicOrigin, sameOrigin } from "./http.mjs";
import { loadSettings, saveSettings, defaultDomains } from "./settings.mjs";
import { authenticate, authMethods, adminToken, tokenMatches, sessionCookie, clearSessionCookie } from "./auth.mjs";
import { createLink } from "./links.mjs";
import { signInProviders } from "./users.mjs";
import { alertsEnabled } from "./alerts.mjs";
import { newDomainDays } from "./screening.mjs";
import { setting } from "./limits.mjs";
import { adminHtml } from "../generated/ui.mjs";

// same-origin referrers let browsers send a real Origin header on admin form posts.
const privateHeaders = { "Cache-Control": "private, no-store", "X-Robots-Tag": "noindex, nofollow, noarchive", "Referrer-Policy": "same-origin" };
const json = (body, status = 200, headers = {}) => reply(body, status, undefined, { ...privateHeaders, ...headers });
const page = (data, status = 200, headers = {}) => render(adminHtml, data, status, { ...privateHeaders, ...headers });
const redirect = (headers) => new Response(null, { status: 303, headers: { ...privateHeaders, Location: "/admin", ...headers } });

// Which abuse protections this deployment has configured.
async function protection(env) {
  const feed = await env.DB.prepare("SELECT value FROM settings WHERE key = 'threat_feed'").first();
  return {
    turnstile: Boolean(env.TURNSTILE_SITE_KEY && env.TURNSTILE_SECRET_KEY), safe_browsing: Boolean(env.SAFE_BROWSING_API_KEY),
    urlhaus: Boolean(env.URLHAUS_AUTH_KEY), new_domain_days: newDomainDays(env), sign_in: signInProviders(env), alerts: alertsEnabled(env),
    abuse_email: env.ABUSE_EMAIL || null, threat_feed: feed ? JSON.parse(feed.value) : null,
    links_per_hour: setting(env, "LINKS_PER_HOUR", 10), user_links_per_day: setting(env, "USER_LINKS_PER_DAY", 50),
    anonymous_link_days: setting(env, "ANONYMOUS_LINK_DAYS", 30), report_threshold: setting(env, "REPORT_THRESHOLD", 3),
  };
}

async function overview(env, url, identity) {
  const settings = await loadSettings(env);
  let defaults = null;
  try { defaults = defaultDomains(env); } catch { /* Shown as unavailable; saved domains still apply. */ }
  const stats = await env.DB.prepare(`SELECT COUNT(*) AS links, COALESCE(SUM(clicks), 0) AS clicks, COALESCE(SUM(disabled), 0) AS disabled,
    COALESCE(SUM(CASE WHEN created_at >= ? THEN 1 ELSE 0 END), 0) AS recent,
    (SELECT COUNT(DISTINCT reports.slug) FROM reports JOIN links AS reported ON reported.slug = reports.slug WHERE reported.disabled = 0) AS reported
    FROM links`).bind(Math.floor(Date.now() / 1000) - 7 * 86400).first();
  return {
    identity, auth: authMethods(env), short_origin: publicOrigin(env, url), protection: await protection(env),
    settings: { domain_policy: settings.domain_policy, link_creation: settings.link_creation, approved_domains: settings.approved_domains,
      domains_customized: settings.domains_customized, default_domains: defaults },
    stats: { links: Number(stats.links), clicks: Number(stats.clicks), disabled: Number(stats.disabled), created_7d: Number(stats.recent),
      reported: Number(stats.reported) },
  };
}

const filters = {
  all: "", reported: "EXISTS (SELECT 1 FROM reports WHERE reports.slug = links.slug)", visitors: "links.source != 'admin'",
  disabled: "links.disabled = 1",
};

async function listLinks(env, url) {
  const search = (url.searchParams.get("q") || "").trim().slice(0, 200);
  const filter = filters[url.searchParams.get("filter")] ?? "";
  const limit = Math.min(Math.max(Number.parseInt(url.searchParams.get("limit"), 10) || 25, 1), 100);
  const offset = Math.min(Math.max(Number.parseInt(url.searchParams.get("offset"), 10) || 0, 0), 1_000_000);
  const pattern = `%${search.replace(/[\\%_]/g, (char) => `\\${char}`)}%`;
  const conditions = [search && "(links.slug LIKE ?1 ESCAPE '\\' OR links.original LIKE ?1 ESCAPE '\\')", filter].filter(Boolean);
  const where = conditions.length ? `WHERE ${conditions.join(" AND ")}` : "";
  const bind = (statement) => search ? statement.bind(pattern) : statement;
  const total = await bind(env.DB.prepare(`SELECT COUNT(*) AS total FROM links ${where}`)).first();
  const { results } = await bind(env.DB.prepare(`SELECT links.slug, links.original, links.created_at, links.clicks, links.last_clicked_at,
    links.disabled, links.disabled_reason, links.source, links.creator, links.expires_at, users.name AS creator_name, users.banned AS creator_banned,
    (SELECT COUNT(*) FROM reports WHERE reports.slug = links.slug) AS reports
    FROM links LEFT JOIN users ON users.id = links.creator ${where}
    ORDER BY links.created_at DESC, links.slug LIMIT ${limit} OFFSET ${offset}`)).all();
  return { total: Number(total.total), limit, offset,
    links: results.map((link) => ({ ...link, clicks: Number(link.clicks), reports: Number(link.reports), disabled: Boolean(link.disabled),
      creator_banned: Boolean(link.creator_banned) })) };
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
    return json(await createLink(await payload(request, 8192, { json: true }), env, settings, publicOrigin(env, url), url.hostname, { kind: "admin" }), 201);
  }
  const match = /^\/links\/([A-Za-z0-9_-]{1,63})$/.exec(path);
  if (match && method === "PATCH") {
    const data = await payload(request, 1024, { json: true });
    if (typeof data.disabled !== "boolean") throw new ValidationError("Set disabled to true or false.", 400, "disabled");
    // Re-enabling clears earlier reports, so the same reports do not disable the link again.
    const writes = [env.DB.prepare("UPDATE links SET disabled = ?, disabled_reason = ? WHERE slug = ?").bind(data.disabled ? 1 : 0, data.disabled ? "admin" : null, match[1])];
    if (!data.disabled) writes.push(env.DB.prepare("DELETE FROM reports WHERE slug = ?").bind(match[1]));
    const [result] = await env.DB.batch(writes);
    return result.meta.changes ? json({ shortened: match[1], disabled: data.disabled }) : json({ error: "Short link not found." }, 404);
  }
  if (match && method === "DELETE") {
    const [result] = await env.DB.batch([env.DB.prepare("DELETE FROM links WHERE slug = ?").bind(match[1]), env.DB.prepare("DELETE FROM reports WHERE slug = ?").bind(match[1])]);
    return result.meta.changes ? json({ deleted: match[1] }) : json({ error: "Short link not found." }, 404);
  }
  const user = /^\/users\/((?:github|google)(?::|%3A)[A-Za-z0-9._-]{1,200})$/i.exec(path);
  if (user && method === "PATCH") {
    const data = await payload(request, 1024, { json: true });
    if (typeof data.banned !== "boolean") throw new ValidationError("Set banned to true or false.", 400, "banned");
    // Banning also disables every link the account created; unbanning leaves them disabled for review.
    const id = user[1].replace(/%3A/i, ":");
    const writes = [env.DB.prepare("UPDATE users SET banned = ? WHERE id = ?").bind(data.banned ? 1 : 0, id)];
    if (data.banned) writes.push(env.DB.prepare("UPDATE links SET disabled = 1, disabled_reason = 'banned' WHERE creator = ? AND disabled = 0").bind(id));
    const [result, links] = await env.DB.batch(writes);
    return result.meta.changes ? json({ user: id, banned: data.banned, disabled_links: links?.meta.changes ?? 0 }) : json({ error: "User not found." }, 404);
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
