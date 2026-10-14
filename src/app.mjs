import { destination, onDomains, ValidationError } from "./policy.mjs";
import { createLink } from "./links.mjs";
import { security, reply, render, decode, payload, publicOrigin, fill } from "./http.mjs";
import { loadSettings, allowedFor } from "./settings.mjs";
import { authenticate } from "./auth.mjs";
import { adminResponse } from "./admin.mjs";
import { authResponse, currentUser, signInProviders } from "./users.mjs";
import { reportLink } from "./abuse.mjs";
import { setting } from "./limits.mjs";
import { html, interstitialHtml, assets, icons } from "../generated/ui.mjs";

function interstitial(env, slug, origin, target, { reported = false, status = 200 } = {}) {
  const abuse = env.ABUSE_EMAIL || "";
  const page = fill(interstitialHtml, {
    short: `${origin.replace(/^https?:\/\//, "")}/${slug}`, slug, host: new URL(target).hostname, target,
    reported_class: reported ? "" : "hidden", report_class: reported ? "hidden" : "", abuse_email: abuse, abuse_class: abuse ? "" : "hidden",
  });
  return reply(page, status, "text/html; charset=utf-8", { "X-Robots-Tag": "noindex, nofollow" });
}

async function route(request, env, ctx, meta) {
  const url = new URL(request.url);
  const origin = publicOrigin(env, url);
  const method = request.method;
  const { host: shortHost, hostname } = new URL(origin);
  // Example destinations use the parent domain of the short host: s.example.com suggests example.com.
  const labels = hostname.split(".");
  const exampleHost = labels.length > 2 && !/^[\d.]+$/.test(hostname) ? labels.slice(1).join(".") : "example.com";
  const home = html.replaceAll("__ORIGIN__", origin).replaceAll("__SHORT_HOST__", shortHost).replaceAll("__EXAMPLE_HOST__", exampleHost);
  const admin = await adminResponse(request, env, url);
  if (admin) return admin;
  const auth = await authResponse(request, env, url, (error, status, cookies = []) =>
    render(home, { error, field: "form" }, status, cookies.length ? { "Set-Cookie": cookies[0] } : {}));
  if (auth) return auth;
  if (url.pathname.startsWith("/assets/") && ["GET", "HEAD"].includes(method)) {
    const asset = assets[url.pathname];
    return asset ? reply(decode(asset.data), 200, asset.type, { "Cache-Control": "public, max-age=31536000, immutable" }) : reply({ error: "Asset not found." }, 404);
  }
  if (url.pathname === "/" && ["GET", "HEAD"].includes(method)) return render(home);
  if (icons[url.pathname] && ["GET", "HEAD"].includes(method)) {
    const icon = icons[url.pathname];
    return reply(decode(icon.data), 200, icon.type, { "Cache-Control": "public, max-age=86400" });
  }
  if (url.pathname === "/robots.txt" && ["GET", "HEAD"].includes(method)) {
    return reply(`User-agent: *\nDisallow: /api/\nDisallow: /auth/\n\nSitemap: ${origin}/sitemap.xml\n`, 200, "text/plain; charset=utf-8",
      { "Cache-Control": "public, max-age=86400" });
  }
  if (url.pathname === "/sitemap.xml" && ["GET", "HEAD"].includes(method)) {
    return reply(`<?xml version="1.0" encoding="UTF-8"?>\n<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9"><url><loc>${origin}/</loc></url></urlset>\n`,
      200, "application/xml; charset=utf-8", { "Cache-Control": "public, max-age=86400" });
  }
  const settings = await loadSettings(env);
  if (url.pathname === "/api/config" && ["GET", "HEAD"].includes(method)) {
    const user = await currentUser(request, env);
    const anonymousDays = setting(env, "ANONYMOUS_LINK_DAYS", 30);
    return reply({ approved_domains: settings.approved_domains, domain_policy: settings.domain_policy, include_subdomains: true,
      any_domain: allowedFor(settings, user ? "user" : "public") === null, link_creation: settings.link_creation, short_origin: origin,
      turnstile_site_key: env.TURNSTILE_SECRET_KEY && env.TURNSTILE_SITE_KEY || null, sign_in: signInProviders(env),
      user: user ? { name: user.name } : null, link_days: user ? null : anonymousDays || null, abuse_email: env.ABUSE_EMAIL || null });
  }
  if (url.pathname === "/.well-known/health" && ["GET", "HEAD"].includes(method)) {
    await env.DB.prepare("SELECT slug FROM links LIMIT 1").first();
    return reply({ status: "ok", release: env.DEPLOYMENT_SHA || "initial", approved_domains_count: settings.approved_domains.length,
      domain_policy: settings.domain_policy });
  }
  if (["/", "/api/links"].includes(url.pathname) && method === "POST") {
    const form = url.pathname === "/" && !request.headers.get("Accept")?.includes("application/json");
    const data = await payload(request);
    try {
      // The bearer token or a Cloudflare Access identity makes the request an administrator's.
      const actor = await authenticate(request, env) ? { kind: "admin" }
        : await currentUser(request, env).then((user) => user ? { kind: "user", id: user.id, ip: meta.clientIp } : { kind: "public", ip: meta.clientIp });
      if (settings.link_creation === "admin" && actor.kind !== "admin") {
        throw new ValidationError("Link creation is limited to administrators.", 403, "form");
      }
      const result = await createLink(data, env, settings, origin, url.hostname, actor);
      return form ? render(home, { result }) : reply(result, 201);
    } catch (error) {
      if (error instanceof ValidationError && form) {
        return render(home, { error: error.message, field: error.field, original: data.original, shortened: data.shortened }, error.status);
      }
      throw error;
    }
  }
  if (url.pathname === "/api/reports" && method === "POST") {
    const form = !request.headers.get("Content-Type")?.includes("application/json");
    const data = await payload(request, 2048);
    const result = await reportLink(env, data, meta.clientIp, origin);
    ctx?.waitUntil?.(result.alert);
    if (!form) return reply({ slug: result.slug, reported: true }, 201);
    const link = await env.DB.prepare("SELECT original FROM links WHERE slug = ?").bind(result.slug).first();
    return interstitial(env, result.slug, origin, link.original, { reported: true });
  }
  if (!["GET", "HEAD"].includes(method)) return reply({ error: "Method not allowed." }, 405, undefined, { Allow: "GET, HEAD, POST" });
  const match = /^\/([A-Za-z0-9_-]{1,63})$/.exec(url.pathname);
  if (!match) return reply({ error: "Short link not found." }, 404);
  const link = await env.DB.prepare("SELECT original, disabled, source, expires_at FROM links WHERE slug = ?").bind(match[1]).first();
  if (!link) return reply({ error: "Short link not found." }, 404);
  if (link.disabled) return reply({ error: "This short link has been disabled." }, 410);
  if (link.expires_at && link.expires_at * 1000 <= Date.now()) return reply({ error: "This short link has expired." }, 410);
  // Enforce the current policy on redirects too, including links made before a policy change.
  const target = destination(link.original, allowedFor(settings, link.source), [new URL(origin).hostname, url.hostname]);
  if (method === "GET") {
    const count = env.DB.prepare("UPDATE links SET clicks = clicks + 1, last_clicked_at = ? WHERE slug = ?")
      .bind(Math.floor(Date.now() / 1000), match[1]).run().catch(() => {});
    ctx?.waitUntil?.(count);
  }
  // Only administrators' links and approved domains redirect directly; visitors' other links show where they lead first.
  if (link.source === "admin" || onDomains(new URL(target).hostname, settings.approved_domains)) {
    return new Response(null, { status: 302, headers: { ...security, Location: target } });
  }
  return interstitial(env, match[1], origin, target);
}

// `meta.clientIp` is the visitor address as established by the runtime, never a request header the client chose.
export async function handle(request, env, ctx, meta = {}) {
  try {
    const result = await route(request, env, ctx, meta);
    return request.method === "HEAD" ? new Response(null, result) : result;
  } catch (error) {
    if (error instanceof ValidationError) return reply({ error: error.message, field: error.field }, error.status);
    console.error("Shortener request failed.");
    return reply({ error: "The shortener is temporarily unavailable. Try again shortly." }, 503);
  }
}
