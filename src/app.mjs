import { destination, ValidationError } from "./policy.mjs";
import { createLink } from "./links.mjs";
import { security, reply, render, decode, payload, publicOrigin } from "./http.mjs";
import { loadSettings } from "./settings.mjs";
import { authenticate } from "./auth.mjs";
import { adminResponse } from "./admin.mjs";
import { html, assets } from "../generated/ui.mjs";

async function route(request, env, ctx) {
  const url = new URL(request.url);
  const origin = publicOrigin(env, url);
  const method = request.method;
  const admin = await adminResponse(request, env, url);
  if (admin) return admin;
  if (url.pathname.startsWith("/assets/") && ["GET", "HEAD"].includes(method)) {
    const asset = assets[url.pathname];
    return asset ? reply(decode(asset.data), 200, asset.type, { "Cache-Control": "public, max-age=31536000, immutable" }) : reply({ error: "Asset not found." }, 404);
  }
  if (url.pathname === "/" && ["GET", "HEAD"].includes(method)) return render(html);
  const settings = await loadSettings(env);
  if (url.pathname === "/api/config" && ["GET", "HEAD"].includes(method)) {
    return reply({ approved_domains: settings.allowed || [], domain_policy: settings.domain_policy, include_subdomains: true,
      link_creation: settings.link_creation, short_origin: origin });
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
      // Admin-only creation accepts a bearer token or Cloudflare Access identity on the public API.
      if (settings.link_creation === "admin" && !await authenticate(request, env)) {
        throw new ValidationError("Link creation is limited to administrators.", 403, "form");
      }
      const result = await createLink(data, env, settings, origin, url.hostname);
      return form ? render(html, { result }) : reply(result, 201);
    } catch (error) {
      if (error instanceof ValidationError && form) {
        return render(html, { error: error.message, field: error.field, original: data.original, shortened: data.shortened }, error.status);
      }
      throw error;
    }
  }
  if (!["GET", "HEAD"].includes(method)) return reply({ error: "Method not allowed." }, 405, undefined, { Allow: "GET, HEAD, POST" });
  const match = /^\/([A-Za-z0-9_-]{1,63})$/.exec(url.pathname);
  if (!match) return reply({ error: "Short link not found." }, 404);
  const link = await env.DB.prepare("SELECT original, disabled FROM links WHERE slug = ?").bind(match[1]).first();
  if (!link) return reply({ error: "Short link not found." }, 404);
  if (link.disabled) return reply({ error: "This short link has been disabled." }, 410);
  // Enforce the current policy on redirects too, including links made before a policy change.
  const target = destination(link.original, settings.allowed, [new URL(origin).hostname, url.hostname]);
  if (method === "GET") {
    const count = env.DB.prepare("UPDATE links SET clicks = clicks + 1, last_clicked_at = ? WHERE slug = ?")
      .bind(Math.floor(Date.now() / 1000), match[1]).run().catch(() => {});
    ctx?.waitUntil?.(count);
  }
  return new Response(null, { status: 302, headers: { ...security, Location: target } });
}

export async function handle(request, env, ctx) {
  try {
    const result = await route(request, env, ctx);
    return request.method === "HEAD" ? new Response(null, result) : result;
  } catch (error) {
    if (error instanceof ValidationError) return reply({ error: error.message, field: error.field }, error.status);
    console.error("Shortener request failed.");
    return reply({ error: "The shortener is temporarily unavailable. Try again shortly." }, 503);
  }
}
