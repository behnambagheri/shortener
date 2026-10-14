import { destination, alias, onDomains, ValidationError } from "./policy.mjs";
import { allowedFor } from "./settings.mjs";
import { clientKey, consume, setting } from "./limits.mjs";
import { screenDestination, verifyTurnstile, ScreeningError } from "./screening.mjs";

function randomAlias() {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
  const chars = [];
  // Rejection sampling avoids modulo bias in the generated names.
  while (chars.length < 8) for (const value of crypto.getRandomValues(new Uint8Array(12))) {
    if (value < 248 && chars.length < 8) chars.push(alphabet[value % 62]);
  }
  return chars.join("");
}

// `actor` is { kind: "admin" }, { kind: "user", id, ip } or { kind: "public", ip }.
// Visitors' links to domains outside the approved list pass Turnstile and destination screening first.
export async function createLink(data, env, settings, origin, ownHost, actor) {
  const original = destination(data.original, allowedFor(settings, actor.kind), [new URL(origin).hostname, ownHost]);
  const custom = data.shortened !== undefined && data.shortened !== "";
  if (custom) alias(data.shortened);
  const now = Math.floor(Date.now() / 1000);
  let creatorIp = null;
  if (actor.kind !== "admin") {
    creatorIp = await clientKey(env, actor.ip);
    const allowed = actor.kind === "user"
      ? await consume(env, `create:user:${actor.id}`, 86400, setting(env, "USER_LINKS_PER_DAY", 50))
      : await consume(env, `create:ip:${creatorIp}`, 3600, setting(env, "LINKS_PER_HOUR", 10));
    if (!allowed) throw new ValidationError(actor.kind === "user" ? "You have reached today's link limit. Try again tomorrow." : "Too many links from your network. Try again in an hour.", 429, "form");
    if (!onDomains(new URL(original).hostname, settings.approved_domains)) {
      if (!await verifyTurnstile(env, data.turnstile ?? data["cf-turnstile-response"], actor.ip)) {
        throw new ValidationError("Complete the verification check, then try again.", 403, "form");
      }
      try { await screenDestination(env, original); }
      catch (error) { throw error instanceof ScreeningError ? new ValidationError(error.message, 403) : error; }
    }
  }
  const days = setting(env, "ANONYMOUS_LINK_DAYS", 30);
  const expires = actor.kind === "public" && days ? now + days * 86400 : null;
  for (let attempt = 0; attempt < 5; attempt++) {
    const slug = custom ? data.shortened : randomAlias();
    const result = await env.DB.prepare(`INSERT INTO links (slug, original, created_at, source, creator, creator_ip, expires_at)
      VALUES (?, ?, ?, ?, ?, ?, ?) ON CONFLICT(slug) DO NOTHING`)
      .bind(slug, original, now, actor.kind, actor.id ?? null, creatorIp, expires).run();
    if (result.meta.changes === 1) return { original, shortened: slug, short_url: `${origin}/${slug}`, expires_at: expires };
    if (custom) throw new ValidationError("That short name is already taken. Choose another.", 409, "shortened");
  }
  throw new Error("Unable to allocate a short name.");
}
