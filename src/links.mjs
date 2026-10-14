import { destination, alias, ValidationError } from "./policy.mjs";

function randomAlias() {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
  const chars = [];
  // Rejection sampling avoids modulo bias in the generated names.
  while (chars.length < 8) for (const value of crypto.getRandomValues(new Uint8Array(12))) {
    if (value < 248 && chars.length < 8) chars.push(alphabet[value % 62]);
  }
  return chars.join("");
}

export async function createLink(data, env, settings, origin, ownHost) {
  const original = destination(data.original, settings.allowed, [new URL(origin).hostname, ownHost]);
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
