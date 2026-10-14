const encoder = new TextEncoder();

export function setting(env, name, fallback) {
  const value = Number.parseInt(env[name] ?? "", 10);
  return Number.isFinite(value) && value >= 0 ? value : fallback;
}

// IPv6 clients usually control a whole /64, so they share one bucket.
export function ipBucket(ip) {
  if (typeof ip !== "string" || !ip) return "unknown";
  if (!ip.includes(":")) return ip;
  const [head, tail = ""] = ip.toLowerCase().replace(/^\[|\]$/g, "").split("::");
  const left = head ? head.split(":") : [];
  const right = tail ? tail.split(":") : [];
  const groups = [...left, ...Array(Math.max(0, 8 - left.length - right.length)).fill("0"), ...right];
  return `${groups.slice(0, 4).map((group) => group.padStart(4, "0")).join(":")}::/64`;
}

// Stores a keyed hash rather than the address itself.
export async function clientKey(env, ip) {
  const secret = env.SESSION_SECRET || env.ADMIN_TOKEN || "bea-shortener";
  const key = await crypto.subtle.importKey("raw", encoder.encode(`client-key:${secret}`), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const digest = new Uint8Array(await crypto.subtle.sign("HMAC", key, encoder.encode(ipBucket(ip))));
  return Array.from(digest.slice(0, 16), (byte) => byte.toString(16).padStart(2, "0")).join("");
}

// Fixed-window counter. Returns false once `limit` uses of `key` fall in the current window; 0 disables the limit.
export async function consume(env, key, windowSeconds, limit, now = Date.now()) {
  if (!limit) return true;
  const start = Math.floor(now / 1000 / windowSeconds) * windowSeconds;
  const row = await env.DB.prepare(`INSERT INTO rate_limits (key, window_start, count) VALUES (?, ?, 1)
    ON CONFLICT(key) DO UPDATE SET count = CASE WHEN rate_limits.window_start = excluded.window_start THEN rate_limits.count + 1 ELSE 1 END,
    window_start = excluded.window_start RETURNING count`).bind(key, start).first();
  return Number(row.count) <= limit;
}
