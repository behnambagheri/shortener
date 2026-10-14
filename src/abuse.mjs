import { ValidationError, onDomains } from "./policy.mjs";
import { loadSettings } from "./settings.mjs";
import { clientKey, consume, setting } from "./limits.mjs";
import { feedKey, feedMatcher, safeBrowsing, timedFetch } from "./screening.mjs";
import { notify } from "./alerts.mjs";

export const reportReasons = ["phishing", "malware", "scam", "spam", "other"];
const defaultFeeds = ["https://openphish.com/feed.txt"];

// Records one report per network and link. Enough distinct reporters disable a visitor-created link.
export async function reportLink(env, data, ip, origin) {
  const slug = typeof data.slug === "string" && /^[A-Za-z0-9_-]{1,63}$/.test(data.slug) ? data.slug : null;
  const reason = reportReasons.includes(data.reason) ? data.reason : "other";
  if (!slug) throw new ValidationError("Choose a short link to report.", 400, "slug");
  const reporter = await clientKey(env, ip);
  if (!await consume(env, `report:${reporter}`, 3600, setting(env, "REPORTS_PER_HOUR", 20))) {
    throw new ValidationError("Too many reports from your network. Try again later.", 429, "form");
  }
  const link = await env.DB.prepare("SELECT original, source, disabled FROM links WHERE slug = ?").bind(slug).first();
  if (!link) throw new ValidationError("Short link not found.", 404, "slug");
  const now = Math.floor(Date.now() / 1000);
  await env.DB.prepare("INSERT INTO reports (slug, reporter, reason, created_at) VALUES (?, ?, ?, ?) ON CONFLICT DO NOTHING").bind(slug, reporter, reason, now).run();
  const threshold = setting(env, "REPORT_THRESHOLD", 3);
  const { count } = await env.DB.prepare("SELECT COUNT(*) AS count FROM reports WHERE slug = ?").bind(slug).first();
  let disabled = false;
  if (threshold && Number(count) >= threshold && link.source !== "admin" && !link.disabled) {
    const result = await env.DB.prepare("UPDATE links SET disabled = 1, disabled_reason = 'reports' WHERE slug = ? AND disabled = 0").bind(slug).run();
    disabled = result.meta.changes === 1;
  }
  const alert = disabled
    ? notify(env, `Disabled ${origin}/${slug} after ${count} abuse reports. Destination: ${link.original}`)
    : notify(env, `Abuse report (${reason}) for ${origin}/${slug} (${count} so far). Destination: ${link.original}`);
  return { slug, reported: true, disabled, alert };
}

// Replaces the stored feed with the current one, writing only the difference.
export async function syncThreatFeed(env, now = Math.floor(Date.now() / 1000)) {
  const sources = env.THREAT_FEED_URLS === undefined ? defaultFeeds : env.THREAT_FEED_URLS.split(/[\s,]+/).filter(Boolean);
  if (!sources.length) return null;
  const entries = new Map();
  for (const source of sources) {
    const response = await timedFetch(source, { redirect: "follow" }, 15000);
    if (!response.ok) throw new Error(`Threat feed ${source} returned ${response.status}.`);
    for (const line of (await response.text()).split("\n")) {
      if (entries.size >= 50000) break;
      const key = !line.startsWith("#") && feedKey(line);
      if (key) entries.set(key.entry, key.host);
    }
  }
  const { results } = await env.DB.prepare("SELECT entry FROM threat_feed").all();
  const existing = new Set(results.map((row) => row.entry));
  const writes = [];
  for (const [entry, host] of entries) if (!existing.has(entry)) writes.push(env.DB.prepare("INSERT INTO threat_feed (entry, host, added_at) VALUES (?, ?, ?) ON CONFLICT DO NOTHING").bind(entry, host, now));
  for (const entry of existing) if (!entries.has(entry)) writes.push(env.DB.prepare("DELETE FROM threat_feed WHERE entry = ?").bind(entry));
  for (let index = 0; index < writes.length; index += 100) await env.DB.batch(writes.slice(index, index + 100));
  await env.DB.prepare("INSERT INTO settings (key, value, updated_at) VALUES ('threat_feed', ?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at")
    .bind(JSON.stringify({ entries: entries.size, synced_at: now }), now).run();
  return entries.size;
}

// Re-checks active visitor links outside the approved domains, oldest check first, and disables listed ones.
export async function recheckLinks(env, origin, now = Math.floor(Date.now() / 1000)) {
  const settings = await loadSettings(env);
  const { results } = await env.DB.prepare(`SELECT slug, original FROM links WHERE source != 'admin' AND disabled = 0
    AND (expires_at IS NULL OR expires_at > ?) ORDER BY COALESCE(checked_at, 0), created_at DESC LIMIT 1000`).bind(now).all();
  const candidates = results.filter((link) => {
    try { return !onDomains(new URL(link.original).hostname, settings.approved_domains); } catch { return false; }
  }).slice(0, 500);
  if (!candidates.length) return { checked: 0, disabled: [] };
  let listed = new Set();
  try { listed = await safeBrowsing(env, candidates.map((link) => link.original)); }
  catch { console.warn("Safe Browsing re-check failed; using the threat feed only."); }
  const inFeed = await feedMatcher(env);
  const flagged = candidates.filter((link) => listed.has(link.original) || inFeed(link.original));
  const writes = flagged.map((link) => env.DB.prepare("UPDATE links SET disabled = 1, disabled_reason = 'unsafe' WHERE slug = ?").bind(link.slug));
  for (let index = 0; index < candidates.length; index += 90) {
    const chunk = candidates.slice(index, index + 90);
    writes.push(env.DB.prepare(`UPDATE links SET checked_at = ? WHERE slug IN (${chunk.map(() => "?").join(", ")})`).bind(now, ...chunk.map((link) => link.slug)));
  }
  await env.DB.batch(writes);
  if (flagged.length) {
    await notify(env, `Disabled ${flagged.length} unsafe short link(s):\n${flagged.slice(0, 20).map((link) => `${origin}/${link.slug} → ${link.original}`).join("\n")}`);
  }
  return { checked: candidates.length, disabled: flagged.map((link) => link.slug) };
}

// New visitor links that suddenly draw many clicks are a typical sign of a phishing campaign.
export async function alertClickSpikes(env, origin, now = Math.floor(Date.now() / 1000)) {
  const threshold = setting(env, "SPIKE_CLICKS", 100);
  if (!threshold) return [];
  const { results } = await env.DB.prepare(`SELECT slug, original, clicks FROM links WHERE source != 'admin' AND disabled = 0 AND alerted_at IS NULL
    AND created_at >= ? AND clicks >= ? ORDER BY clicks DESC LIMIT 20`).bind(now - 2 * 86400, threshold).all();
  if (!results.length) return [];
  await env.DB.batch(results.map((link) => env.DB.prepare("UPDATE links SET alerted_at = ? WHERE slug = ?").bind(now, link.slug)));
  await notify(env, `Click spike on new visitor link(s); review them in the admin area:\n${results.map((link) => `${origin}/${link.slug} (${link.clicks} clicks) → ${link.original}`).join("\n")}`);
  return results.map((link) => link.slug);
}

// The scheduled job: refresh the feed, re-check links, alert on spikes, drop stale counters. Each step is independent.
export async function runMaintenance(env, now = Math.floor(Date.now() / 1000)) {
  const origin = (env.PUBLIC_ORIGIN || "").replace(/\/+$/, "");
  const summary = {};
  for (const [name, step] of [
    ["feed", () => syncThreatFeed(env, now)],
    ["recheck", () => recheckLinks(env, origin, now)],
    ["spikes", () => alertClickSpikes(env, origin, now)],
    ["cleanup", () => env.DB.prepare("DELETE FROM rate_limits WHERE window_start < ?").bind(now - 2 * 86400).run().then(() => true)],
  ]) {
    try { summary[name] = await step(); } catch (error) { console.error(`Maintenance step ${name} failed: ${error.message}`); summary[name] = null; }
  }
  return summary;
}
