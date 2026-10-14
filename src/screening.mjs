import { onDomains } from "./policy.mjs";

// Destination screening for links that do not point to an approved domain.
// Static rules run first; remote checks fail open so an outage does not block every visitor,
// and the scheduled re-check catches what they missed.

export const shorteners = ["bit.ly", "bitly.com", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "v.gd", "buff.ly", "rebrand.ly",
  "cutt.ly", "shorturl.at", "rb.gy", "t.ly", "tiny.cc", "bl.ink", "s.id", "x.gd", "qrco.de", "lnkd.in", "shorte.st", "adf.ly",
  "linktr.ee", "short.gy", "clck.ru", "u.to", "urlz.fr", "tny.im", "shrtco.de", "rebrandly.com", "t2m.io", "soo.gd", "surl.li"];

// Free hosting and tunnelling services that phishing kits use heavily. Approve a domain to allow it.
export const abusedHosts = ["pages.dev", "workers.dev", "r2.dev", "web.app", "firebaseapp.com", "appspot.com", "glitch.me", "repl.co",
  "replit.app", "replit.dev", "vercel.app", "netlify.app", "onrender.com", "herokuapp.com", "fly.dev", "gitbook.io", "weebly.com",
  "weeblysite.com", "wixsite.com", "webflow.io", "framer.app", "framer.website", "square.site", "godaddysites.com", "000webhostapp.com",
  "blogspot.com", "sites.google.com", "forms.gle", "ngrok.io", "ngrok.app", "ngrok-free.app", "trycloudflare.com", "loca.lt", "serveo.net",
  "duckdns.org", "ddns.net", "hopto.org", "zapto.org", "ipfs.io", "dweb.link", "mypinata.cloud", "azurewebsites.net", "web.core.windows.net",
  "blob.core.windows.net", "storage.googleapis.com", "firebasestorage.googleapis.com", "s3.amazonaws.com", "surge.sh", "tiiny.site",
  "carrd.co", "mystrikingly.com", "jimdosite.com", "yolasite.com", "typedream.app", "backblazeb2.com"];

const keywords = /(?:^|[^a-z0-9])(?:log-?in|sign-?in|logon|verif(?:y|ication)|wallet|passw(?:or)?d|unlock|recover(?:y)?|seed-?phrase|webscr|2fa|otp|kyc|airdrop|account-?(?:update|locked|suspended|verify|confirm)|confirm-?(?:identity|payment))(?:[^a-z0-9]|$)/;

export class ScreeningError extends Error {}

function decoded(value) {
  try { return decodeURIComponent(value); } catch { return value; }
}

// Returns why a destination is refused by the static rules, or null.
export function staticReason(href) {
  const url = new URL(href);
  const host = url.hostname;
  if (/^\d+(\.\d+){3}$/.test(host) || host.startsWith("[")) return "points to an IP address instead of a domain";
  if (host.split(".").some((label) => label.startsWith("xn--"))) return "uses an internationalized (punycode) domain";
  if (url.port) return "uses a non-standard port";
  if (onDomains(host, shorteners)) return "is another link shortener";
  if (onDomains(host, abusedHosts)) return "is on a free hosting service that is often used for phishing";
  if (host.split(".").length > 5) return "has an unusually deep domain";
  if (keywords.test(host) || keywords.test(decoded(`${url.pathname}${url.search}`).toLowerCase())) return "looks like a sign-in, verification or wallet page";
  return null;
}

export async function timedFetch(url, init = {}, ms = 4000) {
  return fetch(url, { ...init, signal: AbortSignal.timeout(ms) });
}

// Feed entries and destinations are compared as host + path, ignoring scheme, case of the host and a trailing slash.
export function feedKey(href) {
  let url;
  try { url = new URL(href.trim()); } catch { return null; }
  if (!["http:", "https:"].includes(url.protocol) || !url.hostname) return null;
  const host = url.hostname.toLowerCase().replace(/\.$/, "");
  return { host, entry: `${host}${url.pathname.replace(/\/+$/, "")}${url.search}` };
}

// A listed site root covers the whole host; otherwise the listed path must prefix the destination.
function listed(entries, key) {
  return entries.some((entry) => entry === key.host || key.entry === entry || key.entry.startsWith(`${entry}/`) || key.entry.startsWith(`${entry}?`));
}

export async function feedMatch(env, href) {
  const key = feedKey(href);
  if (!key) return false;
  const { results } = await env.DB.prepare("SELECT entry FROM threat_feed WHERE host = ?").bind(key.host).all();
  return listed(results.map((row) => row.entry), key);
}

// Loads the whole feed once for checking many destinations.
export async function feedMatcher(env) {
  const { results } = await env.DB.prepare("SELECT entry, host FROM threat_feed").all();
  const byHost = new Map();
  for (const { entry, host } of results) byHost.set(host, [...(byHost.get(host) || []), entry]);
  return (href) => {
    const key = feedKey(href);
    return Boolean(key && byHost.has(key.host) && listed(byHost.get(key.host), key));
  };
}

// Google Safe Browsing Lookup API v4. Returns the subset of `urls` that matched.
export async function safeBrowsing(env, urls) {
  if (!env.SAFE_BROWSING_API_KEY || !urls.length) return new Set();
  const matched = new Set();
  for (let index = 0; index < urls.length; index += 500) {
    const response = await timedFetch(`https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${encodeURIComponent(env.SAFE_BROWSING_API_KEY)}`, {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        client: { clientId: "bea-shortener", clientVersion: "1" },
        threatInfo: { threatTypes: ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
          platformTypes: ["ANY_PLATFORM"], threatEntryTypes: ["URL"], threatEntries: urls.slice(index, index + 500).map((url) => ({ url })) },
      }),
    }, 8000);
    if (!response.ok) throw new Error(`Safe Browsing returned ${response.status}.`);
    for (const match of (await response.json()).matches || []) if (match.threat?.url) matched.add(match.threat.url);
  }
  return matched;
}

// abuse.ch URLhaus lookup; known malware URLs are refused whether or not they are still online.
export async function urlhaus(env, url) {
  if (!env.URLHAUS_AUTH_KEY) return false;
  const response = await timedFetch("https://urlhaus-api.abuse.ch/v1/url/", {
    method: "POST", headers: { "Auth-Key": env.URLHAUS_AUTH_KEY, "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({ url }).toString(),
  });
  if (!response.ok) throw new Error(`URLhaus returned ${response.status}.`);
  return (await response.json()).query_status === "ok";
}

let bootstrap = null;
const ages = new Map();
async function rdapServers() {
  if (bootstrap && bootstrap.expires > Date.now()) return bootstrap.servers;
  const response = await timedFetch("https://data.iana.org/rdap/dns.json", { cf: { cacheTtl: 86400, cacheEverything: true } });
  if (!response.ok) throw new Error("RDAP bootstrap is unavailable.");
  const servers = new Map();
  for (const [tlds, urls] of (await response.json()).services || []) {
    const base = urls.find((url) => url.startsWith("https://")) || urls[0];
    for (const tld of tlds) servers.set(tld.toLowerCase(), base.endsWith("/") ? base : `${base}/`);
  }
  bootstrap = { servers, expires: Date.now() + 86400000 };
  return servers;
}

// Days since the registrable domain was registered, or null when RDAP cannot say.
// Without a public suffix list, try the last two, three, then four labels: "co.uk" is not itself registered.
export async function domainAgeDays(host, now = Date.now()) {
  if (ages.has(host)) return ages.get(host);
  const labels = host.split(".");
  const base = (await rdapServers()).get(labels.at(-1));
  let age = null;
  if (base) for (let count = 2; count <= Math.min(4, labels.length); count++) {
    const domain = labels.slice(-count).join(".");
    const response = await timedFetch(`${base}domain/${domain}`, { headers: { Accept: "application/rdap+json, application/json" } });
    if (response.status === 404) continue;
    if (!response.ok) break;
    const registered = ((await response.json()).events || []).find((event) => event.eventAction === "registration")?.eventDate;
    if (registered && !Number.isNaN(Date.parse(registered))) age = Math.floor((now - Date.parse(registered)) / 86400000);
    break;
  }
  if (ages.size > 500) ages.clear();
  ages.set(host, age);
  return age;
}

export function newDomainDays(env) {
  const days = Number.parseInt(env.NEW_DOMAIN_DAYS ?? "30", 10);
  return Number.isFinite(days) && days > 0 ? days : 0;
}

async function remote(label, check) {
  try { return await check(); } catch { console.warn(`${label} check failed; continuing without it.`); return null; }
}

// Throws ScreeningError with a visitor-facing reason when the destination is refused.
export async function screenDestination(env, href) {
  const reason = staticReason(href);
  if (reason) throw new ScreeningError(`This destination can't be shortened here because it ${reason}.`);
  const unsafe = "This destination can't be shortened here because it is listed as unsafe.";
  if (await feedMatch(env, href)) throw new ScreeningError(unsafe);
  const [listed, malware] = await Promise.all([
    remote("Safe Browsing", async () => (await safeBrowsing(env, [href])).size > 0),
    remote("URLhaus", () => urlhaus(env, href)),
  ]);
  if (listed || malware) throw new ScreeningError(unsafe);
  const days = newDomainDays(env);
  if (days) {
    const age = await remote("RDAP", () => domainAgeDays(new URL(href).hostname));
    if (age !== null && age < days) throw new ScreeningError(`This destination can't be shortened here because its domain was registered less than ${days} days ago.`);
  }
}

// Cloudflare Turnstile. Returns true when Turnstile is not configured.
export async function verifyTurnstile(env, token, ip) {
  if (!env.TURNSTILE_SECRET_KEY || !env.TURNSTILE_SITE_KEY) return true;
  if (typeof token !== "string" || !token || token.length > 4096) return false;
  const body = new URLSearchParams({ secret: env.TURNSTILE_SECRET_KEY, response: token });
  if (ip) body.set("remoteip", ip);
  try {
    const response = await timedFetch("https://challenges.cloudflare.com/turnstile/v0/siteverify", { method: "POST", body });
    return response.ok && (await response.json()).success === true;
  } catch { return false; }
}
