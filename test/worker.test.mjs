import { test } from "node:test";
import assert from "node:assert/strict";
import { Miniflare } from "miniflare";
import { approvedDomains, destination, alias } from "../src/policy.mjs";
import { staticReason, feedKey } from "../src/screening.mjs";
import { ipBucket } from "../src/limits.mjs";
import { migrations } from "../generated/migrations.mjs";

const token = "test-admin-token-0123456789";
// Stands in for every outbound service: RDAP, Turnstile, Safe Browsing, the threat feed, webhooks and GitHub.
const outside = { unsafe: new Set(), alerts: [], githubCreated: "2015-01-01T00:00:00Z" };
async function outbound(request) {
  const url = new URL(request.url);
  if (url.hostname === "data.iana.org") return Response.json({ services: [[["example"], ["https://rdap.test/"]]] });
  if (url.hostname === "rdap.test") {
    const domain = url.pathname.split("/").pop();
    if (domain === "fresh.example") return Response.json({ events: [{ eventAction: "registration", eventDate: new Date(Date.now() - 3 * 86400000).toISOString() }] });
    return new Response("{}", { status: 404 });
  }
  if (url.hostname === "challenges.cloudflare.com") return Response.json({ success: new URLSearchParams(await request.text()).get("response") === "pass" });
  if (url.hostname === "safebrowsing.googleapis.com") {
    const entries = (await request.json()).threatInfo.threatEntries;
    return Response.json({ matches: entries.filter((entry) => outside.unsafe.has(entry.url)).map((entry) => ({ threat: { url: entry.url } })) });
  }
  if (url.hostname === "feed.test") return new Response("# comment\nhttps://phish.example/page\nhttps://whole.example/\nnot a url\n");
  if (url.hostname === "hooks.test") { outside.alerts.push((await request.json()).text); return new Response("ok"); }
  if (url.href === "https://github.com/login/oauth/access_token") {
    const code = new URLSearchParams(await request.text()).get("code");
    return Response.json({ access_token: `token-${code}` });
  }
  if (url.href === "https://api.github.com/user") {
    const young = request.headers.get("Authorization") === "Bearer token-young";
    return Response.json({ id: young ? 2 : 1, login: young ? "newbie" : "octocat", created_at: young ? new Date().toISOString() : outside.githubCreated });
  }
  return new Response("Not found", { status: 404 });
}
const options = (bindings = {}) => ({ modules: true, scriptPath: "dist/worker.mjs", compatibilityDate: "2026-08-01", d1Databases: ["DB"],
  outboundService: outbound, bindings: { PUBLIC_ORIGIN: "https://s.bea.sh", APPROVED_DOMAINS: '["bea.sh","behnam.pro"]', ADMIN_TOKEN: token, ...bindings } });
async function migrate(db) {
  for (const { sql } of migrations) for (const statement of sql.split(";").map((part) => part.trim()).filter(Boolean)) await db.prepare(statement).run();
}

test("domain policy accepts subdomains and rejects authority spoofing", () => {
  const domains = approvedDomains(["BEA.sh", " behnam.pro"]);
  assert.deepEqual(domains, ["bea.sh", "behnam.pro"]);
  assert.equal(destination("HTTPS://IP.BEA.SH/path?q=1#ok", domains), "https://ip.bea.sh/path?q=1#ok");
  for (const url of ["https://evilbea.sh", "https://bea.sh.evil.com", "https://bea.sh@evil.com", "https://u:p@bea.sh", "javascript:alert(1)", "//bea.sh", "https://bea.sh\\@evil.com", "https://bea.sh\n"]) assert.throws(() => destination(url, domains), url);
  assert.throws(() => destination("https://s.bea.sh/a", domains, ["s.bea.sh"]));
  assert.equal(destination("https://anything.example/x", null), "https://anything.example/x");
  assert.throws(() => destination("https://u:p@anything.example/", null));
  for (const bad of [[], "", ["*.bea.sh"], ["bea.sh/path"], ["127.0.0.1"], "[bad"]) assert.throws(() => approvedDomains(bad));
  for (const bad of ["api", "Assets", "admin", "../x", "a".repeat(64)]) assert.throws(() => alias(bad));
});

test("D1 integration: creation, immutable aliases, current policy and assets", async () => {
  const mf = new Miniflare(options());
  try {
    const db = await mf.getD1Database("DB");
    await migrate(db);
    const post = (body, path = "/api/links", headers = {}) => mf.dispatchFetch(`https://s.bea.sh${path}`, { method: "POST", headers: { "Content-Type": "application/json", ...headers }, body: JSON.stringify(body) });
    const created = await post({ original: "https://ip.bea.sh/?x=1", shortened: "example" });
    assert.equal(created.status, 201); assert.equal((await created.json()).short_url, "https://s.bea.sh/example");
    const race = await Promise.all([post({ original: "https://bea.sh/a", shortened: "race" }), post({ original: "https://bea.sh/b", shortened: "race" })]);
    assert.deepEqual(race.map((r) => r.status).sort(), [201, 409]);
    assert.equal((await post({ original: "https://bea.sh/other", shortened: "example" })).status, 409);
    const redirect = await mf.dispatchFetch("https://s.bea.sh/example", { redirect: "manual" });
    assert.equal(redirect.status, 302); assert.equal(redirect.headers.get("location"), "https://ip.bea.sh/?x=1");
    assert.equal(redirect.headers.get("cache-control"), "no-store");
    assert.equal((await post({ original: "https://unapproved.example/" })).status, 403);
    assert.equal((await post({ original: "https://bea.sh/", shortened: "api" })).status, 400);
    assert.equal((await post({ original: "https://bea.sh/", padding: "x".repeat(9000) })).status, 413);
    await db.prepare("INSERT INTO links (slug, original, created_at) VALUES (?, ?, ?)").bind("revoked", "https://evil.example/", 0).run();
    assert.equal((await mf.dispatchFetch("https://s.bea.sh/revoked")).status, 403);
    assert.equal((await mf.dispatchFetch("https://s.bea.sh/missing")).status, 404);
    const injected = await post({ original: "https://evil.example/</script><script>alert(1)</script>" }, "/");
    const html = await injected.text(); assert.ok(!html.includes("<script>alert(1)</script>"));
    const home = await mf.dispatchFetch("https://s.bea.sh/"); const body = await home.text();
    const css = body.match(/href="(\/assets\/app-[^"]+\.css)"/)[1];
    const asset = await mf.dispatchFetch(`https://s.bea.sh${css}`); assert.equal(asset.status, 200); assert.ok((await asset.text()).includes(".btn"));
    assert.ok(body.includes('<link rel="canonical" href="https://s.bea.sh/">')); assert.ok(!html.includes("__ORIGIN__"));
    const ld = JSON.parse(body.match(/<script type="application\/ld\+json">(.*?)<\/script>/)[1]); assert.equal(ld.url, "https://s.bea.sh/");
    assert.ok(body.includes('href="/favicon.svg"')); assert.ok(!body.includes('href="/admin"'));
    for (const [path, type] of [["/favicon.svg", "image/svg+xml"], ["/favicon.ico", "image/x-icon"], ["/apple-touch-icon.png", "image/png"]]) {
      const icon = await mf.dispatchFetch(`https://s.bea.sh${path}`); assert.equal(icon.status, 200); assert.equal(icon.headers.get("content-type"), type);
      assert.ok((await icon.arrayBuffer()).byteLength > 100);
    }
    const robots = await mf.dispatchFetch("https://s.bea.sh/robots.txt"); assert.equal(robots.status, 200);
    assert.ok((await robots.text()).includes("Sitemap: https://s.bea.sh/sitemap.xml"));
    const sitemap = await mf.dispatchFetch("https://s.bea.sh/sitemap.xml"); assert.equal(sitemap.headers.get("content-type"), "application/xml; charset=utf-8");
    assert.ok((await sitemap.text()).includes("<loc>https://s.bea.sh/</loc>"));
    const head = await mf.dispatchFetch("https://s.bea.sh/example", { method: "HEAD", redirect: "manual" }); assert.equal(head.status, 302); assert.equal(await head.text(), "");
    assert.equal((await (await mf.dispatchFetch("https://s.bea.sh/.well-known/health")).json()).status, "ok");
    await mf.setOptions(options({ APPROVED_DOMAINS: "[]" }));
    assert.equal((await mf.dispatchFetch("https://s.bea.sh/api/config")).status, 503);
  } finally { await mf.dispose(); }
});

test("admin: token sign-in, settings, link management and cross-site protection", async () => {
  const mf = new Miniflare(options());
  try {
    await migrate(await mf.getD1Database("DB"));
    const fetch = (path, init = {}) => mf.dispatchFetch(`https://s.bea.sh${path}`, { redirect: "manual", ...init });
    const login = await fetch("/admin");
    assert.equal(login.status, 200);
    assert.match(login.headers.get("cache-control"), /private/);
    assert.match(await login.text(), /"view":"login"/);
    assert.equal((await fetch("/admin/api/overview")).status, 401);
    const form = (value, headers = {}) => fetch("/admin/login", { method: "POST", headers: { "Content-Type": "application/x-www-form-urlencoded", ...headers }, body: new URLSearchParams({ token: value }).toString() });
    assert.equal((await form("wrong-token-value-000000")).status, 401);
    assert.equal((await form(token, { Origin: "https://evil.example" })).status, 403);
    assert.equal((await form(token, { "Sec-Fetch-Site": "cross-site" })).status, 403);
    // Browsers may send Origin: null; fetch metadata then decides.
    assert.equal((await form(token, { Origin: "null", "Sec-Fetch-Site": "same-origin" })).status, 303);
    const signedIn = await form(token, { Origin: "https://s.bea.sh" });
    assert.equal(signedIn.status, 303);
    const setCookie = signedIn.headers.get("set-cookie");
    assert.match(setCookie, /HttpOnly/); assert.match(setCookie, /SameSite=Strict/); assert.match(setCookie, /Secure/); assert.match(setCookie, /Path=\/admin/);
    const cookie = setCookie.split(";")[0];
    const forged = cookie.replace(/\.[0-9a-f]{64}$/, `.${"0".repeat(64)}`);
    assert.equal((await fetch("/admin/api/overview", { headers: { Cookie: forged } })).status, 401);
    const session = (path, init = {}) => fetch(path, { ...init, headers: { Cookie: cookie, "Content-Type": "application/json", ...init.headers } });
    assert.match(await (await session("/admin")).text(), /"view":"dashboard"/);
    const overview = await (await session("/admin/api/overview")).json();
    assert.deepEqual(overview.settings.approved_domains, ["bea.sh", "behnam.pro"]);
    assert.equal(overview.settings.domains_customized, false);
    assert.equal(overview.identity.method, "session");

    // Cross-site writes are rejected even with a valid cookie.
    assert.equal((await session("/admin/api/settings", { method: "PUT", headers: { Origin: "https://evil.example" }, body: JSON.stringify({ link_creation: "admin" }) })).status, 403);
    assert.equal((await session("/admin/api/settings", { method: "PUT", headers: { "Content-Type": "text/plain" }, body: JSON.stringify({ link_creation: "admin" }) })).status, 415);
    assert.equal((await session("/admin/api/settings", { method: "PUT", body: JSON.stringify({ approved_domains: ["bad domain"] }) })).status, 400);
    assert.equal((await session("/admin/api/settings", { method: "PUT", body: JSON.stringify({ domain_policy: "everything" }) })).status, 400);

    // Managed domains override deployment defaults.
    const saved = await (await session("/admin/api/settings", { method: "PUT", body: JSON.stringify({ approved_domains: ["example.org", "bea.sh"] }) })).json();
    assert.deepEqual(saved.approved_domains, ["bea.sh", "example.org"]); assert.equal(saved.domains_customized, true);
    const publicPost = (original) => fetch("/api/links", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ original }) });
    assert.equal((await publicPost("https://www.example.org/")).status, 201);
    assert.equal((await publicPost("https://behnam.pro/")).status, 403);

    // Admin-only creation blocks anonymous creation but accepts the bearer token.
    await session("/admin/api/settings", { method: "PUT", body: JSON.stringify({ link_creation: "admin" }) });
    assert.equal((await publicPost("https://bea.sh/")).status, 403);
    assert.equal((await (await fetch("/api/config")).json()).link_creation, "admin");
    const bearer = await fetch("/api/links", { method: "POST", headers: { "Content-Type": "application/json", Authorization: `Bearer ${token}` }, body: JSON.stringify({ original: "https://bea.sh/b", shortened: "bearer" }) });
    assert.equal(bearer.status, 201);
    const adminCreated = await session("/admin/api/links", { method: "POST", body: JSON.stringify({ original: "https://bea.sh/admin", shortened: "made-by-admin" }) });
    assert.equal(adminCreated.status, 201);

    // Any-domain mode, then back to approved-only, which re-applies to existing links.
    await session("/admin/api/settings", { method: "PUT", body: JSON.stringify({ domain_policy: "any", link_creation: "public" }) });
    assert.equal((await publicPost("https://other.example/x")).status, 201);
    const anyLink = await (await fetch("/api/links", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ original: "https://other.example/y", shortened: "any-link" }) })).json();
    // A visitor's link outside the approved domains shows the destination instead of redirecting.
    const warning = await fetch(`/${anyLink.shortened}`);
    assert.equal(warning.status, 200); assert.match(await warning.text(), /other\.example/);
    await session("/admin/api/settings", { method: "PUT", body: JSON.stringify({ domain_policy: "approved" }) });
    assert.equal((await fetch("/any-link")).status, 403);
    const reset = await (await session("/admin/api/settings", { method: "PUT", body: JSON.stringify({ approved_domains: null }) })).json();
    assert.deepEqual(reset.approved_domains, ["bea.sh", "behnam.pro"]);

    // Clicks, disable, delete, search.
    for (let i = 0; i < 2; i++) assert.equal((await fetch("/bearer")).status, 302);
    let found;
    for (let attempt = 0; attempt < 20; attempt++) {
      found = await (await session("/admin/api/links?q=bear")).json();
      if (found.links[0]?.clicks === 2) break;
      await new Promise((resolve) => setTimeout(resolve, 50));
    }
    assert.equal(found.total, 1); assert.equal(found.links[0].slug, "bearer"); assert.equal(found.links[0].clicks, 2);
    assert.equal((await (await session("/admin/api/links?q=%25")).json()).total, 0);
    assert.equal((await session("/admin/api/links/bearer", { method: "PATCH", body: JSON.stringify({ disabled: true }) })).status, 200);
    assert.equal((await fetch("/bearer")).status, 410);
    assert.equal((await session("/admin/api/links/bearer", { method: "PATCH", body: JSON.stringify({ disabled: false }) })).status, 200);
    assert.equal((await fetch("/bearer")).status, 302);
    assert.equal((await session("/admin/api/links/bearer", { method: "DELETE" })).status, 200);
    assert.equal((await session("/admin/api/links/bearer", { method: "DELETE" })).status, 404);
    assert.equal((await fetch("/bearer")).status, 404);
    const stats = (await (await session("/admin/api/overview")).json()).stats;
    assert.ok(stats.links >= 4 && stats.clicks >= 1);

    const logout = await fetch("/admin/logout", { method: "POST", headers: { Cookie: cookie, Origin: "https://s.bea.sh" } });
    assert.equal(logout.status, 303); assert.match(logout.headers.get("set-cookie"), /Max-Age=0/);

    // A rotated token invalidates existing sessions; a short token disables token sign-in.
    await mf.setOptions(options({ ADMIN_TOKEN: "rotated-admin-token-abcdefghij" }));
    assert.equal((await fetch("/admin/api/overview", { headers: { Cookie: cookie } })).status, 401);
    await mf.setOptions(options({ ADMIN_TOKEN: "short" }));
    assert.equal((await fetch("/admin/api/overview", { headers: { Authorization: "Bearer short" } })).status, 401);
    assert.equal((await form("short")).status, 403);
  } finally { await mf.dispose(); }
});

test("destination rules, feed keys and IPv6 buckets", () => {
  for (const [url, reason] of [["http://192.0.2.1/", /IP address/], ["http://[2001:db8::1]/", /IP address/], ["https://xn--pypal-4ve.com/", /punycode/],
    ["https://example.com:8443/", /port/], ["https://bit.ly/x", /shortener/], ["https://evil.pages.dev/", /free hosting/],
    ["https://a.b.c.d.e.example.com/", /deep/], ["https://example.com/secure/Login.php", /sign-in/], ["https://example.com/?next=%2Fverify", /sign-in/],
    ["https://wallet-connect.example/", /wallet/]]) assert.match(staticReason(url) || "", reason, url);
  for (const url of ["https://example.com/blog/catalogue", "https://example.com/blogin", "https://docs.example.org/accounts"]) {
    assert.equal(staticReason(url), null, url);
  }
  assert.deepEqual(feedKey("HTTPS://Phish.Example/a/?x=1"), { host: "phish.example", entry: "phish.example/a?x=1" });
  assert.equal(feedKey("ftp://x.example/"), null);
  assert.equal(ipBucket("2001:db8:1:2:3:4:5:6"), ipBucket("2001:db8:1:2::9"));
  assert.notEqual(ipBucket("2001:db8:1:2::1"), ipBucket("2001:db8:1:3::1"));
  assert.equal(ipBucket("198.51.100.7"), "198.51.100.7");
});

test("abuse protection: warning page, screening, limits, reports, re-checks, alerts and visitor accounts", async () => {
  const mf = new Miniflare(options({ TURNSTILE_SITE_KEY: "site-key", TURNSTILE_SECRET_KEY: "secret-key", SAFE_BROWSING_API_KEY: "sb-key",
    THREAT_FEED_URLS: "https://feed.test/feed.txt", ALERT_WEBHOOK_URL: "https://hooks.test/", REPORT_THRESHOLD: "2", SPIKE_CLICKS: "2",
    ABUSE_EMAIL: "abuse@bea.sh", SESSION_SECRET: "s".repeat(40), GITHUB_CLIENT_ID: "client", GITHUB_CLIENT_SECRET: "secret" }));
  try {
    const db = await mf.getD1Database("DB");
    await migrate(db);
    let ip = 1;
    const fetch = (path, init = {}) => mf.dispatchFetch(`https://s.bea.sh${path}`, { redirect: "manual", ...init,
      headers: { "CF-Connecting-IP": `198.51.100.${ip}`, ...init.headers } });
    const create = (body, headers = {}) => fetch("/api/links", { method: "POST", headers: { "Content-Type": "application/json", ...headers }, body: JSON.stringify(body) });
    const admin = { Authorization: `Bearer ${token}`, "Content-Type": "application/json" };
    const settings = (body) => fetch("/admin/api/settings", { method: "PUT", headers: admin, body: JSON.stringify(body) });
    const error = async (response) => (await response.json()).error;
    assert.equal((await settings({ domain_policy: "any" })).status, 200);
    const config = await (await fetch("/api/config")).json();
    assert.equal(config.turnstile_site_key, "site-key"); assert.equal(config.any_domain, true); assert.deepEqual(config.sign_in, ["github"]);

    // Approved domains need no challenge and still redirect directly.
    assert.equal((await create({ original: "https://bea.sh/ok", shortened: "own" })).status, 201);
    assert.equal((await fetch("/own")).status, 302);

    // Other domains need a passing Turnstile token, then expire and show a warning page.
    assert.match(await error(await create({ original: "https://site.example/a" })), /verification/);
    assert.equal((await create({ original: "https://site.example/a", turnstile: "fail" })).status, 403);
    const visitor = await create({ original: "https://site.example/a?q=<b>", shortened: "visitor", turnstile: "pass" });
    assert.equal(visitor.status, 201);
    const created = await visitor.json();
    assert.ok(created.expires_at > Date.now() / 1000 + 29 * 86400);
    const warning = await fetch("/visitor");
    assert.equal(warning.status, 200); assert.equal(warning.headers.get("x-robots-tag"), "noindex, nofollow");
    const page = await warning.text();
    assert.match(page, /site\.example/); assert.ok(page.includes("q=%3Cb%3E")); assert.ok(!page.includes("<b>"));
    assert.match(page, /abuse@bea\.sh/); assert.match(page, /name="slug" value="visitor"/);
    assert.equal((await fetch("/visitor", { method: "HEAD" })).status, 200);

    // Screening: static rules, Safe Browsing, newly registered domains.
    ip = 2;
    for (const [original, reason] of [["https://evil.pages.dev/", /free hosting/], ["https://bank.example/signin", /sign-in/], ["https://tinyurl.com/x", /shortener/]]) {
      const response = await create({ original, turnstile: "pass" });
      assert.equal(response.status, 403); assert.match(await error(response), reason);
    }
    outside.unsafe.add("https://listed.example/");
    assert.match(await error(await create({ original: "https://listed.example/", turnstile: "pass" })), /listed as unsafe/);
    assert.match(await error(await create({ original: "https://fresh.example/", turnstile: "pass" })), /less than 30 days/);

    // Ten links per network per hour; IPv6 addresses in one /64 share the limit. Rejected attempts count too.
    for (let index = 0; index < 5; index++) assert.equal((await create({ original: `https://bea.sh/${index}` })).status, 201);
    assert.equal((await create({ original: "https://bea.sh/limit" })).status, 429);
    const v6 = (suffix, original) => create({ original }, { "CF-Connecting-IP": `2001:db8:5:6::${suffix}` });
    for (let index = 0; index < 10; index++) assert.equal((await v6(index + 1, `https://bea.sh/v6-${index}`)).status, 201);
    assert.equal((await v6(99, "https://bea.sh/v6-over")).status, 429);
    assert.equal((await create({ original: "https://bea.sh/admin-unlimited" }, admin)).status, 201);

    // The scheduled job syncs the feed, disables listed and newly unsafe links, and alerts on click spikes.
    ip = 3;
    for (const [shortened, original] of [["feed-hit", "https://phish.example/page/next"], ["later-bad", "https://later.example/"], ["popular", "https://popular.example/"]]) {
      assert.equal((await create({ original, shortened, turnstile: "pass" })).status, 201);
    }
    assert.equal((await create({ original: "https://other.example/x", shortened: "trusted" }, admin)).status, 201);
    assert.equal((await fetch("/trusted")).status, 302);
    for (let index = 0; index < 2; index++) assert.equal((await fetch("/popular")).status, 200);
    outside.unsafe.add("https://later.example/");
    await (await mf.getWorker()).scheduled({ cron: "17 */3 * * *" });
    let rows;
    for (let attempt = 0; attempt < 40; attempt++) {
      rows = Object.fromEntries((await db.prepare("SELECT slug, disabled, disabled_reason, alerted_at FROM links").all()).results.map((row) => [row.slug, row]));
      if (rows["later-bad"].disabled && rows.popular.alerted_at) break;
      await new Promise((resolve) => setTimeout(resolve, 50));
    }
    assert.equal(rows["feed-hit"].disabled_reason, "unsafe"); assert.equal(rows["later-bad"].disabled_reason, "unsafe");
    assert.equal(rows.visitor.disabled, 0); assert.ok(rows.popular.alerted_at);
    assert.equal((await fetch("/feed-hit")).status, 410);
    assert.ok(outside.alerts.some((text) => text.includes("s.bea.sh/later-bad")));
    assert.ok(outside.alerts.some((text) => text.includes("Click spike") && text.includes("s.bea.sh/popular")));
    assert.match(await error(await create({ original: "https://whole.example/any/path", turnstile: "pass" })), /listed as unsafe/);
    const overview = await (await fetch("/admin/api/overview", { headers: admin })).json();
    assert.equal(overview.protection.threat_feed.entries, 2); assert.equal(overview.protection.turnstile, true);

    // Reports from distinct networks disable a visitor link; the form shows a confirmation.
    const report = (body, from) => fetch("/api/reports", { method: "POST", headers: { "Content-Type": "application/json", "CF-Connecting-IP": from }, body: JSON.stringify(body) });
    assert.equal((await report({ slug: "visitor", reason: "phishing" }, "192.0.2.10")).status, 201);
    assert.equal((await report({ slug: "visitor", reason: "phishing" }, "192.0.2.10")).status, 201);
    assert.equal((await fetch("/visitor")).status, 200);
    assert.equal((await (await fetch("/admin/api/links?filter=reported", { headers: admin })).json()).links[0].reports, 1);
    const confirmation = await fetch("/api/reports", { method: "POST", headers: { "Content-Type": "application/x-www-form-urlencoded", "CF-Connecting-IP": "192.0.2.11" }, body: "slug=visitor&reason=scam" });
    assert.match(await confirmation.text(), /The report was recorded/);
    assert.equal((await fetch("/visitor")).status, 410);
    assert.ok(outside.alerts.some((text) => text.startsWith("🚩 Abuse report\nReason: Phishing\nReports: 1 / 2\nStatus: Enabled\n")
      && text.includes("\n🔗 Short link\nhttps://s.bea.sh/visitor\n\n🌐 Destination\n")));
    assert.ok(outside.alerts.some((text) => text.startsWith("🚫 Short link disabled\nReason: Scam\nReports: 2 / 2\nStatus: Disabled\n")));
    assert.equal((await report({ slug: "missing" }, "192.0.2.12")).status, 404);
    for (let index = 0; index < 2; index++) await report({ slug: "trusted" }, `192.0.2.${20 + index}`);
    assert.equal((await fetch("/trusted")).status, 302);
    // Re-enabling clears the reports.
    await fetch("/admin/api/links/visitor", { method: "PATCH", headers: admin, body: JSON.stringify({ disabled: false }) });
    assert.equal((await fetch("/visitor")).status, 200);
    assert.equal((await db.prepare("SELECT COUNT(*) AS count FROM reports WHERE slug = 'visitor'").first()).count, 0);

    // Expired visitor links stop working.
    await db.prepare("UPDATE links SET expires_at = 1 WHERE slug = 'visitor'").run();
    assert.match(await error(await fetch("/visitor")), /expired/);

    // Signed-in visitors may link anywhere in signed_in mode; anonymous visitors may not.
    ip = 4;
    assert.equal((await settings({ domain_policy: "signed_in" })).status, 200);
    assert.equal((await create({ original: "https://site.example/b", turnstile: "pass" })).status, 403);
    const start = await fetch("/auth/github");
    assert.equal(start.status, 303);
    const authorize = new URL(start.headers.get("location"));
    assert.equal(authorize.origin + authorize.pathname, "https://github.com/login/oauth/authorize");
    assert.equal(authorize.searchParams.get("redirect_uri"), "https://s.bea.sh/auth/github/callback");
    const state = authorize.searchParams.get("state");
    const stateCookie = start.headers.get("set-cookie").split(";")[0];
    assert.equal((await fetch(`/auth/github/callback?code=ok&state=${"0".repeat(32)}`, { headers: { Cookie: stateCookie } })).status, 400);
    const young = await fetch(`/auth/github/callback?code=young&state=${state}`, { headers: { Cookie: stateCookie } });
    assert.equal(young.status, 403); assert.match(await young.text(), /younger than 30 days/);
    const callback = await fetch(`/auth/github/callback?code=ok&state=${state}`, { headers: { Cookie: stateCookie } });
    assert.equal(callback.status, 303);
    const userCookie = callback.headers.getSetCookie().find((value) => value.startsWith("shortener_user=")).split(";")[0];
    const signedIn = { Cookie: userCookie };
    assert.deepEqual((await (await fetch("/api/config", { headers: signedIn })).json()).user, { name: "octocat" });
    const own = await create({ original: "https://site.example/b", shortened: "by-user", turnstile: "pass" }, signedIn);
    assert.equal(own.status, 201); assert.equal((await own.json()).expires_at, null);
    assert.equal((await fetch("/by-user")).status, 200);
    const listed = (await (await fetch("/admin/api/links?q=by-user", { headers: admin })).json()).links[0];
    assert.equal(listed.source, "user"); assert.equal(listed.creator_name, "octocat");
    // Banning disables the account's links and signs it out of link creation.
    const ban = await fetch(`/admin/api/users/${encodeURIComponent(listed.creator)}`, { method: "PATCH", headers: admin, body: JSON.stringify({ banned: true }) });
    assert.deepEqual(await ban.json(), { user: "github:1", banned: true, disabled_links: 1 });
    assert.equal((await fetch("/by-user")).status, 410);
    assert.equal((await (await fetch("/api/config", { headers: signedIn })).json()).user, null);
    assert.equal((await create({ original: "https://site.example/c", turnstile: "pass" }, signedIn)).status, 403);
    const logout = await fetch("/auth/logout", { method: "POST", headers: { Origin: "https://s.bea.sh" } });
    assert.equal(logout.status, 303); assert.match(logout.headers.get("set-cookie"), /shortener_user=; Max-Age=0/);
  } finally { await mf.dispose(); }
});
