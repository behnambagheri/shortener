import { test } from "node:test";
import assert from "node:assert/strict";
import { Miniflare } from "miniflare";
import { approvedDomains, destination, alias } from "../src/policy.mjs";
import { migrations } from "../generated/migrations.mjs";

const token = "test-admin-token-0123456789";
const options = (bindings = {}) => ({ modules: true, scriptPath: "dist/worker.mjs", compatibilityDate: "2026-08-01", d1Databases: ["DB"],
  bindings: { PUBLIC_ORIGIN: "https://s.bea.sh", APPROVED_DOMAINS: '["bea.sh","behnam.pro"]', ADMIN_TOKEN: token, ...bindings } });
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
    assert.equal((await fetch(`/${anyLink.shortened}`)).status, 302);
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
