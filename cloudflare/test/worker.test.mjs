import { test } from "node:test";
import assert from "node:assert/strict";
import { Miniflare } from "miniflare";
import { readFile } from "node:fs/promises";
import { approvedDomains, destination, alias } from "../policy.mjs";

test("domain policy accepts subdomains and rejects authority spoofing", () => {
  const domains = approvedDomains(["BEA.sh", "behnam.pro"]);
  assert.equal(destination("HTTPS://IP.BEA.SH/path?q=1#ok", domains), "https://ip.bea.sh/path?q=1#ok");
  for (const url of ["https://evilbea.sh", "https://bea.sh.evil.com", "https://bea.sh@evil.com", "https://u:p@bea.sh", "javascript:alert(1)", "//bea.sh", "https://bea.sh\\@evil.com", "https://bea.sh\n"]) assert.throws(() => destination(url, domains), url);
  assert.throws(() => destination("https://s.bea.sh/a", domains, ["s.bea.sh"]));
  for (const bad of [[], "", ["*.bea.sh"], ["bea.sh/path"], ["127.0.0.1"], "[bad"]) assert.throws(() => approvedDomains(bad));
  for (const bad of ["api", "Assets", "../x", "a".repeat(64)]) assert.throws(() => alias(bad));
});

test("D1 integration: creation, immutable aliases, current policy and assets", async () => {
  const mf = new Miniflare({ modules: true, scriptPath: "dist/worker.mjs", compatibilityDate: "2026-08-01",
    d1Databases: ["DB"], bindings: { PUBLIC_ORIGIN: "https://s.bea.sh", APPROVED_DOMAINS: '["bea.sh","behnam.pro"]' } });
  try {
    const db = await mf.getD1Database("DB");
    await db.exec((await readFile("migrations/0001_links.sql", "utf8")).replace(/\n/g, " "));
    const post = (body, path = "/api/links", headers = {}) => mf.dispatchFetch(`https://s.bea.sh${path}`, { method: "POST", headers: { "Content-Type": "application/json", ...headers }, body: JSON.stringify(body) });
    const created = await post({ original: "https://ip.bea.sh/?x=1", shortened: "example" });
    assert.equal(created.status, 201); assert.equal((await created.json()).short_url, "https://s.bea.sh/example");
    const race = await Promise.all([post({original:"https://bea.sh/a",shortened:"race"}), post({original:"https://bea.sh/b",shortened:"race"})]);
    assert.deepEqual(race.map(r=>r.status).sort(), [201,409]);
    assert.equal((await post({ original: "https://bea.sh/other", shortened: "example" })).status, 409);
    const redirect = await mf.dispatchFetch("https://s.bea.sh/example", { redirect: "manual" });
    assert.equal(redirect.status, 302); assert.equal(redirect.headers.get("location"), "https://ip.bea.sh/?x=1");
    assert.equal(redirect.headers.get("cache-control"), "no-store");
    assert.equal((await post({original:"https://unapproved.example/"})).status, 403);
    assert.equal((await post({original:"https://bea.sh/",shortened:"api"})).status, 400);
    assert.equal((await post({original:"https://bea.sh/",padding:"x".repeat(9000)})).status, 413);
    await db.prepare("INSERT INTO links VALUES (?, ?, ?)").bind("revoked", "https://evil.example/", 0).run();
    assert.equal((await mf.dispatchFetch("https://s.bea.sh/revoked")).status, 403);
    assert.equal((await mf.dispatchFetch("https://s.bea.sh/missing")).status, 404);
    const injected = await post({original:"https://evil.example/</script><script>alert(1)</script>"}, "/");
    const html = await injected.text(); assert.ok(!html.includes("<script>alert(1)</script>"));
    const home = await mf.dispatchFetch("https://s.bea.sh/"); const body = await home.text();
    const css = body.match(/href="(\/assets\/app-[^"]+\.css)"/)[1];
    const asset = await mf.dispatchFetch(`https://s.bea.sh${css}`); assert.equal(asset.status, 200); assert.ok((await asset.text()).includes(".btn"));
    const head = await mf.dispatchFetch("https://s.bea.sh/example", {method:"HEAD",redirect:"manual"}); assert.equal(head.status, 302); assert.equal(await head.text(), "");
    assert.equal((await (await mf.dispatchFetch("https://s.bea.sh/.well-known/health")).json()).status,"ok");
    await mf.setOptions({ modules: true, scriptPath: "dist/worker.mjs", compatibilityDate: "2026-08-01", d1Databases:["DB"], bindings: {APPROVED_DOMAINS:"[]"} });
    assert.equal((await mf.dispatchFetch("https://s.bea.sh/api/config")).status, 503);
  } finally { await mf.dispose(); }
});
