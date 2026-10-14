import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { startServer, serverConfig } from "../dist/server.mjs";

const token = "container-admin-token-0123456789";

test("server configuration validates and ignores empty values", () => {
  const config = serverConfig({ PORT: "9000", PUBLIC_ORIGIN: "https://s.example.com", APPROVED_DOMAINS: "", ADMIN_TOKEN: token });
  assert.equal(config.port, 9000);
  assert.deepEqual(config.values, { PUBLIC_ORIGIN: "https://s.example.com", ADMIN_TOKEN: token });
  assert.throws(() => serverConfig({ PORT: "70000" }));
  assert.throws(() => serverConfig({ PUBLIC_ORIGIN: "https://s.example.com/path" }));
  assert.equal(serverConfig({ CLIENT_IP_HEADER: " X-Forwarded-For " }).clientIpHeader, "x-forwarded-for");
  assert.throws(() => serverConfig({ CLIENT_IP_HEADER: "bad header" }));
});

test("container server: rate limits use the trusted proxy's client address", async () => {
  const dataDir = await mkdtemp(path.join(tmpdir(), "shortener-"));
  const service = await startServer({ PORT: "0", HOST: "127.0.0.1", DATA_DIR: dataDir, APPROVED_DOMAINS: "example.com", LINKS_PER_HOUR: "1",
    CLIENT_IP_HEADER: "x-forwarded-for", MAINTENANCE: "off" });
  try {
    const create = (forwarded) => fetch(`http://127.0.0.1:${service.server.address().port}/api/links`, { method: "POST",
      headers: { "Content-Type": "application/json", "X-Forwarded-For": forwarded }, body: JSON.stringify({ original: "https://example.com/" }) });
    assert.equal((await create("192.0.2.1")).status, 201);
    assert.equal((await create("192.0.2.1")).status, 429);
    // A client-supplied first entry does not change the bucket; the proxy's last entry does.
    assert.equal((await create("192.0.2.9, 192.0.2.1")).status, 429);
    assert.equal((await create("192.0.2.1, 192.0.2.2")).status, 201);
  } finally {
    await service.close();
    await rm(dataDir, { recursive: true, force: true });
  }
});

test("container server: SQLite persistence, admin token sign-in and redirects", async () => {
  const dataDir = await mkdtemp(path.join(tmpdir(), "shortener-"));
  const env = { PORT: "0", HOST: "127.0.0.1", DATA_DIR: dataDir, ADMIN_TOKEN: token, APPROVED_DOMAINS: "example.com" };
  let service = await startServer(env);
  try {
    const origin = () => `http://127.0.0.1:${service.server.address().port}`;
    const request = (pathname, init = {}) => fetch(origin() + pathname, { redirect: "manual", ...init });
    const health = await (await request("/.well-known/health")).json();
    assert.equal(health.status, "ok"); assert.equal(health.approved_domains_count, 1);
    const created = await request("/api/links", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ original: "https://www.example.com/a", shortened: "persisted" }) });
    assert.equal(created.status, 201);
    assert.equal((await created.json()).short_url, `${origin()}/persisted`);
    assert.equal((await request("/api/links", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ original: "https://bea.sh/" }) })).status, 403);
    assert.equal((await request("/api/links", { method: "POST", headers: { "Content-Type": "application/json" }, body: "x".repeat(20000) })).status, 413);

    // Form sign-in without JavaScript, then the JSON API with the session cookie.
    const login = await request("/admin/login", { method: "POST", headers: { "Content-Type": "application/x-www-form-urlencoded" }, body: `token=${token}` });
    assert.equal(login.status, 303);
    const cookie = login.headers.get("set-cookie").split(";")[0];
    assert.doesNotMatch(login.headers.get("set-cookie"), /Secure/);
    const settings = await request("/admin/api/settings", { method: "PUT", headers: { Cookie: cookie, "Content-Type": "application/json", Origin: origin() }, body: JSON.stringify({ approved_domains: ["example.com", "example.org"] }) });
    assert.equal(settings.status, 200);
    assert.equal((await request("/api/links", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ original: "https://example.org/" }) })).status, 201);
    assert.equal((await request("/admin/api/overview", { headers: { Authorization: `Bearer ${token}` } })).status, 200);
    const head = await request("/persisted", { method: "HEAD" });
    assert.equal(head.status, 302); assert.equal(await head.text(), "");

    // Restart with the same data directory: links, clicks and settings survive.
    assert.equal((await request("/persisted")).status, 302);
    await service.close();
    service = await startServer(env);
    const redirect = await request("/persisted");
    assert.equal(redirect.status, 302); assert.equal(redirect.headers.get("location"), "https://www.example.com/a");
    const links = await (await request("/admin/api/links?q=persisted", { headers: { Authorization: `Bearer ${token}` } })).json();
    assert.equal(links.links[0].clicks, 2);
    assert.deepEqual((await (await request("/api/config")).json()).approved_domains, ["example.com", "example.org"]);
    assert.equal((await request("/admin/api/overview")).status, 401);
  } finally {
    await service.close();
    await rm(dataDir, { recursive: true, force: true });
  }
});
