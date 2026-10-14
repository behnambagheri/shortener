import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import { readFile } from "node:fs/promises";

const origin = (process.argv[2] || "https://s.bea.sh").replace(/\/$/, "");
const expectedRelease = process.argv[3];
const config = JSON.parse(await readFile(new URL("../wrangler.jsonc", import.meta.url)));
const slug = `qa-${randomBytes(8).toString("hex")}`;
const request = (path, options = {}) => fetch(origin + path, { redirect: "manual", signal: AbortSignal.timeout(10000), ...options });
const post = (data) => request("/api/links", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(data) });
async function waitForRelease() {
  const deadline = Date.now() + 60000;
  let lastError;
  do {
    try {
      const health = await request("/.well-known/health");
      assert.equal(health.status, 200);
      const state = await health.json(); assert.equal(state.status, "ok");
      if (expectedRelease) assert.equal(state.release, expectedRelease);
      return state;
    } catch (error) { lastError = error; }
    if (Date.now() >= deadline) break;
    await new Promise(resolve => setTimeout(resolve, 3000));
  } while (Date.now() < deadline);
  throw lastError;
}
let created = false;
try {
  await waitForRelease();
  const policy = await request("/api/config"); assert.equal(policy.status, 200);
  assert.ok((await policy.json()).approved_domains.includes("bea.sh"));
  const home = await request("/"); assert.equal(home.status, 200);
  const html = await home.text(); assert.ok(html.includes("Short links"));
  for (const path of [...html.matchAll(/(?:src|href)="(\/assets\/[^"<>]+)"/g)].map(match => match[1])) assert.equal((await request(path)).status, 200);
  const original = `https://bea.sh/?shortener-check=${slug}`;
  const result = await post({original, shortened:slug}); assert.equal(result.status, 201); created = true;
  assert.equal((await result.json()).short_url, `https://s.bea.sh/${slug}`);
  const redirect = await request(`/${slug}`); assert.equal(redirect.status, 302); assert.equal(redirect.headers.get("Location"), original);
  assert.equal((await post({original:"https://bea.sh/",shortened:slug})).status,409);
  for (const original of ["https://unapproved.example/", "https://bea.sh.evil.example/", "https://evilbea.sh/"]) assert.equal((await post({original})).status,403);
  assert.equal((await post({original:"https://person:password@bea.sh/"})).status,400);
  console.log(`Live checks passed: UI/assets, domain rules, create/redirect, duplicate protection${expectedRelease ? ", release " + expectedRelease : ""}.`);
} finally {
  if (created) {
    const token = process.env.CLOUDFLARE_API_TOKEN;
    if (!token) throw new Error("CLOUDFLARE_API_TOKEN is required to remove the smoke fixture.");
    const response = await fetch(`https://api.cloudflare.com/client/v4/accounts/${config.account_id}/d1/database/${config.d1_databases[0].database_id}/query`, {
      method:"POST", headers:{Authorization:`Bearer ${token}`,"Content-Type":"application/json"},
      body:JSON.stringify({sql:"DELETE FROM links WHERE slug = ? AND original = ?",params:[slug, `https://bea.sh/?shortener-check=${slug}`]}) });
    const result = await response.json(); assert.ok(response.ok && result.success, "Unable to remove the smoke fixture.");
  }
}
