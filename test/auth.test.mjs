import { test } from "node:test";
import assert from "node:assert/strict";
import { generateKeyPair, exportJWK, SignJWT, createLocalJWKSet } from "jose";
import { authenticate } from "../src/auth.mjs";

const env = { ACCESS_ISSUER: "https://bea.cloudflareaccess.com", ACCESS_AUD: "audience-tag", ADMIN_EMAILS: "Admin@Example.com, other@example.com" };

test("Cloudflare Access JWTs authenticate only allowlisted administrators", async () => {
  const { publicKey, privateKey } = await generateKeyPair("RS256");
  const keySet = createLocalJWKSet({ keys: [{ ...await exportJWK(publicKey), kid: "k1", alg: "RS256" }] });
  const sign = (claims, options = {}) => new SignJWT({ email: "admin@example.com", ...claims }).setProtectedHeader({ alg: "RS256", kid: "k1" })
    .setIssuer(options.issuer || env.ACCESS_ISSUER).setAudience(options.audience || env.ACCESS_AUD).setSubject("user").setIssuedAt()
    .setExpirationTime(options.expires || "5m").sign(privateKey);
  const check = async (jwt, overrides = env) => authenticate(new Request("https://s.bea.sh/admin", { headers: { "Cf-Access-Jwt-Assertion": jwt } }), overrides, { keySet });
  assert.deepEqual(await check(await sign({})), { method: "access", email: "admin@example.com" });
  assert.equal(await check(await sign({ email: "intruder@example.com" })), null);
  assert.equal(await check(await sign({}, { audience: "other" })), null);
  assert.equal(await check(await sign({}, { issuer: "https://evil.cloudflareaccess.com" })), null);
  assert.equal(await check(await sign({}, { expires: Math.floor(Date.now() / 1000) - 60 })), null);
  assert.equal(await check("not-a-jwt"), null);
  // Without full configuration, Access identities are ignored.
  assert.equal(await check(await sign({}), { ...env, ADMIN_EMAILS: "" }), null);
  assert.equal(await check(await sign({}), { ...env, ACCESS_ISSUER: "https://example.com" }), null);
});
