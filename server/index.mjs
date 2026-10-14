import { createServer } from "node:http";
import { Readable } from "node:stream";
import { mkdirSync } from "node:fs";
import path from "node:path";
import { pathToFileURL } from "node:url";
import { handle } from "../src/app.mjs";
import { adminToken, authMethods } from "../src/auth.mjs";
import { SQLiteD1 } from "./sqlite.mjs";

const bindings = ["PUBLIC_ORIGIN", "APPROVED_DOMAINS", "ADMIN_TOKEN", "ACCESS_ISSUER", "ACCESS_AUD", "ADMIN_EMAILS", "DEPLOYMENT_SHA"];

export function serverConfig(env = process.env) {
  const port = Number(env.PORT || 8080);
  if (!Number.isInteger(port) || port < 0 || port > 65535) throw new Error("Invalid PORT.");
  if (env.PUBLIC_ORIGIN && !/^https?:\/\/[^/?#\s]+\/?$/.test(env.PUBLIC_ORIGIN)) throw new Error("PUBLIC_ORIGIN must be an origin such as https://s.example.com.");
  const values = Object.fromEntries(bindings.filter((name) => env[name] !== undefined && env[name] !== "").map((name) => [name, env[name]]));
  return { port, host: env.HOST || "0.0.0.0", dataDir: env.DATA_DIR || "/var/lib/shortener", values };
}

function hostHeader(value) {
  return typeof value === "string" && /^[A-Za-z0-9.-]+(?::\d{1,5})?$|^\[[0-9A-Fa-f:.]+\](?::\d{1,5})?$/.test(value) ? value : "localhost";
}

export function createHTTPServer(env) {
  return createServer({ requestTimeout: 15000, headersTimeout: 10000, maxHeaderSize: 16384 }, async (incoming, outgoing) => {
    try {
      // Use only the path from the request target; the handler never fetches the Host.
      if (!incoming.url.startsWith("/")) { outgoing.writeHead(400); outgoing.end(); return; }
      const headers = new Headers();
      for (const [key, value] of Object.entries(incoming.headers)) if (value !== undefined) headers.set(key, Array.isArray(value) ? value.join(", ") : value);
      const body = ["GET", "HEAD"].includes(incoming.method) ? undefined : Readable.toWeb(incoming);
      const request = new Request(`http://${hostHeader(incoming.headers.host)}${incoming.url}`, { method: incoming.method, headers, body, duplex: "half" });
      const response = await handle(request, env, { waitUntil() {} });
      outgoing.writeHead(response.status, Object.fromEntries(response.headers));
      outgoing.end(response.body ? Buffer.from(await response.arrayBuffer()) : undefined);
    } catch {
      if (!outgoing.headersSent) outgoing.writeHead(500, { "Content-Type": "application/json; charset=utf-8", "Cache-Control": "no-store" });
      outgoing.end('{"error":"Request could not be processed."}');
    }
  });
}

export async function startServer(env = process.env) {
  const config = serverConfig(env);
  mkdirSync(config.dataDir, { recursive: true });
  const db = new SQLiteD1(path.join(config.dataDir, "shortener.sqlite3"));
  const applied = db.migrate();
  if (applied.length) console.log(`Applied migrations: ${applied.join(", ")}`);
  const values = { ...config.values, DB: db };
  if (env.ADMIN_TOKEN && !adminToken(values)) console.warn("ADMIN_TOKEN is shorter than 16 characters; token sign-in is disabled.");
  const server = createHTTPServer(values);
  await new Promise((resolve, reject) => { server.once("error", reject); server.listen(config.port, config.host, resolve); });
  const methods = authMethods(values);
  console.log(`Shortener listening on port ${server.address().port}; admin sign-in: ${[methods.token && "token", methods.access && "Cloudflare Access"].filter(Boolean).join(", ") || "disabled"}.`);
  return {
    server, db,
    async close() { server.closeIdleConnections(); await new Promise((resolve) => server.close(resolve)); db.close(); },
  };
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  try {
    const service = await startServer();
    for (const signal of ["SIGTERM", "SIGINT"]) process.once(signal, async () => { await service.close(); process.exit(0); });
  } catch (error) {
    console.error(`Shortener could not start: ${error.message}`);
    process.exitCode = 1;
  }
}
