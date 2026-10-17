import { createServer } from "node:http";
import { Readable } from "node:stream";
import { mkdirSync } from "node:fs";
import path from "node:path";
import { pathToFileURL } from "node:url";
import { handle } from "../src/app.mjs";
import { adminToken, authMethods } from "../src/auth.mjs";
import { runMaintenance } from "../src/abuse.mjs";
import { SQLiteD1 } from "./sqlite.mjs";

const bindings = ["PUBLIC_ORIGIN", "CANONICAL_ORIGIN", "APPROVED_DOMAINS", "ADMIN_TOKEN", "ACCESS_ISSUER", "ACCESS_AUD", "ADMIN_EMAILS", "DEPLOYMENT_SHA",
  "SESSION_SECRET", "GITHUB_CLIENT_ID", "GITHUB_CLIENT_SECRET", "GOOGLE_CLIENT_ID", "GOOGLE_CLIENT_SECRET", "MIN_ACCOUNT_DAYS",
  "TURNSTILE_SITE_KEY", "TURNSTILE_SECRET_KEY", "SAFE_BROWSING_API_KEY", "URLHAUS_AUTH_KEY", "THREAT_FEED_URLS", "NEW_DOMAIN_DAYS",
  "LINKS_PER_HOUR", "USER_LINKS_PER_DAY", "REPORTS_PER_HOUR", "REPORT_THRESHOLD", "ANONYMOUS_LINK_DAYS", "SPIKE_CLICKS",
  "ABUSE_EMAIL", "ALERT_WEBHOOK_URL", "TELEGRAM_BOT_TOKEN", "TELEGRAM_CHAT_ID"];
const maintenanceInterval = 3 * 60 * 60 * 1000;

export function serverConfig(env = process.env) {
  const port = Number(env.PORT || 8080);
  if (!Number.isInteger(port) || port < 0 || port > 65535) throw new Error("Invalid PORT.");
  for (const name of ["PUBLIC_ORIGIN", "CANONICAL_ORIGIN"]) {
    if (env[name] && !/^https?:\/\/[^/?#\s]+\/?$/.test(env[name])) throw new Error(`${name} must be an origin such as https://s.example.com.`);
  }
  const values = Object.fromEntries(bindings.filter((name) => env[name] !== undefined && env[name] !== "").map((name) => [name, env[name]]));
  // CLIENT_IP_HEADER names a header set by a trusted reverse proxy, such as cf-connecting-ip or x-forwarded-for.
  const clientIpHeader = (env.CLIENT_IP_HEADER || "").trim().toLowerCase() || null;
  if (clientIpHeader && !/^[a-z0-9-]+$/.test(clientIpHeader)) throw new Error("CLIENT_IP_HEADER must be a header name.");
  return { port, host: env.HOST || "0.0.0.0", dataDir: env.DATA_DIR || "/var/lib/shortener", values, clientIpHeader,
    maintenance: env.MAINTENANCE !== "off" };
}

function hostHeader(value) {
  return typeof value === "string" && /^[A-Za-z0-9.-]+(?::\d{1,5})?$|^\[[0-9A-Fa-f:.]+\](?::\d{1,5})?$/.test(value) ? value : "localhost";
}

function clientIp(incoming, header) {
  // Proxies append to x-forwarded-for, so the last entry is the one the trusted proxy added.
  const value = header ? incoming.headers[header] : undefined;
  const forwarded = (Array.isArray(value) ? value.at(-1) : value)?.split(",").at(-1).trim();
  return forwarded || incoming.socket.remoteAddress?.replace(/^::ffff:/, "") || null;
}

export function createHTTPServer(env, { clientIpHeader = null } = {}) {
  return createServer({ requestTimeout: 15000, headersTimeout: 10000, maxHeaderSize: 16384 }, async (incoming, outgoing) => {
    try {
      // Use only the path from the request target; the handler never fetches the Host.
      if (!incoming.url.startsWith("/")) { outgoing.writeHead(400); outgoing.end(); return; }
      const headers = new Headers();
      for (const [key, value] of Object.entries(incoming.headers)) if (value !== undefined) headers.set(key, Array.isArray(value) ? value.join(", ") : value);
      const body = ["GET", "HEAD"].includes(incoming.method) ? undefined : Readable.toWeb(incoming);
      const request = new Request(`http://${hostHeader(incoming.headers.host)}${incoming.url}`, { method: incoming.method, headers, body, duplex: "half" });
      const response = await handle(request, env, { waitUntil() {} }, { clientIp: clientIp(incoming, clientIpHeader) });
      const responseHeaders = Object.fromEntries(response.headers);
      // Headers.entries() joins repeated Set-Cookie headers; Node needs them separately.
      if (response.headers.getSetCookie().length > 1) responseHeaders["set-cookie"] = response.headers.getSetCookie();
      outgoing.writeHead(response.status, responseHeaders);
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
  const server = createHTTPServer(values, config);
  await new Promise((resolve, reject) => { server.once("error", reject); server.listen(config.port, config.host, resolve); });
  const methods = authMethods(values);
  console.log(`Shortener listening on port ${server.address().port}; admin sign-in: ${[methods.token && "token", methods.access && "Cloudflare Access"].filter(Boolean).join(", ") || "disabled"}.`);
  // The container's equivalent of the Worker cron trigger: first run after a minute, then every three hours.
  const maintain = () => runMaintenance(values).catch(() => {});
  const timers = config.maintenance ? [setTimeout(maintain, 60000), setInterval(maintain, maintenanceInterval)] : [];
  for (const timer of timers) timer.unref();
  return {
    server, db,
    async close() {
      for (const timer of timers) clearTimeout(timer);
      server.closeIdleConnections(); await new Promise((resolve) => server.close(resolve)); db.close();
    },
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
