import { Miniflare } from "miniflare";
import { readFile } from "node:fs/promises";
const mf = new Miniflare({ modules: true, scriptPath: "dist/worker.mjs", compatibilityDate: "2026-08-01", port: 8787,
  d1Databases: ["DB"], bindings: { PUBLIC_ORIGIN: "http://localhost:8787" } });
const db = await mf.getD1Database("DB");
await db.exec((await readFile("migrations/0001_links.sql", "utf8")).replace(/\n/g, " "));
console.log(`Preview: ${await mf.ready}`);
for (const signal of ["SIGINT", "SIGTERM"]) process.on(signal, async () => { await mf.dispose(); process.exit(); });
