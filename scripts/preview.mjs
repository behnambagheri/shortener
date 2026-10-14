import { Miniflare } from "miniflare";
import { migrations } from "../generated/migrations.mjs";

// Local Workers runtime preview with a temporary D1 database. ADMIN_TOKEN enables /admin sign-in.
const port = Number(process.env.PORT || 8787);
const mf = new Miniflare({ modules: true, scriptPath: "dist/worker.mjs", compatibilityDate: "2026-08-01", port,
  d1Databases: ["DB"], bindings: { PUBLIC_ORIGIN: `http://localhost:${port}`, ADMIN_TOKEN: process.env.ADMIN_TOKEN || "local-preview-admin-token" } });
const db = await mf.getD1Database("DB");
for (const { sql } of migrations) for (const statement of sql.split(";").map((part) => part.trim()).filter(Boolean)) await db.prepare(statement).run();
console.log(`Preview: ${await mf.ready} (admin token: ${process.env.ADMIN_TOKEN ? "from ADMIN_TOKEN" : "local-preview-admin-token"})`);
for (const signal of ["SIGINT", "SIGTERM"]) process.on(signal, async () => { await mf.dispose(); process.exit(); });
