import { readFile, writeFile, mkdir, readdir } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { createHash } from "node:crypto";
import path from "node:path";
import postcss from "postcss";
import tailwind from "@tailwindcss/postcss";
import { build } from "esbuild";
import { approvedDomains } from "../src/policy.mjs";

// One build feeds both runtimes: the Cloudflare Worker and the Node container server.
const project = path.dirname(path.dirname(fileURLToPath(import.meta.url)));
const at = (...parts) => path.join(project, ...parts);
const hash = (value) => createHash("sha256").update(value).digest("hex").slice(0, 12);
approvedDomains(JSON.parse(await readFile(at("approved_domains.json"), "utf8")));
await mkdir(at("generated"), { recursive: true });

const font = await readFile(at("ui/fonts/SpaceGrotesk-latin.woff2"));
const fontPath = `/assets/font-${hash(font)}.woff2`;
const source = (await readFile(at("src/styles.css"), "utf8")).replace("__FONT__", fontPath);
const css = Buffer.from((await postcss([tailwind()]).process(source, { from: at("src/styles.css") })).css);
const bundle = async (entry) => (await build({ entryPoints: [at(entry)], bundle: true, minify: true, format: "esm", platform: "browser", target: "es2022", write: false })).outputFiles[0].contents;
const js = await bundle("src/client.mjs");
const adminJs = await bundle("src/admin-client.mjs");
const paths = { css: `/assets/app-${hash(css)}.css`, js: `/assets/app-${hash(js)}.js`, admin: `/assets/admin-${hash(adminJs)}.js` };
const assets = {};
for (const [url, bytes, type] of [[paths.css, css, "text/css; charset=utf-8"], [paths.js, js, "application/javascript; charset=utf-8"],
  [paths.admin, adminJs, "application/javascript; charset=utf-8"], [fontPath, font, "font/woff2"]]) {
  assets[url] = { data: Buffer.from(bytes).toString("base64"), type };
}
const template = async (name) => (await readFile(at("templates", name), "utf8"))
  .replace("{{ css_url }}", paths.css).replace("{{ js_url }}", paths.js).replace("{{ admin_js_url }}", paths.admin);
await writeFile(at("generated/ui.mjs"), `export const html = ${JSON.stringify(await template("index.html"))};\n` +
  `export const adminHtml = ${JSON.stringify(await template("admin.html"))};\nexport const assets = ${JSON.stringify(assets)};\n`);

// The container applies the same migration files Wrangler applies to D1.
const names = (await readdir(at("migrations"))).filter((name) => /^\d{4}_[\w-]+\.sql$/.test(name)).sort();
const migrations = await Promise.all(names.map(async (name) => ({ name, sql: await readFile(at("migrations", name), "utf8") })));
await writeFile(at("generated/migrations.mjs"), `export const migrations = ${JSON.stringify(migrations)};\n`);

await build({ entryPoints: [at("src/worker.mjs")], outfile: at("dist/worker.mjs"), bundle: true, minify: true, format: "esm",
  platform: "browser", conditions: ["workerd", "worker", "browser"], target: "es2022" });
await build({ entryPoints: [at("server/index.mjs")], outfile: at("dist/server.mjs"), bundle: true, format: "esm", platform: "node", target: "node24" });
console.log("Built the daisyUI frontend, the Cloudflare Worker, and the container server.");
