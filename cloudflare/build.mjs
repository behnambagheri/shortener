import { readFile, writeFile, mkdir } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { createHash } from "node:crypto";
import path from "node:path";
import postcss from "postcss";
import tailwind from "@tailwindcss/postcss";
import { build } from "esbuild";
import { approvedDomains } from "./policy.mjs";

const root = path.dirname(fileURLToPath(import.meta.url));
const project = path.dirname(root);
const hash = (value) => createHash("sha256").update(value).digest("hex").slice(0, 12);
approvedDomains(JSON.parse(await readFile(path.join(project, "approved_domains.json"), "utf8")));
await mkdir(path.join(root, "generated"), { recursive: true });
await mkdir(path.join(project, "public/assets"), { recursive: true });
const font = await readFile(path.join(project, "ui/fonts/SpaceGrotesk-latin.woff2"));
const fontPath = `/assets/font-${hash(font)}.woff2`;
const source = (await readFile(path.join(root, "styles.css"), "utf8")).replace("__FONT__", fontPath);
const css = (await postcss([tailwind()]).process(source, { from: path.join(root, "styles.css") })).css;
const script = await build({ entryPoints: [path.join(root, "client.mjs")], bundle: true, minify: true, format: "esm", platform: "browser", write: false });
const js = script.outputFiles[0].contents;
const cssPath = `/assets/app-${hash(css)}.css`;
const jsPath = `/assets/app-${hash(js)}.js`;
const files = [[cssPath, Buffer.from(css), "text/css; charset=utf-8"], [jsPath, Buffer.from(js), "application/javascript; charset=utf-8"], [fontPath, font, "font/woff2"]];
const assets = {};
for (const [url, bytes, type] of files) {
  await writeFile(path.join(project, "public", url), bytes);
  assets[url] = { data: bytes.toString("base64"), type };
}
await writeFile(path.join(project, "public/manifest.json"), JSON.stringify({ css_url: cssPath, js_url: jsPath }));
const template = await readFile(path.join(project, "templates/index.html"), "utf8");
const html = template.replace("{{ css_url }}", cssPath).replace("{{ js_url }}", jsPath)
  .replace('{{ page_data|json_script:"page-data" }}', '<script id="page-data" type="application/json">__PAGE_DATA__</script>');
await writeFile(path.join(root, "generated/ui.mjs"), `export const html = ${JSON.stringify(html)};\nexport const assets = ${JSON.stringify(assets)};\n`);
await build({ entryPoints: [path.join(root, "worker.mjs")], outfile: path.join(root, "dist/worker.mjs"), bundle: true, minify: true, format: "esm", platform: "browser", target: "es2022" });
console.log("Built daisyUI frontend, hashed assets, and the Worker.");
