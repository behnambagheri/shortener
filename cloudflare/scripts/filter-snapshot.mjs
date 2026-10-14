// Private migration artifacts belong outside the repository.
import { spawn } from "node:child_process";
import { createInterface } from "node:readline";
import { writeFile, readFile } from "node:fs/promises";
import path from "node:path";
import { approvedDomains, destination, alias } from "../policy.mjs";

const folder = process.argv[2];
if (!folder || !path.isAbsolute(folder)) throw new Error("Provide a private absolute snapshot directory.");
const domains = approvedDomains(JSON.parse(await readFile(new URL("../../approved_domains.json", import.meta.url))));
const code = `import sqlite3,json,sys
c=sqlite3.connect('file:'+sys.argv[1]+'?mode=ro',uri=True)
print(json.dumps({'rows':c.execute('SELECT COUNT(*) FROM app_url').fetchone()[0]}))
for row in c.execute('SELECT u.id,u.original,u.shortened FROM app_url u JOIN (SELECT MAX(id) id FROM app_url GROUP BY shortened) latest ON u.id=latest.id ORDER BY u.id'):
 print(json.dumps(row))`;
const proc = spawn(process.env.PYTHON || "python3", ["-c", code, path.join(folder, "source.sqlite3")], { stdio: ["ignore", "pipe", "inherit"] });
const done = new Promise((resolve, reject) => { proc.on("error", reject); proc.on("close", code => code === 0 ? resolve() : reject(new Error("Snapshot reader failed."))); });
const stats = { source_rows: 0, unique_names: 0, imported: 0, excluded_destination: 0, excluded_name: 0 };
const entries = []; const statements = [];
const quote = (value) => `'${value.replace(/'/g, "''")}'`;
for await (const line of createInterface({ input: proc.stdout })) {
  const row = JSON.parse(line);
  if (!Array.isArray(row)) { stats.source_rows = row.rows; continue; }
  stats.unique_names++;
  const [id, original, shortened] = row;
  let normalized;
  try { normalized = destination(original, domains, ["s.bea.sh", "bea-shortener.bagheri.workers.dev"]); }
  catch { stats.excluded_destination++; continue; }
  try { alias(shortened); } catch { stats.excluded_name++; continue; }
  entries.push({ id, original: normalized, shortened });
  statements.push(`INSERT INTO links (slug, original, created_at) VALUES (${quote(shortened)}, ${quote(normalized)}, 0) ON CONFLICT(slug) DO UPDATE SET original=excluded.original WHERE links.created_at=0;`);
  stats.imported++;
}
await done;
stats.duplicate_rows = stats.source_rows - stats.unique_names;
await writeFile(path.join(folder, "approved-entries.json"), JSON.stringify(entries), { mode: 0o600 });
await writeFile(path.join(folder, "import.sql"), statements.join("\n"), { mode: 0o600 });
await writeFile(path.join(folder, "summary.json"), JSON.stringify(stats, null, 2), { mode: 0o600 });
console.log(JSON.stringify(stats));
