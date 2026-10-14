import { DatabaseSync } from "node:sqlite";
import { migrations } from "../generated/migrations.mjs";

// The subset of the Cloudflare D1 API the shared handler uses, backed by a local SQLite file.
class Statement {
  constructor(db, sql, params = []) { this.db = db; this.sql = sql; this.params = params; }
  bind(...params) { return new Statement(this.db, this.sql, params); }
  async first() { return this.db.prepare(this.sql).get(...this.params) ?? null; }
  async all() { return { success: true, results: this.db.prepare(this.sql).all(...this.params) }; }
  async run() { return this.runSync(); }
  runSync() {
    const result = this.db.prepare(this.sql).run(...this.params);
    return { success: true, meta: { changes: Number(result.changes), last_row_id: Number(result.lastInsertRowid) } };
  }
}

export class SQLiteD1 {
  constructor(file) {
    this.db = new DatabaseSync(file);
    this.db.exec("PRAGMA journal_mode = WAL; PRAGMA busy_timeout = 5000; PRAGMA synchronous = NORMAL;");
  }
  prepare(sql) { return new Statement(this.db, sql); }
  async batch(statements) { return this.transaction(() => statements.map((statement) => statement.runSync())); }
  transaction(work) {
    this.db.exec("BEGIN IMMEDIATE");
    try { const result = work(); this.db.exec("COMMIT"); return result; }
    catch (error) { this.db.exec("ROLLBACK"); throw error; }
  }
  // Applies the same migration files that Wrangler applies to D1, once each.
  migrate() {
    this.db.exec("CREATE TABLE IF NOT EXISTS schema_migrations (name TEXT PRIMARY KEY, applied_at INTEGER NOT NULL)");
    const applied = new Set(this.db.prepare("SELECT name FROM schema_migrations").all().map((row) => row.name));
    const pending = migrations.filter(({ name }) => !applied.has(name));
    for (const { name, sql } of pending) this.transaction(() => {
      this.db.exec(sql);
      this.db.prepare("INSERT INTO schema_migrations (name, applied_at) VALUES (?, ?)").run(name, Math.floor(Date.now() / 1000));
    });
    return pending.map(({ name }) => name);
  }
  close() { this.db.close(); }
}
