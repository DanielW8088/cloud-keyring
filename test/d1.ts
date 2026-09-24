import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { DatabaseSync, type SQLInputValue } from "node:sqlite";

const MIGRATIONS = join(import.meta.dirname, "..", "migrations");

// Every call yields to the event loop like a real D1 round trip, so concurrent
// requests interleave between statements exactly as they can in production.
const roundTrip = () => new Promise<void>((resolve) => setTimeout(resolve, 0));

class TestStatement {
  constructor(
    private readonly database: TestD1,
    readonly sql: string,
    readonly params: SQLInputValue[] = [],
  ) {}

  bind(...params: SQLInputValue[]): TestStatement {
    return new TestStatement(this.database, this.sql, params);
  }

  async all<T>(): Promise<{ results: T[]; success: true; meta: Record<string, never> }> {
    await roundTrip();
    return this.database.execute<T>(this);
  }

  async first<T>(): Promise<T | null> {
    return (await this.all<T>()).results[0] ?? null;
  }

  async run(): Promise<{ results: unknown[]; success: true; meta: Record<string, never> }> {
    return this.all();
  }
}

/** A minimal D1Database backed by node:sqlite, with D1's batch-as-transaction semantics. */
export class TestD1 {
  readonly sqlite = new DatabaseSync(":memory:");

  constructor() {
    this.sqlite.exec("PRAGMA foreign_keys = ON");
  }

  prepare(sql: string): TestStatement {
    return new TestStatement(this, sql);
  }

  async batch(statements: TestStatement[]): Promise<{ results: unknown[] }[]> {
    await roundTrip();
    this.sqlite.exec("BEGIN");
    try {
      const results = statements.map((statement) => this.execute(statement));
      this.sqlite.exec("COMMIT");
      return results;
    } catch (error) {
      this.sqlite.exec("ROLLBACK");
      throw error;
    }
  }

  execute<T>(statement: TestStatement): { results: T[]; success: true; meta: Record<string, never> } {
    const results = this.sqlite.prepare(statement.sql).all(...statement.params) as T[];
    return { results, success: true, meta: {} };
  }

  query<T>(sql: string, ...params: SQLInputValue[]): T[] {
    return this.sqlite.prepare(sql).all(...params) as T[];
  }

  applyMigrations(filter: (name: string) => boolean = () => true): this {
    for (const name of readdirSync(MIGRATIONS).filter((file) => file.endsWith(".sql")).sort()) {
      if (filter(name)) this.sqlite.exec(readFileSync(join(MIGRATIONS, name), "utf8"));
    }
    return this;
  }

  asD1(): D1Database {
    return this as unknown as D1Database;
  }
}
