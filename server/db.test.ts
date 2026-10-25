import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { openDb } from "./db.ts";

describe("openDb", () => {
  it("uses WAL and migrates once", () => {
    const path = join(mkdtempSync(join(tmpdir(), "siem-")), "nested", "siem.db");
    const first = openDb(path);
    expect(first.prepare("PRAGMA journal_mode").get()).toEqual({ journal_mode: "wal" });
    first.close();

    const second = openDb(path);
    expect(second.prepare("SELECT COUNT(*) AS n FROM schema_migrations").get()).toEqual({ n: 4 });
    second.close();
  });

  it("keeps a signal when its rule is deleted", () => {
    const db = openDb(":memory:");
    db.exec(`INSERT INTO rules (id, title, level, source, created_at, updated_at) VALUES ('r', 'T', 'high', 's', 'now', 'now');
      INSERT INTO signals (id, rule_id, rule_title, severity, host, count, first_seen, last_seen, samples) VALUES ('s', 'r', 'T', 'high', 'web-1', 1, 'now', 'now', '[]');
      DELETE FROM rules`);
    expect(db.prepare("SELECT rule_id, rule_title FROM signals").get()).toEqual({ rule_id: null, rule_title: "T" });
  });
});
