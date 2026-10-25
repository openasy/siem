import { mkdirSync } from "node:fs";
import { dirname } from "node:path";
import { DatabaseSync } from "node:sqlite";

// Forward-only migrations (ADR 0010): append new entries, never edit or remove old ones.
const MIGRATIONS = [
  `CREATE TABLE settings (key TEXT PRIMARY KEY, value TEXT NOT NULL);
   -- Security events as they arrived: the fields are kept as sent, flat, and searched in place (ADR 0040).
   CREATE TABLE events (
     id INTEGER PRIMARY KEY AUTOINCREMENT,
     time TEXT NOT NULL,
     host TEXT,
     source TEXT,
     message TEXT,
     fields TEXT NOT NULL,
     received_at TEXT NOT NULL
   );
   CREATE INDEX events_time ON events (time);
   CREATE INDEX events_host ON events (host, time);
   -- Detection rules, as written (Sigma YAML or JSON). The source is the truth; it is compiled again on start.
   CREATE TABLE rules (
     id TEXT PRIMARY KEY,
     title TEXT NOT NULL,
     level TEXT NOT NULL CHECK (level IN ('critical', 'high', 'medium', 'low')),
     enabled INTEGER NOT NULL DEFAULT 1,
     source TEXT NOT NULL,
     matches INTEGER NOT NULL DEFAULT 0,
     last_match_at TEXT,
     last_error TEXT,
     created_by TEXT,
     created_at TEXT NOT NULL,
     updated_at TEXT NOT NULL
   );
   -- A signal is what a rule found on one host within a window: the events are summed up, not repeated.
   CREATE TABLE signals (
     id TEXT PRIMARY KEY,
     rule_id TEXT REFERENCES rules (id) ON DELETE SET NULL,
     rule_title TEXT NOT NULL,
     severity TEXT NOT NULL CHECK (severity IN ('critical', 'high', 'medium', 'low')),
     host TEXT NOT NULL,
     status TEXT NOT NULL DEFAULT 'new' CHECK (status IN ('new', 'investigating', 'closed', 'false-positive')),
     reason TEXT,
     changed_by TEXT,
     count INTEGER NOT NULL,
     first_seen TEXT NOT NULL,
     last_seen TEXT NOT NULL,
     samples TEXT NOT NULL
   );
   CREATE INDEX signals_group ON signals (rule_id, host, last_seen);
   CREATE INDEX signals_open ON signals (status, last_seen)`,
  // A signal severe enough opens an incident in OpenAsy Incidents (ADR 0040, 0041). pending until Incidents has it,
  // tried again while it is unreachable; opened with the incident's key and page; failed when it was given up.
  `ALTER TABLE signals ADD COLUMN incident_state TEXT CHECK (incident_state IN ('pending', 'opened', 'failed'));
   ALTER TABLE signals ADD COLUMN incident_key TEXT;
   ALTER TABLE signals ADD COLUMN incident_url TEXT;
   ALTER TABLE signals ADD COLUMN incident_error TEXT;
   CREATE INDEX signals_incident ON signals (incident_state) WHERE incident_state = 'pending'`,
  // The matches a correlation rule reads, per group, kept for a day, its longest timespan (ADR 0040). One event that
  // two of its rules match is one row per rule; counts take each event once.
  `CREATE TABLE correlation_hits (
     correlation_id TEXT NOT NULL REFERENCES rules (id) ON DELETE CASCADE,
     group_key TEXT NOT NULL,
     rule_id TEXT NOT NULL,
     time TEXT NOT NULL,
     event_id INTEGER NOT NULL,
     value TEXT
   );
   CREATE INDEX correlation_hits_group ON correlation_hits (correlation_id, group_key, time)`,
  // siem-agent instances and the hosts they read over SSH, from the install's hosts file (ADR 0040, 0031, 0052). The
  // journal cursor says where the last read stopped; it moves only after its events are kept, so a failed write is
  // read again rather than lost.
  `CREATE TABLE agents (
     id TEXT PRIMARY KEY,
     name TEXT NOT NULL UNIQUE,
     enroll_token_hash TEXT UNIQUE,
     enroll_expires_at TEXT,
     secret_hash TEXT UNIQUE,
     version TEXT,
     ca_public_key TEXT,
     key_public_key TEXT,
     setup TEXT,
     last_seen_at TEXT,
     last_error TEXT,
     created_at TEXT NOT NULL
   );
   CREATE TABLE hosts (
     id TEXT PRIMARY KEY,
     name TEXT NOT NULL UNIQUE,
     agent_id TEXT NOT NULL REFERENCES agents (id),
     address TEXT NOT NULL,
     port INTEGER NOT NULL DEFAULT 22,
     ssh_user TEXT NOT NULL DEFAULT 'openasy',
     auth TEXT NOT NULL CHECK (auth IN ('certificate', 'key')),
     key_file TEXT,
     file_host_key TEXT,
     interval_seconds INTEGER NOT NULL DEFAULT 60,
     host_keys TEXT NOT NULL DEFAULT '[]',
     pending_host_keys TEXT NOT NULL DEFAULT '[]',
     status TEXT NOT NULL DEFAULT 'new',
     status_detail TEXT,
     unreadable TEXT NOT NULL DEFAULT '[]',
     journal_cursor TEXT,
     events_in INTEGER NOT NULL DEFAULT 0,
     last_attempt_at TEXT,
     last_success_at TEXT,
     read_requested INTEGER NOT NULL DEFAULT 0,
     key_requested INTEGER NOT NULL DEFAULT 1,
     lease_until TEXT,
     created_at TEXT NOT NULL
   )`,
];

/** Opens the product's single SQLite file in WAL mode (ADR 0011) and migrates it forward. */
export function openDb(path: string): DatabaseSync {
  if (path !== ":memory:") mkdirSync(dirname(path), { recursive: true });
  const db = new DatabaseSync(path);
  db.exec("PRAGMA journal_mode = WAL; PRAGMA foreign_keys = ON; PRAGMA busy_timeout = 5000;");
  db.exec("CREATE TABLE IF NOT EXISTS schema_migrations (version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL)");
  const row = db.prepare("SELECT COALESCE(MAX(version), 0) AS v FROM schema_migrations").get() as { v: number };
  for (let v = row.v; v < MIGRATIONS.length; v++) {
    db.exec("BEGIN");
    try {
      db.exec(MIGRATIONS[v]!);
      db.prepare("INSERT INTO schema_migrations (version, applied_at) VALUES (?, ?)").run(v + 1, new Date().toISOString());
      db.exec("COMMIT");
    } catch (err) {
      db.exec("ROLLBACK");
      throw err;
    }
  }
  return db;
}
