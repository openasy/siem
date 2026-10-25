import { randomUUID } from "node:crypto";
import type { DatabaseSync, SQLInputValue } from "node:sqlite";
import type { IncidentsLink } from "./incidents.ts";
import { compileRule, fieldValue, fires, MAX_TIMESPAN_MS, SigmaError, type Event, type Hit, type Level, type Rule } from "./sigma.ts";

export type ProblemCode =
  | "invalid-token"
  | "invalid-json"
  | "invalid-body"
  | "invalid-event"
  | "invalid-rule"
  | "not-found"
  | "conflict"
  | "not-configured"
  | "payload-too-large"
  | "internal-error";

export class SiemError extends Error {
  readonly status: number;
  readonly code: ProblemCode;
  constructor(status: number, code: ProblemCode, detail: string) {
    super(detail);
    this.status = status;
    this.code = code;
  }
}

export type Status = "new" | "investigating" | "closed" | "false-positive";
export const LEVELS: Level[] = ["critical", "high", "medium", "low"];
const STATUSES: Status[] = ["new", "investigating", "closed", "false-positive"];
const RANK_SQL = `CASE severity WHEN 'critical' THEN 4 WHEN 'high' THEN 3 WHEN 'medium' THEN 2 ELSE 1 END`;

/** Events in one request, fields in one event, and the size of one event once written out. */
export const MAX_EVENTS = 1000;
const MAX_FIELDS = 64;
const MAX_VALUE = 4096;
const MAX_EVENT_BYTES = 16 * 1024;
const MAX_RULE_BYTES = 64 * 1024;
const MAX_RULES = 2000;
const FIELD = /^[A-Za-z_][A-Za-z0-9_.@-]{0,63}$/;
const SAMPLES = 5;

const now = () => new Date().toISOString();
const bad = (detail: string) => new SiemError(422, "invalid-body", detail);
const notFound = (what: string) => new SiemError(404, "not-found", `${what} does not exist.`);

export interface Page<T> {
  items: T[];
  /** Opaque; pass it back as `cursor` for the next page. Absent on the last page (ADR 0024). */
  nextCursor?: string;
}

const encodeCursor = (offset: number) => Buffer.from(JSON.stringify({ o: offset })).toString("base64url");
function decodeCursor(cursor: string | undefined): number {
  if (!cursor) return 0;
  try {
    const o = (JSON.parse(Buffer.from(cursor, "base64url").toString("utf8")) as { o?: unknown }).o;
    if (typeof o === "number" && Number.isSafeInteger(o) && o >= 0) return o;
  } catch {
    // fall through
  }
  throw bad("cursor is not one this API returned.");
}

export function parseLimit(value: string | null, max = 500, fallback = 100): number {
  if (value === null) return fallback;
  const n = Number(value);
  if (!Number.isInteger(n) || n < 1 || n > max) throw bad(`limit must be between 1 and ${max}.`);
  return n;
}

interface NewEvent {
  time: string;
  host: string | null;
  source: string | null;
  message: string | null;
  /** Every field, as sent, with the four above under their own names. */
  fields: Event;
}

/** Checks one event from a request body. `at` says which event of the request, for the message. */
export function parseEvent(raw: unknown, at: string): NewEvent {
  const err = (why: string) => new SiemError(422, "invalid-event", `${at}: ${why}`);
  if (raw === null || typeof raw !== "object" || Array.isArray(raw)) throw err("an event is a JSON object.");
  const entries = Object.entries(raw as Record<string, unknown>);
  if (entries.length > MAX_FIELDS) throw err(`an event may have at most ${MAX_FIELDS} fields.`);
  const fields: Event = {};
  for (const [k, v] of entries) {
    if (!FIELD.test(k)) throw err(`the field name "${k.slice(0, 40)}" is not allowed; use letters, digits, . _ @ and -, starting with a letter.`);
    if (v !== null && typeof v !== "string" && typeof v !== "number" && typeof v !== "boolean")
      throw err(`"${k}" must be text, a number, true/false or null; events are flat.`);
    if (typeof v === "string" && v.length > MAX_VALUE) throw err(`"${k}" may have at most ${MAX_VALUE} characters.`);
    fields[k] = v;
  }
  let time = now();
  if (fields.time !== undefined && fields.time !== null) {
    const t = typeof fields.time === "number" ? fields.time : Date.parse(String(fields.time));
    if (!Number.isFinite(t)) throw err('"time" must be an ISO 8601 date or a number of milliseconds since 1970.');
    if (t > Date.now() + 86_400_000) throw err('"time" is more than a day in the future.');
    time = new Date(t).toISOString();
  }
  fields.time = time;
  const text = (name: string) => {
    const v = fields[name];
    if (v === undefined || v === null) return null;
    if (typeof v !== "string") throw err(`"${name}" must be text.`);
    return v.trim() || null;
  };
  const event = { time, host: text("host"), source: text("source"), message: text("message"), fields };
  if (Buffer.byteLength(JSON.stringify(fields)) > MAX_EVENT_BYTES) throw err(`an event may have at most ${MAX_EVENT_BYTES / 1024} KiB.`);
  return event;
}

export interface SiemOptions {
  /** Events, and signals nobody is working on, older than this are deleted (ADR 0015). */
  retentionDays?: number;
  /** Matches of one rule on one host closer together than this are one signal. */
  windowMinutes?: number;
  /** Reads a rule's text. Tests replace it with one that fails, to show a failing rule does not stop ingest. */
  compile?: (source: string) => Rule;
  /** Opens an incident in OpenAsy Incidents for each new signal this severe or more (ADR 0041). */
  incidents?: {
    link: IncidentsLink;
    minSeverity: Level;
    /** The signal's page in siem, linked from the incident. */
    signalUrl: (id: string) => string;
  };
}

/** A signal's incident is tried again while Incidents is unreachable, for a day at most. */
const INCIDENT_TRIES_MS = 86_400_000;
const RANK: Record<Level, number> = { critical: 4, high: 3, medium: 2, low: 1 };

interface EventRow {
  id: number;
  time: string;
  host: string | null;
  source: string | null;
  message: string | null;
  fields: string;
  received_at: string;
}

export function createSiem(db: DatabaseSync, { retentionDays = 30, windowMinutes = 60, compile: compileText = compileRule, incidents }: SiemOptions = {}) {
  /** Enabled detection rules, compiled: each makes signals of its own. A rule that no longer compiles is left out and says why. */
  const compiled = new Map<string, Rule>();
  /** Detection rules an enabled correlation reads, switched on or off: their matches feed it. */
  const bases = new Map<string, Rule>();
  /** Enabled correlation rules, with the ids of the rules they read, in their order. */
  const correlations = new Map<string, { rule: Rule; refs: string[] }>();
  const markError = (id: string, message: string | null) => db.prepare("UPDATE rules SET last_error = ? WHERE id = ?").run(message, id);

  /** The rules a correlation names, by name or id, among the rules here; a name no rule has, or a correlation, says why. */
  function resolve(rule: Rule, all: Map<string, Rule>): string[] {
    return rule.correlation!.rules.map((ref) => {
      const found = [...all].find(([, r]) => r.name === ref || r.id === ref);
      if (!found) throw new SigmaError(`The correlation reads ${ref}, which no rule here has as its name or id.`);
      if (found[1].correlation) throw new SigmaError(`The correlation reads ${ref}, a correlation: a correlation of correlations is not supported yet.`);
      return found[0];
    });
  }

  /** Every rule, compiled again; called on start and after each change, so correlations follow the rules they read. */
  function load() {
    compiled.clear();
    bases.clear();
    correlations.clear();
    const all = new Map<string, Rule>();
    const on = new Set<string>();
    for (const r of db.prepare("SELECT id, source, enabled FROM rules").all() as Array<{ id: string; source: string; enabled: number }>) {
      try {
        all.set(r.id, compileText(r.source));
        if (r.enabled) markError(r.id, null);
      } catch (e) {
        if (r.enabled) markError(r.id, (e as Error).message.slice(0, 500));
      }
      if (r.enabled) on.add(r.id);
    }
    for (const [id, rule] of all) {
      if (!on.has(id)) continue;
      if (!rule.correlation) {
        compiled.set(id, rule);
        continue;
      }
      try {
        const refs = resolve(rule, all);
        correlations.set(id, { rule, refs });
        for (const ref of refs) bases.set(ref, all.get(ref)!);
      } catch (e) {
        markError(id, (e as Error).message.slice(0, 500));
      }
    }
  }
  load();

  /** A correlation's group as people read it: the host alone, or field=value pairs; "all" without group-by. */
  const groupLabel = (fields: string[], values: Array<string | null>) =>
    !fields.length
      ? "all"
      : fields.length === 1 && fields[0] === "host"
        ? (values[0] ?? "unknown")
        : fields.map((f, i) => `${f}=${values[i] ?? "-"}`).join(", ");

  function compile(source: unknown): Rule {
    if (typeof source !== "string" || !source.trim()) throw bad("source is required: the rule as Sigma YAML or JSON.");
    if (Buffer.byteLength(source) > MAX_RULE_BYTES) throw new SiemError(413, "payload-too-large", `A rule may have at most ${MAX_RULE_BYTES / 1024} KiB.`);
    try {
      return compileText(source);
    } catch (e) {
      if (e instanceof SigmaError) throw new SiemError(422, "invalid-rule", e.message);
      throw e;
    }
  }

  const present = (e: EventRow) => {
    const { time: _t, host: _h, source: _s, message: _m, ...rest } = JSON.parse(e.fields) as Event;
    return { id: e.id, time: e.time, host: e.host, source: e.source, message: e.message, fields: rest, receivedAt: e.received_at };
  };

  const presentRule = (r: Record<string, any>) => {
    let meta: Rule | undefined = compiled.get(r.id) ?? correlations.get(r.id)?.rule;
    if (!meta) {
      try {
        meta = compileRule(r.source);
      } catch {
        meta = undefined;
      }
    }
    return {
      id: r.id as string,
      title: r.title as string,
      level: r.level as Level,
      enabled: r.enabled === 1,
      description: meta?.description ?? null,
      tags: meta?.tags ?? [],
      kind: (meta?.correlation ? "correlation" : "detection") as "correlation" | "detection",
      name: meta?.name ?? null,
      source: r.source as string,
      matches: r.matches as number,
      lastMatchAt: (r.last_match_at as string | null) ?? null,
      lastError: (r.last_error as string | null) ?? null,
      createdBy: (r.created_by as string | null) ?? null,
      createdAt: r.created_at as string,
      updatedAt: r.updated_at as string,
    };
  };

  const ruleRow = (id: string) => {
    const r = db.prepare("SELECT * FROM rules WHERE id = ?").get(id) as Record<string, any> | undefined;
    if (!r) throw notFound("The rule");
    return r;
  };

  const presentSignal = (s: Record<string, any>) => ({
    id: s.id as string,
    rule: { id: (s.rule_id as string | null) ?? null, title: s.rule_title as string },
    severity: s.severity as Level,
    host: s.host as string,
    status: s.status as Status,
    reason: (s.reason as string | null) ?? null,
    changedBy: (s.changed_by as string | null) ?? null,
    count: s.count as number,
    firstSeen: s.first_seen as string,
    lastSeen: s.last_seen as string,
    incident: s.incident_state
      ? {
          state: s.incident_state as "pending" | "opened" | "failed",
          key: (s.incident_key as string | null) ?? null,
          url: (s.incident_url as string | null) ?? null,
          error: (s.incident_error as string | null) ?? null,
        }
      : null,
  });

  let delivering: Promise<void> | undefined;
  /**
   * Sends the signals waiting for an incident to Incidents, one at a time. One that fails stays waiting, with why, and
   * is tried again at the next turn, for a day; Incidents keeps one incident per signal however often it is asked.
   */
  function deliverIncidents(): Promise<void> {
    if (!incidents) return Promise.resolve();
    if (delivering) return delivering;
    const run = (async () => {
      const cutoff = new Date(Date.now() - INCIDENT_TRIES_MS).toISOString();
      db.prepare(
        "UPDATE signals SET incident_state = 'failed', incident_error = COALESCE(incident_error, 'Incidents was not reached for a day.') WHERE incident_state = 'pending' AND first_seen < ?",
      ).run(cutoff);
      const waiting = db.prepare("SELECT * FROM signals WHERE incident_state = 'pending' ORDER BY first_seen LIMIT 50").all() as Array<Record<string, any>>;
      for (const s of waiting) {
        try {
          const opened = await incidents.link.open({
            reference: `signal:${s.id}`,
            title: `${s.rule_title} on ${s.host}`,
            severity: s.severity as Level,
            summary: `SIEM: the rule "${s.rule_title}" matched on ${s.host}, first at ${s.first_seen}. The signal lists its first events.`,
            evidence: { title: `SIEM signal: ${s.rule_title} on ${s.host}`, url: incidents.signalUrl(s.id as string) },
          });
          db.prepare("UPDATE signals SET incident_state = 'opened', incident_key = ?, incident_url = ?, incident_error = NULL WHERE id = ?").run(
            opened.key,
            opened.url,
            s.id,
          );
        } catch (err) {
          db.prepare("UPDATE signals SET incident_error = ? WHERE id = ?").run((err as Error).message.slice(0, 300), s.id);
        }
      }
    })();
    // Cleared after it is set, also when there was nothing to send and the run ended at once.
    delivering = run.finally(() => (delivering = undefined));
    return delivering;
  }

  const signalRow = (id: string) => {
    const s = db.prepare("SELECT * FROM signals WHERE id = ?").get(id) as Record<string, any> | undefined;
    if (!s) throw notFound("The signal");
    return s;
  };

  return {
    reload: load,
    deliverIncidents,

    /**
     * Keeps events and runs every enabled rule over them. A rule that fails on an event is noted on the rule and
     * skipped; it never stops events from being kept.
     */
    ingest(body: unknown) {
      const list = Array.isArray(body) ? body : [body];
      if (!list.length) throw bad("Send an event or a non-empty array of events.");
      if (list.length > MAX_EVENTS) throw new SiemError(413, "payload-too-large", `Send at most ${MAX_EVENTS} events in one request.`);
      const events = list.map((e, i) => parseEvent(e, list.length === 1 && !Array.isArray(body) ? "The event" : `Event ${i}`));
      const received = now();
      const touched = new Set<string>();
      let opened = false;
      db.exec("BEGIN IMMEDIATE");
      try {
        const insert = db.prepare("INSERT INTO events (time, host, source, message, fields, received_at) VALUES (?, ?, ?, ?, ?, ?)");
        const find = db.prepare(
          "SELECT id, first_seen, samples FROM signals WHERE rule_id = ? AND host = ? AND status IN ('new', 'investigating') AND last_seen >= ? ORDER BY last_seen DESC LIMIT 1",
        );
        const hit = db.prepare("UPDATE rules SET matches = matches + 1, last_match_at = ? WHERE id = ?");
        const keep = db.prepare("INSERT INTO correlation_hits (correlation_id, group_key, rule_id, time, event_id, value) VALUES (?, ?, ?, ?, ?, ?)");
        const forget = db.prepare("DELETE FROM correlation_hits WHERE correlation_id = ? AND group_key = ? AND time < ?");
        const window = db.prepare(
          "SELECT rule_id AS rule, time, event_id AS event, value FROM correlation_hits WHERE correlation_id = ? AND group_key = ? AND time >= ? AND time <= ? ORDER BY time, rowid LIMIT 10001",
        );
        const failed = new Set<string>();
        /** One signal per rule and host (or correlation group) in the window: a new one, or one more on the open one. */
        const signal = (ruleId: string, rule: Rule, host: string, time: string, eventId: number) => {
          hit.run(received, ruleId);
          const since = new Date(Date.parse(time) - windowMinutes * 60_000).toISOString();
          const open = find.get(ruleId, host, since) as { id: string; first_seen: string; samples: string } | undefined;
          if (open) {
            const samples = JSON.parse(open.samples) as number[];
            if (samples.length < SAMPLES) samples.push(eventId);
            db.prepare("UPDATE signals SET count = count + 1, last_seen = MAX(last_seen, ?), first_seen = MIN(first_seen, ?), samples = ? WHERE id = ?").run(
              time,
              time,
              JSON.stringify(samples),
              open.id,
            );
            touched.add(open.id);
          } else {
            const sid = randomUUID();
            const incident = incidents && RANK[rule.level] >= RANK[incidents.minSeverity] ? "pending" : null;
            db.prepare(
              "INSERT INTO signals (id, rule_id, rule_title, severity, host, count, first_seen, last_seen, samples, incident_state) VALUES (?, ?, ?, ?, ?, 1, ?, ?, ?, ?)",
            ).run(sid, ruleId, rule.title, rule.level, host, time, time, JSON.stringify([eventId]), incident);
            touched.add(sid);
            if (incident) opened = true;
          }
        };
        for (const e of events) {
          const id = Number(insert.run(e.time, e.host, e.source, e.message, JSON.stringify(e.fields), received).lastInsertRowid);
          // Each rule is run once on an event, whether for its own signals, a correlation, or both.
          const results = new Map<string, boolean>();
          const test = (ruleId: string, rule: Rule) => {
            let matched = results.get(ruleId);
            if (matched !== undefined) return matched;
            try {
              matched = rule.matches(e.fields);
            } catch (err) {
              if (!failed.has(ruleId)) (failed.add(ruleId), markError(ruleId, `Failed on an event: ${(err as Error).message}`.slice(0, 500)));
              matched = false;
            }
            results.set(ruleId, matched);
            return matched;
          };
          for (const [ruleId, rule] of compiled) if (test(ruleId, rule)) signal(ruleId, rule, e.host ?? "unknown", e.time, id);
          for (const [cid, { rule, refs }] of correlations) {
            const matched = refs.filter((ref) => test(ref, bases.get(ref)!));
            if (!matched.length) continue;
            const c = rule.correlation!;
            const values = c.groupBy.map((f) => fieldValue(e.fields, f));
            const key = JSON.stringify(values);
            const value = c.condition?.field ? fieldValue(e.fields, c.condition.field) : null;
            for (const ref of matched) keep.run(cid, key, ref, e.time, id, value);
            const from = new Date(Date.parse(e.time) - c.timespanMs).toISOString();
            forget.run(cid, key, new Date(Date.parse(e.time) - MAX_TIMESPAN_MS).toISOString());
            if (fires(c, refs, window.all(cid, key, from, e.time) as unknown as Hit[])) signal(cid, rule, groupLabel(c.groupBy, values), e.time, id);
          }
        }
        db.exec("COMMIT");
      } catch (err) {
        db.exec("ROLLBACK");
        throw err;
      }
      // Incidents is called after the answer is decided, so a slow or absent Incidents never holds back events.
      if (opened) void deliverIncidents();
      return { accepted: events.length, signals: touched.size };
    },

    searchEvents(
      f: { host?: string; source?: string; q?: string; since?: string; until?: string },
      cursor: string | undefined,
      limit: number,
    ): Page<ReturnType<typeof present>> {
      const where: string[] = [];
      const args: SQLInputValue[] = [];
      if (f.host) (where.push("host = ?"), args.push(f.host));
      if (f.source) (where.push("source = ?"), args.push(f.source));
      if (f.since) (where.push("time >= ?"), args.push(f.since));
      if (f.until) (where.push("time <= ?"), args.push(f.until));
      if (f.q) {
        const like = `%${f.q.replace(/[\\%_]/g, "\\$&")}%`;
        where.push("(message LIKE ? ESCAPE '\\' OR fields LIKE ? ESCAPE '\\')");
        args.push(like, like);
      }
      const offset = decodeCursor(cursor);
      const rows = db
        .prepare(`SELECT * FROM events ${where.length ? `WHERE ${where.join(" AND ")}` : ""} ORDER BY time DESC, id DESC LIMIT ? OFFSET ?`)
        .all(...args, limit + 1, offset) as unknown as EventRow[];
      return { items: rows.slice(0, limit).map(present), ...(rows.length > limit && { nextCursor: encodeCursor(offset + limit) }) };
    },

    event(id: number) {
      const e = db.prepare("SELECT * FROM events WHERE id = ?").get(id) as unknown as EventRow | undefined;
      if (!e) throw notFound("The event");
      return present(e);
    },

    // ------------------------------------------------------------ Rules
    createRule(body: Record<string, unknown>, by: string) {
      const { source, enabled = true, ...rest } = body;
      if (Object.keys(rest).length || typeof enabled !== "boolean") throw bad("Expected { source, enabled? }.");
      const rule = compile(source);
      if ((db.prepare("SELECT COUNT(*) AS n FROM rules").get() as { n: number }).n >= MAX_RULES)
        throw new SiemError(409, "conflict", `At most ${MAX_RULES} rules.`);
      const id = randomUUID();
      const at = now();
      db.prepare("INSERT INTO rules (id, title, level, enabled, source, created_by, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)").run(
        id,
        rule.title,
        rule.level,
        enabled ? 1 : 0,
        source as string,
        by,
        at,
        at,
      );
      load();
      return presentRule(ruleRow(id));
    },

    listRules(cursor: string | undefined, limit: number): Page<ReturnType<typeof presentRule>> {
      const offset = decodeCursor(cursor);
      const rows = db.prepare("SELECT * FROM rules ORDER BY title, id LIMIT ? OFFSET ?").all(limit + 1, offset) as Array<Record<string, any>>;
      return { items: rows.slice(0, limit).map(presentRule), ...(rows.length > limit && { nextCursor: encodeCursor(offset + limit) }) };
    },

    rule: (id: string) => presentRule(ruleRow(id)),

    updateRule(id: string, body: Record<string, unknown>) {
      const current = ruleRow(id);
      const { source, enabled, ...rest } = body;
      if (Object.keys(rest).length || (source === undefined && enabled === undefined)) throw bad("Expected { source?, enabled? }.");
      if (enabled !== undefined && typeof enabled !== "boolean") throw bad("enabled must be true or false.");
      const next = source === undefined ? undefined : compile(source);
      const on = enabled === undefined ? current.enabled === 1 : enabled;
      db.prepare("UPDATE rules SET enabled = ?, source = ?, title = ?, level = ?, last_error = NULL, updated_at = ? WHERE id = ?").run(
        on ? 1 : 0,
        next ? (source as string) : current.source,
        next?.title ?? current.title,
        next?.level ?? current.level,
        now(),
        id,
      );
      if (on && !next) {
        try {
          compileText(current.source);
        } catch (e) {
          throw new SiemError(422, "invalid-rule", (e as Error).message);
        }
      }
      load();
      return presentRule(ruleRow(id));
    },

    deleteRule(id: string) {
      ruleRow(id);
      const readers = [...correlations.values()].filter((c) => c.refs.includes(id)).map((c) => c.rule.title);
      if (readers.length) throw new SiemError(409, "conflict", `${readers.join(", ")} reads this rule: change or delete the correlation first.`);
      db.prepare("DELETE FROM rules WHERE id = ?").run(id);
      load();
    },

    /** Runs rule text over the newest events without saving anything, so a rule is checked before it goes live. */
    testRule(body: Record<string, unknown>) {
      const { source, limit = 1000, ...rest } = body;
      if (Object.keys(rest).length || typeof limit !== "number" || !Number.isInteger(limit) || limit < 1 || limit > 5000)
        throw bad("Expected { source, limit? }; limit is between 1 and 5000.");
      const rule = compile(source);
      const rows = db.prepare("SELECT * FROM events ORDER BY time DESC, id DESC LIMIT ?").all(limit) as unknown as EventRow[];
      const matched: EventRow[] = [];
      const groups = new Set<string>();
      if (!rule.correlation) {
        for (const r of rows) {
          try {
            if (rule.matches(JSON.parse(r.fields) as Event)) (matched.push(r), groups.add(r.host ?? "unknown"));
          } catch (e) {
            throw new SiemError(422, "invalid-rule", `The rule failed on event ${r.id}: ${(e as Error).message}`);
          }
        }
      } else {
        // A correlation is run over the events oldest first, as ingest would have, with the rules it reads as they are now.
        const all = new Map<string, Rule>();
        for (const r of db.prepare("SELECT id, source FROM rules").all() as Array<{ id: string; source: string }>) {
          try {
            all.set(r.id, compileText(r.source));
          } catch {
            // A rule that does not compile is no rule to read.
          }
        }
        let refs: string[];
        try {
          refs = resolve(rule, all);
        } catch (e) {
          throw new SiemError(422, "invalid-rule", (e as Error).message);
        }
        const c = rule.correlation;
        const hits = new Map<string, Hit[]>();
        for (const r of [...rows].reverse()) {
          const fields = JSON.parse(r.fields) as Event;
          const ruleHits = refs.filter((ref) => {
            try {
              return all.get(ref)!.matches(fields);
            } catch {
              return false;
            }
          });
          if (!ruleHits.length) continue;
          const values = c.groupBy.map((f) => fieldValue(fields, f));
          const key = JSON.stringify(values);
          const from = new Date(Date.parse(r.time) - c.timespanMs).toISOString();
          const value = c.condition?.field ? fieldValue(fields, c.condition.field) : null;
          const group = (hits.get(key) ?? []).filter((h) => h.time >= from);
          for (const ref of ruleHits) group.push({ rule: ref, time: r.time, event: r.id, value });
          hits.set(key, group);
          if (fires(c, refs, group)) (matched.push(r), groups.add(groupLabel(c.groupBy, values)));
        }
        matched.reverse();
      }
      return {
        rule: { title: rule.title, level: rule.level, kind: rule.correlation ? "correlation" : "detection" },
        evaluated: rows.length,
        matches: matched.length,
        hosts: groups.size,
        events: matched.slice(0, SAMPLES).map(present),
      };
    },

    // ------------------------------------------------------------ Signals
    signals(
      f: { status?: Status | "open"; severity?: Level[]; host?: string; rule?: string },
      cursor: string | undefined,
      limit: number,
    ): Page<ReturnType<typeof presentSignal>> {
      const where: string[] = [];
      const args: SQLInputValue[] = [];
      if (f.status === "open") where.push("status IN ('new', 'investigating')");
      else if (f.status) (where.push("status = ?"), args.push(f.status));
      if (f.severity?.length) (where.push(`severity IN (${f.severity.map(() => "?").join(",")})`), args.push(...f.severity));
      if (f.host) (where.push("host = ?"), args.push(f.host));
      if (f.rule) (where.push("rule_id = ?"), args.push(f.rule));
      const offset = decodeCursor(cursor);
      const rows = db
        .prepare(`SELECT * FROM signals ${where.length ? `WHERE ${where.join(" AND ")}` : ""} ORDER BY ${RANK_SQL} DESC, last_seen DESC, id LIMIT ? OFFSET ?`)
        .all(...args, limit + 1, offset) as Array<Record<string, any>>;
      return { items: rows.slice(0, limit).map(presentSignal), ...(rows.length > limit && { nextCursor: encodeCursor(offset + limit) }) };
    },

    signal(id: string) {
      const s = signalRow(id);
      const ids = JSON.parse(s.samples) as number[];
      const events = ids.length
        ? (db.prepare(`SELECT * FROM events WHERE id IN (${ids.map(() => "?").join(",")}) ORDER BY time, id`).all(...ids) as unknown as EventRow[]).map(present)
        : [];
      return { ...presentSignal(s), events };
    },

    setStatus(id: string, body: Record<string, unknown>, by: string) {
      signalRow(id);
      const { status, reason, ...rest } = body;
      if (Object.keys(rest).length || typeof status !== "string" || !STATUSES.includes(status as Status))
        throw bad(`Expected { status, reason? }; status is one of ${STATUSES.join(", ")}.`);
      if (reason !== undefined && (typeof reason !== "string" || reason.length > 500)) throw bad("reason must be text of at most 500 characters.");
      // A false positive without a why teaches nobody (ADR 0040).
      if (status === "false-positive" && (typeof reason !== "string" || reason.trim().length < 3))
        throw bad("reason is required for a false positive: 3 to 500 characters.");
      db.prepare("UPDATE signals SET status = ?, reason = ?, changed_by = ? WHERE id = ?").run(
        status,
        typeof reason === "string" && reason.trim() ? reason.trim() : null,
        by,
        id,
      );
      return presentSignal(signalRow(id));
    },

    summary() {
      const day = new Date(Date.now() - 86_400_000).toISOString();
      const open: Record<Level, number> = { critical: 0, high: 0, medium: 0, low: 0 };
      for (const r of db.prepare("SELECT severity, COUNT(*) AS n FROM signals WHERE status IN ('new', 'investigating') GROUP BY severity").all() as Array<{
        severity: Level;
        n: number;
      }>)
        open[r.severity] = r.n;
      const rules = db
        .prepare("SELECT COUNT(*) AS total, COALESCE(SUM(enabled), 0) AS enabled, COALESCE(SUM(last_error IS NOT NULL), 0) AS failing FROM rules")
        .get() as { total: number; enabled: number; failing: number };
      return {
        events: (db.prepare("SELECT COUNT(*) AS n FROM events").get() as { n: number }).n,
        eventsLastDay: (db.prepare("SELECT COUNT(*) AS n FROM events WHERE received_at >= ?").get(day) as { n: number }).n,
        lastEventAt: (db.prepare("SELECT MAX(time) AS t FROM events").get() as { t: string | null }).t,
        rules: { total: rules.total, enabled: rules.enabled, failing: rules.failing },
        open,
        hours: hourly(db),
        days: daily(db),
      };
    },

    purge() {
      const before = new Date(Date.now() - retentionDays * 86_400_000).toISOString();
      db.prepare("DELETE FROM events WHERE time < ?").run(before);
      db.prepare("DELETE FROM signals WHERE status IN ('closed', 'false-positive') AND last_seen < ?").run(before);
      db.prepare("DELETE FROM correlation_hits WHERE time < ?").run(new Date(Date.now() - MAX_TIMESPAN_MS).toISOString());
    },
  };
}

export type Siem = ReturnType<typeof createSiem>;

const HOUR = 3_600_000;
const DAY = 86_400_000;

/** The starts of the last n periods of `size` milliseconds, UTC, the current one last. */
export function periodStarts(n: number, size: number, now = Date.now()): string[] {
  const current = Math.floor(now / size) * size;
  return Array.from({ length: n }, (_, i) => new Date(current - (n - 1 - i) * size).toISOString());
}

/** Events in each of the last 24 hours, by the time they happened, oldest first. */
function hourly(db: DatabaseSync) {
  const hours = periodStarts(24, HOUR).map((start) => ({ start, events: 0 }));
  const at = new Map(hours.map((h) => [h.start.slice(0, 13), h]));
  for (const r of db.prepare("SELECT substr(time, 1, 13) AS h, COUNT(*) AS n FROM events WHERE time >= ? GROUP BY h").all(hours[0]!.start) as Array<{
    h: string;
    n: number;
  }>) {
    const h = at.get(r.h);
    if (h) h.events = r.n;
  }
  return hours;
}

/** Signals first seen on each of the last 14 days, by severity, oldest first. */
function daily(db: DatabaseSync) {
  const days = periodStarts(14, DAY).map((start) => ({
    start: start.slice(0, 10),
    signals: { critical: 0, high: 0, medium: 0, low: 0 } as Record<Level, number>,
  }));
  const at = new Map(days.map((d) => [d.start, d]));
  for (const r of db
    .prepare("SELECT substr(first_seen, 1, 10) AS d, severity, COUNT(*) AS n FROM signals WHERE first_seen >= ? GROUP BY d, severity")
    .all(days[0]!.start) as Array<{ d: string; severity: Level; n: number }>) {
    const d = at.get(r.d);
    if (d) d.signals[r.severity] = r.n;
  }
  return days;
}
