import { gzipSync } from "node:zlib";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { compileRule } from "./sigma.ts";
import { FAILED_LOGIN, MIMIKATZ, rule, startApp } from "./test-app.ts";

let app: Awaited<ReturnType<typeof startApp>>;
beforeAll(async () => {
  app = await startApp({ version: "0.1.0" });
});
afterAll(() => app.close());

const json = async (res: Response) => (await res.json()) as any;
const at = (minutesAgo: number) => new Date(Date.now() - minutesAgo * 60_000).toISOString();
const ssh = (host: string, minutesAgo = 1, extra: Record<string, unknown> = {}) => ({
  time: at(minutesAgo),
  host,
  source: "sshd",
  message: "Failed password for root from 10.0.0.9",
  ...extra,
});

describe("rules", () => {
  it("adds a rule from Sigma YAML, or JSON, and says what is wrong with a bad one", async () => {
    const created = await app.addRule(FAILED_LOGIN);
    expect(created.status).toBe(201);
    expect(await json(created)).toMatchObject({ title: "Failed login", level: "medium", enabled: true, matches: 0, lastError: null, source: FAILED_LOGIN });
    const asJson = await app.addRule(JSON.stringify({ title: "From JSON", level: "low", detection: { s: { source: "audit" }, condition: "s" } }));
    expect(await json(asJson)).toMatchObject({ title: "From JSON", level: "low" });
    await app.addRule(MIMIKATZ, false);

    const invalid = await app.addRule("title: Broken\ndetection:\n  s:\n    a|base64: 1\n  condition: s");
    expect(invalid.status).toBe(422);
    expect(await json(invalid)).toMatchObject({ code: "invalid-rule", detail: expect.stringContaining("base64") });
    expect((await app.addRule("")).status).toBe(422);
    expect((await app.admin("/api/v1/rules", { method: "POST", body: JSON.stringify({ source: FAILED_LOGIN, extra: 1 }) })).status).toBe(422);
    expect((await app.addRule("x".repeat(70_000))).status).toBe(413);
    expect((await json(await app.admin("/api/v1/rules"))).rules.map((r: { title: string }) => r.title)).toEqual([
      "Credential dumping tool",
      "Failed login",
      "From JSON",
    ]);
  });

  it("tests a rule against recent events before it is saved", async () => {
    await app.send([ssh("web-1", 5), ssh("web-2", 4), { time: at(3), host: "web-1", source: "audit", message: "ok" }]);
    const test = async (source: string, limit?: number) =>
      app.admin("/api/v1/rules/test", { method: "POST", body: JSON.stringify({ source, ...(limit !== undefined && { limit }) }) });
    const res = await json(await test(rule("Probe", "s:\n  message|contains: password\ncondition: s")));
    expect(res).toMatchObject({ rule: { title: "Probe", level: "high" }, evaluated: 3, matches: 2, hosts: 2 });
    expect(res.events).toHaveLength(2);
    expect((await json(await test(rule("Probe", "s:\n  message|contains: password\ncondition: s"), 1))).evaluated).toBe(1);
    expect((await test("title: x")).status).toBe(422);
    expect((await test(FAILED_LOGIN, 0)).status).toBe(422);
    // Nothing was saved or alerted by testing.
    expect((await json(await app.admin("/api/v1/rules"))).rules).toHaveLength(3);
  });
});

describe("events and signals", () => {
  it("turns matches into one signal per rule and host, and counts them", async () => {
    const before = await json(await app.send([ssh("web-1", 3), ssh("web-1", 2), ssh("web-1", 1), ssh("web-2", 1)]));
    expect(before).toEqual({ accepted: 4, signals: 2 });
    const open = (await json(await app.admin("/api/v1/signals"))).signals.filter((s: { rule: { title: string } }) => s.rule.title === "Failed login");
    expect(open).toHaveLength(2);
    const web1 = open.find((s: { host: string }) => s.host === "web-1");
    expect(web1).toMatchObject({ rule: { title: "Failed login" }, severity: "medium", status: "new", count: 4, firstSeen: expect.any(String) });
    expect(open.find((s: { host: string }) => s.host === "web-2").count).toBe(2);
    const detail = await json(await app.admin(`/api/v1/signals/${web1.id}`));
    expect(detail.events).toHaveLength(4);
    expect(detail.events[0]).toMatchObject({ host: "web-1", source: "sshd" });
  });

  it("counts events by hour and new signals by day and severity", async () => {
    const s = await json(await app.admin("/api/v1/summary"));
    expect(s.hours).toHaveLength(24);
    expect(s.days).toHaveLength(14);
    // The four events above happened in the last few minutes, so in this hour or the one before.
    expect(s.hours.slice(-2).reduce((n: number, h: { events: number }) => n + h.events, 0)).toBeGreaterThanOrEqual(4);
    expect(s.hours[23].start).toBe(new Date(Math.floor(Date.now() / 3_600_000) * 3_600_000).toISOString());
    const signals = (await json(await app.admin("/api/v1/signals"))).signals.length;
    const counted = s.days.reduce((n: number, d: { signals: Record<string, number> }) => n + Object.values(d.signals).reduce((a, b) => a + b, 0), 0);
    expect(counted).toBe(signals);
  });

  it("keeps at most five sample events and starts a new signal after the window", async () => {
    await app.send(Array.from({ length: 6 }, (_, i) => ssh("web-3", 30 - i)));
    const web3 = (await json(await app.admin("/api/v1/signals?host=web-3"))).signals[0];
    expect(web3.count).toBe(6);
    expect((await json(await app.admin(`/api/v1/signals/${web3.id}`))).events).toHaveLength(5);
    // 90 minutes after the last match is outside the 60 minute window.
    await app.send([ssh("web-3", -90 + 24)].map((e) => ({ ...e, time: new Date(Date.now() + 90 * 60_000 - 24 * 60_000 - 1 * 60_000).toISOString() })));
    expect((await json(await app.admin("/api/v1/signals?host=web-3"))).signals).toHaveLength(2);
  });

  it("applies exclusions in a rule, and only enabled rules", async () => {
    await app.send([{ time: at(1), host: "pc-1", Image: "C:\\Tools\\Mimikatz.exe", User: "bob" }]);
    expect((await json(await app.admin("/api/v1/signals?host=pc-1"))).signals).toEqual([]);
    const mimi = (await json(await app.admin("/api/v1/rules"))).rules.find((r: { title: string }) => r.title === "Credential dumping tool");
    expect((await app.admin(`/api/v1/rules/${mimi.id}`, { method: "PATCH", body: JSON.stringify({ enabled: true }) })).status).toBe(200);
    await app.send([
      { time: at(1), host: "pc-1", Image: "C:\\Tools\\Mimikatz.exe", User: "bob" },
      { time: at(1), host: "pc-2", Image: "C:\\Tools\\Mimikatz.exe", User: "SYSTEM" },
    ]);
    const signals = (await json(await app.admin("/api/v1/signals?host=pc-1"))).signals;
    expect(signals).toMatchObject([{ severity: "critical", count: 1 }]);
    expect((await json(await app.admin("/api/v1/signals?host=pc-2"))).signals).toEqual([]);
    expect((await json(await app.admin(`/api/v1/rules/${mimi.id}`))).matches).toBe(1);
  });

  it("lists most severe first and filters", async () => {
    const all = (await json(await app.admin("/api/v1/signals"))).signals;
    expect(all[0].severity).toBe("critical");
    expect((await json(await app.admin("/api/v1/signals?severity=medium"))).signals.every((s: { severity: string }) => s.severity === "medium")).toBe(true);
    const page = await json(await app.admin("/api/v1/signals?limit=1"));
    expect(page.signals).toHaveLength(1);
    expect((await json(await app.admin(`/api/v1/signals?limit=1&cursor=${page.nextCursor}`))).signals[0].id).not.toBe(page.signals[0].id);
    expect((await app.admin("/api/v1/signals?severity=urgent")).status).toBe(422);
    expect((await app.admin("/api/v1/signals?status=gone")).status).toBe(422);
  });

  it("moves a signal through its statuses, and wants a reason for a false positive", async () => {
    const s = (await json(await app.admin("/api/v1/signals?host=web-2"))).signals[0];
    const set = (body: unknown) => app.admin(`/api/v1/signals/${s.id}`, { method: "PATCH", body: JSON.stringify(body) });
    expect(await json(await set({ status: "investigating" }))).toMatchObject({ status: "investigating", changedBy: "admin token" });
    expect((await json(await app.admin("/api/v1/signals?host=web-2"))).signals).toHaveLength(1);
    expect((await set({ status: "false-positive" })).status).toBe(422);
    expect((await set({ status: "done" })).status).toBe(422);
    expect((await set({ status: "closed", reason: 5 })).status).toBe(422);
    expect(await json(await set({ status: "false-positive", reason: "A scanner we run" }))).toMatchObject({
      status: "false-positive",
      reason: "A scanner we run",
    });
    expect((await json(await app.admin("/api/v1/signals?host=web-2"))).signals).toEqual([]);
    expect((await json(await app.admin("/api/v1/signals?status=false-positive"))).signals).toHaveLength(1);
    // A closed signal does not collect new matches: the next one is a new signal.
    await app.send([ssh("web-2", 0)]);
    expect((await json(await app.admin("/api/v1/signals?host=web-2"))).signals).toMatchObject([{ status: "new", count: 1 }]);
  });

  it("searches events", async () => {
    const q = async (query: string) => (await json(await app.admin(`/api/v1/events?${query}`))).events;
    expect((await q("host=pc-1")).length).toBe(2);
    expect((await q("source=audit")).length).toBe(1);
    expect((await q("q=mimikatz"))[0]).toMatchObject({ host: expect.stringMatching(/pc-/), fields: { Image: "C:\\Tools\\Mimikatz.exe" } });
    expect((await q(`since=${encodeURIComponent(at(2.5))}`)).every((e: { time: string }) => e.time >= at(3))).toBe(true);
    expect((await q("until=2000-01-01")).length).toBe(0);
    const first = await json(await app.admin("/api/v1/events?limit=2"));
    expect(first.events).toHaveLength(2);
    expect(first.nextCursor).toBeDefined();
    const one = await json(await app.admin(`/api/v1/events/${first.events[0].id}`));
    expect(one).toMatchObject({ id: first.events[0].id });
    expect((await app.admin("/api/v1/events/999999")).status).toBe(404);
    expect((await app.admin("/api/v1/events/abc")).status).toBe(404);
    expect((await app.admin("/api/v1/events?since=yesterday")).status).toBe(422);
  });
});

describe("taking events", () => {
  it("accepts one event, a gzipped array, and defaults the time", async () => {
    expect(await json(await app.send({ host: "h", message: "hello" }))).toEqual({ accepted: 1, signals: 0 });
    const gz = await app.ingest("/api/v1/events", {
      method: "POST",
      body: gzipSync(JSON.stringify([{ host: "h" }, { host: "h" }])),
      headers: { "content-encoding": "gzip" },
    });
    expect(await json(gz)).toMatchObject({ accepted: 2 });
    expect((await json(await app.admin("/api/v1/events?host=h"))).events[0].time).toMatch(/^\d{4}-\d\d-\d\dT/);
  });

  it("refuses events it cannot keep, and keeps none of a request that has a bad one", async () => {
    const count = async () => (await json(await app.admin("/api/v1/summary"))).events;
    const before = await count();
    const refuse = async (body: unknown, detail: RegExp) => {
      const res = await app.send(body);
      expect(res.status).toBe(422);
      expect(await json(res)).toMatchObject({ code: "invalid-event", detail: expect.stringMatching(detail) });
    };
    await refuse([{ host: "ok" }, { host: "bad", nested: { a: 1 } }], /Event 1: "nested" must be text/);
    await refuse({ "bad name": 1 }, /field name/);
    await refuse({ time: "yesterday" }, /ISO 8601/);
    await refuse({ time: new Date(Date.now() + 3 * 86_400_000).toISOString() }, /future/);
    await refuse({ host: 5 }, /"host" must be text/);
    await refuse({ message: "x".repeat(5000) }, /at most 4096/);
    await refuse("a string", /JSON object/);
    await refuse(Object.fromEntries(Array.from({ length: 70 }, (_, i) => [`f${i}`, i])), /at most 64 fields/);
    expect((await app.send([])).status).toBe(422);
    expect((await app.send(Array.from({ length: 1001 }, () => ({})))).status).toBe(413);
    expect((await app.ingest("/api/v1/events", { method: "POST", body: "{nope" })).status).toBe(400);
    expect((await app.ingest("/api/v1/events", { method: "POST", body: "x", headers: { "content-encoding": "br" } })).status).toBe(400);
    expect(await count()).toBe(before);
  });

  it("keeps events when a rule fails, and says so on the rule", async () => {
    const failing = await startApp({
      version: "0.1.0",
      siem: {
        compile: (source) => {
          const real = compileRule(source);
          return source.includes("Throws")
            ? {
                ...real,
                matches: () => {
                  throw new Error("boom");
                },
              }
            : real;
        },
      },
    });
    await failing.addRule(rule("Throws", "s:\n  message: x\ncondition: s"));
    const fine = await json(await failing.addRule(rule("Fine", "s:\n  message: ok\ncondition: s")));
    expect(
      await json(
        await failing.send([
          { host: "h", message: "ok" },
          { host: "h", message: "ok" },
        ]),
      ),
    ).toEqual({ accepted: 2, signals: 1 });
    const rules = (await json(await failing.admin("/api/v1/rules"))).rules;
    expect(rules.find((r: { title: string }) => r.title === "Throws").lastError).toBe("Failed on an event: boom");
    expect(rules.find((r: { id: string }) => r.id === fine.id).lastError).toBeNull();
    expect((await json(await failing.admin("/api/v1/summary"))).rules.failing).toBe(1);
    expect((await json(await failing.admin("/api/v1/events"))).events).toHaveLength(2);
    await failing.close();
  });

  it("marks a rule that no longer compiles when the product starts", () => {
    app.db.prepare("INSERT INTO rules (id, title, level, source, created_at, updated_at) VALUES ('old', 'Old', 'low', 'title: Old', 'now', 'now')").run();
    app.siem.reload();
    expect((app.db.prepare("SELECT last_error FROM rules WHERE id = 'old'").get() as { last_error: string }).last_error).toContain("detection");
  });
});

describe("access", () => {
  it("lets the ingest token send events and nothing else, and keeps rules to admins", async () => {
    const anon = (path: string, init: RequestInit = {}) => fetch(app.base + path, init);
    expect((await anon("/api/v1/events", { method: "POST", body: "{}" })).status).toBe(401);
    expect((await anon("/api/v1/events", { method: "POST", body: "{}", headers: { authorization: "Bearer nope" } })).status).toBe(401);
    expect((await anon("/api/v1/signals")).status).toBe(401);
    expect((await app.ingest("/api/v1/signals")).status).toBe(401);
    expect((await app.ingest("/api/v1/events")).status).toBe(401);
    expect((await app.ingest("/api/v1/rules", { method: "POST", body: JSON.stringify({ source: FAILED_LOGIN }) })).status).toBe(401);
    expect((await app.ingest("/api/v1/rules/test", { method: "POST", body: "{}" })).status).toBe(401);
    const closed = await startApp({ version: "0.1.0", ingestToken: undefined, adminToken: undefined });
    expect((await fetch(`${closed.base}/api/v1/events`, { method: "POST", body: "{}" })).status).toBe(503);
    await closed.close();
  });

  it("deletes a rule and keeps its signals", async () => {
    const r = (await json(await app.admin("/api/v1/rules"))).rules.find((x: { title: string }) => x.title === "Failed login");
    expect((await app.admin(`/api/v1/rules/${r.id}`, { method: "DELETE" })).status).toBe(204);
    expect((await app.admin(`/api/v1/rules/${r.id}`)).status).toBe(404);
    expect((await app.admin(`/api/v1/rules/${r.id}`, { method: "DELETE" })).status).toBe(404);
    expect((await json(await app.admin("/api/v1/signals?host=web-1"))).signals[0].rule).toEqual({ id: null, title: "Failed login" });
    const patch = (body: unknown) => app.admin(`/api/v1/rules/${r.id as string}`, { method: "PATCH", body: JSON.stringify(body) });
    expect((await patch({ enabled: false })).status).toBe(404);
  });

  it("changes a rule's text and level, and refuses a bad edit", async () => {
    const created = await json(await app.addRule(rule("Edit me", "s:\n  message: one\ncondition: s", "low")));
    const patch = (body: unknown) => app.admin(`/api/v1/rules/${created.id}`, { method: "PATCH", body: JSON.stringify(body) });
    expect(await json(await patch({ source: rule("Edited", "s:\n  message: two\ncondition: s", "critical") }))).toMatchObject({
      title: "Edited",
      level: "critical",
    });
    expect((await patch({ source: "title: x" })).status).toBe(422);
    expect((await patch({})).status).toBe(422);
    expect((await patch({ enabled: "yes" })).status).toBe(422);
    expect((await patch({ id: "x" })).status).toBe(422);
    await app.send({ host: "edit-1", message: "two" });
    expect((await json(await app.admin("/api/v1/signals?host=edit-1"))).signals).toMatchObject([{ severity: "critical" }]);
  });

  it("answers version, health and metrics", async () => {
    expect(await json(await fetch(`${app.base}/api/v1/version`))).toEqual({ product: "siem", version: "0.1.0" });
    expect((await fetch(`${app.base}/readyz`)).status).toBe(200);
    const metrics = await (await fetch(`${app.base}/metrics`)).text();
    expect(metrics).toContain('openasy_build_info{product="siem",version="0.1.0"} 1');
    expect(metrics).toMatch(/openasy_siem_events \d+/);
    expect(metrics).toContain('openasy_siem_open_signals{severity="critical"}');
    expect(metrics).toContain('openasy_siem_rules{state="enabled"}');
  });
});

describe("the overview", () => {
  let own: Awaited<ReturnType<typeof startApp>>;
  beforeAll(async () => {
    own = await startApp({ version: "0.1.0" });
  });
  afterAll(() => own.close());

  it("counts signals of 30 days by status and ranks rules and hosts", async () => {
    await own.addRule(FAILED_LOGIN);
    await own.send([ssh("web-1", 3), ssh("web-1", 2), ssh("web-2", 1)]);
    const o = await json(await own.admin("/api/v1/overview"));
    expect(o.byStatus).toEqual({ new: 2, investigating: 0, closed: 0, "false-positive": 0 });
    expect(o.topRules).toEqual([{ rule: expect.any(String), title: "Failed login", open: 2, severity: "medium" }]);
    expect(o.topHosts.map((h: { host: string }) => h.host).sort()).toEqual(["web-1", "web-2"]);
  });
});
