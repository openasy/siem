import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { compileRule, fires, SigmaError, type Correlation, type Hit } from "./sigma.ts";
import { startApp } from "./test-app.ts";

const correlation = (body: string, title = "Many failed logins", level = "high") =>
  `title: ${title}\nlevel: ${level}\ncorrelation:\n${body.replace(/^/gm, "  ")}\n`;
const refused = (source: string) => {
  try {
    compileRule(source);
  } catch (e) {
    if (e instanceof SigmaError) return e.message;
    throw e;
  }
  return "compiled";
};

describe("correlation rules (ADR 0040)", () => {
  it("reads Sigma's correlation types, and refuses what it cannot do with a reason", () => {
    const c = compileRule(correlation("type: event_count\nrules:\n  - failed_login\ngroup-by:\n  - host\ntimespan: 10m\ncondition:\n  gte: 3"));
    expect(c.correlation).toEqual({
      type: "event_count",
      rules: ["failed_login"],
      groupBy: ["host"],
      timespanMs: 600_000,
      condition: { op: "gte", value: 3, field: null },
    });
    expect(c.matches({ message: "anything" })).toBe(false);
    expect(compileRule(correlation("type: value_count\nrules: failed_login\ntimespan: 1h\ncondition:\n  gt: 4\n  field: user")).correlation).toMatchObject({
      rules: ["failed_login"],
      groupBy: [],
      condition: { op: "gt", value: 4, field: "user" },
    });

    expect(refused(correlation("type: event_count\nrules: [a]\ntimespan: 10m\ncondition:\n  lt: 3"))).toMatch(/lt or lte.*not supported yet/);
    expect(refused(correlation("type: value_sum\nrules: [a]\ntimespan: 10m"))).toMatch(/value_sum is not supported yet/);
    expect(refused(correlation("type: temporal\nrules: [a]\ntimespan: 10m"))).toMatch(/two rules or more/);
    expect(refused(correlation("type: event_count\nrules: [a]\ntimespan: 2d\ncondition:\n  gte: 1"))).toMatch(/between 1s and 1d/);
    expect(refused(correlation("type: event_count\nrules: [a]\ntimespan: 10m"))).toMatch(/needs a condition/);
    expect(refused(correlation("type: value_count\nrules: [a]\ntimespan: 10m\ncondition:\n  gte: 2"))).toMatch(/names the field/);
    expect(refused(correlation("type: event_count\nrules: [a]\ntimespan: 10m\naliases:\n  ip:\n    a: src\ncondition:\n  gte: 2"))).toMatch(/aliases/);
    expect(refused("title: Both\ndetection:\n  s:\n    a: 1\n  condition: s\ncorrelation:\n  type: temporal\n")).toMatch(/not both/);
  });

  it("decides each type from the hits of a group within its timespan", () => {
    const hit = (rule: string, minute: number, event = minute, value: string | null = null): Hit => ({
      rule,
      time: `2026-10-25T10:${String(minute).padStart(2, "0")}:00.000Z`,
      event,
      value,
    });
    const count: Correlation = { type: "event_count", rules: ["a"], groupBy: [], timespanMs: 600_000, condition: { op: "gte", value: 3, field: null } };
    expect(fires(count, ["a"], [hit("a", 1), hit("a", 2)])).toBe(false);
    expect(fires(count, ["a"], [hit("a", 1), hit("a", 2), hit("a", 3)])).toBe(true);
    // One event that two rules match counts once.
    expect(fires({ ...count, rules: ["a", "b"] }, ["a", "b"], [hit("a", 1), hit("b", 1), hit("a", 2)])).toBe(false);
    const distinct: Correlation = { ...count, type: "value_count", condition: { op: "eq", value: 2, field: "user" } };
    expect(fires(distinct, ["a"], [hit("a", 1, 1, "x"), hit("a", 2, 2, "x"), hit("a", 3, 3, null)])).toBe(false);
    expect(fires(distinct, ["a"], [hit("a", 1, 1, "x"), hit("a", 2, 2, "y")])).toBe(true);
    const temporal: Correlation = { type: "temporal", rules: ["a", "b"], groupBy: [], timespanMs: 600_000, condition: null };
    expect(fires(temporal, ["a", "b"], [hit("b", 1), hit("a", 2)])).toBe(true);
    expect(fires({ ...temporal, type: "temporal_ordered" }, ["a", "b"], [hit("b", 1), hit("a", 2)])).toBe(false);
    expect(fires({ ...temporal, type: "temporal_ordered" }, ["a", "b"], [hit("b", 1), hit("a", 2), hit("b", 3)])).toBe(true);
  });
});

describe("correlations over events", () => {
  let app: Awaited<ReturnType<typeof startApp>>;
  const json = async (res: Response) => (await res.json()) as any;
  const at = (minutesAgo: number) => new Date(Date.now() - minutesAgo * 60_000).toISOString();
  const failed = (host: string, user: string, minutesAgo: number) => ({ time: at(minutesAgo), host, user, message: "Failed password" });
  const signalsOf = async (title: string) =>
    ((await json(await app.admin("/api/v1/signals?status=open"))).signals as Array<Record<string, any>>).filter((s) => s.rule.title === title);
  let failedLogin = "";

  beforeAll(async () => {
    app = await startApp({ version: "0.1.0" });
    // The rule a correlation reads, switched off: it makes no signals of its own, and still feeds the correlation.
    const base = await app.addRule(
      "title: Failed login\nname: failed_login\nlevel: low\ndetection:\n  s:\n    message|contains: Failed password\n  condition: s\n",
      false,
    );
    failedLogin = (await json(base)).id;
    await app.addRule("title: Root shell\nname: root_shell\nlevel: low\ndetection:\n  s:\n    message|contains: root shell\n  condition: s\n", false);
  });
  afterAll(() => app.close());

  it("makes one signal per group once the count is reached, and adds to it after", async () => {
    const res = await app.addRule(correlation("type: event_count\nrules: failed_login\ngroup-by:\n  - host\ntimespan: 10m\ncondition:\n  gte: 3"));
    expect(await json(res)).toMatchObject({ kind: "correlation", lastError: null });
    await app.send([failed("web-1", "a", 9), failed("web-1", "b", 8), failed("web-2", "a", 8)]);
    expect(await signalsOf("Many failed logins")).toEqual([]);
    expect(await signalsOf("Failed login")).toEqual([]);
    await app.send([failed("web-1", "c", 7), failed("web-1", "d", 6)]);
    const [signal, ...more] = await signalsOf("Many failed logins");
    expect(more).toEqual([]);
    expect(signal).toMatchObject({ host: "web-1", severity: "high", count: 2 });
    // Two failures from long ago are outside the timespan: web-2 has one in it.
    await app.send([failed("web-2", "a", 50), failed("web-2", "b", 45)]);
    expect((await signalsOf("Many failed logins")).map((s) => s.host)).toEqual(["web-1"]);
  });

  it("counts distinct values, and wants the rules of a temporal_ordered one in order", async () => {
    await app.addRule(
      correlation("type: value_count\nrules: failed_login\ngroup-by:\n  - host\ntimespan: 10m\ncondition:\n  gte: 3\n  field: user", "Password spraying"),
    );
    await app.addRule(correlation("type: temporal_ordered\nrules:\n  - failed_login\n  - root_shell\ngroup-by:\n  - host\ntimespan: 5m", "Login then root"));
    await app.send([failed("db-1", "x", 4), failed("db-1", "x", 4), failed("db-1", "y", 3)]);
    expect(await signalsOf("Password spraying")).toEqual([]);
    await app.send([failed("db-1", "z", 2)]);
    expect((await signalsOf("Password spraying")).map((s) => s.host)).toEqual(["db-1"]);

    await app.send([{ time: at(3), host: "db-2", message: "root shell opened" }]);
    await app.send([failed("db-2", "x", 2)]);
    expect(await signalsOf("Login then root")).toEqual([]);
    await app.send([{ time: at(1), host: "db-2", message: "root shell opened" }]);
    expect((await signalsOf("Login then root")).map((s) => s.host)).toEqual(["db-2"]);
  });

  it("tests a correlation over recent events, names a rule it cannot find, and keeps the rules it reads", async () => {
    const test = await json(
      await app.admin("/api/v1/rules/test", {
        method: "POST",
        body: JSON.stringify({ source: correlation("type: event_count\nrules: failed_login\ngroup-by:\n  - host\ntimespan: 10m\ncondition:\n  gte: 3") }),
      }),
    );
    expect(test).toMatchObject({ rule: { title: "Many failed logins" }, hosts: 2 });
    expect(test.matches).toBeGreaterThan(0);
    const missing = await app.admin("/api/v1/rules/test", {
      method: "POST",
      body: JSON.stringify({ source: correlation("type: temporal\nrules: [failed_login, nope]\ntimespan: 10m") }),
    });
    expect(missing.status).toBe(422);
    expect((await json(missing)).detail).toBe("The correlation reads nope, which no rule here has as its name or id.");

    // A saved one that reads no rule here is kept, and says why on the rule.
    const broken = await json(await app.addRule(correlation("type: temporal\nrules: [failed_login, nope]\ntimespan: 10m", "Broken")));
    expect((await json(await app.admin(`/api/v1/rules/${broken.id}`))).lastError).toMatch(/reads nope/);
    const del = await app.admin(`/api/v1/rules/${failedLogin}`, { method: "DELETE" });
    expect(del.status).toBe(409);
    expect((await json(del)).detail).toMatch(/reads this rule/);
  });
});
