import { describe, expect, it } from "vitest";
import { compileRule, SigmaError, type Event } from "./sigma.ts";

const rule = (detection: string, extra = "title: T\nlevel: high\n") => compileRule(`${extra}detection:\n${detection.replace(/^/gm, "  ")}`);
const hit = (r: ReturnType<typeof compileRule>, e: Event) => r.matches(e);
const bad = (src: string) => {
  try {
    compileRule(src);
  } catch (e) {
    expect(e).toBeInstanceOf(SigmaError);
    return (e as Error).message;
  }
  throw new Error("compiled");
};

describe("fields and modifiers", () => {
  it("compares text without regard to case, and a list means any", () => {
    const r = rule("selection:\n  Image:\n    - C:\\Windows\\cmd.exe\n    - C:\\Windows\\powershell.exe\ncondition: selection");
    expect(hit(r, { Image: "c:\\windows\\CMD.EXE" })).toBe(true);
    expect(hit(r, { Image: "C:\\Windows\\notepad.exe" })).toBe(false);
    expect(hit(r, {})).toBe(false);
  });

  it("applies contains, startswith and endswith", () => {
    const r = (m: string) => rule(`selection:\n  CommandLine|${m}: 'Net User'\ncondition: selection`);
    expect(hit(r("contains"), { CommandLine: "cmd /c net user add" })).toBe(true);
    expect(hit(r("contains"), { CommandLine: "cmd /c net" })).toBe(false);
    expect(hit(r("startswith"), { CommandLine: "net user x" })).toBe(true);
    expect(hit(r("startswith"), { CommandLine: "x net user" })).toBe(false);
    expect(hit(r("endswith"), { CommandLine: "x net user" })).toBe(true);
    expect(hit(r("endswith"), { CommandLine: "net user x" })).toBe(false);
  });

  it("needs every value with all, and any without it", () => {
    const all = rule("selection:\n  m|contains|all:\n    - alpha\n    - beta\ncondition: selection");
    expect(hit(all, { m: "beta and alpha" })).toBe(true);
    expect(hit(all, { m: "alpha only" })).toBe(false);
    const any = rule("selection:\n  m|contains:\n    - alpha\n    - beta\ncondition: selection");
    expect(hit(any, { m: "alpha only" })).toBe(true);
  });

  it("understands wildcards and escapes", () => {
    const r = rule("selection:\n  f: 'C:\\\\Users\\\\*\\\\run?.exe'\ncondition: selection");
    expect(hit(r, { f: "c:\\users\\bob\\run1.exe" })).toBe(true);
    expect(hit(r, { f: "c:\\users\\bob\\run12.exe" })).toBe(false);
    const literal = rule("selection:\n  f: 'a\\*b'\ncondition: selection");
    expect(hit(literal, { f: "a*b" })).toBe(true);
    expect(hit(literal, { f: "axxb" })).toBe(false);
    const inner = rule("selection:\n  f|contains: 'x*z'\ncondition: selection");
    expect(hit(inner, { f: "12xyyyz34" })).toBe(true);
  });

  it("runs regular expressions as written, case-sensitive", () => {
    const r = rule("selection:\n  m|re: '^fail(ed)? login for \\w+$'\ncondition: selection");
    expect(hit(r, { m: "failed login for root" })).toBe(true);
    expect(hit(r, { m: "Failed login for root" })).toBe(false);
  });

  it("matches null against a missing or empty field, and numbers as text", () => {
    const missing = rule("selection:\n  user: null\ncondition: selection");
    expect(hit(missing, {})).toBe(true);
    expect(hit(missing, { user: "" })).toBe(true);
    expect(hit(missing, { user: "bob" })).toBe(false);
    const num = rule("selection:\n  port: 22\ncondition: selection");
    expect(hit(num, { port: 22 })).toBe(true);
    expect(hit(num, { port: "22" })).toBe(true);
    expect(hit(num, { port: 2222 })).toBe(false);
  });

  it("needs all fields of a map, and any map of a list", () => {
    const map = rule("selection:\n  a: 1\n  b: 2\ncondition: selection");
    expect(hit(map, { a: 1, b: 2 })).toBe(true);
    expect(hit(map, { a: 1 })).toBe(false);
    const list = rule("selection:\n  - a: 1\n  - b: 2\ncondition: selection");
    expect(hit(list, { b: 2 })).toBe(true);
    expect(hit(list, { c: 3 })).toBe(false);
  });

  it("searches keywords in the message and in any value", () => {
    const r = rule("keywords:\n  - mimikatz\n  - 'sekurlsa::*'\ncondition: keywords");
    expect(hit(r, { message: "ran MimiKatz.exe" })).toBe(true);
    expect(hit(r, { other: "sekurlsa::logonpasswords" })).toBe(true);
    expect(hit(r, { message: "benign" })).toBe(false);
  });
});

describe("conditions", () => {
  const body = "a:\n  x: 1\nb:\n  y: 2\nfilter_c:\n  z: 3\nfilter_d:\n  w: 4\n";
  const c = (cond: string) => rule(`${body}condition: ${cond}`);
  const e = (o: Event) => o;

  it("combines with and, or and not, and binds not before and before or", () => {
    expect(hit(c("a and b"), e({ x: 1, y: 2 }))).toBe(true);
    expect(hit(c("a and b"), e({ x: 1 }))).toBe(false);
    expect(hit(c("a or b"), e({ y: 2 }))).toBe(true);
    expect(hit(c("a and not b"), e({ x: 1 }))).toBe(true);
    expect(hit(c("a and not b"), e({ x: 1, y: 2 }))).toBe(false);
    // a or (b and not filter_c)
    expect(hit(c("a or b and not filter_c"), e({ x: 1, z: 3 }))).toBe(true);
    expect(hit(c("a or b and not filter_c"), e({ y: 2, z: 3 }))).toBe(false);
    expect(hit(c("not not a"), e({ x: 1 }))).toBe(true);
  });

  it("groups with parentheses", () => {
    expect(hit(c("(a or b) and not filter_c"), e({ y: 2 }))).toBe(true);
    expect(hit(c("(a or b) and not filter_c"), e({ y: 2, z: 3 }))).toBe(false);
    expect(hit(c("not (a or b)"), e({}))).toBe(true);
  });

  it("expands 1 of, any of and all of over patterns and them", () => {
    expect(hit(c("1 of filter_*"), e({ w: 4 }))).toBe(true);
    expect(hit(c("1 of filter_*"), e({ x: 1 }))).toBe(false);
    expect(hit(c("any of filter_*"), e({ z: 3 }))).toBe(true);
    expect(hit(c("all of filter_*"), e({ z: 3 }))).toBe(false);
    expect(hit(c("all of filter_*"), e({ z: 3, w: 4 }))).toBe(true);
    expect(hit(c("1 of them"), e({ y: 2 }))).toBe(true);
    expect(hit(c("all of them"), e({ x: 1, y: 2, z: 3, w: 4 }))).toBe(true);
    expect(hit(c("all of them"), e({ x: 1, y: 2, z: 3 }))).toBe(false);
    expect(hit(c("a and 1 of filter_*"), e({ x: 1, w: 4 }))).toBe(true);
    expect(hit(c("a and not 1 of filter_*"), e({ x: 1, w: 4 }))).toBe(false);
  });

  it("takes a list of conditions as alternatives", () => {
    const r = rule("a:\n  x: 1\nb:\n  y: 2\ncondition:\n  - a\n  - b");
    expect(hit(r, { y: 2 })).toBe(true);
    expect(hit(r, { y: 3 })).toBe(false);
  });
});

describe("rule metadata and refusals", () => {
  it("reads title, id, level, tags and takes JSON too", () => {
    const r = compileRule(
      "title: Odd login\nid: 1b2c\nstatus: test\nlevel: informational\ndescription: d\ntags:\n  - attack.t1078\ndetection:\n  s:\n    a: 1\n  condition: s",
    );
    expect(r).toMatchObject({ title: "Odd login", id: "1b2c", status: "test", level: "low", description: "d", tags: ["attack.t1078"] });
    const j = compileRule(JSON.stringify({ title: "J", level: "critical", detection: { s: { a: 1 }, condition: "s" } }));
    expect(j.level).toBe("critical");
    expect(j.matches({ a: 1 })).toBe(true);
    expect(compileRule("title: T\ndetection:\n  s:\n    a: 1\n  condition: s").level).toBe("medium");
  });

  it("explains what is wrong", () => {
    expect(bad("title: T\ndetection:\n  s:\n    a: 1\n  condition: s | count() > 5")).toContain("Aggregations");
    expect(bad("title: T\ndetection:\n  s:\n    a: 1\n  timeframe: 5m\n  condition: s")).toContain("timeframe");
    expect(bad("title: T\ndetection:\n  s:\n    a|base64: 1\n  condition: s")).toContain('"base64" is not supported');
    expect(bad("title: T\ndetection:\n  s:\n    a: 1\n  condition: t")).toContain('names "t"');
    expect(bad("title: T\ndetection:\n  s:\n    a: 1\n  condition: 1 of x*")).toContain("matches nothing");
    expect(bad("title: T\ndetection:\n  s:\n    a: 1\n  condition: s and")).toContain("ends too early");
    expect(bad("title: T\ndetection:\n  s:\n    a: 1\n  condition: (s")).toContain("( without");
    expect(bad("title: T\ndetection:\n  s:\n    a: 1\n  condition: s s")).toContain("where");
    expect(bad("title: T\ndetection:\n  s:\n    a: 1")).toContain("needs a condition");
    expect(bad("detection:\n  s:\n    a: 1\n  condition: s")).toContain("title");
    expect(bad("title: T\nlevel: severe\ndetection:\n  s:\n    a: 1\n  condition: s")).toContain("level must be");
    expect(bad("title: T")).toContain("detection");
    expect(bad("title: T\ndetection:\n  condition: s")).toContain("at least one selection");
    expect(bad("title: T\ndetection:\n  s: {}\n  condition: s")).toContain("not supported");
    expect(bad("title: T\ndetection:\n  s:\n    a|re: '(a+)+$'\n  condition: s")).toContain("backtrack");
    expect(bad("title: T\ndetection:\n  s:\n    a|re: '['\n  condition: s")).toContain("not valid");
    expect(bad("title: T\ndetection:\n  s:\n    a|re|contains: x\n  condition: s")).toContain("cannot be combined");
    expect(bad("title: T\ndetection:\n  s:\n    a|contains|endswith: x\n  condition: s")).toContain("one of");
    expect(bad("title: T\ndetection:\n  s:\n    a:\n      - [1]\n  condition: s")).toContain("must be text");
    expect(bad("- a\n- b")).toContain("map");
    expect(bad("{nope")).toContain("not valid JSON");
    expect(bad("title: T\n  bad: indent")).toContain("Line");
  });

  it("cuts very long values before a regular expression sees them", () => {
    const r = rule("s:\n  m|re: 'x$'\ncondition: s");
    expect(hit(r, { m: "a".repeat(100_000) + "x" })).toBe(false);
  });
});
