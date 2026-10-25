import { parseYaml, YamlError } from "./yaml.ts";

// A Sigma rule, as far as ADR 0040 goes: selections of fields with the modifiers contains, startswith, endswith, re
// and all; keyword lists; conditions with and, or, not, parentheses and `1 of`, `any of`, `all of` over names, patterns
// and `them`. Aggregations (`| count()`) and timeframes are refused with a message, not ignored.
//
// A correlation rule (Sigma's correlation specification) reads the matches of other rules, named by their name or id:
// event_count and value_count count them, or the distinct values of a field, per group within a timespan; temporal
// wants every rule to match within it, and temporal_ordered in the order listed. What it cannot do yet, such as waiting
// for fewer events (lt, lte) or a correlation of correlations, is refused with a message.

export class SigmaError extends Error {}

export type Level = "critical" | "high" | "medium" | "low";
export type Event = Record<string, string | number | boolean | null | undefined>;

export interface Rule {
  id: string | null;
  /** Sigma's name, which a correlation names the rule by, as it may by id. */
  name: string | null;
  title: string;
  description: string | null;
  status: string | null;
  level: Level;
  tags: string[];
  /** Set for a correlation rule, which matches no event on its own. */
  correlation: Correlation | null;
  /** True when the event matches. May throw only for a bug; callers keep ingesting. */
  matches(event: Event): boolean;
}

export type CorrelationType = "event_count" | "value_count" | "temporal" | "temporal_ordered";

export interface Correlation {
  type: CorrelationType;
  /** The rules it reads, by name or id, as written. */
  rules: string[];
  /** Fields whose values make a group; with none, every event is one group. */
  groupBy: string[];
  timespanMs: number;
  /** For event_count and value_count: the count wanted. field is value_count's. */
  condition: { op: "gt" | "gte" | "eq"; value: number; field: string | null } | null;
}

/** A match of a rule a correlation reads: its time, the event, and for value_count the field's value. */
export interface Hit {
  rule: string;
  time: string;
  event: number;
  value: string | null;
}

/** The longest timespan a correlation may have: its matches are kept that long. */
export const MAX_TIMESPAN_MS = 86_400_000;
const CORRELATION_TYPES: CorrelationType[] = ["event_count", "value_count", "temporal", "temporal_ordered"];
const UNITS: Record<string, number> = { s: 1000, m: 60_000, h: 3_600_000, d: 86_400_000 };

const LEVELS: Record<string, Level> = { informational: "low", low: "low", medium: "medium", high: "high", critical: "critical" };
const MODIFIERS = new Set(["contains", "startswith", "endswith", "re", "all"]);
const MAX_PATTERN = 512;
/** Values longer than this are cut before a regular expression sees them. */
const MAX_VALUE = 4096;

const isObj = (v: unknown): v is Record<string, unknown> => v !== null && typeof v === "object" && !Array.isArray(v);

/** `*` and `?` are wildcards; a backslash makes the next character plain. Returns a source for a case-insensitive RegExp. */
function globSource(pattern: string): string {
  let out = "";
  for (let i = 0; i < pattern.length; i++) {
    const c = pattern[i]!;
    if (c === "\\" && (pattern[i + 1] === "*" || pattern[i + 1] === "?" || pattern[i + 1] === "\\")) {
      out += pattern[i + 1]!.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
      i++;
    } else if (c === "*") out += ".*";
    else if (c === "?") out += ".";
    else out += c.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  }
  return out;
}

/** Nested quantifiers such as (a+)+ can take minutes on a long value. */
const BACKTRACKS = /\([^)]*[+*][^)]*\)[+*{]/;

type Test = (actual: string) => boolean;

function valueTest(expected: unknown, mods: string[], where: string): Test {
  if (typeof expected !== "string" && typeof expected !== "number" && typeof expected !== "boolean")
    throw new SigmaError(`${where}: a value must be text, a number or true/false.`);
  const text = String(expected);
  if (mods.includes("re")) {
    if (text.length > MAX_PATTERN) throw new SigmaError(`${where}: a regular expression may have at most ${MAX_PATTERN} characters.`);
    if (BACKTRACKS.test(text)) throw new SigmaError(`${where}: this regular expression can backtrack without end; rewrite it without nested repetition.`);
    let re: RegExp;
    try {
      re = new RegExp(text);
    } catch (err) {
      throw new SigmaError(`${where}: the regular expression is not valid (${(err as Error).message}).`);
    }
    return (a) => re.test(a.slice(0, MAX_VALUE));
  }
  const contains = mods.includes("contains");
  const starts = mods.includes("startswith");
  const ends = mods.includes("endswith");
  // Plain text takes the fast path; wildcards and the escapes \\, \* and \? (Sigma's) go through a pattern.
  const special = /[*?]|\\[\\*?]/.test(text);
  if (!special) {
    const t = text.toLowerCase();
    if (contains) return (a) => a.toLowerCase().includes(t);
    if (starts) return (a) => a.toLowerCase().startsWith(t);
    if (ends) return (a) => a.toLowerCase().endsWith(t);
    return (a) => a.toLowerCase() === t;
  }
  const body = globSource(text);
  const source = `^${contains || ends ? ".*" : ""}${body}${contains || starts ? ".*" : ""}$`;
  const re = new RegExp(source, "is");
  return (a) => re.test(a.slice(0, MAX_VALUE));
}

type Pred = (event: Event) => boolean;

function fieldPredicate(spec: string, expected: unknown, where: string): Pred {
  const [field, ...mods] = spec.split("|");
  if (!field) throw new SigmaError(`${where}: a field name is missing before "|".`);
  for (const m of mods)
    if (!MODIFIERS.has(m)) throw new SigmaError(`${where}: the modifier "${m}" is not supported (supported: ${[...MODIFIERS].join(", ")}).`);
  if (mods.includes("re") && mods.some((m) => m !== "re" && m !== "all"))
    throw new SigmaError(`${where}: "re" cannot be combined with contains, startswith or endswith.`);
  if (mods.filter((m) => m === "contains" || m === "startswith" || m === "endswith").length > 1)
    throw new SigmaError(`${where}: use one of contains, startswith and endswith.`);
  const all = mods.includes("all");
  const values = Array.isArray(expected) ? expected : [expected];
  if (!values.length) throw new SigmaError(`${where}: the list of values is empty.`);
  const tests: Array<Test | null> = values.map((v) => (v === null ? null : valueTest(v, mods, `${where} (${field})`)));
  return (event) => {
    const actual = event[field];
    const present = actual !== undefined && actual !== null && actual !== "";
    const check = (t: Test | null) => (t === null ? !present : present && t(String(actual)));
    return all ? tests.every(check) : tests.some(check);
  };
}

function selectionPredicate(name: string, def: unknown): Pred {
  const where = `detection "${name}"`;
  if (isObj(def)) {
    const parts = Object.entries(def).map(([k, v]) => fieldPredicate(k, v, where));
    if (!parts.length) throw new SigmaError(`${where} is empty.`);
    return (e) => parts.every((p) => p(e));
  }
  if (Array.isArray(def)) {
    if (!def.length) throw new SigmaError(`${where} is empty.`);
    if (def.every(isObj)) {
      const alternatives = def.map((m) => selectionPredicate(name, m));
      return (e) => alternatives.some((p) => p(e));
    }
    // Keywords: text that may appear in the message or in any value of the event.
    const tests = def.map((v) => valueTest(v, ["contains"], where));
    return (e) => Object.values(e).some((v) => typeof v === "string" && tests.some((t) => t(v)));
  }
  throw new SigmaError(`${where} must be a map of fields, a list of maps or a list of keywords.`);
}

// ---------------------------------------------------------------- Conditions

type Node =
  { op: "ref"; name: string } | { op: "of"; quantifier: "1" | "all"; names: string[] } | { op: "not"; a: Node } | { op: "and" | "or"; a: Node; b: Node };

function tokens(condition: string): string[] {
  return condition.match(/\(|\)|[^\s()]+/g) ?? [];
}

function parseCondition(source: string, names: string[]): Node {
  if (source.includes("|")) throw new SigmaError("Aggregations in a condition (the part after |) are not supported yet.");
  const t = tokens(source);
  let i = 0;
  const peek = () => t[i];
  const next = () => t[i++];
  const expand = (pattern: string): string[] => {
    const found =
      pattern === "them"
        ? names
        : names.filter((n) =>
            new RegExp(
              `^${pattern
                .split("*")
                .map((p) => p.replace(/[.+?^${}()|[\]\\]/g, "\\$&"))
                .join(".*")}$`,
            ).test(n),
          );
    if (!found.length) throw new SigmaError(`The condition names "${pattern}", which matches nothing in detection.`);
    return found;
  };
  function atom(): Node {
    const tok = next();
    if (tok === undefined) throw new SigmaError("The condition ends too early.");
    if (tok === "(") {
      const e = or();
      if (next() !== ")") throw new SigmaError("The condition has a ( without its ).");
      return e;
    }
    if (tok === ")") throw new SigmaError("The condition has a ) without its (.");
    if (/^(1|any|all)$/i.test(tok) && peek()?.toLowerCase() === "of") {
      next();
      const target = next();
      if (!target) throw new SigmaError('"of" needs a name, a pattern or "them".');
      return { op: "of", quantifier: tok.toLowerCase() === "all" ? "all" : "1", names: expand(target) };
    }
    if (/^(and|or|not|of)$/i.test(tok)) throw new SigmaError(`The condition has "${tok}" where a name was expected.`);
    if (!names.includes(tok)) throw new SigmaError(`The condition names "${tok}", which detection does not define.`);
    return { op: "ref", name: tok };
  }
  function not(): Node {
    if (peek()?.toLowerCase() === "not") {
      next();
      return { op: "not", a: not() };
    }
    return atom();
  }
  function and(): Node {
    let a = not();
    while (peek()?.toLowerCase() === "and") (next(), (a = { op: "and", a, b: not() }));
    return a;
  }
  function or(): Node {
    let a = and();
    while (peek()?.toLowerCase() === "or") (next(), (a = { op: "or", a, b: and() }));
    return a;
  }
  const tree = or();
  if (i < t.length) throw new SigmaError(`The condition has "${t[i]}" where "and", "or" or the end was expected.`);
  return tree;
}

function evaluate(node: Node, preds: Map<string, Pred>, event: Event): boolean {
  switch (node.op) {
    case "ref":
      return preds.get(node.name)!(event);
    case "of":
      return node.quantifier === "all" ? node.names.every((n) => preds.get(n)!(event)) : node.names.some((n) => preds.get(n)!(event));
    case "not":
      return !evaluate(node.a, preds, event);
    case "and":
      return evaluate(node.a, preds, event) && evaluate(node.b, preds, event);
    case "or":
      return evaluate(node.a, preds, event) || evaluate(node.b, preds, event);
  }
}

const str = (v: unknown) => (typeof v === "string" && v.trim() ? v.trim() : null);

/** A field's value as a correlation groups and counts it: text, or null when the event has none. */
export function fieldValue(event: Event, field: string): string | null {
  const v = event[field];
  return v === undefined || v === null || v === "" ? null : String(v);
}

function compileCorrelation(c: unknown): Correlation {
  if (!isObj(c)) throw new SigmaError("correlation is a map with a type, rules, a timespan and, for counts, a condition.");
  const known = new Set(["type", "rules", "group-by", "timespan", "condition", "generate", "aliases"]);
  const unknown = Object.keys(c).filter((k) => !known.has(k));
  if (unknown.length) throw new SigmaError(`correlation does not know ${unknown.join(", ")}.`);
  if ("aliases" in c) throw new SigmaError("correlation aliases are not supported yet; give the rules the same field names.");
  if (c.generate !== undefined && typeof c.generate !== "boolean") throw new SigmaError("correlation generate is true or false.");
  const type = c.type as CorrelationType;
  if (!CORRELATION_TYPES.includes(type)) throw new SigmaError(`correlation type ${String(c.type)} is not supported yet; use ${CORRELATION_TYPES.join(", ")}.`);
  const list = typeof c.rules === "string" ? [c.rules] : c.rules;
  if (!Array.isArray(list) || !list.length || list.some((r) => typeof r !== "string" || !r.trim()))
    throw new SigmaError("correlation rules is a list of the names or ids of the rules it reads.");
  const rules = [...new Set((list as string[]).map((r) => r.trim()))];
  if (type.startsWith("temporal") && rules.length < 2) throw new SigmaError(`A ${type} correlation reads two rules or more.`);
  const by = c["group-by"] === undefined ? [] : typeof c["group-by"] === "string" ? [c["group-by"]] : c["group-by"];
  if (!Array.isArray(by) || by.some((f) => typeof f !== "string" || !f.trim())) throw new SigmaError("correlation group-by is a list of field names.");
  const span = typeof c.timespan === "string" ? /^(\d+)([smhd])$/.exec(c.timespan.trim()) : null;
  if (!span) throw new SigmaError("correlation timespan is a number and a unit, such as 30s, 10m, 1h or 1d.");
  const timespanMs = Number(span[1]) * UNITS[span[2]!]!;
  if (timespanMs < 1000 || timespanMs > MAX_TIMESPAN_MS) throw new SigmaError("correlation timespan is between 1s and 1d.");
  let condition: Correlation["condition"] = null;
  if (type === "event_count" || type === "value_count") {
    const cond = c.condition;
    if (!isObj(cond)) throw new SigmaError(`A ${type} correlation needs a condition, such as gte: 10.`);
    const ops = Object.keys(cond).filter((k) => k !== "field");
    if (ops.some((k) => k === "lt" || k === "lte"))
      throw new SigmaError("A condition with lt or lte, which waits for fewer events than a number, is not supported yet.");
    const op = ops[0] as "gt" | "gte" | "eq" | undefined;
    if (ops.length !== 1 || !op || !["gt", "gte", "eq"].includes(op)) throw new SigmaError("condition has one of gt, gte or eq, such as gte: 10.");
    const value = cond[op];
    if (typeof value !== "number" || !Number.isInteger(value) || value < 1 || value > 10_000)
      throw new SigmaError(`condition ${op} is a whole number from 1 to 10000.`);
    const field = type === "value_count" ? str(cond.field) : null;
    if (type === "value_count" && !field) throw new SigmaError("A value_count condition names the field whose values it counts, such as field: User.");
    if (type === "event_count" && cond.field !== undefined) throw new SigmaError("field is for value_count.");
    condition = { op, value, field };
  } else if (c.condition !== undefined) throw new SigmaError(`A ${type} correlation has no condition: every rule matching is the condition.`);
  return { type, rules, groupBy: (by as string[]).map((f) => f.trim()), timespanMs, condition };
}

/**
 * Whether a correlation holds at the newest of its group's hits, given the hits of that group within the timespan
 * before it, oldest first. Pure, so a test run over recent events decides exactly as ingest does.
 */
export function fires(c: Correlation, refs: string[], hits: Hit[]): boolean {
  const test = (n: number) =>
    c.condition!.op === "gt" ? n > c.condition!.value : c.condition!.op === "gte" ? n >= c.condition!.value : n === c.condition!.value;
  switch (c.type) {
    case "event_count":
      return test(new Set(hits.map((h) => h.event)).size);
    case "value_count":
      return test(new Set(hits.filter((h) => h.value !== null).map((h) => h.value)).size);
    case "temporal":
      return refs.every((r) => hits.some((h) => h.rule === r));
    case "temporal_ordered": {
      let at = "";
      for (const r of refs) {
        const next = hits.find((h) => h.rule === r && h.time >= at);
        if (!next) return false;
        at = next.time;
      }
      return true;
    }
  }
}

/** Reads a rule from YAML or JSON text. Throws SigmaError with a message a person can act on. */
export function compileRule(source: string): Rule {
  let doc: unknown;
  try {
    doc = source.trimStart().startsWith("{") ? JSON.parse(source) : parseYaml(source);
  } catch (err) {
    if (err instanceof YamlError) throw new SigmaError(err.message);
    if (err instanceof SyntaxError) throw new SigmaError(`The rule is not valid JSON (${err.message}).`);
    throw err;
  }
  if (!isObj(doc)) throw new SigmaError("A rule is a map with a title and a detection.");
  const title = str(doc.title);
  if (!title) throw new SigmaError("The rule needs a title.");
  if (title.length > 200) throw new SigmaError("The title may have at most 200 characters.");
  const level = doc.level === undefined ? "medium" : LEVELS[String(doc.level).toLowerCase()];
  if (!level) throw new SigmaError(`level must be one of ${Object.keys(LEVELS).join(", ")}.`);
  const meta = {
    id: str(doc.id),
    name: str(doc.name),
    title,
    description: str(doc.description),
    status: str(doc.status),
    level,
    tags: Array.isArray(doc.tags) ? doc.tags.filter((t): t is string => typeof t === "string") : [],
  };
  if (doc.correlation !== undefined) {
    if (doc.detection !== undefined) throw new SigmaError("A rule has a detection or a correlation, not both.");
    return { ...meta, correlation: compileCorrelation(doc.correlation), matches: () => false };
  }
  const detection = doc.detection;
  if (!isObj(detection)) throw new SigmaError("The rule needs a detection with selections and a condition.");
  if ("timeframe" in detection) throw new SigmaError("timeframe is not supported yet.");
  const { condition, ...selections } = detection;
  const names = Object.keys(selections);
  if (!names.length) throw new SigmaError("detection needs at least one selection.");
  const conditions = (Array.isArray(condition) ? condition : [condition]).filter((c) => c !== undefined);
  if (!conditions.length || conditions.some((c) => typeof c !== "string" || !c.trim()))
    throw new SigmaError("detection needs a condition, such as `selection`.");
  const preds = new Map<string, Pred>(names.map((n) => [n, selectionPredicate(n, selections[n])]));
  const trees = (conditions as string[]).map((c) => parseCondition(c, names));
  return { ...meta, correlation: null, matches: (event) => trees.some((t) => evaluate(t, preds, event)) };
}
