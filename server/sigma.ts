import { parseYaml, YamlError } from "./yaml.ts";

// A Sigma rule, as far as ADR 0040 goes: selections of fields with the modifiers contains, startswith, endswith, re
// and all; keyword lists; conditions with and, or, not, parentheses and `1 of`, `any of`, `all of` over names, patterns
// and `them`. Aggregations (`| count()`) and timeframes are refused with a message, not ignored.

export class SigmaError extends Error {}

export type Level = "critical" | "high" | "medium" | "low";
export type Event = Record<string, string | number | boolean | null | undefined>;

export interface Rule {
  id: string | null;
  title: string;
  description: string | null;
  status: string | null;
  level: Level;
  tags: string[];
  /** True when the event matches. May throw only for a bug; callers keep ingesting. */
  matches(event: Event): boolean;
}

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
  return {
    id: str(doc.id),
    title,
    description: str(doc.description),
    status: str(doc.status),
    level,
    tags: Array.isArray(doc.tags) ? doc.tags.filter((t): t is string => typeof t === "string") : [],
    matches: (event) => trees.some((t) => evaluate(t, preds, event)),
  };
}
