// A small parser for the YAML that Sigma rules use (ADR 0040): block maps and lists, plain, quoted and block scalars,
// inline lists, comments. Anchors, tags, merge keys, flow maps and multiple documents are not supported and say so.
export class YamlError extends Error {}

interface Line {
  n: number;
  indent: number;
  text: string;
}

const fail = (n: number, what: string): never => {
  throw new YamlError(`Line ${n}: ${what}`);
};

/** Removes a trailing comment that is not inside quotes. */
function stripComment(s: string): string {
  let quote: string | null = null;
  for (let i = 0; i < s.length; i++) {
    const c = s[i]!;
    if (quote) {
      if (c === "\\" && quote === '"') i++;
      else if (c === quote) quote = null;
    } else if ((c === '"' || c === "'") && (i === 0 || /[\s[,:-]/.test(s[i - 1]!))) quote = c;
    else if (c === "#" && (i === 0 || /\s/.test(s[i - 1]!))) return s.slice(0, i);
  }
  return s;
}

function scalar(raw: string, n: number): unknown {
  const s = raw.trim();
  if (s === "" || s === "~" || s === "null") return null;
  if (s === "true") return true;
  if (s === "false") return false;
  if (/^-?\d+(\.\d+)?$/.test(s) && s.length < 16) return Number(s);
  if (s.startsWith("'")) {
    if (!s.endsWith("'") || s.length < 2) fail(n, "a single-quoted string is not closed.");
    return s.slice(1, -1).replaceAll("''", "'");
  }
  if (s.startsWith('"')) {
    if (!s.endsWith('"') || s.length < 2) fail(n, "a double-quoted string is not closed.");
    try {
      return JSON.parse(s) as string;
    } catch {
      return fail(n, "a double-quoted string has an escape that is not supported.");
    }
  }
  if (/^[&*!]/.test(s) || s.startsWith("{")) fail(n, "anchors, aliases, tags and flow maps are not supported.");
  if (s.startsWith("[")) return inlineList(s, n);
  return s;
}

function inlineList(s: string, n: number): unknown[] {
  if (!s.endsWith("]")) fail(n, "an inline list is not closed.");
  const body = s.slice(1, -1).trim();
  if (!body) return [];
  const items: string[] = [];
  let cur = "";
  let quote: string | null = null;
  for (const c of body) {
    if (quote) {
      cur += c;
      if (c === quote) quote = null;
    } else if (c === '"' || c === "'") (quote = c, (cur += c));
    else if (c === ",") (items.push(cur), (cur = ""));
    else cur += c;
  }
  items.push(cur);
  return items.map((i) => scalar(i, n));
}

const KEY = /^("(?:[^"\\]|\\.)*"|'(?:[^']|'')*'|[^\s:#'"][^:]*?)\s*:(?:\s+(.*))?$/;

export function parseYaml(text: string): unknown {
  if (/^---\s*$/m.test(text.trim().replace(/^---\s*\n/, ""))) fail(1, "more than one document is not supported.");
  const lines: Line[] = [];
  text.replace(/^---\s*\n/, "").split(/\r?\n/).forEach((raw, i) => {
    if (/^\t/.test(raw)) fail(i + 1, "indent with spaces, not tabs.");
    const body = stripComment(raw).replace(/\s+$/, "");
    if (!body.trim()) return;
    lines.push({ n: i + 1, indent: body.length - body.trimStart().length, text: body.trimStart() });
  });
  if (!lines.length) return null;
  let pos = 0;

  function block(indent: number): unknown {
    const l = lines[pos]!;
    return l.text === "-" || l.text.startsWith("- ") ? list(indent) : map(indent);
  }

  /** The value after `key:` or `-`: inline, or the deeper block that follows. */
  function value(rest: string | undefined, n: number, parentIndent: number, allowSameIndentList: boolean): unknown {
    if (rest !== undefined && rest !== "") {
      if (rest === "|" || rest === ">" || /^[|>][+-]?$/.test(rest)) return blockScalar(rest, parentIndent);
      return scalar(rest, n);
    }
    const next = lines[pos];
    if (next && next.indent > parentIndent) return block(next.indent);
    if (allowSameIndentList && next && next.indent === parentIndent && (next.text === "-" || next.text.startsWith("- "))) return list(parentIndent);
    return null;
  }

  function blockScalar(style: string, parentIndent: number): string {
    const out: string[] = [];
    let indent = -1;
    while (pos < lines.length && lines[pos]!.indent > parentIndent) {
      const l = lines[pos++]!;
      if (indent < 0) indent = l.indent;
      out.push(" ".repeat(Math.max(0, l.indent - indent)) + l.text);
    }
    return style.startsWith("|") ? out.join("\n") : out.join(" ");
  }

  function map(indent: number): Record<string, unknown> {
    const out: Record<string, unknown> = {};
    while (pos < lines.length && lines[pos]!.indent === indent) {
      const l = lines[pos]!;
      if (l.text === "-" || l.text.startsWith("- ")) break;
      const m = KEY.exec(l.text);
      if (!m) return fail(l.n, `expected "key: value", found "${l.text.slice(0, 40)}".`);
      pos++;
      const rawKey = m[1]!;
      const key = rawKey.startsWith("'") || rawKey.startsWith('"') ? String(scalar(rawKey, l.n)) : rawKey.trim();
      if (key in out) fail(l.n, `the key "${key}" appears twice.`);
      out[key] = value(m[2], l.n, indent, true);
    }
    if (pos < lines.length && lines[pos]!.indent > indent) fail(lines[pos]!.n, "the indentation does not match the lines above.");
    return out;
  }

  function list(indent: number): unknown[] {
    const out: unknown[] = [];
    while (pos < lines.length && lines[pos]!.indent === indent && (lines[pos]!.text === "-" || lines[pos]!.text.startsWith("- "))) {
      const l = lines[pos]!;
      const rest = l.text === "-" ? "" : l.text.slice(2).trim();
      if (rest && KEY.test(rest) && !rest.startsWith("[") && !/^["'].*["']$/.test(rest)) {
        // "- key: value" starts a map whose other keys are indented under the key.
        const inner = indent + (l.text.length - l.text.slice(1).trimStart().length);
        lines[pos] = { n: l.n, indent: inner, text: rest };
        out.push(map(inner));
      } else {
        pos++;
        out.push(value(rest, l.n, indent, false));
      }
    }
    return out;
  }

  const result = block(lines[0]!.indent);
  if (pos < lines.length) fail(lines[pos]!.n, "the indentation does not match the lines above.");
  return result;
}
