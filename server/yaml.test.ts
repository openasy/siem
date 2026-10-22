import { describe, expect, it } from "vitest";
import { parseYaml, YamlError } from "./yaml.ts";

describe("parseYaml", () => {
  it("reads maps, nested maps, lists and scalars", () => {
    expect(
      parseYaml(`title: Suspicious cmd # a comment
level: high
count: 3
on: true
nothing:
detection:
  selection:
    Image|endswith:
      - '\\cmd.exe'
      - "\\\\powershell.exe"
    CommandLine: 'it''s here'
  condition: selection
tags:
- attack.execution
- attack.t1059
`),
    ).toEqual({
      title: "Suspicious cmd",
      level: "high",
      count: 3,
      on: true,
      nothing: null,
      detection: { selection: { "Image|endswith": ["\\cmd.exe", "\\powershell.exe"], CommandLine: "it's here" }, condition: "selection" },
      tags: ["attack.execution", "attack.t1059"],
    });
  });

  it("reads inline lists, lists of maps and block scalars", () => {
    expect(parseYaml("a: [x, 'y z', 3]\nb:\n  - k: 1\n    m: 2\n  - k: 3\nc: |\n  line one\n  line two\nd: >\n  folded\n  text\ne: []\n")).toEqual({
      a: ["x", "y z", 3],
      b: [{ k: 1, m: 2 }, { k: 3 }],
      c: "line one\nline two",
      d: "folded text",
      e: [],
    });
  });

  it("keeps colons, hashes and backslashes inside values", () => {
    expect(parseYaml("path: C:\\Windows\\System32\nurl: 'http://x/#frag'\nq: \"a # b\"\n")).toEqual({ path: "C:\\Windows\\System32", url: "http://x/#frag", q: "a # b" });
  });

  it("says where it cannot read", () => {
    const msg = (t: string) => {
      try {
        parseYaml(t);
      } catch (e) {
        expect(e).toBeInstanceOf(YamlError);
        return (e as Error).message;
      }
      return "";
    };
    expect(msg("a: 1\na: 2")).toContain('Line 2: the key "a" appears twice');
    expect(msg("a:\n\tb: 1")).toContain("tabs");
    expect(msg("a: &x 1")).toContain("not supported");
    expect(msg("a: {b: 1}")).toContain("not supported");
    expect(msg("a: 'open")).toContain("not closed");
    expect(msg("a: [1, 2")).toContain("not closed");
    expect(msg("just text")).toContain('expected "key: value"');
    expect(msg("a: 1\n---\nb: 2")).toContain("more than one document");
  });

  it("returns null for an empty document", () => {
    expect(parseYaml("# nothing\n\n")).toBeNull();
  });
});
