import { describe, expect, it } from "vitest";
import { periodStarts } from "./siem.ts";

describe("periodStarts", () => {
  it("starts each period on its boundary in UTC, the current one last", () => {
    const now = Date.parse("2026-10-24T23:30:00.000Z");
    expect(periodStarts(2, 3_600_000, now)).toEqual(["2026-10-24T22:00:00.000Z", "2026-10-24T23:00:00.000Z"]);
    expect(periodStarts(2, 86_400_000, now)).toEqual(["2026-10-23T00:00:00.000Z", "2026-10-24T00:00:00.000Z"]);
  });
});
