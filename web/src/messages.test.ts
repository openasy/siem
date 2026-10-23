import { messageProblems } from "@openasy/ui";
import { describe, expect, it } from "vitest";
import en from "./messages/en.json";

describe("page words", () => {
  it("has no empty message, and every language has every message with the same placeholders", () => {
    expect(messageProblems({ en })).toEqual([]);
  });
});
