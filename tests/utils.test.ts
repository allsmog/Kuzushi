import { describe, expect, it } from "vitest";
import { isRecord, normalizeCostUsd, toErrorMessage } from "../src/utils.js";

describe("utils", () => {
  describe("isRecord", () => {
    it("returns true for plain objects", () => {
      expect(isRecord({ a: 1 })).toBe(true);
    });

    it("returns false for null and primitives", () => {
      expect(isRecord(null)).toBe(false);
      expect(isRecord("x")).toBe(false);
      expect(isRecord(1)).toBe(false);
    });

    it("returns false for arrays", () => {
      expect(isRecord([])).toBe(false);
      expect(isRecord([1, 2, 3])).toBe(false);
      expect(isRecord(["a"])).toBe(false);
    });
  });

  describe("toErrorMessage", () => {
    it("returns error.message for Error instances", () => {
      expect(toErrorMessage(new Error("boom"))).toBe("boom");
    });

    it("stringifies unknown values", () => {
      expect(toErrorMessage("failure")).toBe("failure");
      expect(toErrorMessage({ reason: "x" })).toBe("[object Object]");
    });
  });

  describe("normalizeCostUsd", () => {
    it("returns finite non-negative numbers", () => {
      expect(normalizeCostUsd(0)).toBe(0);
      expect(normalizeCostUsd(0.125)).toBe(0.125);
    });

    it("normalizes invalid values to zero", () => {
      expect(normalizeCostUsd(-1)).toBe(0);
      expect(normalizeCostUsd(Number.NaN)).toBe(0);
      expect(normalizeCostUsd("1")).toBe(0);
    });
  });
});
