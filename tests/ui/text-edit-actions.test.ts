/**
 * Lock-in for the prompt's backspace semantics.
 *
 * Regression: Ink 5 surfaces the physical Backspace key (`\x7f`) as
 * `key.delete`, not `key.backspace`. The shell's old `key.delete` branch
 * did a forward-delete and bailed early when the cursor was at end-of-
 * line — so typing "ruse" then Backspace was a no-op. Both surfaces now
 * route through `applyBackspace`, which always deletes left.
 */

import { describe, expect, it } from "vitest";
import { applyBackspace, isCtrlChord } from "../../src/ui/hooks/text-edit-actions.js";

describe("applyBackspace", () => {
  it("deletes the character before the cursor when at end-of-line (the regression)", () => {
    expect(applyBackspace("ruse", 4)).toEqual({ value: "rus", cursor: 3 });
  });

  it("deletes the character before the cursor mid-line", () => {
    expect(applyBackspace("hello", 3)).toEqual({ value: "helo", cursor: 2 });
  });

  it("returns null when the buffer is empty", () => {
    expect(applyBackspace("", 0)).toBeNull();
  });

  it("returns null when the cursor is at position 0", () => {
    expect(applyBackspace("abc", 0)).toBeNull();
  });

  it("clamps an out-of-range cursor instead of slicing past the end", () => {
    expect(applyBackspace("abc", 99)).toEqual({ value: "ab", cursor: 2 });
  });

  it("returns null instead of producing a negative cursor when given garbage", () => {
    expect(applyBackspace("hi", -3)).toBeNull();
  });
});

describe("isCtrlChord", () => {
  it("matches the bare letter when ctrl is held", () => {
    expect(isCtrlChord("a", "a", true)).toBe(true);
    expect(isCtrlChord("U", "u", true)).toBe(true);
  });

  it("matches the literal control byte (some terminals deliver \\x01 for Ctrl+A)", () => {
    expect(isCtrlChord(String.fromCharCode(1), "a", true)).toBe(true);
    expect(isCtrlChord(String.fromCharCode(21), "u", true)).toBe(true);
  });

  it("ignores the chord when ctrl is not held", () => {
    expect(isCtrlChord("a", "a", false)).toBe(false);
  });

  it("does not match a different letter", () => {
    expect(isCtrlChord("b", "a", true)).toBe(false);
  });

  it("does not match an empty input", () => {
    expect(isCtrlChord("", "a", true)).toBe(false);
  });
});
