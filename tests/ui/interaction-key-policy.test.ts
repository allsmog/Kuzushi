import { describe, expect, it } from "vitest";
import {
  isAbortInput,
  isCancelInput,
  isEscapeInput,
  isPlainTextInput,
} from "../../src/ui/interaction-key-policy.js";

describe("interaction key policy", () => {
  it("treats Ctrl+C/Ctrl+D and raw ETX/EOT as abort input", () => {
    expect(isAbortInput("c", { ctrl: true })).toBe(true);
    expect(isAbortInput("D", { ctrl: true })).toBe(true);
    expect(isAbortInput("\u0003", { ctrl: true })).toBe(true);
    expect(isAbortInput("\u0004", { ctrl: true })).toBe(true);
  });

  it("treats Escape and abort chords as cancellation", () => {
    expect(isEscapeInput("", { escape: true })).toBe(true);
    expect(isCancelInput("", { escape: true })).toBe(true);
    expect(isCancelInput("c", { ctrl: true })).toBe(true);
    expect(isCancelInput("x", {})).toBe(false);
  });

  it("keeps invalid control/meta/tab keystrokes out of text insertion", () => {
    expect(isPlainTextInput("a", {})).toBe(true);
    expect(isPlainTextInput("a", { ctrl: true })).toBe(false);
    expect(isPlainTextInput("a", { meta: true })).toBe(false);
    expect(isPlainTextInput("a", { tab: true })).toBe(false);
    expect(isPlainTextInput("", {})).toBe(false);
  });
});
