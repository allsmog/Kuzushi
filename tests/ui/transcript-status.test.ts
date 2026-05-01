import { describe, expect, it } from "vitest";
import {
  formatStatusLine,
  parseStatusLine,
  plainStatusLine,
} from "../../src/ui/transcript-status.js";

// biome-ignore lint/suspicious/noControlCharactersInRegex: matches ANSI escapes
const ANSI_RE = /\[[0-9;]*m/g;
const stripAnsi = (s: string): string => s.replace(ANSI_RE, "");

describe("formatStatusLine", () => {
  it("emits the [*] glyph for info", () => {
    expect(stripAnsi(formatStatusLine("info", "ready"))).toBe("[*] ready");
  });
  it("emits the [+] glyph for ok", () => {
    expect(stripAnsi(formatStatusLine("ok", "done"))).toBe("[+] done");
  });
  it("emits the [-] glyph for fail", () => {
    expect(stripAnsi(formatStatusLine("fail", "boom"))).toBe("[-] boom");
  });
  it("emits the [!] glyph for warn", () => {
    expect(stripAnsi(formatStatusLine("warn", "stale"))).toBe("[!] stale");
  });
  it("preserves the body verbatim (no leading/trailing trim)", () => {
    const out = stripAnsi(formatStatusLine("info", "  spaced body  "));
    expect(out).toBe("[*]   spaced body  ");
  });
});

describe("plainStatusLine", () => {
  it("never injects ANSI escapes", () => {
    const out = plainStatusLine("info", "hello world");
    expect(out).toBe("[*] hello world");
    expect(stripAnsi(out)).toBe(out);
  });
});

describe("parseStatusLine", () => {
  it("recognises every glyph", () => {
    expect(parseStatusLine("[*] hello")).toEqual({ kind: "info", message: "hello" });
    expect(parseStatusLine("[+] ok")).toEqual({ kind: "ok", message: "ok" });
    expect(parseStatusLine("[-] no")).toEqual({ kind: "fail", message: "no" });
    expect(parseStatusLine("[!] warn")).toEqual({ kind: "warn", message: "warn" });
  });
  it("collapses tabs/extra spaces between glyph and message", () => {
    expect(parseStatusLine("[*]    spaced")).toEqual({ kind: "info", message: "spaced" });
  });
  it("returns null when no glyph leads", () => {
    expect(parseStatusLine("plain")).toBeNull();
    expect(parseStatusLine("[?] unknown")).toBeNull();
  });
  it("round-trips through plainStatusLine", () => {
    const line = plainStatusLine("warn", "stale context");
    const parsed = parseStatusLine(line);
    expect(parsed).toEqual({ kind: "warn", message: "stale context" });
  });
});
