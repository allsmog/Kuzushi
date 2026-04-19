import { describe, expect, it } from "vitest";
import { createArraySink, createPrintSink, stripAnsi } from "../../src/copilot/print.js";

describe("print helpers", () => {
  it("tags messages with msfconsole-style prefixes", () => {
    const sink = createArraySink();
    sink.status("scanning");
    sink.good("opened session 1");
    sink.error("connect failed");
    sink.warn("auth timeout");
    sink.line("plain");
    expect(sink.lines.map((l) => l.level)).toEqual(["status", "good", "error", "warn", "line"]);
    expect(sink.lines[0].text).toBe("[*] scanning");
    expect(sink.lines[1].text).toBe("[+] opened session 1");
    expect(sink.lines[2].text).toBe("[-] connect failed");
    expect(sink.lines[3].text).toBe("[!] auth timeout");
    expect(sink.lines[4].text).toBe("plain");
  });

  it("applies colors when color option is true", () => {
    const parts: string[] = [];
    const sink = createPrintSink({ color: true, write: (s) => parts.push(s) });
    sink.good("ok");
    expect(stripAnsi(parts.join(""))).toBe("[+] ok\n");
    expect(parts.join("")).not.toBe("[+] ok\n");
  });

  it("respects NO_COLOR when auto-detecting", () => {
    const before = process.env["NO_COLOR"];
    process.env["NO_COLOR"] = "1";
    try {
      const parts: string[] = [];
      const sink = createPrintSink({ write: (s) => parts.push(s) });
      sink.good("ok");
      expect(parts.join("")).toBe("[+] ok\n");
    } finally {
      if (before === undefined) delete process.env["NO_COLOR"];
      else process.env["NO_COLOR"] = before;
    }
  });

  it("invokes onPrint hook for every level", () => {
    const hook: Array<{ level: string; text: string }> = [];
    const sink = createPrintSink({
      color: false,
      write: () => {},
      onPrint: (text, level) => hook.push({ level, text }),
    });
    sink.status("a");
    sink.error("b");
    expect(hook).toEqual([
      { level: "status", text: "[*] a" },
      { level: "error", text: "[-] b" },
    ]);
  });
});
