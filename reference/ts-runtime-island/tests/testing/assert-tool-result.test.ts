import { describe, expect, it } from "vitest";
import { assertToolResult } from "../../src/testing/index.js";

describe("assertToolResult", () => {
  it("passes on a matching ok + outputContains string", () => {
    expect(() =>
      assertToolResult(
        { ok: true, output: "scan complete with 3 findings" },
        { ok: true, outputContains: "scan complete" },
      ),
    ).not.toThrow();
  });

  it("passes on an array of outputContains needles (string + regex)", () => {
    expect(() =>
      assertToolResult(
        { ok: true, output: "scan complete: findings=3" },
        { outputContains: ["scan complete", /findings=\d+/] },
      ),
    ).not.toThrow();
  });

  it("throws when ok does not match expectation", () => {
    expect(() => assertToolResult({ ok: false, output: "x" }, { ok: true })).toThrowError(
      /expected ok=true, got ok=false/,
    );
  });

  it("throws when outputContains needle is missing", () => {
    expect(() =>
      assertToolResult({ ok: true, output: "abc" }, { outputContains: "zzz" }),
    ).toThrowError(/expected output to contain "zzz"/);
  });

  it("throws when outputMatches regex does not match", () => {
    expect(() =>
      assertToolResult({ ok: true, output: "no digits" }, { outputMatches: /\d+/ }),
    ).toThrowError(/expected output to match \/\\d\+\//);
  });

  it("applies dataShape predicate", () => {
    expect(() =>
      assertToolResult(
        { ok: true, output: "", data: { count: 3 } },
        {
          dataShape: (d) => typeof (d as { count?: number })?.count === "number",
        },
      ),
    ).not.toThrow();
    expect(() =>
      assertToolResult({ ok: true, output: "", data: null }, { dataShape: (d) => d !== null }),
    ).toThrowError(/dataShape predicate returned false/);
  });

  it("catches dataShape predicate exceptions with a clear message", () => {
    expect(() =>
      assertToolResult(
        { ok: true, output: "" },
        {
          dataShape: () => {
            throw new Error("boom");
          },
        },
      ),
    ).toThrowError(/dataShape predicate threw: boom/);
  });

  it("enforces costUsdMax", () => {
    expect(() =>
      assertToolResult({ ok: true, output: "", costUsd: 0.5 }, { costUsdMax: 0.1 }),
    ).toThrowError(/expected costUsd <= 0.1, got 0.5/);
    // Treats missing costUsd as 0.
    expect(() => assertToolResult({ ok: true, output: "" }, { costUsdMax: 0.01 })).not.toThrow();
  });

  it("rejects non-object inputs", () => {
    expect(() => assertToolResult(null as unknown as never, { ok: true })).toThrowError(
      /expected a ToolResult object/,
    );
  });
});
