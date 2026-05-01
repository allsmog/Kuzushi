/**
 * Assertion helpers for validating `ToolResult` shapes in unit tests.
 *
 * Third parties can replace the conventional
 *   `expect(result.ok).toBe(true); expect(result.output).toContain("…")`
 * triple with a single `assertToolResult(result, { ok: true, outputContains: "…" })`
 * call. Throws a descriptive `Error` — vitest picks it up as a test failure.
 */

import type { ToolResult } from "../modules/types.js";

import { toErrorMessage } from "../utils.js";
export interface ToolResultExpectations {
  /** Expected value of `result.ok`. */
  ok?: boolean;
  /** Substring(s) or regex(es) that must all appear in `result.output`. */
  outputContains?: string | RegExp | Array<string | RegExp>;
  /** Regex that `result.output` must match. */
  outputMatches?: RegExp;
  /** Predicate applied to `result.data`. Return `false` to fail. */
  dataShape?: (data: unknown) => boolean;
  /** Upper bound on `result.costUsd` (fails if `result.costUsd` exceeds). */
  costUsdMax?: number;
}

function matchFail(result: ToolResult, reason: string): Error {
  // Clear, copy-pasteable failure message with a compact dump of the
  // failing `ToolResult`.
  const dump = JSON.stringify(
    {
      ok: result.ok,
      output:
        typeof result.output === "string" && result.output.length > 400
          ? `${result.output.slice(0, 400)}…`
          : result.output,
      data: result.data,
      costUsd: result.costUsd,
    },
    null,
    2,
  );
  return new Error(`assertToolResult: ${reason}\n--- actual ToolResult ---\n${dump}`);
}

/**
 * Assert a `ToolResult` satisfies the given expectations. Throws a clear
 * `Error` on any mismatch. Suitable for use in vitest / jest / bare
 * `node:test` suites.
 *
 * @example
 *   const result = await tool.execute({ target: "." }, ctx);
 *   assertToolResult(result, {
 *     ok: true,
 *     outputContains: ["scan complete", /findings: \d+/],
 *     dataShape: (d) => Array.isArray((d as any)?.findings),
 *     costUsdMax: 0.05,
 *   });
 */
export function assertToolResult(result: ToolResult, expectations: ToolResultExpectations): void {
  if (!result || typeof result !== "object") {
    throw new Error(`assertToolResult: expected a ToolResult object, got ${typeof result}`);
  }

  if (expectations.ok !== undefined && result.ok !== expectations.ok) {
    throw matchFail(result, `expected ok=${expectations.ok}, got ok=${result.ok}`);
  }

  if (expectations.outputContains !== undefined) {
    const needles = Array.isArray(expectations.outputContains)
      ? expectations.outputContains
      : [expectations.outputContains];
    for (const needle of needles) {
      const hit =
        typeof needle === "string" ? result.output.includes(needle) : needle.test(result.output);
      if (!hit) {
        throw matchFail(
          result,
          `expected output to contain ${needle instanceof RegExp ? needle.source : JSON.stringify(needle)}`,
        );
      }
    }
  }

  if (expectations.outputMatches !== undefined) {
    if (!expectations.outputMatches.test(result.output)) {
      throw matchFail(result, `expected output to match /${expectations.outputMatches.source}/`);
    }
  }

  if (expectations.dataShape !== undefined) {
    let ok = false;
    try {
      ok = expectations.dataShape(result.data) === true;
    } catch (error) {
      throw matchFail(result, `dataShape predicate threw: ${toErrorMessage(error)}`);
    }
    if (!ok) {
      throw matchFail(result, "dataShape predicate returned false");
    }
  }

  if (expectations.costUsdMax !== undefined) {
    const cost = result.costUsd ?? 0;
    if (cost > expectations.costUsdMax) {
      throw matchFail(result, `expected costUsd <= ${expectations.costUsdMax}, got ${cost}`);
    }
  }
}
