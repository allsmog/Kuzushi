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
import { repeatableRegexTest } from "./regex.js";
export interface ToolResultExpectations {
  /** Expected value of `result.ok`. */
  ok?: boolean;
  /** Substring(s) or regex(es) that must all appear in `result.output`. */
  outputContains?: string | RegExp | Array<string | RegExp>;
  /** Regex that `result.output` must match. */
  outputMatches?: RegExp;
  /** Predicate applied to `result.data`. Return `false` to fail. */
  dataShape?: (data: unknown) => boolean;
  /**
   * Finite, nonnegative upper bound on `result.costUsd`. Supplying a bound
   * requires the result to contain a finite, nonnegative measured cost.
   */
  costUsdMax?: number;
  /** Expected unresolved-provider-spend marker on a cost-incomplete result. */
  providerSpendUnresolved?: boolean;
  /** Finite, nonnegative upper bound on the observed subtotal. */
  observedCostUsdMax?: number;
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
      observedCostUsd: result.observedCostUsd,
      providerSpendUnresolved: result.providerSpendUnresolved,
    },
    null,
    2,
  );
  return new Error(`assertToolResult: ${reason}\n--- actual ToolResult ---\n${dump}`);
}

function assertResultObject(result: ToolResult): void {
  if (!result || typeof result !== "object") {
    throw new Error(`assertToolResult: expected a ToolResult object, got ${typeof result}`);
  }
}

function assertExpectedOk(result: ToolResult, expected: boolean | undefined): void {
  if (expected === undefined) return;
  if (result.ok !== expected) {
    throw matchFail(result, `expected ok=${expected}, got ok=${result.ok}`);
  }
}

function outputNeedles(expected: string | RegExp | Array<string | RegExp>): Array<string | RegExp> {
  return Array.isArray(expected) ? expected : [expected];
}

function outputIncludes(output: string, needle: string | RegExp): boolean {
  if (typeof needle === "string") return output.includes(needle);
  return repeatableRegexTest(needle, output);
}

function needleLabel(needle: string | RegExp): string {
  return needle instanceof RegExp ? needle.source : JSON.stringify(needle);
}

function assertOutputContains(
  result: ToolResult,
  expected: ToolResultExpectations["outputContains"],
): void {
  if (expected === undefined) return;
  for (const needle of outputNeedles(expected)) {
    if (outputIncludes(result.output, needle)) continue;
    throw matchFail(result, `expected output to contain ${needleLabel(needle)}`);
  }
}

function assertOutputMatches(result: ToolResult, expression: RegExp | undefined): void {
  if (expression === undefined) return;
  if (!repeatableRegexTest(expression, result.output)) {
    throw matchFail(result, `expected output to match /${expression.source}/`);
  }
}

function evaluateDataShape(result: ToolResult, predicate: (data: unknown) => boolean): boolean {
  try {
    return predicate(result.data) === true;
  } catch (error) {
    throw matchFail(result, `dataShape predicate threw: ${toErrorMessage(error)}`);
  }
}

function assertDataShape(result: ToolResult, predicate: ToolResultExpectations["dataShape"]): void {
  if (predicate === undefined) return;
  if (!evaluateDataShape(result, predicate)) {
    throw matchFail(result, "dataShape predicate returned false");
  }
}

function assertCost(result: ToolResult, maximum: number | undefined): void {
  if (maximum === undefined) return;
  assertValidCostMaximum(maximum);
  const cost: unknown = result.costUsd;
  assertMeasuredCost(result, cost);
  if (cost > maximum) {
    throw matchFail(result, `expected costUsd <= ${maximum}, got ${cost}`);
  }
}

function assertObservedCost(result: ToolResult, maximum: number | undefined): void {
  if (maximum === undefined) return;
  assertValidCostMaximum(maximum, "observedCostUsdMax");
  const cost: unknown = result.observedCostUsd;
  assertMeasuredCost(result, cost, "observedCostUsd");
  if (cost > maximum) {
    throw matchFail(result, `expected observedCostUsd <= ${maximum}, got ${cost}`);
  }
}

function assertProviderSpendState(result: ToolResult, expected: boolean | undefined): void {
  if (expected === undefined) return;
  if (result.providerSpendUnresolved !== expected) {
    throw matchFail(
      result,
      `expected providerSpendUnresolved=${expected}, got ${String(result.providerSpendUnresolved)}`,
    );
  }
}

function assertValidCostMaximum(maximum: number, label = "costUsdMax"): void {
  if (!Number.isFinite(maximum) || maximum < 0) {
    throw new Error(
      `assertToolResult: ${label} must be a finite nonnegative number, got ${String(maximum)}`,
    );
  }
}

function assertMeasuredCost(
  result: ToolResult,
  cost: unknown,
  label = "costUsd",
): asserts cost is number {
  if (typeof cost !== "number") {
    throw matchFail(result, `expected a measured numeric ${label}, got ${valueLabel(cost)}`);
  }
  if (!Number.isFinite(cost)) {
    throw matchFail(result, `expected a finite ${label}, got ${String(cost)}`);
  }
  if (cost < 0) {
    throw matchFail(result, `expected a nonnegative ${label}, got ${cost}`);
  }
}

function valueLabel(value: unknown): string {
  return value === undefined ? "missing" : `${typeof value} ${JSON.stringify(value)}`;
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
  assertResultObject(result);
  assertExpectedOk(result, expectations.ok);
  assertOutputContains(result, expectations.outputContains);
  assertOutputMatches(result, expectations.outputMatches);
  assertDataShape(result, expectations.dataShape);
  assertCost(result, expectations.costUsdMax);
  assertObservedCost(result, expectations.observedCostUsdMax);
  assertProviderSpendState(result, expectations.providerSpendUnresolved);
}
