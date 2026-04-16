import type { BenchCase } from "./harness.js";
import { deduplicateFindings } from "../src/scanners/dedup.js";
import { makeFindings } from "./fixtures.js";

export function benchDedup(): BenchCase[] {
  const cases: BenchCase[] = [];

  for (const size of [1_000, 10_000]) {
    let findings: ReturnType<typeof makeFindings>;
    cases.push({
      name: `dedup ${size} findings`,
      setup: () => {
        findings = makeFindings(size);
      },
      run: () => {
        // deduplicateFindings mutates ordering but not the array we pass, so
        // we can reuse the same fixture across iterations.
        deduplicateFindings(findings);
      },
    });
  }

  return cases;
}
