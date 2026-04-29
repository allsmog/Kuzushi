import { DagRegistry } from "../src/modules/dag-registry.js";
import { makeTaskRegistrySnapshot } from "./fixtures.js";
import type { BenchCase } from "./harness.js";

export function benchRegistry(): BenchCase[] {
  const cases: BenchCase[] = [];

  for (const size of [100, 500]) {
    let registry: DagRegistry;
    let enabled: string[];
    cases.push({
      name: `resolveOrder ${size} tasks`,
      setup: () => {
        const snap = makeTaskRegistrySnapshot(size);
        registry = new DagRegistry();
        for (const t of snap.tasks) registry.register(t);
        enabled = snap.ids;
      },
      run: () => {
        registry.resolveOrder(enabled);
      },
    });
  }

  return cases;
}
