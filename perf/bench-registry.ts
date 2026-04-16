import type { BenchCase } from "./harness.js";
import { TaskRegistry } from "../src/agents/registry.js";
import { makeTaskRegistrySnapshot } from "./fixtures.js";

export function benchRegistry(): BenchCase[] {
  const cases: BenchCase[] = [];

  for (const size of [100, 500]) {
    let registry: TaskRegistry;
    let enabled: string[];
    cases.push({
      name: `resolveOrder ${size} tasks`,
      setup: () => {
        const snap = makeTaskRegistrySnapshot(size);
        registry = new TaskRegistry();
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
