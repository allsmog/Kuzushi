import { describe, expect, it } from "vitest";
import { __crossAnalyzeInternals } from "../../../../../src/agents/tasks/taint-analysis/cross-service/analyze.js";

const { Semaphore } = __crossAnalyzeInternals;

describe("Semaphore", () => {
  it("allows concurrent access up to the limit", async () => {
    const sem = new Semaphore(2);
    const order: string[] = [];

    const t1 = sem.acquire().then((release) => {
      order.push("t1-acquired");
      return release;
    });

    const t2 = sem.acquire().then((release) => {
      order.push("t2-acquired");
      return release;
    });

    // Both should acquire immediately
    const [r1, r2] = await Promise.all([t1, t2]);
    expect(order).toEqual(["t1-acquired", "t2-acquired"]);

    // Third should wait
    let t3Resolved = false;
    const t3Promise = sem.acquire().then((release) => {
      t3Resolved = true;
      return release;
    });

    // Give the microtask queue a tick
    await new Promise((r) => setTimeout(r, 10));
    expect(t3Resolved).toBe(false);

    // Release one, t3 should acquire
    r1();
    const r3 = await t3Promise;
    expect(t3Resolved).toBe(true);

    r2();
    r3();
  });

  it("processes items sequentially with concurrency 1", async () => {
    const sem = new Semaphore(1);
    const order: number[] = [];

    const tasks = [1, 2, 3].map(async (id) => {
      const release = await sem.acquire();
      order.push(id);
      await new Promise((r) => setTimeout(r, 10));
      release();
    });

    await Promise.all(tasks);
    expect(order).toHaveLength(3);
    // All 3 should complete
    expect(new Set(order).size).toBe(3);
  });

  it("treats concurrency < 1 as 1", async () => {
    const sem = new Semaphore(0);
    const r1 = await sem.acquire();
    let secondAcquired = false;
    const p2 = sem.acquire().then((release) => {
      secondAcquired = true;
      return release;
    });
    await new Promise((r) => setTimeout(r, 10));
    expect(secondAcquired).toBe(false);
    r1();
    const r2 = await p2;
    expect(secondAcquired).toBe(true);
    r2();
  });
});

describe("taintAnalysisCrossAnalyzeTask metadata", () => {
  it("has correct task properties", async () => {
    // Dynamically import to verify the export
    const { taintAnalysisCrossAnalyzeTask } = await import(
      "../../../../../src/agents/tasks/taint-analysis/cross-service/analyze.js"
    );

    expect(taintAnalysisCrossAnalyzeTask.id).toBe("taint-analysis-cross-analyze");
    expect(taintAnalysisCrossAnalyzeTask.outputKind).toBe("custom");
    expect(taintAnalysisCrossAnalyzeTask.dependsOn).toEqual(["taint-analysis-discover"]);
  });
});
