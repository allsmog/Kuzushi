/**
 * Regression test for v0.21 followup O7 — the cost-cap halt card never
 * fired in practice because no subscriber flipped `state.costCapHalted = true`
 * on `budget:exceeded`. The UI card, state field, key bindings (c/a) all
 * existed; the missing piece was the report-worker subscriber.
 */

import { describe, expect, it, vi } from "vitest";
import { InProcessBus } from "../../src/bus/adapters/in-process.js";
import { createEvent, generateRunId } from "../../src/bus/helpers.js";
import { registerReportWorker } from "../../src/bus/workers/report-worker.js";
import type { KuzushiConfig } from "../../src/types.js";
import { createUIStore } from "../../src/ui/state.js";

describe("budget:exceeded → costCapHalted (O7)", () => {
  it("flips store.costCapHalted to true and emits an error notice", async () => {
    vi.spyOn(console, "log").mockImplementation(() => {});

    const bus = new InProcessBus();
    const store = createUIStore();
    expect(store.getState().costCapHalted).toBeFalsy();

    const config: KuzushiConfig = {
      model: "anthropic:claude-sonnet-4-6",
      busBackend: "in-process",
      triageBatchSize: 15,
      triageConcurrency: 2,
      scanMode: "parallel",
      tasks: [],
      severity: ["ERROR"],
      excludePatterns: [],
      reportOutput: "",
      taskConfig: {},
    };

    // Pass `db: undefined` — the worker's budget:exceeded handler doesn't
    // touch the DB, so we don't need a real sqlite instance.
    registerReportWorker(bus, { db: undefined, config }, store);

    const runId = generateRunId();
    const context = {
      runId,
      repoRoot: "/tmp/repo",
      repoName: "repo",
      dbPath: "/tmp/repo/.kuzushi/findings.sqlite3",
    };
    await bus.publish(
      createEvent("budget:exceeded", runId, {
        context,
        totalCostUsd: 12.5,
        budgetUsd: 10,
      }),
    );

    expect(store.getState().costCapHalted).toBe(true);

    const notices = store.getState().notices ?? [];
    const exceeded = notices.find((n) => n.message === "Budget exceeded");
    expect(exceeded?.level).toBe("error");
    expect(exceeded?.detail).toContain("12.5");
    expect(exceeded?.detail).toContain("10");

    vi.restoreAllMocks();
  });
});
