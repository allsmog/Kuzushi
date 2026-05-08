/**
 * Coverage for the bus publisher helpers — activity, phase, and output.
 *
 * These are thin wrappers around `bus.publish(createEvent(...))` so the
 * point is mostly "it shapes the envelope correctly" + "it doesn't blow
 * up when the bus rejects". Output publisher is the new one in Phase 15.
 */
import { describe, expect, it, vi } from "vitest";
import {
  publishTaskActivity,
  publishTaskOutput,
  publishTaskPhase,
} from "../../src/bus/activity.js";
import { InProcessBus } from "../../src/bus/adapters/in-process.js";

describe("publishTaskOutput", () => {
  it("publishes a task:output event with the supplied taskId + line", async () => {
    const bus = new InProcessBus();
    const received: Array<{ taskId: string; line: string }> = [];
    bus.subscribe("task:output", (event: { payload: { taskId: string; line: string } }) => {
      received.push(event.payload);
    });

    publishTaskOutput(bus, "sast:scan", "Read(src/foo.ts)");
    // Give the in-process publish microtask a tick to land.
    await new Promise((r) => setTimeout(r, 0));

    expect(received).toEqual([{ taskId: "sast:scan", line: "Read(src/foo.ts)" }]);
    await bus.close();
  });

  it("defaults runId to 'shell' when unspecified", async () => {
    const bus = new InProcessBus();
    const meta: Array<Record<string, unknown>> = [];
    bus.subscribe("task:output", (event: { meta: Record<string, unknown> }) => {
      meta.push(event.meta);
    });

    publishTaskOutput(bus, "t", "line");
    await new Promise((r) => setTimeout(r, 0));

    expect(meta[0]?.["runId"]).toBe("shell");
    await bus.close();
  });

  it("honors a custom runId when provided", async () => {
    const bus = new InProcessBus();
    const meta: Array<Record<string, unknown>> = [];
    bus.subscribe("task:output", (event: { meta: Record<string, unknown> }) => {
      meta.push(event.meta);
    });

    publishTaskOutput(bus, "t", "line", { runId: "run-abc" });
    await new Promise((r) => setTimeout(r, 0));

    expect(meta[0]?.["runId"]).toBe("run-abc");
    await bus.close();
  });

  it("swallows publish errors — progress is best-effort", () => {
    // A bus whose publish() rejects should not propagate into the caller.
    const brokenBus = {
      publish: vi.fn().mockRejectedValue(new Error("boom")),
    } as unknown as Parameters<typeof publishTaskOutput>[0];

    expect(() => publishTaskOutput(brokenBus, "t", "line")).not.toThrow();
  });
});

describe("publishTaskActivity", () => {
  it("publishes a task:activity event with the supplied fields", async () => {
    const bus = new InProcessBus();
    const received: Array<{
      taskId: string;
      description: string;
      phase?: string;
      step?: number;
      total?: number;
    }> = [];
    bus.subscribe("task:activity", (event: { payload: (typeof received)[number] }) => {
      received.push(event.payload);
    });

    publishTaskActivity(bus, "task-1", "scanning", { phase: "s2", step: 3, total: 10 });
    await new Promise((r) => setTimeout(r, 0));

    expect(received).toEqual([
      { taskId: "task-1", description: "scanning", phase: "s2", step: 3, total: 10 },
    ]);
    await bus.close();
  });
});

describe("publishTaskPhase", () => {
  it("publishes a task:phase-progress event", async () => {
    const bus = new InProcessBus();
    const received: Array<{ taskId: string; phase: string }> = [];
    bus.subscribe(
      "task:phase-progress",
      (event: { payload: { taskId: string; phase: string } }) => {
        received.push(event.payload);
      },
    );

    publishTaskPhase(bus, "task-2", "phase 2 (S4 threats)");
    await new Promise((r) => setTimeout(r, 0));

    expect(received).toEqual([{ taskId: "task-2", phase: "phase 2 (S4 threats)" }]);
    await bus.close();
  });
});
