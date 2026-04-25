/**
 * Tests for the activity-emission helpers in `src/agent-runtime/claude.ts`.
 *
 * The helpers run inside the SDK message loop on every assistant message and
 * tool-use block — they're what make the spinner subtitle and the
 * "N agents active" counter come alive when a triage / verify / poc agent is
 * mid-flight. We exercise them against a captured-event mock bus rather than
 * a real one because we only care about the published envelope shape.
 */
import { describe, expect, it, vi } from "vitest";
import { __activityInternals } from "../../src/agent-runtime/claude.js";
import type { AnyEvent, MessageBus } from "../../src/bus/types.js";

function createCaptureBus(): { bus: MessageBus; events: AnyEvent[] } {
  const events: AnyEvent[] = [];
  const bus: MessageBus = {
    publish: vi.fn(async (event: AnyEvent) => {
      events.push(event);
    }),
    subscribe: vi.fn(),
    unsubscribe: vi.fn(),
    waitFor: vi.fn(async () => {
      throw new Error("not used");
    }),
    close: vi.fn(async () => {}),
  } as unknown as MessageBus;
  return { bus, events };
}

const { emitActivityForAssistant, emitActivityDone } = __activityInternals;

describe("claude runtime activity helpers", () => {
  it("emits task:activity per tool_use block", async () => {
    const { bus, events } = createCaptureBus();
    emitActivityForAssistant(
      bus,
      [
        { type: "text", text: "thinking..." },
        { type: "tool_use", name: "Read", input: { file_path: "src/a.ts" } },
        { type: "tool_use", name: "Bash", input: { command: "ls" } },
      ],
      { runId: "run-1", taskId: "triage", fingerprint: "fp-1", phase: "triage" },
    );
    // publishTaskActivity awaits inside but is fire-and-forget at the helper
    // level — flush microtasks so the captured-events array is populated.
    await new Promise((r) => setImmediate(r));
    const taskActivities = events.filter((e) => e.type === "task:activity");
    expect(taskActivities).toHaveLength(2);
    const descriptions = taskActivities.map(
      (e) => (e.payload as { description: string }).description,
    );
    expect(descriptions).toContain("Calling Read…");
    expect(descriptions).toContain("Calling Bash…");
  });

  it("emits ${phase}:agent-activity only when phase + fingerprint are set", async () => {
    const { bus, events } = createCaptureBus();
    emitActivityForAssistant(bus, [{ type: "tool_use", name: "Read", input: {} }], {
      runId: "run-1",
      taskId: "triage",
      fingerprint: "fp-1",
      phase: "triage",
    });
    await new Promise((r) => setImmediate(r));
    const agentActivities = events.filter((e) => e.type === "triage:agent-activity");
    expect(agentActivities).toHaveLength(1);
    const payload = agentActivities[0].payload as {
      fingerprint: string;
      kind: string;
      toolName?: string;
    };
    expect(payload.fingerprint).toBe("fp-1");
    expect(payload.kind).toBe("tool-start");
    expect(payload.toolName).toBe("Read");
  });

  it("skips ${phase}:agent-activity when fingerprint is missing", async () => {
    const { bus, events } = createCaptureBus();
    emitActivityForAssistant(bus, [{ type: "tool_use", name: "Read", input: {} }], {
      runId: "run-1",
      taskId: "triage",
      phase: "triage",
    });
    await new Promise((r) => setImmediate(r));
    expect(events.some((e) => e.type === "triage:agent-activity")).toBe(false);
    // The spinner subtitle should still fire — that channel works without
    // a per-target identifier.
    expect(events.some((e) => e.type === "task:activity")).toBe(true);
  });

  it("ignores blocks that aren't tool_use", async () => {
    const { bus, events } = createCaptureBus();
    emitActivityForAssistant(
      bus,
      [
        { type: "text", text: "hello" },
        { type: "thinking", text: "…" },
      ],
      { runId: "run-1" },
    );
    await new Promise((r) => setImmediate(r));
    expect(events).toHaveLength(0);
  });

  it("is a no-op when bus is null", () => {
    expect(() =>
      emitActivityForAssistant(null, [{ type: "tool_use", name: "Read" }], {
        phase: "triage",
        fingerprint: "fp-1",
      }),
    ).not.toThrow();
  });

  it("is a no-op when content blocks aren't an array", () => {
    const { bus, events } = createCaptureBus();
    emitActivityForAssistant(bus, "not an array", { runId: "run-1" });
    expect(events).toHaveLength(0);
  });

  it("emitActivityDone fires done:true for the configured phase + fingerprint", async () => {
    const { bus, events } = createCaptureBus();
    emitActivityDone(bus, { phase: "verification", fingerprint: "fp-2" });
    await new Promise((r) => setImmediate(r));
    const done = events.find((e) => e.type === "verification:agent-activity");
    expect(done).toBeDefined();
    expect((done!.payload as { done: boolean }).done).toBe(true);
  });

  it("emitActivityDone is a no-op when phase or fingerprint is missing", async () => {
    const { bus, events } = createCaptureBus();
    emitActivityDone(bus, { fingerprint: "fp-2" });
    emitActivityDone(bus, { phase: "triage" });
    await new Promise((r) => setImmediate(r));
    expect(events).toHaveLength(0);
  });
});
