import { describe, it, expect, vi, beforeEach } from "vitest";
import { createApprovalGate } from "../../../src/agents/tasks/approval-gate.js";
import type { TaskContext } from "../../../src/agents/types.js";
import type { MessageBus } from "../../../src/bus/types.js";

function createMockBus(): MessageBus {
  return {
    publish: vi.fn().mockResolvedValue(undefined),
    subscribe: vi.fn(),
    unsubscribe: vi.fn(),
    waitFor: vi.fn().mockResolvedValue(undefined),
    close: vi.fn().mockResolvedValue(undefined),
  };
}

function createMockContext(bus: MessageBus): TaskContext {
  return {
    runId: "test-run-1",
    repoRoot: "/tmp/test-repo",
    repoName: "test-repo",
    config: {} as any,
    bus,
    upstreamOutputs: new Map(),
  };
}

describe("createApprovalGate", () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });

  it("creates a task with correct metadata", () => {
    const gate = createApprovalGate("test-gate", "Test Gate", ["dep1"]);
    expect(gate.id).toBe("test-gate");
    expect(gate.displayName).toBe("Test Gate");
    expect(gate.outputKind).toBe("custom");
    expect(gate.dependsOn).toEqual(["dep1"]);
    expect(gate.promptMode).toBe("none");
  });

  it("auto-denies in non-interactive mode by default", async () => {
    const originalIsTTY = process.stdin.isTTY;
    Object.defineProperty(process.stdin, "isTTY", { value: false, configurable: true });

    const gate = createApprovalGate("test-gate", "Test Gate", []);
    const bus = createMockBus();
    const ctx = createMockContext(bus);

    const result = await gate.run({}, ctx);

    expect(result.approved).toBe(false);
    expect(result.method).toBe("auto");

    Object.defineProperty(process.stdin, "isTTY", { value: originalIsTTY, configurable: true });
  });

  it("auto-approves in non-interactive mode when defaultOnTimeout is true", async () => {
    const originalIsTTY = process.stdin.isTTY;
    Object.defineProperty(process.stdin, "isTTY", { value: false, configurable: true });

    const gate = createApprovalGate("test-gate", "Test Gate", [], {
      defaultOnTimeout: true,
    });
    const bus = createMockBus();
    const ctx = createMockContext(bus);

    const result = await gate.run({}, ctx);

    expect(result.approved).toBe(true);
    expect(result.method).toBe("auto");

    Object.defineProperty(process.stdin, "isTTY", { value: originalIsTTY, configurable: true });
  });

  it("emits task:approval-requested event", async () => {
    const originalIsTTY = process.stdin.isTTY;
    Object.defineProperty(process.stdin, "isTTY", { value: false, configurable: true });

    const gate = createApprovalGate("test-gate", "Test Gate", []);
    const bus = createMockBus();
    const ctx = createMockContext(bus);

    await gate.run({}, ctx);

    expect(bus.publish).toHaveBeenCalledWith(
      expect.objectContaining({
        type: "task:approval-requested",
        payload: expect.objectContaining({
          taskId: "test-gate",
        }),
      }),
    );

    Object.defineProperty(process.stdin, "isTTY", { value: originalIsTTY, configurable: true });
  });

  it("condition returns false when no upstream findings", () => {
    const gate = createApprovalGate("test-gate", "Test Gate", [], {
      condition: (upstreamOutputs) => {
        for (const [, output] of upstreamOutputs) {
          if (Array.isArray(output) && output.length > 0) return true;
        }
        return false;
      },
    });

    const result = gate.condition!(new Map(), {} as any);
    expect(result).toBe(false);
  });

  it("condition returns true when upstream has findings", () => {
    const gate = createApprovalGate("test-gate", "Test Gate", [], {
      condition: (upstreamOutputs) => {
        for (const [, output] of upstreamOutputs) {
          if (Array.isArray(output) && output.length > 0) return true;
        }
        return false;
      },
    });

    const upstreams = new Map<string, unknown>([["scanner", [{ id: "finding1" }]]]);
    const result = gate.condition!(upstreams, {} as any);
    expect(result).toBe(true);
  });
});
