import { afterEach, describe, expect, it, vi } from "vitest";
import { createUIStore } from "../../src/ui/state.js";

afterEach(() => {
  vi.useRealTimers();
});

describe("UIStore scan activity updates", () => {
  it("does not notify for duplicate scan activity before the heartbeat refresh interval", () => {
    vi.useFakeTimers();
    vi.setSystemTime(0);

    const store = createUIStore();
    store.initStages([{ id: "scan", label: "Scan" }]);
    store.upsertSubTask("scan", {
      id: "semgrep",
      label: "semgrep",
      status: "active",
    });

    let notifications = 0;
    store.subscribe(() => {
      notifications += 1;
    });

    store.addScanActivity("semgrep", {
      kind: "tool-progress",
      toolName: "Read",
      elapsedSeconds: 0,
    });
    expect(notifications).toBe(1);

    vi.setSystemTime(500);
    store.addScanActivity("semgrep", {
      kind: "tool-progress",
      toolName: "Read",
      elapsedSeconds: 0,
    });
    expect(notifications).toBe(1);

    vi.setSystemTime(1500);
    store.addScanActivity("semgrep", {
      kind: "tool-progress",
      toolName: "Read",
      elapsedSeconds: 0,
    });
    expect(notifications).toBe(2);
  });
});
