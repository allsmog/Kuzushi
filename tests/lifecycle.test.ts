import { describe, it, expect, beforeEach } from "vitest";
import {
  getShutdownHookCount,
  registerShutdownHook,
  isShuttingDown,
  clearShutdownHooks,
} from "../src/lifecycle.js";

describe("lifecycle", () => {
  beforeEach(() => {
    clearShutdownHooks();
  });

  it("isShuttingDown returns false initially", () => {
    expect(isShuttingDown()).toBe(false);
  });

  it("registerShutdownHook does not throw", () => {
    expect(() => {
      registerShutdownHook("test", async () => {}, 1);
    }).not.toThrow();
  });

  it("registerShutdownHook returns a disposer that removes the hook", () => {
    const dispose = registerShutdownHook("test", async () => {}, 1);
    expect(getShutdownHookCount()).toBe(1);

    dispose();
    expect(getShutdownHookCount()).toBe(0);
  });

  it("disposing per-run hooks prevents accumulation across repeated cycles", () => {
    for (let i = 0; i < 3; i += 1) {
      const disposeBus = registerShutdownHook(`bus-${i}`, async () => {}, 1);
      const disposeDb = registerShutdownHook(`db-${i}`, async () => {}, 2);
      expect(getShutdownHookCount()).toBe(2);
      disposeDb();
      disposeBus();
      expect(getShutdownHookCount()).toBe(0);
    }
  });

  it("clearShutdownHooks resets state", () => {
    registerShutdownHook("test", async () => {}, 1);
    clearShutdownHooks();
    // Should not throw when re-registering
    expect(() => {
      registerShutdownHook("test2", async () => {}, 1);
    }).not.toThrow();
  });
});
