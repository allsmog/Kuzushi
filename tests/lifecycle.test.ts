import { describe, it, expect, beforeEach } from "vitest";
import {
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

  it("clearShutdownHooks resets state", () => {
    registerShutdownHook("test", async () => {}, 1);
    clearShutdownHooks();
    // Should not throw when re-registering
    expect(() => {
      registerShutdownHook("test2", async () => {}, 1);
    }).not.toThrow();
  });
});
