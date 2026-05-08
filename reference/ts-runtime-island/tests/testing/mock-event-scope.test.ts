import { describe, expect, it } from "vitest";
import { createMockEventScope } from "../../src/testing/index.js";

describe("createMockEventScope", () => {
  it("records emitted events in order", () => {
    const events = createMockEventScope();
    events.emit("scan:start", { id: 1 });
    events.emit("scan:done", { id: 1, count: 3 });
    expect(events.emitted).toEqual([
      { event: "scan:start", payload: { id: 1 } },
      { event: "scan:done", payload: { id: 1, count: 3 } },
    ]);
  });

  it("dispatches to subscribers registered via on", () => {
    const events = createMockEventScope();
    const seen: unknown[] = [];
    events.on("ping", (p) => {
      seen.push(p);
    });
    events.emit("ping", "a");
    events.emit("ping", "b");
    expect(seen).toEqual(["a", "b"]);
  });

  it("once() handlers fire exactly once then auto-detach", () => {
    const events = createMockEventScope();
    let calls = 0;
    events.once("beat", () => {
      calls += 1;
    });
    events.emit("beat", null);
    events.emit("beat", null);
    expect(calls).toBe(1);
  });

  it("on() returns an unsubscribe closure", () => {
    const events = createMockEventScope();
    const seen: unknown[] = [];
    const off = events.on("k", (p) => {
      seen.push(p);
    });
    events.emit("k", 1);
    off();
    events.emit("k", 2);
    expect(seen).toEqual([1]);
  });

  it("captures handler exceptions in .errors without failing emit", () => {
    const events = createMockEventScope();
    events.on("boom", () => {
      throw new Error("handler died");
    });
    expect(() => events.emit("boom", null)).not.toThrow();
    expect(events.errors).toHaveLength(1);
    expect(events.errors[0]?.event).toBe("boom");
  });

  it("disposeAll clears all subscriptions", () => {
    const events = createMockEventScope();
    const seen: unknown[] = [];
    events.on("p", () => seen.push(1));
    events.disposeAll();
    events.emit("p", null);
    expect(seen).toEqual([]);
  });

  it("clear() drops emissions + errors but keeps subscribers", () => {
    const events = createMockEventScope();
    let count = 0;
    events.on("t", () => {
      count += 1;
    });
    events.emit("t", null);
    events.clear();
    expect(events.emitted).toEqual([]);
    events.emit("t", null);
    expect(count).toBe(2);
  });
});
