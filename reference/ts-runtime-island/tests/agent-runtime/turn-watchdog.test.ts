import { afterEach, describe, expect, it } from "vitest";
import { TurnWatchdog } from "../../src/agent-runtime/turn-watchdog.js";

describe("TurnWatchdog", () => {
  let watchdog: TurnWatchdog;
  let controller: AbortController;

  afterEach(() => {
    watchdog?.stop();
  });

  it("does not fire before timeout", () => {
    controller = new AbortController();
    watchdog = new TurnWatchdog(controller, 1000);
    watchdog.kick();
    expect(watchdog.hasFired()).toBe(false);
    expect(controller.signal.aborted).toBe(false);
  });

  it("fires after timeout", async () => {
    controller = new AbortController();
    watchdog = new TurnWatchdog(controller, 30);
    watchdog.kick();
    await new Promise((r) => setTimeout(r, 60));
    expect(watchdog.hasFired()).toBe(true);
    expect(controller.signal.aborted).toBe(true);
  });

  it("resets timer on kick", async () => {
    controller = new AbortController();
    watchdog = new TurnWatchdog(controller, 50);
    watchdog.kick();
    await new Promise((r) => setTimeout(r, 30));
    watchdog.kick(); // Reset
    await new Promise((r) => setTimeout(r, 30));
    expect(watchdog.hasFired()).toBe(false);
  });

  it("stop prevents firing", async () => {
    controller = new AbortController();
    watchdog = new TurnWatchdog(controller, 30);
    watchdog.kick();
    watchdog.stop();
    await new Promise((r) => setTimeout(r, 60));
    expect(watchdog.hasFired()).toBe(false);
    expect(controller.signal.aborted).toBe(false);
  });

  it("does not fire after already fired", async () => {
    controller = new AbortController();
    watchdog = new TurnWatchdog(controller, 10);
    watchdog.kick();
    await new Promise((r) => setTimeout(r, 30));
    expect(watchdog.hasFired()).toBe(true);
    // Kicking after fire should be a no-op
    watchdog.kick();
    expect(watchdog.hasFired()).toBe(true);
  });
});
