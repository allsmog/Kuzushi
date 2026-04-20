/**
 * Coverage for the wave-V dev-loop commands: sleep / wait_for / time /
 * clear / version / logs / connect. Each handler is exercised through
 * the real CoreDispatcher + DispatcherDriver so argument parsing and
 * the result shape are validated end-to-end.
 */

import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { createServer, type Server } from "node:net";
import os from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { ModuleEventBus } from "../../src/bus/module-events.js";
import { CoreDispatcher } from "../../src/copilot/dispatcher/core-dispatcher.js";
import { DispatcherDriver } from "../../src/copilot/dispatcher/driver.js";
import { Datastore } from "../../src/copilot/options.js";
import { createArraySink } from "../../src/copilot/print.js";
import { ModuleRegistry } from "../../src/modules/registry.js";

const tempDirs: string[] = [];

function seed(overrides: Partial<ConstructorParameters<typeof CoreDispatcher>[0]> = {}): {
  driver: DispatcherDriver;
  events: ModuleEventBus;
} {
  const registry = new ModuleRegistry();
  const events = new ModuleEventBus();
  const core = new CoreDispatcher({
    registry,
    globals: new Datastore(),
    history: () => [],
    events,
    frameworkVersion: "9.9.9",
    ...overrides,
  });
  const driver = new DispatcherDriver({ base: core, cwd: "/tmp", print: createArraySink() });
  return { driver, events };
}

afterEach(() => {
  while (tempDirs.length > 0) rmSync(tempDirs.pop()!, { recursive: true, force: true });
});

describe("sleep", () => {
  it("waits at least the requested duration (small sample)", async () => {
    const { driver } = seed();
    const started = Date.now();
    const result = await driver.handle("sleep 0.05");
    const elapsed = Date.now() - started;
    expect(elapsed).toBeGreaterThanOrEqual(40);
    expect(result.output).toContain("Slept 0.05s");
  });

  it("rejects non-numeric input", async () => {
    const { driver } = seed();
    const result = await driver.handle("sleep abc");
    expect(result.output).toContain("Usage: sleep");
  });
});

describe("wait_for", () => {
  it("resolves when the event fires", async () => {
    const { driver, events } = seed();
    const run = driver.handle("wait_for test:fired 5");
    // Emit after a tick so the subscription is in place.
    setImmediate(() => events.emit("test:fired", { hello: "world" }));
    const result = await run;
    expect(result.output).toContain("test:fired fired after");
    expect(result.output).toContain("hello");
  });

  it("times out when nothing fires", async () => {
    const { driver } = seed();
    const result = await driver.handle("wait_for ghost:event 0.05");
    expect(result.output).toContain("timed out");
  });
});

describe("time", () => {
  it("appends an elapsed footer to the wrapped command output", async () => {
    const { driver } = seed();
    const result = await driver.handle("time modules");
    expect(result.output).toMatch(/ms$/);
    expect(result.output).toMatch(/modules/);
  });
});

describe("clear", () => {
  it("returns an empty-ish result (real clear is TTY-gated)", async () => {
    const { driver } = seed();
    const result = await driver.handle("clear");
    expect(result.output ?? "").toBe("");
  });
});

describe("version", () => {
  it("reports the configured framework version + module counts", async () => {
    const { driver } = seed();
    const result = await driver.handle("version");
    expect(result.output).toContain("Kuzushi 9.9.9");
    expect(result.output).toContain("Modules loaded");
  });
});

describe("logs", () => {
  it("requires getLogPath to be wired", async () => {
    const { driver } = seed();
    const result = await driver.handle("logs");
    expect(result.output).toContain("not enabled");
  });

  it("tails the last N lines of the configured file", async () => {
    const dir = mkdtempSync(path.join(os.tmpdir(), "kz-logs-"));
    tempDirs.push(dir);
    const file = path.join(dir, "audit.log");
    writeFileSync(file, Array.from({ length: 120 }, (_, i) => `line-${i + 1}`).join("\n"));
    const { driver } = seed({ getLogPath: () => file });
    const result = await driver.handle("logs 5");
    const lines = (result.output ?? "").split("\n");
    expect(lines).toHaveLength(5);
    expect(lines[0]).toBe("line-116");
    expect(lines[4]).toBe("line-120");
  });
});

describe("connect", () => {
  it("receives the bytes written by the target after connect", async () => {
    // Stand up a local TCP echo-banner server.
    let server: Server | undefined;
    const port = await new Promise<number>((resolve, reject) => {
      server = createServer((sock) => {
        sock.write("banner-from-test\n");
        sock.end();
      });
      server.on("error", reject);
      server.listen(0, "127.0.0.1", () => {
        const addr = server?.address();
        if (addr && typeof addr !== "string") resolve(addr.port);
      });
    });
    try {
      const { driver } = seed();
      const result = await driver.handle(`connect 127.0.0.1 ${port}`);
      expect(result.output).toContain("banner-from-test");
    } finally {
      server?.close();
    }
  });

  it("reports usage when args are missing", async () => {
    const { driver } = seed();
    const result = await driver.handle("connect");
    expect(result.output).toContain("Usage: connect");
  });
});
