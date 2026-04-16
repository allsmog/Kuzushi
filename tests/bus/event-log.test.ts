import { existsSync, mkdirSync, readFileSync, rmSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { describe, expect, it } from "vitest";
import { InProcessBus } from "../../src/bus/adapters/in-process.js";
import { registerEventLogWriter } from "../../src/bus/event-log.js";

function makeTmpDir(): string {
  const dir = path.join(
    os.tmpdir(),
    `kuzushi-evlog-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
  );
  mkdirSync(dir, { recursive: true });
  return dir;
}

async function cleanup(dir: string): Promise<void> {
  await new Promise((r) => setTimeout(r, 50));
  try {
    rmSync(dir, { recursive: true, force: true });
  } catch {
    /* ok */
  }
}

describe("EventLogWriter", () => {
  it("creates log directory if missing", async () => {
    const dir = makeTmpDir();
    const subDir = path.join(dir, "nested", "dir");
    const bus = new InProcessBus();
    const writer = registerEventLogWriter(bus, { logDir: subDir, runId: "t1" });
    expect(existsSync(subDir)).toBe(true);
    writer.close();
    await cleanup(dir);
  });

  it("writes NDJSON events to file", async () => {
    const dir = makeTmpDir();
    const bus = new InProcessBus();
    const writer = registerEventLogWriter(bus, { logDir: dir, runId: "t2" });

    await bus.publish({
      type: "pipeline:start",
      meta: { runId: "t2", timestamp: new Date().toISOString(), eventId: "e1" },
      payload: { context: { runId: "t2" } },
    });

    await new Promise((r) => setTimeout(r, 50));
    writer.close();

    const logFile = path.join(dir, "events-t2-0.ndjson");
    expect(existsSync(logFile)).toBe(true);

    const lines = readFileSync(logFile, "utf-8").trim().split("\n");
    expect(lines.length).toBeGreaterThan(0);

    const parsed = JSON.parse(lines[0]);
    expect(parsed.type).toBe("pipeline:start");
    expect(parsed.timestamp).toBeDefined();

    await cleanup(dir);
  });

  it("redacts API keys in logged events", async () => {
    const dir = makeTmpDir();
    const bus = new InProcessBus();
    const writer = registerEventLogWriter(bus, { logDir: dir, runId: "t3" });

    await bus.publish({
      type: "pipeline:error",
      meta: { runId: "t3", timestamp: new Date().toISOString(), eventId: "e2" },
      payload: {
        error: "Auth failed with key sk-ant-api03-abcdefghijklmnopqrstuvwxyz1234567890",
        fatal: true,
      },
    });

    await new Promise((r) => setTimeout(r, 50));
    writer.close();

    const logFile = path.join(dir, "events-t3-0.ndjson");
    const content = readFileSync(logFile, "utf-8");
    expect(content).not.toContain("sk-ant-api03-abcdefghijklmnopqrstuvwxyz1234567890");
    expect(content).toContain("sk-ant...");

    await cleanup(dir);
  });

  it("close restores original publish", async () => {
    const dir = makeTmpDir();
    const bus = new InProcessBus();
    const originalPublish = bus.publish;
    const writer = registerEventLogWriter(bus, { logDir: dir, runId: "t4" });
    expect(bus.publish).not.toBe(originalPublish);
    writer.close();
    expect(bus.publish).toBe(originalPublish);
    await cleanup(dir);
  });
});
