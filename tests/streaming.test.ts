import http from "node:http";
import { afterEach, describe, expect, it } from "vitest";
import type { MessageBus } from "../src/bus/types.js";
import { startStreamingServer } from "../src/streaming.js";

/** Minimal mock bus for testing. */
function createMockBus(): MessageBus & {
  handlers: Map<string, Function[]>;
  emit: (type: string, event: any) => Promise<void>;
} {
  const handlers = new Map<string, Function[]>();

  return {
    handlers,
    async publish(event: any) {
      const fns = handlers.get(event.type) ?? [];
      for (const fn of fns) await fn(event);
    },
    subscribe(eventType: string, handler: Function) {
      if (!handlers.has(eventType)) handlers.set(eventType, []);
      handlers.get(eventType)!.push(handler);
    },
    unsubscribe() {},
    async waitFor() {
      return {} as any;
    },
    async close() {},
    async emit(type: string, event: any) {
      const fns = handlers.get(type) ?? [];
      for (const fn of fns) await fn(event);
    },
  };
}

function makeEvent(type: string, payload: Record<string, unknown>) {
  return {
    type,
    meta: { id: "test-id", timestamp: new Date().toISOString(), runId: "run-1" },
    payload,
  };
}

function fetchSSE(port: number, minEvents: number = 1, timeoutMs: number = 500): Promise<string[]> {
  return new Promise((resolve, reject) => {
    const events: string[] = [];
    let settled = false;
    let resolveTimer: NodeJS.Timeout | null = null;
    const finish = () => {
      if (settled) {
        return;
      }
      settled = true;
      if (resolveTimer) {
        clearTimeout(resolveTimer);
      }
      req.destroy();
      resolve(events);
    };

    const req = http.get(`http://localhost:${port}/events`, (res) => {
      res.on("data", (chunk: Buffer) => {
        const text = chunk.toString();
        const lines = text.split("\n").filter((l) => l.startsWith("data: "));
        for (const line of lines) {
          events.push(line.replace("data: ", ""));
        }

        if (events.length >= minEvents && resolveTimer == null) {
          resolveTimer = setTimeout(finish, 50);
        }
      });
    });
    req.on("error", (error) => {
      if (!settled) {
        reject(error);
      }
    });
    setTimeout(finish, timeoutMs);
  });
}

describe("Streaming Server", () => {
  let cleanup: (() => Promise<void>) | null = null;

  afterEach(async () => {
    if (cleanup) {
      await cleanup();
      cleanup = null;
    }
  });

  it("starts and responds to health check", async () => {
    const bus = createMockBus();
    const streaming = startStreamingServer(bus, 0);
    cleanup = streaming.close;

    // Wait for server to start
    await new Promise((r) => setTimeout(r, 100));

    const port = streaming.port;
    expect(port).toBeGreaterThan(0);

    // Health check
    const health = await new Promise<string>((resolve, reject) => {
      http
        .get(`http://localhost:${port}/health`, (res) => {
          let data = "";
          res.on("data", (chunk) => {
            data += chunk;
          });
          res.on("end", () => resolve(data));
        })
        .on("error", reject);
    });

    const parsed = JSON.parse(health);
    expect(parsed.status).toBe("ok");
  });

  it("streams triage:result events via SSE", async () => {
    const bus = createMockBus();
    const streaming = startStreamingServer(bus, 0);
    cleanup = streaming.close;

    await new Promise((r) => setTimeout(r, 100));

    // Start SSE listener
    const eventsPromise = fetchSSE(streaming.port, 2, 3_000);

    // Wait for connection to establish
    await new Promise((r) => setTimeout(r, 200));

    // Emit a triage result event
    await bus.publish(
      makeEvent("triage:result", {
        context: { runId: "run-1", repoRoot: "/tmp", repoName: "test", dbPath: "/tmp/db" },
        finding: {
          fingerprint: "fp-123",
          filePath: "src/app.ts",
          startLine: 10,
          ruleId: "rule-1",
          severity: "ERROR",
          message: "SQL injection",
          cwe: ["CWE-89"],
        },
        result: {
          verdict: "tp",
          confidence: 0.92,
          rationale: "Unsanitized input",
          triageCostUsd: 0.003,
        },
        index: 1,
        total: 5,
      }),
    );

    const events = await eventsPromise;

    // Should have at least the connected event + triage result
    expect(events.length).toBeGreaterThanOrEqual(2);

    // First event is "connected"
    const connected = JSON.parse(events[0]!);
    expect(connected.message).toBe("Streaming pipeline events");

    // Second event is the triage result
    const triageResult = JSON.parse(events[1]!);
    expect(triageResult.fingerprint).toBe("fp-123");
    expect(triageResult.verdict).toBe("tp");
    expect(triageResult.confidence).toBe(0.92);
  });

  it("returns 404 for unknown paths", async () => {
    const bus = createMockBus();
    const streaming = startStreamingServer(bus, 0);
    cleanup = streaming.close;

    await new Promise((r) => setTimeout(r, 100));

    const status = await new Promise<number>((resolve, reject) => {
      http
        .get(`http://localhost:${streaming.port}/unknown`, (res) => {
          resolve(res.statusCode ?? 0);
        })
        .on("error", reject);
    });

    expect(status).toBe(404);
  });
});
