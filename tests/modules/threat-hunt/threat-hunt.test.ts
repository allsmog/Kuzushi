import { describe, expect, it } from "vitest";
import type { AgentMessage, AgentRuntime } from "../../../src/agent-runtime/types.js";
import type {
  DfdElement,
  ThreatModelDocument,
} from "../../../src/agents/tasks/threat-modeling/types.js";
import { publishAgentActivity } from "../../../src/bus/activity.js";
import { InProcessBus } from "../../../src/bus/adapters/in-process.js";
import type {
  ScanAgentActivityEvent,
  TaskActivityEvent,
  TaskAgentActivityEvent,
} from "../../../src/bus/events.js";
import {
  __threatHuntInternals,
  threatHuntTool,
} from "../../../src/modules/threat-hunt/threat-hunt.js";
import type { ExecutionContext } from "../../../src/modules/types.js";

const { extractActors, buildPrompt, buildActorFingerprint, resolveConfig, runActorHunt } =
  __threatHuntInternals;

function makeDfdElement(overrides: Partial<DfdElement> = {}): DfdElement {
  return {
    id: "actor-1",
    type: "external-entity",
    name: "Unauthenticated User",
    description: "Public internet user with no credentials",
    trustZone: "external",
    ...overrides,
  };
}

function makeThreatModelOutput(elements: DfdElement[] = []) {
  const doc: ThreatModelDocument = {
    version: "1.0",
    dfd: {
      elements,
      trustBoundaries: [],
    },
    threats: [],
    summary: {
      total: 0,
      bySeverity: {},
      byCategory: {
        spoofing: 0,
        tampering: 0,
        repudiation: 0,
        "information-disclosure": 0,
        "denial-of-service": 0,
        "elevation-of-privilege": 0,
      },
    },
  };
  return { document: doc, findings: [] };
}

/**
 * Build an ExecutionContext for direct DagTool invocation in tests. Wires
 * `reportActivity` and `reportAgentActivity` through the in-process bus the
 * same way `CopilotCore.executeTool` does in production.
 */
function makeExecutionContext(
  bus: InProcessBus,
  runtime: AgentRuntime,
  opts: {
    upstreamOutputs?: Map<string, unknown>;
    taskConfig?: Record<string, unknown>;
  } = {},
): ExecutionContext {
  const upstreamOutputs = opts.upstreamOutputs ?? new Map<string, unknown>();
  const taskConfig = opts.taskConfig ?? {};
  const runContext = {
    runId: "test-run",
    repoRoot: "/tmp/repo",
    repoName: "repo",
    dbPath: "",
  };
  return {
    cwd: "/tmp/repo",
    runtime,
    bus,
    config: {
      model: "anthropic:claude-sonnet-4-6",
      taskConfig: { "threat-hunt": taskConfig },
    } as never,
    dag: {
      runId: "test-run",
      repoRoot: "/tmp/repo",
      repoName: "repo",
      upstreamOutputs,
    },
    reportActivity: (description, meta) => {
      void bus.publish({
        type: "task:activity",
        meta: { id: "a", timestamp: new Date().toISOString(), runId: "test-run" },
        payload: {
          taskId: "threat-hunt",
          description,
          ...(meta?.phase !== undefined ? { phase: meta.phase } : {}),
          ...(meta?.step !== undefined ? { step: meta.step } : {}),
          ...(meta?.total !== undefined ? { total: meta.total } : {}),
        },
      } as never);
    },
    reportAgentActivity: (fingerprint, kind, meta) => {
      publishAgentActivity(bus, "threat-hunt", fingerprint, kind, {
        ...meta,
        runContext,
      });
    },
  };
}

describe("threat-hunt", () => {
  describe("extractActors", () => {
    it("filters to external-entity elements only", () => {
      const upstream = new Map<string, unknown>();
      upstream.set(
        "threat-model-randori",
        makeThreatModelOutput([
          makeDfdElement({ id: "a1", type: "external-entity", name: "User" }),
          makeDfdElement({ id: "p1", type: "process", name: "Auth Service" }),
          makeDfdElement({ id: "ds1", type: "data-store", name: "User DB" }),
          makeDfdElement({ id: "a2", type: "external-entity", name: "Admin" }),
        ]),
      );

      const actors = extractActors(upstream);
      expect(actors).toHaveLength(2);
      expect(actors.map((a) => a.name)).toEqual(["User", "Admin"]);
    });

    it("returns empty array when no threat model output", () => {
      const upstream = new Map<string, unknown>();
      expect(extractActors(upstream)).toEqual([]);
    });

    it("returns empty array when DFD has no elements", () => {
      const upstream = new Map<string, unknown>();
      upstream.set("threat-model-randori", makeThreatModelOutput([]));
      expect(extractActors(upstream)).toEqual([]);
    });

    it("returns empty array when DFD has no external entities", () => {
      const upstream = new Map<string, unknown>();
      upstream.set(
        "threat-model-randori",
        makeThreatModelOutput([makeDfdElement({ id: "p1", type: "process", name: "API" })]),
      );
      expect(extractActors(upstream)).toEqual([]);
    });
  });

  describe("buildPrompt", () => {
    it("includes actor name, description, and trust zone", () => {
      const actor = makeDfdElement({
        name: "External API Consumer",
        description: "Third-party service calling our REST API",
        trustZone: "partner-network",
      });

      const prompt = buildPrompt(actor, []);
      expect(prompt).toContain("External API Consumer");
      expect(prompt).toContain("Third-party service calling our REST API");
      expect(prompt).toContain("partner-network");
    });

    it("includes CTF framing", () => {
      const prompt = buildPrompt(makeDfdElement(), []);
      expect(prompt).toContain("competing in a CTF");
    });

    it("includes anti-hallucination constraints", () => {
      const prompt = buildPrompt(makeDfdElement(), []);
      expect(prompt).toContain("Anti-hallucination constraints");
    });

    it("does not include framework awareness", () => {
      const prompt = buildPrompt(makeDfdElement(), []);
      expect(prompt).not.toContain("Framework Awareness");
    });
  });

  describe("resolveConfig", () => {
    async function runResolve(taskConfig: Record<string, unknown> = {}, input: unknown = {}) {
      const bus = new InProcessBus();
      const runtime: AgentRuntime = {
        id: "stub",
        query(): AsyncIterable<AgentMessage> {
          return (async function* () {})();
        },
      };
      const ctx = makeExecutionContext(bus, runtime, { taskConfig });
      try {
        return await resolveConfig(input, ctx);
      } finally {
        await bus.close();
      }
    }

    it("defaults runsPerActor to 1 when no taskConfig", async () => {
      const config = await runResolve();
      expect(config.runsPerActor).toBe(1);
    });

    it("reads runsPerActor from taskConfig", async () => {
      const config = await runResolve({ runsPerActor: 3 });
      expect(config.runsPerActor).toBe(3);
    });

    it("allows runsPerActor exactly at cap (5)", async () => {
      const config = await runResolve({ runsPerActor: 5 });
      expect(config.runsPerActor).toBe(5);
    });

    it("caps runsPerActor above 5", async () => {
      const config = await runResolve({ runsPerActor: 10 });
      expect(config.runsPerActor).toBe(5);
    });

    it("defaults maxConcurrentHunts to 3", async () => {
      const config = await runResolve();
      expect(config.maxConcurrentHunts).toBe(3);
    });

    it("reads runsPerActor from tool input over defaults", async () => {
      const config = await runResolve({}, { runsPerActor: 2 });
      expect(config.runsPerActor).toBe(2);
    });
  });

  describe("tool definition", () => {
    it("has correct metadata", () => {
      expect(threatHuntTool.name).toBe("threat-hunt:run");
      expect(threatHuntTool.dag.outputKind).toBe("findings");
      expect(threatHuntTool.dag.dependsOn).toEqual(["threat-model-randori"]);
    });

    it("has triageAgentConfig on the DAG spec", () => {
      expect(threatHuntTool.dag.triageAgentConfig).toBeDefined();

      const config = threatHuntTool.dag.triageAgentConfig!(
        {
          taskId: "threat-hunt",
          fingerprint: "abc",
          ruleId: "hunt/sqli",
          filePath: "src/api.ts",
          startLine: 42,
          severity: "ERROR",
          message: "SQL injection",
          evidence: "User input concatenated into query",
          scannerConfidence: "HIGH",
          subcategory: ["vuln"],
          likelihood: "HIGH",
          impact: "HIGH",
          cwe: ["CWE-89"],
          score: 90,
        },
        "test-repo",
      );

      expect(config.prompt).toContain("threat-driven hunt");
      expect(config.prompt).toContain("src/api.ts:42");
      expect(config.prompt).toContain("SQL injection");
    });

    describe("renderResult", () => {
      it("returns the first non-empty output line as-is (avoids dup with runSingleTaskPipeline summary)", () => {
        const rendered = threatHuntTool.renderResult?.({
          ok: true,
          output: "Threat hunt complete: teleport — 22 findings ($24.30)\nSecond line is dropped",
          data: { stats: { totalFindings: 22 } },
        });
        expect(rendered).toBe("Threat hunt complete: teleport — 22 findings ($24.30)");
      });

      it("synthesizes from data.stats when output is empty", () => {
        const rendered = threatHuntTool.renderResult?.({
          ok: true,
          output: "",
          data: { stats: { totalFindings: 4 } },
        });
        expect(rendered).toBe("Threat hunt complete · 4 findings");
      });

      it("falls back to generic completion when no output and no stats", () => {
        const rendered = threatHuntTool.renderResult?.({
          ok: true,
          output: "",
        });
        expect(rendered).toBe("Threat hunt complete");
      });

      it("signals failure when result.ok is false and output is empty", () => {
        const rendered = threatHuntTool.renderResult?.({
          ok: false,
          output: "",
        });
        expect(rendered).toBe("Threat hunt failed");
      });
    });
  });

  describe("run() activity emissions", () => {
    it("publishes task:activity for each setup stage and per-actor hunt", async () => {
      const bus = new InProcessBus();
      const activity: Array<{ description: string; step?: number; total?: number }> = [];
      bus.subscribe<TaskActivityEvent>("task:activity", (event) => {
        activity.push({
          description: event.payload.description,
          step: event.payload.step,
          total: event.payload.total,
        });
      });

      const emptyRuntime: AgentRuntime = {
        id: "stub",
        query(): AsyncIterable<AgentMessage> {
          return (async function* () {
            // No tool calls, no result — simulates the silent thinking phase.
          })();
        },
      };

      const upstream = new Map<string, unknown>();
      upstream.set(
        "threat-model-randori",
        makeThreatModelOutput([
          makeDfdElement({ id: "a1", name: "Attacker", type: "external-entity" }),
        ]),
      );

      const ctx = makeExecutionContext(bus, emptyRuntime, {
        upstreamOutputs: upstream,
        taskConfig: { maxActors: 1, runsPerActor: 1 },
      });

      await threatHuntTool.run({}, ctx);
      // Give best-effort publishes a tick to drain.
      await new Promise((resolve) => setImmediate(resolve));

      const descriptions = activity.map((a) => a.description);
      expect(descriptions).toEqual([
        "reading threat model",
        "queuing 1 actor × 1 run",
        "batch 1/1: hunting 1 actor",
        expect.stringMatching(/^hunting as Attacker — thinking \(/),
      ]);
      const batch = activity.find((a) => a.description.startsWith("batch "));
      expect(batch?.step).toBe(1);
      expect(batch?.total).toBe(1);

      await bus.close();
    });

    it("skips hunt activity when the threat model has no external entities", async () => {
      const bus = new InProcessBus();
      const activity: string[] = [];
      bus.subscribe<TaskActivityEvent>("task:activity", (event) => {
        activity.push(event.payload.description);
      });

      const emptyRuntime: AgentRuntime = {
        id: "stub",
        query(): AsyncIterable<AgentMessage> {
          return (async function* () {})();
        },
      };

      const upstream = new Map<string, unknown>();
      upstream.set("threat-model-randori", makeThreatModelOutput([]));

      const ctx = makeExecutionContext(bus, emptyRuntime, { upstreamOutputs: upstream });

      await threatHuntTool.run({}, ctx);
      await new Promise((resolve) => setImmediate(resolve));

      expect(activity).toEqual(["reading threat model"]);

      await bus.close();
    });
  });

  describe("buildActorFingerprint", () => {
    it("sanitizes whitespace so multi-word actor names produce parseable fingerprints", () => {
      const fp = buildActorFingerprint(makeDfdElement({ name: "Unauthenticated User" }), 0);
      expect(fp).toBe("threat-hunt:Unauthenticated_User:0");
    });

    it("sanitizes embedded colons so the channel:key convention isn't broken", () => {
      const fp = buildActorFingerprint(makeDfdElement({ name: "system:admin" }), 2);
      expect(fp).toBe("threat-hunt:system_admin:2");
    });

    it("produces distinct fingerprints per runIndex for the same actor", () => {
      const actor = makeDfdElement({ name: "StripeAPI" });
      expect(buildActorFingerprint(actor, 0)).not.toBe(buildActorFingerprint(actor, 1));
      expect(buildActorFingerprint(actor, 1)).not.toBe(buildActorFingerprint(actor, 2));
    });
  });

  describe("runActorHunt agent-activity emission", () => {
    function makeStubRuntime(messages: AgentMessage[]): AgentRuntime {
      return {
        id: "stub",
        query(): AsyncIterable<AgentMessage> {
          return (async function* () {
            for (const m of messages) yield m;
          })();
        },
      };
    }

    async function captureEvents(
      bus: InProcessBus,
      ctx: ExecutionContext,
      actor: DfdElement,
      runIndex: number,
    ): Promise<TaskAgentActivityEvent["payload"][]> {
      const events: TaskAgentActivityEvent["payload"][] = [];
      bus.subscribe<TaskAgentActivityEvent>("threat-hunt:agent-activity", (event) => {
        events.push(event.payload);
      });
      const config = await resolveConfig({}, ctx);
      await runActorHunt(actor, [], ctx, config, runIndex, 1);
      // Drain best-effort publishes.
      await new Promise((resolve) => setImmediate(resolve));
      return events;
    }

    it("forwards tool-progress messages with the actor fingerprint", async () => {
      const bus = new InProcessBus();
      const runtime = makeStubRuntime([
        { type: "tool-progress", toolUseId: "t1", toolName: "Read", elapsedSeconds: 0.42 },
        { type: "result", subtype: "success", result: '{"findings":[]}' },
      ]);
      const ctx = makeExecutionContext(bus, runtime);
      const actor = makeDfdElement({ name: "StripeAPI" });

      const events = await captureEvents(bus, ctx, actor, 0);

      const toolProgress = events.find((e) => e.kind === "tool-progress");
      expect(toolProgress).toBeDefined();
      expect(toolProgress!.fingerprint).toBe("threat-hunt:StripeAPI:0");
      expect(toolProgress!.toolName).toBe("Read");
      expect(toolProgress!.elapsedSeconds).toBe(0.42);

      await bus.close();
    });

    it("maps tool-summary messages to kind: tool-complete", async () => {
      const bus = new InProcessBus();
      const runtime = makeStubRuntime([
        {
          type: "tool-summary",
          summary: "read 412 lines from src/api.ts",
          precedingToolUseIds: ["t1"],
        },
        { type: "result", subtype: "success", result: '{"findings":[]}' },
      ]);
      const ctx = makeExecutionContext(bus, runtime);
      const actor = makeDfdElement({ name: "Attacker" });

      const events = await captureEvents(bus, ctx, actor, 0);

      const complete = events.find((e) => e.kind === "tool-complete" && e.summary);
      expect(complete?.summary).toBe("read 412 lines from src/api.ts");

      await bus.close();
    });

    it("dispatches assistant blocks via emitAssistantActivity (tool-start + reasoning)", async () => {
      const bus = new InProcessBus();
      const runtime = makeStubRuntime([
        {
          type: "assistant",
          content: [
            { type: "text", text: "Reviewing the auth middleware now" },
            { type: "tool_use", name: "Grep", input: { pattern: "verifyToken" } },
          ],
        },
        { type: "result", subtype: "success", result: '{"findings":[]}' },
      ]);
      const ctx = makeExecutionContext(bus, runtime);
      const actor = makeDfdElement({ name: "Attacker" });

      const events = await captureEvents(bus, ctx, actor, 0);

      const reasoning = events.find((e) => e.kind === "reasoning");
      expect(reasoning?.summary).toBe("Reviewing the auth middleware now");

      const toolStart = events.find((e) => e.kind === "tool-start");
      expect(toolStart?.toolName).toBe("Grep");
      expect(toolStart?.toolInput).toEqual({ pattern: "verifyToken" });

      await bus.close();
    });

    it("emits scan:agent-activity events when reportAgentActivity is not wired", async () => {
      const bus = new InProcessBus();
      const runtime = makeStubRuntime([
        { type: "tool-progress", toolUseId: "t1", toolName: "Read", elapsedSeconds: 0.2 },
        { type: "result", subtype: "success", result: '{"findings":[]}' },
      ]);
      const baseCtx = makeExecutionContext(bus, runtime);
      const ctx: ExecutionContext = {
        ...baseCtx,
        reportAgentActivity: undefined,
      };
      const actor = makeDfdElement({ name: "Attacker" });
      const events: ScanAgentActivityEvent["payload"][] = [];
      bus.subscribe<ScanAgentActivityEvent>("scan:agent-activity", (event) => {
        events.push(event.payload);
      });
      const config = await resolveConfig({}, ctx);
      await runActorHunt(actor, [], ctx, config, 0, 1);
      await new Promise((resolve) => setImmediate(resolve));

      const progress = events.find((e) => e.kind === "tool-progress");
      expect(progress).toBeDefined();
      expect(progress?.taskId).toBe("threat-hunt");
      expect(progress?.toolName).toBe("Read");

      await bus.close();
    });

    it("publishes a final done:true event so the UI row clears when the hunt ends", async () => {
      const bus = new InProcessBus();
      const runtime = makeStubRuntime([
        { type: "result", subtype: "success", result: '{"findings":[]}' },
      ]);
      const ctx = makeExecutionContext(bus, runtime);
      const actor = makeDfdElement({ name: "Attacker" });

      const events = await captureEvents(bus, ctx, actor, 0);

      const last = events[events.length - 1];
      expect(last?.done).toBe(true);
      expect(last?.fingerprint).toBe("threat-hunt:Attacker:0");

      await bus.close();
    });

    it("still publishes done:true when the runtime throws mid-stream", async () => {
      const bus = new InProcessBus();
      const failingRuntime: AgentRuntime = {
        id: "stub",
        query(): AsyncIterable<AgentMessage> {
          return (async function* () {
            yield {
              type: "tool-progress",
              toolUseId: "t1",
              toolName: "Read",
              elapsedSeconds: 0.1,
            };
            throw new Error("simulated subprocess crash");
          })();
        },
      };
      const ctx = makeExecutionContext(bus, failingRuntime);
      const actor = makeDfdElement({ name: "Attacker" });

      const events: TaskAgentActivityEvent["payload"][] = [];
      bus.subscribe<TaskAgentActivityEvent>("threat-hunt:agent-activity", (event) => {
        events.push(event.payload);
      });
      const config = await resolveConfig({}, ctx);
      await expect(runActorHunt(actor, [], ctx, config, 0, 1)).rejects.toThrow(
        /simulated subprocess crash/,
      );
      await new Promise((resolve) => setImmediate(resolve));

      expect(events.some((e) => e.done === true)).toBe(true);

      await bus.close();
    });
  });
});
