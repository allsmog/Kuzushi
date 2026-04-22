import { describe, expect, it } from "vitest";
import type { AgentMessage, AgentRuntime } from "../../../src/agent-runtime/types.js";
import { __threatHuntInternals, threatHuntTask } from "../../../src/agents/tasks/threat-hunt.js";
import type {
  DfdElement,
  ThreatModelDocument,
} from "../../../src/agents/tasks/threat-modeling/types.js";
import type { TaskContext } from "../../../src/agents/types.js";
import { InProcessBus } from "../../../src/bus/adapters/in-process.js";
import type { TaskActivityEvent } from "../../../src/bus/events.js";

const { extractActors, buildPrompt, resolveConfig } = __threatHuntInternals;

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
    function makeCtx(
      taskConfig: Record<string, unknown> = {},
    ): Parameters<typeof resolveConfig>[0] {
      return {
        runId: "test",
        repoRoot: "/tmp/repo",
        repoName: "test-repo",
        config: {
          model: "anthropic:claude-sonnet-4-6",
          taskConfig: { "threat-hunt": taskConfig },
        } as any,
        runtime: {} as any,
        bus: {} as any,
        upstreamOutputs: new Map(),
      };
    }

    it("defaults runsPerActor to 1 when no taskConfig", () => {
      const config = resolveConfig(makeCtx());
      expect(config.runsPerActor).toBe(1);
    });

    it("reads runsPerActor from taskConfig", () => {
      const config = resolveConfig(makeCtx({ runsPerActor: 3 }));
      expect(config.runsPerActor).toBe(3);
    });

    it("allows runsPerActor exactly at cap (5)", () => {
      const config = resolveConfig(makeCtx({ runsPerActor: 5 }));
      expect(config.runsPerActor).toBe(5);
    });

    it("caps runsPerActor above 5", () => {
      const config = resolveConfig(makeCtx({ runsPerActor: 10 }));
      expect(config.runsPerActor).toBe(5);
    });

    it("defaults maxConcurrentHunts to 3", () => {
      const config = resolveConfig(makeCtx());
      expect(config.maxConcurrentHunts).toBe(3);
    });
  });

  describe("task definition", () => {
    it("has correct metadata", () => {
      expect(threatHuntTask.id).toBe("threat-hunt");
      expect(threatHuntTask.outputKind).toBe("findings");
      expect(threatHuntTask.dependsOn).toEqual(["threat-model-randori"]);
    });

    it("has triageAgentConfig", () => {
      expect(threatHuntTask.triageAgentConfig).toBeDefined();

      const config = threatHuntTask.triageAgentConfig!(
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

      const ctx: TaskContext = {
        runId: "test-run",
        repoRoot: "/tmp/repo",
        repoName: "repo",
        config: {
          model: "anthropic:claude-sonnet-4-6",
          taskConfig: { "threat-hunt": { maxActors: 1, runsPerActor: 1 } },
        } as any,
        runtime: emptyRuntime,
        bus,
        upstreamOutputs: upstream,
      };

      await threatHuntTask.run({} as any, ctx);
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

      const ctx: TaskContext = {
        runId: "test-run",
        repoRoot: "/tmp/repo",
        repoName: "repo",
        config: { model: "anthropic:claude-sonnet-4-6", taskConfig: {} } as any,
        runtime: emptyRuntime,
        bus,
        upstreamOutputs: upstream,
      };

      await threatHuntTask.run({} as any, ctx);
      await new Promise((resolve) => setImmediate(resolve));

      expect(activity).toEqual(["reading threat model"]);

      await bus.close();
    });
  });
});
