/**
 * Threat-hunt sub-module — CTF-framed actor agents driven by STRIDE threats
 * from the Randori PASTA threat model. Requires both:
 *   - context.appModel  (routes + data stores + auth patterns)
 *   - randori.threatModel (STRIDE threats to hunt)
 */

import type { CopilotModule, ModuleTool, ToolExecutionContext, ToolResult } from "../types.js";
import { resolvePromptValue } from "./prompts.js";
import { runSingleTaskPipeline, targetProperty } from "./shared.js";

function formatThreatHuntSummary(result: ToolResult): string {
  const first = result.output.split("\n", 1)[0]?.trim();
  if (first && first.length > 0) return first;
  const stats = (result.data as { stats?: { totalFindings?: number } | null } | undefined)?.stats;
  const findings =
    typeof stats?.totalFindings === "number" ? `${stats.totalFindings} findings` : null;
  if (result.ok) return findings ? `Threat hunt complete · ${findings}` : "Threat hunt complete";
  return "Threat hunt failed";
}

const threatHuntTool: ModuleTool = {
  name: "threat-hunt:run",
  displayName: "Threat Hunt",
  formatInput(input) {
    const p = input as Record<string, unknown> | undefined;
    const target = typeof p?.["target"] === "string" ? (p["target"] as string) : null;
    const actors = typeof p?.["maxActors"] === "number" ? (p["maxActors"] as number) : null;
    if (target && actors) return `${target} · ${actors} actors`;
    return target ?? null;
  },
  renderResult(result) {
    return formatThreatHuntSummary(result);
  },
  description: "Run the threat-hunt task — CTF-framed actors hunting STRIDE threats end-to-end.",
  inputSchema: {
    type: "object",
    properties: {
      target: targetProperty,
      maxFindings: { type: "integer", default: 50, description: "Maximum findings to retain." },
      maxActors: { type: "integer", default: 5, description: "Maximum threat actors to spawn." },
      runsPerActor: { type: "integer", default: 1, description: "Hunts per actor." },
      maxConcurrentHunts: { type: "integer", default: 3, description: "Concurrent hunts." },
      maxTurnsPerHunt: { type: "integer", default: 50, description: "Turns per hunt." },
      THREAT_HUNT_PROMPT: {
        type: "string",
        description:
          "Override the threat-hunt actor system prompt. Accepts inline text or a path to .md/.txt.",
        "x-advanced": true,
      },
    },
    required: ["target"],
  },
  headless: true,
  async execute(input: unknown, ctx: ToolExecutionContext): Promise<ToolResult> {
    const p = input as Record<string, unknown>;
    const promptOverride = await resolvePromptValue(p["THREAT_HUNT_PROMPT"] as string, ctx.cwd);
    const maxActors = typeof p.maxActors === "number" ? p.maxActors : undefined;
    ctx.reportActivity?.(
      maxActors ? `starting threat hunt (${maxActors} actors max)` : "starting threat hunt",
      { phase: "threat-hunt" },
    );

    const result = await runSingleTaskPipeline(["threat-hunt"], input, ctx, {
      summaryLabel: "Threat hunt",
      taskConfig: {
        "threat-hunt": {
          maxFindings: p.maxFindings,
          maxActors: p.maxActors,
          runsPerActor: p.runsPerActor,
          maxConcurrentHunts: p.maxConcurrentHunts,
          maxTurnsPerHunt: p.maxTurnsPerHunt,
          ...(promptOverride ? { promptOverride } : {}),
        },
      },
    });

    ctx.reportActivity?.(result.ok ? "threat hunt complete" : "threat hunt finished with errors", {
      phase: "threat-hunt",
    });
    return result;
  },
};

export function createThreatHuntModule(): CopilotModule {
  return {
    id: "threat-hunt",
    displayName: "Threat Hunt",
    category: "offense",
    version: "0.17.2",
    description:
      "CTF-framed actor agents that hunt STRIDE threats from the Randori PASTA threat model.",
    rank: "good",
    references: [{ type: "URL", value: "https://unprompted.ai/" }],
    notes: {
      stability: ["stable"],
      reliability: ["variable-recall"],
      sideEffects: ["costs LLM tokens"],
    },
    requires: [
      { kind: "snapshot", moduleId: "context", field: "appModel" },
      { kind: "snapshot", moduleId: "context", field: "threatModel" },
    ],
    tools: [threatHuntTool],
  };
}
