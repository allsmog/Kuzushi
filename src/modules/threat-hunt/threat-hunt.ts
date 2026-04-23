/**
 * Threat-driven hunt — CTF-framed actor agents driven by STRIDE threats
 * from the Randori PASTA threat model.
 *
 * Each external-entity actor in the DFD spawns one or more agents; each
 * agent receives a scoped system prompt, free tool access (read/grep/glob),
 * and structured JSON output. Findings are merged, deduplicated, and
 * severity-capped before return.
 *
 * Single-file DagTool: this is the canonical shape for every module that
 * contributes a DAG node + a user-facing tool. The task body (body of
 * `run`) moved verbatim from `src/agents/tasks/threat-hunt.ts`; the module
 * wrapper (JSON schema, rank, requirements) moved verbatim from
 * `src/modules/sast/core-threat-hunt.ts`. No external wrapper, no
 * `runSingleTaskPipeline` bridge, no duplicated prompt-override path.
 *
 * Inspired by Nicholas Carlini's file-sweep approach demonstrated at
 * [un]prompted 2026, driven by the Randori threat model instead of blind
 * file iteration.
 */

import {
  type AgentActivity,
  type AgentActivityCallback,
  emitAssistantActivity,
  resolveDefaultReadOnlyTools,
} from "../../agent-runtime/execution.js";
import type { AgentEffort } from "../../agent-runtime/types.js";
import { resolveThreatModelOutput } from "../../agents/tasks/threat-model-guidance.js";
import type {
  DfdElement,
  StrideThreat,
  ThreatModelDocument,
} from "../../agents/tasks/threat-modeling/types.js";
import { createLogger } from "../../logger.js";
import { antiHallucinationModule } from "../../prompts/modules.js";
import { ALL_TOOLS, buildPolicyLayers, resolveToolPolicy } from "../../prompts/tool-policy.js";
import {
  FINDING_SCHEMA,
  type FindingOutput,
  parseFindingOutput,
  selectFindings,
} from "../../scanners/normalize-findings.js";
import type { Finding, TriageAgentConfig } from "../../scanners/types.js";
import { attachTaskOutputMeta } from "../../task-output-meta.js";
import type { ScanOpts } from "../../types.js";
import { isRecord, toErrorMessage } from "../../utils.js";
import { defineDagTool, defineModule } from "../define.js";
import { resolvePromptValue } from "../sast/prompts.js";
import { targetProperty } from "../sast/shared.js";
import type { CopilotModule, ExecutionContext, ToolResult } from "../types.js";
import { requireDag } from "../types.js";

const log = createLogger({ stage: "threat-hunt" });

const MODULE_ID = "threat-hunt";

// Threat-hunt defaults to Opus with max thinking — deep reasoning is required
// to avoid false positives on defended code (e.g., sandbox escapes with frozen constructors).
// Users can override via `set THREAT_HUNT_MODEL ...` or taskConfig["threat-hunt"].model.
const DEFAULT_THREAT_HUNT_MODEL = "anthropic:claude-opus-4-6";
const DEFAULT_THREAT_HUNT_EFFORT: AgentEffort = "max";

interface ThreatHuntConfig {
  model: string;
  effort?: AgentEffort;
  thinkingDisabled?: boolean;
  maxFindings: number;
  maxActors: number;
  runsPerActor: number;
  maxConcurrentHunts: number;
  maxTurnsPerHunt: number;
  promptOverride?: string;
}

interface ActorWithThreats {
  actor: DfdElement;
  threats: StrideThreat[];
}

/**
 * Read an option from the unified resolver chain:
 *   1. `ctx.resolveOption(key)` — shell `set`/`setg` then taskConfig[moduleId][key]
 *   2. `input[inputKey]` — LLM-supplied JSON field for this tool call
 *   3. `config.taskConfig[moduleId][legacyKey]` — legacy persisted override
 *
 * Keeps all three lookups in one spot so the DagTool doesn't sprawl across
 * three read patterns.
 */
function readOption<T>(
  ctx: ExecutionContext,
  input: Record<string, unknown>,
  key: string,
  legacyKey?: string,
): T | undefined {
  const fromResolver = ctx.resolveOption?.<T>(key);
  if (fromResolver !== undefined) return fromResolver;
  if (input[key] !== undefined) return input[key] as T;
  if (legacyKey && input[legacyKey] !== undefined) return input[legacyKey] as T;
  if (legacyKey) {
    const bucket = ctx.config.taskConfig?.[MODULE_ID] as Record<string, unknown> | undefined;
    if (bucket && legacyKey in bucket) return bucket[legacyKey] as T;
  }
  return undefined;
}

function readPositiveInt(
  ctx: ExecutionContext,
  input: Record<string, unknown>,
  key: string,
  fallback: number,
): number {
  const raw = readOption<number>(ctx, input, key, key);
  if (typeof raw === "number" && Number.isFinite(raw) && raw >= 1) return Math.floor(raw);
  return fallback;
}

function readModel(ctx: ExecutionContext, input: Record<string, unknown>): string {
  const explicit = ctx.toolModel ?? readOption<string>(ctx, input, "model", "model");
  // Only fall back to the user's global config.model when they explicitly
  // chose something other than the config default — otherwise default to
  // Opus, which threat-hunt needs for its deep-reasoning CTF frame.
  if (typeof explicit === "string" && explicit.length > 0 && explicit !== ctx.config.model) {
    return explicit;
  }
  return DEFAULT_THREAT_HUNT_MODEL;
}

function readEffort(
  ctx: ExecutionContext,
  input: Record<string, unknown>,
): AgentEffort | undefined {
  const raw = readOption<string>(ctx, input, "effort", "effort");
  if (raw === "low" || raw === "medium" || raw === "high" || raw === "max") return raw;
  return undefined;
}

function readThinkingDisabled(
  ctx: ExecutionContext,
  input: Record<string, unknown>,
): boolean | undefined {
  const raw = readOption<boolean>(ctx, input, "thinkingDisabled", "thinkingDisabled");
  return typeof raw === "boolean" ? raw : undefined;
}

function readAllowedTools(ctx: ExecutionContext): string[] {
  const available = dedupeTools(resolveDefaultReadOnlyTools(ctx.runtime));
  if (!ctx.config.toolPolicies) return available;
  const layers = buildPolicyLayers(undefined, ctx.config.toolPolicies);
  return dedupeTools(resolveToolPolicy(available.length > 0 ? available : ALL_TOOLS, layers));
}

function dedupeTools(tools: string[]): string[] {
  return [...new Set(tools.filter(Boolean))];
}

async function resolveConfig(input: unknown, ctx: ExecutionContext): Promise<ThreatHuntConfig> {
  const p = isRecord(input) ? input : {};
  const promptRaw = readOption<string>(ctx, p, "THREAT_HUNT_PROMPT", "promptOverride");
  const promptOverride = await resolvePromptValue(promptRaw, ctx.cwd);
  return {
    model: readModel(ctx, p),
    maxFindings: readPositiveInt(ctx, p, "maxFindings", 50),
    maxActors: readPositiveInt(ctx, p, "maxActors", 5),
    runsPerActor: Math.min(readPositiveInt(ctx, p, "runsPerActor", 1), 5),
    maxConcurrentHunts: readPositiveInt(ctx, p, "maxConcurrentHunts", 3),
    maxTurnsPerHunt: readPositiveInt(ctx, p, "maxTurnsPerHunt", 50),
    effort: readEffort(ctx, p) ?? DEFAULT_THREAT_HUNT_EFFORT,
    thinkingDisabled: readThinkingDisabled(ctx, p) ?? false,
    ...(promptOverride ? { promptOverride } : {}),
  };
}

/**
 * Extract external-entity actors from the Randori threat model output,
 * paired with their HIGH/CRITICAL threats. Actors with no high-severity
 * threats are excluded — their hunt would be speculative. Sorted by
 * threat severity (most critical first).
 */
function extractActorsWithThreats(upstreamOutputs: ReadonlyMap<string, unknown>): {
  prioritized: ActorWithThreats[];
  allActors: DfdElement[];
} {
  const raw = resolveThreatModelOutput(upstreamOutputs as Map<string, unknown>);
  if (!isRecord(raw) || !isRecord(raw["document"])) return { prioritized: [], allActors: [] };
  const doc = raw["document"] as unknown as ThreatModelDocument;
  if (!doc.dfd?.elements || !Array.isArray(doc.dfd.elements))
    return { prioritized: [], allActors: [] };

  const allActors = doc.dfd.elements.filter((el) => el.type === "external-entity");
  const threats: StrideThreat[] = Array.isArray(doc.threats) ? doc.threats : [];

  const highThreats = new Map<string, StrideThreat[]>();
  for (const threat of threats) {
    if (threat.impact !== "critical" && threat.impact !== "high") continue;
    const bucket = highThreats.get(threat.elementId) ?? [];
    bucket.push(threat);
    highThreats.set(threat.elementId, bucket);
  }

  const prioritized = allActors
    .filter((el) => (highThreats.get(el.id)?.length ?? 0) > 0)
    .map((el) => ({ actor: el, threats: highThreats.get(el.id)! }))
    .sort((a, b) => {
      const critA = a.threats.filter((t) => t.impact === "critical").length;
      const critB = b.threats.filter((t) => t.impact === "critical").length;
      if (critB !== critA) return critB - critA;
      return b.threats.length - a.threats.length;
    });

  return { prioritized, allActors };
}

function buildPrompt(actor: DfdElement, threats: StrideThreat[]): string {
  const threatLines: string[] = [];
  if (threats.length > 0) {
    threatLines.push(
      "",
      "The threat model identified these specific threats from your attack surface:",
    );
    for (const [i, t] of threats.entries()) {
      threatLines.push(`${i + 1}. [${t.impact.toUpperCase()}/${t.category}] ${t.title}`);
      threatLines.push(`   Attack vector: ${t.attackVector}`);
      const files = t.affectedFiles
        .slice(0, 2)
        .map((f) => `${f.filePath}:${f.startLine}`)
        .join(", ");
      if (files) threatLines.push(`   Affected code: ${files}`);
      const anchors = (t.evidenceAnchors ?? [])
        .slice(0, 2)
        .map((a) => `${a.filePath}:${a.startLine} — ${a.description}`)
        .join("; ");
      if (anchors) threatLines.push(`   Evidence: ${anchors}`);
    }
    threatLines.push(
      "",
      "Your mission: find additional evidence for these threats, discover new attack vectors in the same surface, or identify variants the threat model missed.",
      "Do NOT re-confirm what is already documented above — find something new or deeper.",
    );
  }

  return [
    `You are competing in a CTF. You are simulating: ${actor.name}`,
    `Description: ${actor.description}`,
    `Trust zone: ${actor.trustZone}`,
    ...threatLines,
    "",
    "Find exploitable security vulnerabilities in this codebase from this actor's perspective.",
    "Explore the codebase using the tools available to you.",
    "Only report findings with concrete evidence of exploitability.",
    "",
    antiHallucinationModule(),
  ].join("\n");
}

function buildScopedPrompt(
  actor: DfdElement,
  threats: StrideThreat[],
  scanScope: string,
  promptOverride?: string,
): string {
  const base = promptOverride ?? buildPrompt(actor, threats);
  return [
    `IMPORTANT: Only examine files under ${scanScope}. Do not read, grep, or navigate outside this directory.`,
    "",
    base,
  ].join("\n");
}

/**
 * Build a stable per-actor-run identifier for `state.agentActivity`. Actor
 * names are free-form ("Unauthenticated User", "External Attacker") —
 * replace whitespace and colons so the fingerprint stays parseable and
 * doesn't collide with the `<channel>:<key>` convention elsewhere.
 */
function buildActorFingerprint(actor: DfdElement, runIndex: number): string {
  const sanitized = actor.name.replace(/[\s:]+/g, "_");
  return `threat-hunt:${sanitized}:${runIndex}`;
}

async function runActorHunt(
  actor: DfdElement,
  threats: StrideThreat[],
  ctx: ExecutionContext,
  config: ThreatHuntConfig,
  runIndex: number,
  totalRuns: number,
): Promise<FindingOutput> {
  ctx.signal?.throwIfAborted();
  const dag = requireDag(ctx);
  const scanScope = dag.scanPath ?? dag.repoRoot;
  const prompt = buildScopedPrompt(actor, threats, scanScope, config.promptOverride);
  const tag = `[threat-hunt/${actor.name}#${runIndex}]`;

  // Link the tool's abort signal to a per-hunt AbortController so Ctrl+C
  // in the shell propagates into pi-ai's turn loop. Without this, a deep-
  // thinking Opus hunt keeps burning tokens after the operator aborts.
  const abortController = new AbortController();
  if (ctx.signal) {
    if (ctx.signal.aborted) abortController.abort();
    else ctx.signal.addEventListener("abort", () => abortController.abort(), { once: true });
  }

  // Per-actor agent-activity stream. Unified via `ctx.reportAgentActivity`,
  // which publishes `threat-hunt:agent-activity` events that the report-
  // worker and shell UI subscribe to (see src/bus/workers/report-worker.ts).
  const fingerprint = buildActorFingerprint(actor, runIndex);
  const activityCallback: AgentActivityCallback | undefined = ctx.reportAgentActivity
    ? async (activity: AgentActivity) => {
        ctx.reportAgentActivity?.(fingerprint, activity.kind, {
          ...(activity.toolName !== undefined ? { toolName: activity.toolName } : {}),
          ...(activity.toolInput !== undefined ? { toolInput: activity.toolInput } : {}),
          ...(activity.summary !== undefined ? { summary: activity.summary } : {}),
          ...(activity.elapsedSeconds !== undefined
            ? { elapsedSeconds: activity.elapsedSeconds }
            : {}),
          index: runIndex,
          total: totalRuns,
        });
      }
    : undefined;

  log.info(`${tag} Starting hunt (model=${config.model})`);
  ctx.reportActivity?.(
    `hunting as ${actor.name} — thinking (${config.model}, effort=${config.effort ?? "default"})`,
  );

  let resultText = "";
  let structuredOutput: unknown;
  let costUsd = 0;
  let executionError: string | null = null;

  try {
    for await (const message of ctx.runtime.query({
      prompt,
      options: {
        cwd: dag.repoRoot,
        model: config.model,
        allowedTools: readAllowedTools(ctx),
        permissionMode: "dontAsk",
        effort: config.effort,
        thinkingDisabled: config.thinkingDisabled,
        abortController,
        outputFormat: {
          type: "json_schema",
          schema: FINDING_SCHEMA,
          strict: true,
          retryInvalidStructuredOutput: 2,
        },
      },
    })) {
      if (ctx.signal?.aborted) break;

      // Fan tool/assistant messages out to the activity callback so the
      // per-actor row in the UI ticks live (e.g. "Read src/api/checkout.ts")
      // instead of sitting on a single static label for the whole hunt.
      if (message.type === "assistant") {
        await emitAssistantActivity(message.content, activityCallback);
        continue;
      }
      if (message.type === "tool-progress") {
        await activityCallback?.({
          kind: "tool-progress",
          toolName: message.toolName,
          elapsedSeconds: message.elapsedSeconds,
        });
        continue;
      }
      if (message.type === "tool-summary") {
        await activityCallback?.({
          kind: "tool-complete",
          summary: message.summary,
        });
        continue;
      }
      if (message.type !== "result") continue;

      if (typeof message.totalCostUsd === "number" && Number.isFinite(message.totalCostUsd)) {
        costUsd = message.totalCostUsd;
      }
      if ("result" in message) {
        resultText = message.result;
        structuredOutput = message.structuredOutput;
        const durationSec = message.durationMs ? (message.durationMs / 1000).toFixed(1) : "?";
        log.info(
          `${tag} Complete in ${durationSec}s — ${message.numTurns} turns, $${message.totalCostUsd?.toFixed(4) ?? "?"}`,
        );
        break;
      }
      executionError =
        (Array.isArray(message.errors) ? message.errors.join("; ") : "") ||
        message.subtype ||
        "unknown error";
    }
  } finally {
    // Drop this fingerprint from the UI's active-agents map regardless of
    // outcome (success, error, or abort). The `done: true` flag is read
    // by `handleAgentActivity` in report-worker.
    ctx.reportAgentActivity?.(fingerprint, "tool-complete", {
      index: runIndex,
      total: totalRuns,
      done: true,
    });
  }

  if (executionError) {
    log.error(`${tag} Failed: ${executionError}`);
    return { findings: [], costUsd };
  }

  const parsed =
    structuredOutput != null || resultText
      ? parseFindingOutput(structuredOutput ?? resultText)
      : { findings: [] };
  return { findings: parsed.findings, costUsd };
}

/**
 * One-line summary for the `⎿  <output>` line under the tool header on
 * completion. Prefer the first non-empty line of `result.output` (from
 * `runSingleTaskPipeline`, which already includes findings + cost — so
 * re-appending them would produce "complete: 22 findings · 22 findings").
 * Only synthesize from `data.stats` when `output` is empty (early exits,
 * no-external-entities path, abort before first log line).
 */
function formatThreatHuntSummary(result: ToolResult): string {
  const first = result.output.split("\n", 1)[0]?.trim();
  if (first && first.length > 0) return first;
  const stats = (result.data as { stats?: { totalFindings?: number } | null } | undefined)?.stats;
  const findings =
    typeof stats?.totalFindings === "number" ? `${stats.totalFindings} findings` : null;
  if (result.ok) return findings ? `Threat hunt complete · ${findings}` : "Threat hunt complete";
  return "Threat hunt failed";
}

const triageAgentConfig = (finding: Finding, repoName: string): TriageAgentConfig => ({
  prompt: [
    `You are triaging a finding from the threat-driven hunt in "${repoName}".`,
    "This finding was discovered by an agent simulating a specific threat actor.",
    "",
    `Rule: ${finding.ruleId}`,
    `File: ${finding.filePath}:${finding.startLine}`,
    `Severity: ${finding.severity}`,
    `Message: ${finding.message}`,
    finding.evidence ? `Evidence: ${finding.evidence}` : "",
    "",
    "Verify the vulnerability is genuine and exploitable:",
    "- Trace the complete data flow from source to sink",
    "- Check for sanitization or framework protections",
    "- Confirm the code is reachable from the stated actor's trust zone",
  ]
    .filter(Boolean)
    .join("\n"),
});

export const threatHuntTool = defineDagTool<
  "threat-hunt",
  ScanOpts | Record<string, unknown>,
  Finding[]
>({
  name: "threat-hunt:run",
  displayName: "Threat Hunt",
  description:
    "CTF-framed actor agents that hunt STRIDE threats end-to-end. Spawns one LLM agent per DFD threat actor with a scoped prompt, free tool access, and structured JSON output.",
  headless: true,
  rank: "good",
  references: [{ type: "URL", value: "https://unprompted.ai/" }],
  notes: {
    stability: ["stable"],
    reliability: ["variable-recall"],
    sideEffects: ["costs LLM tokens"],
  },
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
  dag: {
    outputKind: "findings",
    dependsOn: ["threat-model-randori"],
    triageAgentConfig,
  },
  async run(input, ctx) {
    ctx.signal?.throwIfAborted();
    const config = await resolveConfig(input, ctx);
    ctx.reportActivity?.("reading threat model");
    const dag = requireDag(ctx);
    const { prioritized, allActors } = extractActorsWithThreats(dag.upstreamOutputs);

    if (allActors.length === 0) {
      log.info("[threat-hunt] No external entities in threat model DFD — skipping");
      return attachTaskOutputMeta([], { costUsd: 0 }) as Finding[];
    }

    // Prefer actors with HIGH/CRITICAL threats; fall back to all actors if none qualify.
    const actorsToHunt: ActorWithThreats[] =
      prioritized.length > 0 ? prioritized : allActors.map((a) => ({ actor: a, threats: [] }));

    const capped = actorsToHunt.slice(0, config.maxActors);
    const totalRuns = capped.length * config.runsPerActor;
    log.info(
      `[threat-hunt] Spawning ${totalRuns} hunts (${capped.length} actors x ${config.runsPerActor} runs, from ${allActors.length} external entities)`,
    );
    ctx.reportActivity?.(
      `queuing ${capped.length} actor${capped.length === 1 ? "" : "s"} × ${config.runsPerActor} run${config.runsPerActor === 1 ? "" : "s"}`,
    );

    // Build all hunt tasks, then execute with bounded concurrency.
    const huntTasks: Array<() => Promise<FindingOutput>> = [];
    let runIndex = 0;
    for (const { actor, threats } of capped) {
      for (let i = 0; i < config.runsPerActor; i++) {
        const myRunIndex = runIndex++;
        huntTasks.push(() =>
          runActorHunt(actor, threats, ctx, config, myRunIndex, totalRuns).catch((err) => {
            log.error(`[threat-hunt/${actor.name}#${myRunIndex}] Error: ${toErrorMessage(err)}`);
            return { findings: [], costUsd: 0 } as FindingOutput;
          }),
        );
      }
    }

    const maxConcurrent = Math.min(totalRuns, config.maxConcurrentHunts);
    const totalBatches = Math.ceil(huntTasks.length / maxConcurrent);
    const results: FindingOutput[] = [];
    for (let i = 0; i < huntTasks.length; i += maxConcurrent) {
      if (ctx.signal?.aborted) break;
      const batch = huntTasks.slice(i, i + maxConcurrent);
      const batchIndex = Math.floor(i / maxConcurrent);
      ctx.reportActivity?.(
        `batch ${batchIndex + 1}/${totalBatches}: hunting ${batch.length} actor${batch.length === 1 ? "" : "s"}`,
        { step: batchIndex + 1, total: totalBatches },
      );
      const batchResults = await Promise.all(batch.map((fn) => fn()));
      results.push(...batchResults);
    }

    // Merge all findings, dedup via selectFindings
    const merged: FindingOutput = {
      findings: results.flatMap((r) => r.findings),
      costUsd: results.reduce((sum, r) => sum + (r.costUsd ?? 0), 0),
    };

    const findings = selectFindings(
      merged,
      dag.repoRoot,
      dag.repoName,
      "HEAD",
      "threat-hunt",
      config.maxFindings,
    );

    return attachTaskOutputMeta(findings, { costUsd: merged.costUsd ?? 0 }) as Finding[];
  },
});

export function createThreatHuntModule(): CopilotModule {
  return defineModule({
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
  });
}

// Exported for testing (mirrors the old `__threatHuntInternals` surface)
export const __threatHuntInternals = {
  extractActors: (m: ReadonlyMap<string, unknown>) => extractActorsWithThreats(m).allActors,
  buildPrompt,
  buildActorFingerprint,
  resolveConfig,
  runActorHunt,
};
