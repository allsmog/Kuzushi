/**
 * Threat-driven hunt task — spawns one agent per DFD threat actor
 * (external-entity) with a CTF-framed prompt. Each agent explores the
 * codebase freely from that actor's perspective.
 *
 * Inspired by Nicholas Carlini's file-sweep approach demonstrated at
 * [un]prompted 2026, but driven by the Randori PASTA threat model
 * instead of blind file iteration.
 */

import { createLogger } from "../../logger.js";
import { antiHallucinationModule } from "../../prompts/modules.js";
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
import type { AgentTask, TaskContext } from "../types.js";
import {
  resolveTaskAllowedTools,
  resolveTaskEffort,
  resolveTaskModel,
  resolveTaskPositiveInt,
  resolveTaskRuntime,
  resolveTaskThinkingDisabled,
} from "./runtime-overrides.js";
import { resolveThreatModelOutput } from "./threat-model-guidance.js";
import type { DfdElement, StrideThreat, ThreatModelDocument } from "./threat-modeling/types.js";

const log = createLogger({ stage: "threat-hunt" });

interface ThreatHuntConfig {
  model: string;
  effort?: import("../../agent-runtime/types.js").AgentEffort;
  thinkingDisabled?: boolean;
  maxFindings: number;
  maxActors: number;
  runsPerActor: number;
  maxConcurrentHunts: number;
  maxTurnsPerHunt: number;
  /**
   * Optional system-prompt override. When present, replaces the default
   * buildPrompt() output. Set via the shell's `set THREAT_HUNT_PROMPT ...`
   * or by threading `promptOverride` through taskConfig["threat-hunt"].
   */
  promptOverride?: string;
}

interface ActorWithThreats {
  actor: DfdElement;
  threats: StrideThreat[];
}

// Threat-hunt defaults to Opus with max thinking — deep reasoning is required
// to avoid false positives on defended code (e.g., sandbox escapes with frozen constructors).
// Users can still override via taskConfig["threat-hunt"].model / .effort.
const DEFAULT_THREAT_HUNT_MODEL = "anthropic:claude-opus-4-6";
const DEFAULT_THREAT_HUNT_EFFORT: import("../../agent-runtime/types.js").AgentEffort = "max";

function resolveConfig(ctx: TaskContext): ThreatHuntConfig {
  const model =
    resolveTaskModel(ctx, "threat-hunt") === ctx.config.model
      ? DEFAULT_THREAT_HUNT_MODEL // no explicit override → use Opus
      : resolveTaskModel(ctx, "threat-hunt"); // user explicitly set a model → respect it
  const maxFindings = resolveTaskPositiveInt(ctx, "threat-hunt", "maxFindings", 50);
  const maxActors = resolveTaskPositiveInt(ctx, "threat-hunt", "maxActors", 5);
  const runsPerActor = Math.min(resolveTaskPositiveInt(ctx, "threat-hunt", "runsPerActor", 1), 5);
  const maxConcurrentHunts = resolveTaskPositiveInt(ctx, "threat-hunt", "maxConcurrentHunts", 3);
  // Deep hunts need runway. Pi-ai's turn loop now auto-compacts old
  // tool-result content when `assistant.usage.input` crosses 75% of the
  // model's context window, so a 50-turn free exploration no longer
  // blows the 1M input-context cap. Operators can still override.
  const maxTurnsPerHunt = resolveTaskPositiveInt(ctx, "threat-hunt", "maxTurnsPerHunt", 50);
  const effort = resolveTaskEffort(ctx, "threat-hunt") ?? DEFAULT_THREAT_HUNT_EFFORT;
  const thinkingDisabled = resolveTaskThinkingDisabled(ctx, "threat-hunt") ?? false;
  const rawOverride = ctx.config.taskConfig?.["threat-hunt"]?.["promptOverride"];
  const promptOverride =
    typeof rawOverride === "string" && rawOverride.length > 0 ? rawOverride : undefined;
  return {
    model,
    maxFindings,
    maxActors,
    runsPerActor,
    maxConcurrentHunts,
    maxTurnsPerHunt,
    effort,
    thinkingDisabled,
    ...(promptOverride ? { promptOverride } : {}),
  };
}

/**
 * Extract external-entity actors from the randori threat model output,
 * paired with their HIGH/CRITICAL threats. Actors with no high-severity
 * threats are excluded — their hunt would be speculative.
 * Actors are sorted by threat severity (most critical first).
 */
function extractActorsWithThreats(upstreamOutputs: Map<string, unknown>): {
  prioritized: ActorWithThreats[];
  allActors: DfdElement[];
} {
  const raw = resolveThreatModelOutput(upstreamOutputs);
  if (!isRecord(raw) || !isRecord(raw["document"])) return { prioritized: [], allActors: [] };
  const doc = raw["document"] as unknown as ThreatModelDocument;
  if (!doc.dfd?.elements || !Array.isArray(doc.dfd.elements))
    return { prioritized: [], allActors: [] };

  const allActors = doc.dfd.elements.filter((el) => el.type === "external-entity");
  const threats: StrideThreat[] = Array.isArray(doc.threats) ? doc.threats : [];

  // Group HIGH/CRITICAL threats by elementId
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

async function runActorHunt(
  actor: DfdElement,
  threats: StrideThreat[],
  context: TaskContext,
  config: ThreatHuntConfig,
): Promise<FindingOutput> {
  const scanScope = context.scanPath ?? context.repoRoot;
  const prompt = buildScopedPrompt(actor, threats, scanScope, config.promptOverride);
  const runtime = resolveTaskRuntime(context);
  const tag = `[threat-hunt/${actor.name}]`;

  log.info(`${tag} Starting hunt (model=${config.model})`);

  let resultText = "";
  let structuredOutput: unknown;
  let costUsd = 0;
  let executionError: string | null = null;

  for await (const message of runtime.query({
    prompt,
    options: {
      cwd: context.repoRoot,
      model: config.model,
      allowedTools: resolveTaskAllowedTools(context),
      permissionMode: "dontAsk",
      effort: config.effort,
      thinkingDisabled: config.thinkingDisabled,
      outputFormat: {
        type: "json_schema",
        schema: FINDING_SCHEMA,
        strict: true,
        retryInvalidStructuredOutput: 2,
      },
    },
  })) {
    if (
      message.type === "tool-progress" ||
      message.type === "tool-summary" ||
      message.type === "assistant"
    ) {
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
 * Extract external-entity actors from the upstream threat model output.
 * Simple wrapper over extractActorsWithThreats that returns only the actor list
 * (allActors, not just those with high-severity threats).
 */
function extractActors(upstreamOutputs: Map<string, unknown>): DfdElement[] {
  return extractActorsWithThreats(upstreamOutputs).allActors;
}

async function run(_input: ScanOpts, context: TaskContext): Promise<Finding[]> {
  const config = resolveConfig(context);
  const { prioritized, allActors } = extractActorsWithThreats(context.upstreamOutputs);

  if (allActors.length === 0) {
    log.info("[threat-hunt] No external entities in threat model DFD — skipping");
    return attachTaskOutputMeta([], { costUsd: 0 });
  }

  // Prefer actors with HIGH/CRITICAL threats; fall back to all actors if none qualify.
  const actorsToHunt: ActorWithThreats[] =
    prioritized.length > 0 ? prioritized : allActors.map((a) => ({ actor: a, threats: [] }));

  const capped = actorsToHunt.slice(0, config.maxActors);
  const totalRuns = capped.length * config.runsPerActor;
  log.info(
    `[threat-hunt] Spawning ${totalRuns} hunts (${capped.length} actors x ${config.runsPerActor} runs, from ${allActors.length} external entities)`,
  );

  // Build all hunt tasks, then execute with bounded concurrency to avoid
  // saturating API rate limits or exhausting OS resources.
  const huntTasks: Array<() => Promise<FindingOutput>> = [];
  for (const { actor, threats } of capped) {
    for (let i = 0; i < config.runsPerActor; i++) {
      huntTasks.push(() =>
        runActorHunt(actor, threats, context, config).catch((err) => {
          log.error(`[threat-hunt/${actor.name}] Error: ${toErrorMessage(err)}`);
          return { findings: [], costUsd: 0 } as FindingOutput;
        }),
      );
    }
  }

  const maxConcurrent = Math.min(totalRuns, config.maxConcurrentHunts);
  const results: FindingOutput[] = [];
  for (let i = 0; i < huntTasks.length; i += maxConcurrent) {
    const batch = huntTasks.slice(i, i + maxConcurrent);
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
    context.repoRoot,
    context.repoName,
    "HEAD",
    "threat-hunt",
    config.maxFindings,
  );

  return attachTaskOutputMeta(findings, { costUsd: merged.costUsd ?? 0 });
}

export const threatHuntTask: AgentTask<ScanOpts, Finding[]> = {
  id: "threat-hunt",
  displayName: "Threat-Driven Hunt",
  outputKind: "findings",
  dependsOn: ["threat-model-randori"],
  run,

  triageAgentConfig(finding: Finding, repoName: string): TriageAgentConfig {
    return {
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
    };
  },
};

// Exported for testing
export const __threatHuntInternals = {
  extractActors,
  buildPrompt,
  resolveConfig,
};
