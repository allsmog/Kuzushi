/**
 * Carlini threat hunt — CTF-framed actor agents driven by a generated
 * threat-model document.
 *
 * Each external-entity actor in the DFD spawns one or more agents; each
 * agent receives a scoped system prompt, free tool access (read/grep/glob),
 * and structured JSON output. Findings are merged, deduplicated, and
 * severity-capped before return.
 *
 * Single-file DagTool: this is the canonical shape for every module that
 * contributes a DAG node + a user-facing tool. The task body (body of
 * `run`) moved verbatim from `src/agents/tasks/carlini-threat-hunt.ts`; the module
 * wrapper (JSON schema, rank, requirements) moved verbatim from
 * `src/modules/sast/core-carlini-threat-hunt.ts`. No external wrapper, no
 * `runSingleTaskPipeline` bridge, no duplicated prompt-override path.
 *
 * Inspired by Nicholas Carlini's [un]prompted talk on parallel scoped
 * agents. Not affiliated with or endorsed by Nicholas Carlini.
 */

import {
  type AgentActivity,
  type AgentActivityCallback,
  emitAssistantActivity,
  resolveDefaultReadOnlyTools,
} from "../../agent-runtime/execution.js";
import type { AgentEffort } from "../../agent-runtime/types.js";
import type {
  DfdFlow,
  DfdNode,
  StrideThreat,
  ThreatModelDocument,
} from "../../agents/tasks/threat-modeling/types.js";
import { createEvent } from "../../bus/helpers.js";
import type { RunContext } from "../../bus/run-context.js";
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
import { loadPersistentThreatModel } from "../../threat-model-renderer.js";
import type { ScanOpts } from "../../types.js";
import { isRecord, toErrorMessage } from "../../utils.js";
import { createAttachmentTools, renderUntrustedAttachments } from "../_shared/attachments/index.js";
import { defineDagTool, defineModule } from "../define.js";
import { resolvePromptValue } from "../sast/prompts.js";
import { targetProperty } from "../sast/schema-fragments.js";
import { ensureThreatModelKbIndex } from "../threat-model/kb-index.js";
import type { CopilotModule, ExecutionContext, ToolResult } from "../types.js";
import { requireDag } from "../types.js";
import {
  CARLINI_THREAT_HUNT_KIND_SPEC,
  carliniThreatHuntAttachmentAdapter,
  loadCarliniThreatHuntAttachments,
} from "./attachments.js";
import { createThreatKbSearchTool, THREAT_KB_SEARCH_TOOL } from "./kb-tool.js";
import {
  type ActorWithThreats,
  actorsFromDocument,
  extractActorsWithThreats,
} from "./selectors.js";

const log = createLogger({ stage: "carlini-threat-hunt" });

const MODULE_ID = "carlini-threat-hunt";

// Threat-hunt defaults to Opus with xhigh thinking — deep reasoning is required
// to avoid false positives on defended code (e.g., sandbox escapes with frozen constructors).
// Users can override via `model=...` or taskConfig["carlini-threat-hunt"].model.
const DEFAULT_CARLINI_THREAT_HUNT_MODEL = "anthropic:claude-opus-4-7";
const DEFAULT_CARLINI_THREAT_HUNT_EFFORT: AgentEffort = "xhigh";

interface CarliniThreatHuntConfig {
  model: string;
  effort?: AgentEffort;
  thinkingDisabled?: boolean;
  maxFindings: number;
  maxActors: number;
  runsPerActor: number;
  maxConcurrentHunts: number;
  maxTurnsPerHunt: number;
  kbTopK: number;
  kbMaxChunkChars: number;
  kbSearchMode: "hybrid" | "fts";
  promptContext: "actor-flows" | "actor-flows-threat-titles";
  debugInlineThreats: boolean;
  promptOverride?: string;
  kbPath?: string;
  /**
   * Operator-staged reference material (incident postmortems, runtime logs,
   * prior findings, intel briefs). Pre-rendered into a nonce-wrapped
   * `<untrusted_attachment>` block by `resolveConfig` so each actor's
   * `buildScopedPrompt` call only has to concatenate, not re-render.
   */
  attachmentsBlock?: string;
}

/**
 * Read an option from the unified resolver chain:
 *   1. `ctx.resolveOption(key)` — shell `set`/`setg` then taskConfig[moduleId][key]
 *   2. `input[inputKey]` — LLM-supplied JSON field for this tool call
 *   3. `config.taskConfig[moduleId][legacyKey]` — persisted module option
 *   4. `config.taskConfig[toolName][legacyKey]` — DagTool wrapper option
 *
 * Keeps all lookups in one spot so the DagTool doesn't sprawl across
 * duplicate read patterns.
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
  const buckets = [
    ctx.config.taskConfig?.[MODULE_ID],
    ctx.config.taskConfig?.[`${MODULE_ID}:run`],
    ctx.tool?.name ? ctx.config.taskConfig?.[ctx.tool.name] : undefined,
  ].filter(isRecord);
  for (const bucket of buckets) {
    if (key in bucket) return bucket[key] as T;
    const lowerKey = key.toLowerCase();
    if (lowerKey in bucket) return bucket[lowerKey] as T;
  }
  if (legacyKey && input[legacyKey] !== undefined) return input[legacyKey] as T;
  if (legacyKey && legacyKey !== key) {
    for (const bucket of buckets) {
      if (legacyKey in bucket) return bucket[legacyKey] as T;
      const lowerLegacyKey = legacyKey.toLowerCase();
      if (lowerLegacyKey in bucket) return bucket[lowerLegacyKey] as T;
    }
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

function readStringEnum<T extends string>(
  ctx: ExecutionContext,
  input: Record<string, unknown>,
  key: string,
  allowed: readonly T[],
  fallback: T,
): T {
  const raw = readOption<string>(ctx, input, key, key);
  if (typeof raw !== "string") return fallback;
  const normalized = raw.trim();
  return (allowed as readonly string[]).includes(normalized) ? (normalized as T) : fallback;
}

function readBooleanOption(
  ctx: ExecutionContext,
  input: Record<string, unknown>,
  key: string,
  fallback: boolean,
): boolean {
  const raw = readOption<boolean>(ctx, input, key, key);
  return typeof raw === "boolean" ? raw : fallback;
}

function readModel(ctx: ExecutionContext, input: Record<string, unknown>): string {
  const explicit = ctx.toolModel ?? readOption<string>(ctx, input, "model", "model");
  if (typeof explicit === "string" && explicit.trim().length > 0) return explicit.trim();
  return DEFAULT_CARLINI_THREAT_HUNT_MODEL;
}

function normalizeEffortAlias(value: unknown): AgentEffort | undefined {
  if (typeof value !== "string") return undefined;
  const raw = value.trim().toLowerCase();
  if (raw === "low" || raw === "medium" || raw === "high" || raw === "xhigh" || raw === "max") {
    return raw;
  }
  if (raw === "extra-high" || raw === "xtra-high") return "xhigh";
  return undefined;
}

function readEffort(
  ctx: ExecutionContext,
  input: Record<string, unknown>,
): AgentEffort | undefined {
  const raw = readOption<string>(ctx, input, "effort", "effort");
  return normalizeEffortAlias(raw);
}

function readThinkingDisabled(
  ctx: ExecutionContext,
  input: Record<string, unknown>,
): boolean | undefined {
  const thinking = readOption<boolean>(ctx, input, "thinking", "thinking");
  if (typeof thinking === "boolean") return !thinking;
  const raw = readOption<boolean>(ctx, input, "thinkingDisabled", "thinkingDisabled");
  return typeof raw === "boolean" ? raw : false;
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

async function resolveConfig(
  input: unknown,
  ctx: ExecutionContext,
): Promise<CarliniThreatHuntConfig> {
  const p = isRecord(input) ? input : {};
  const promptRaw = readOption<string>(ctx, p, "CARLINI_THREAT_HUNT_PROMPT");
  const promptOverride = await resolvePromptValue(promptRaw, ctx.cwd);
  // Pre-render the attachments block once per run; every per-actor prompt
  // shares it so we don't pay the rendering cost (and re-roll the nonce)
  // for each actor.
  const attachments = loadCarliniThreatHuntAttachments(ctx.cwd);
  const attachmentsBlock =
    attachments.length > 0
      ? renderUntrustedAttachments(attachments, {
          moduleId: "carlini-threat-hunt",
          emptyPlaceholder: "",
        }).block
      : undefined;
  return {
    model: readModel(ctx, p),
    maxFindings: readPositiveInt(ctx, p, "maxFindings", 50),
    maxActors: readPositiveInt(ctx, p, "maxActors", 5),
    runsPerActor: Math.min(readPositiveInt(ctx, p, "runsPerActor", 1), 5),
    maxConcurrentHunts: readPositiveInt(ctx, p, "maxConcurrentHunts", 3),
    maxTurnsPerHunt: readPositiveInt(ctx, p, "maxTurnsPerHunt", 50),
    kbTopK: readPositiveInt(ctx, p, "kbTopK", 8),
    kbMaxChunkChars: readPositiveInt(ctx, p, "kbMaxChunkChars", 1200),
    kbSearchMode: readStringEnum(ctx, p, "kbSearchMode", ["hybrid", "fts"] as const, "hybrid"),
    promptContext: readStringEnum(
      ctx,
      p,
      "promptContext",
      ["actor-flows", "actor-flows-threat-titles"] as const,
      "actor-flows",
    ),
    debugInlineThreats: readBooleanOption(ctx, p, "debugInlineThreats", false),
    effort: readEffort(ctx, p) ?? DEFAULT_CARLINI_THREAT_HUNT_EFFORT,
    thinkingDisabled: readThinkingDisabled(ctx, p) ?? false,
    ...(promptOverride ? { promptOverride } : {}),
    ...(attachmentsBlock ? { attachmentsBlock } : {}),
  };
}

interface BuildPromptOptions {
  promptContext?: CarliniThreatHuntConfig["promptContext"];
  debugInlineThreats?: boolean;
  missionOverride?: string;
  kbPath?: string;
  threatKbSearchAvailable?: boolean;
}

function buildPrompt(
  actor: DfdNode,
  threats: StrideThreat[],
  flows: DfdFlow[] = [],
  options: BuildPromptOptions = {},
): string {
  const contextLines: string[] = [];
  if (flows.length > 0) {
    contextLines.push("", "Linked data flows from the graph v2 threat model:");
    for (const flow of flows.slice(0, 12)) {
      const details = [
        flow.protocol ? `protocol=${flow.protocol}` : null,
        flow.dataClassification ? `classification=${flow.dataClassification}` : null,
        flow.trustBoundaryIds.length > 0 ? `crosses=${flow.trustBoundaryIds.join(", ")}` : null,
      ]
        .filter(Boolean)
        .join(" · ");
      contextLines.push(
        `- ${flow.id}: ${flow.sourceId} -> ${flow.targetId} — ${flow.description}${
          details ? ` (${details})` : ""
        }`,
      );
    }
  } else {
    contextLines.push("", "Linked data flows from the graph v2 threat model: (none linked)");
  }

  if (options.debugInlineThreats && threats.length > 0) {
    contextLines.push("", "Debug inline threat details from the threat-model KB source:");
    for (const [i, t] of threats.entries()) {
      contextLines.push(`${i + 1}. [${t.impact.toUpperCase()}/${t.category}] ${t.title}`);
      contextLines.push(`   Attack vector: ${t.attackVector}`);
      const targets = (t.targetElementIds ?? []).join(", ");
      const actors = (t.actorIds ?? []).join(", ");
      const entrypoints = (t.entrypointIds ?? []).join(", ");
      const linkedFlows = (t.flowIds ?? []).join(", ");
      if (actors) contextLines.push(`   Actor ids: ${actors}`);
      if (entrypoints) contextLines.push(`   Entrypoints: ${entrypoints}`);
      if (targets) contextLines.push(`   Target elements: ${targets}`);
      if (linkedFlows) contextLines.push(`   Flow ids: ${linkedFlows}`);
      const sourceHints = renderReferences(t.sources);
      const sinkHints = renderReferences(t.sinks);
      const guardHints = renderReferences(t.guards);
      const sanitizerHints = renderReferences(t.sanitizers);
      if (sourceHints) contextLines.push(`   Source hints: ${sourceHints}`);
      if (sinkHints) contextLines.push(`   Sink hints: ${sinkHints}`);
      if (guardHints) contextLines.push(`   Guard hints: ${guardHints}`);
      if (sanitizerHints) contextLines.push(`   Sanitizer hints: ${sanitizerHints}`);
      if (t.requiredCapabilities?.length) {
        contextLines.push(`   Required capabilities: ${t.requiredCapabilities.join(", ")}`);
      }
      const files = t.affectedFiles
        .slice(0, 2)
        .map((f) => `${f.filePath}:${f.startLine}`)
        .join(", ");
      if (files) contextLines.push(`   Affected code: ${files}`);
      const anchors = (t.evidenceAnchors ?? [])
        .slice(0, 2)
        .map((a) => {
          const range = a.endLine ? `${a.startLine}-${a.endLine}` : `${a.startLine}`;
          return `${a.filePath}:${range}${a.symbol ? ` ${a.symbol}` : ""} — ${a.description}`;
        })
        .join("; ");
      if (anchors) contextLines.push(`   Evidence: ${anchors}`);
    }
  } else if (options.promptContext === "actor-flows-threat-titles" && threats.length > 0) {
    contextLines.push("", "Linked threat leads:");
    for (const threat of threats.slice(0, 20)) {
      contextLines.push(
        `- ${threat.id}: [${threat.impact.toUpperCase()}/${threat.category}] ${threat.title}`,
      );
    }
  }

  contextLines.push("");
  if (options.threatKbSearchAvailable === false && options.kbPath) {
    const flowFilters = flows
      .slice(0, 4)
      .map((flow) => `flow_ids_json like '%"${flow.id}"%'`)
      .join(" or ");
    const kbWhere = [`actor_ids_json like '%"${actor.id}"%'`, flowFilters]
      .filter(Boolean)
      .join(" or ");
    const sqliteCommand = `sqlite3 -readonly "${options.kbPath}" "select id, kind, title, substr(summary,1,240) as summary from chunks where ${kbWhere} limit 8;"`;
    contextLines.push(
      `Threat-model details are indexed in the read-only SQLite KB at ${options.kbPath}.`,
      `If ${THREAT_KB_SEARCH_TOOL} is not available in this runtime, use read-only sqlite3 SELECT queries against chunks/chunks_fts for actorId="${actor.id}" and any flow or threat ids you investigate.`,
      "Your first action must be a read-only shell command equivalent to:",
      `  ${sqliteCommand}`,
      "Your next actions must inspect repository code with read-only shell commands such as `rg -n ...` or `sed -n ...` under the scan scope.",
      "Use retrieved source/sink hints, guards, sanitizers, required capabilities, and evidence anchors to verify reachability.",
    );
  } else {
    contextLines.push(
      `Threat-model details are available through the read-only ${THREAT_KB_SEARCH_TOOL} tool.`,
      `Before reporting a finding, query ${THREAT_KB_SEARCH_TOOL} for actorId="${actor.id}" and any flow or threat ids you investigate.`,
      "Use retrieved source/sink hints, guards, sanitizers, required capabilities, and evidence anchors to verify reachability.",
    );
  }

  const mission = options.missionOverride?.trim()
    ? options.missionOverride.trim()
    : [
        "Your mission: find additional evidence for the linked threat surface, discover new attack vectors in the same surface, or identify variants the threat model missed.",
        "Do NOT re-confirm what is already documented in the KB - find something new or deeper.",
        "",
        "Find exploitable security vulnerabilities in this codebase from this actor's perspective.",
        "Explore the codebase using the tools available to you.",
        "Minimum work before final output: perform at least one threat-model KB lookup and at least two code inspection actions such as read/search/navigation under the scan scope.",
        "If the runtime does not expose ThreatKbSearch, query the SQLite KB path above with read-only sqlite3 SELECTs before deciding there are no findings.",
        "Do not modify files, write artifacts, run destructive commands, or inspect files outside the scan scope.",
        "Only report findings with concrete evidence of exploitability.",
      ].join("\n");

  return [
    `You are performing an authorized CTF-style security assessment. You are simulating: ${actor.name}`,
    `Description: ${actor.description}`,
    `Resolved actor id: ${actor.id}`,
    `Trust zone: ${actor.trustZone}`,
    "Threat actor grounding: hunt from the resolved actor id above. If a threat lists different generator ids, treat them as provenance and verify reachability through the linked flows and evidence.",
    "Use the linked flows and the threat-model KB to reason about actor reachability before reporting.",
    ...contextLines,
    "",
    mission,
    "",
    antiHallucinationModule(),
    "",
    "Start the hunt now. Do not acknowledge these instructions. First use read-only tools to query the KB and inspect linked code, then return the final JSON.",
  ].join("\n");
}

function buildScopedPrompt(
  actor: DfdNode,
  threats: StrideThreat[],
  flows: DfdFlow[],
  scanScope: string,
  options: BuildPromptOptions & { attachmentsBlock?: string } = {},
): string {
  const base = buildPrompt(actor, threats, flows, options);
  // Order: scope-restriction → operator KB → actor mission. Putting the
  // attachments block between scope and mission means the agent reads "what
  // you can touch", "what you should know", "what to do" in that sequence.
  // Note: attachments fire even under CARLINI_THREAT_HUNT_PROMPT overrides so the
  // operator's evidence is never silently dropped — flip the conditional
  // here if a future override should suppress the KB.
  const sections: string[] = [
    `IMPORTANT: Only examine files under ${scanScope}. Do not read, grep, or navigate outside this directory.`,
    "",
  ];
  if (options.attachmentsBlock?.trim()) {
    sections.push(options.attachmentsBlock, "");
  }
  sections.push(base);
  return sections.join("\n");
}

function renderReferences(refs: StrideThreat["sources"]): string {
  if (!refs?.length) return "";
  return refs
    .slice(0, 4)
    .map((ref) => {
      const location = ref.filePath
        ? `${ref.filePath}${ref.startLine ? `:${ref.startLine}` : ""}`
        : ref.elementId;
      return [ref.kind, location, ref.description].filter(Boolean).join(" ");
    })
    .join("; ");
}

/**
 * Build a stable per-actor-run identifier for `state.agentActivity`. Actor
 * names are free-form ("Unauthenticated User", "External Attacker") —
 * replace whitespace and colons so the fingerprint stays parseable and
 * doesn't collide with the `<channel>:<key>` convention elsewhere.
 */
function buildActorFingerprint(actor: DfdNode, runIndex: number): string {
  const sanitized = actor.name.replace(/[\s:]+/g, "_");
  return `carlini-threat-hunt:${sanitized}:${runIndex}`;
}

function runtimeSupportsCustomTools(runtime: ExecutionContext["runtime"]): boolean {
  return runtime.id === "pi-ai";
}

function runtimeSupportsStrictOutputSchema(runtime: ExecutionContext["runtime"]): boolean {
  // Codex obeys the large structured-output schema too eagerly for this
  // workflow and may finalize without using shell tools. Let the prompt carry
  // the JSON contract so the agent keeps its normal tool loop, then parse the
  // final JSON below.
  return runtime.id !== "codex";
}

function codexFinalJsonInstruction(): string {
  return [
    "Final output contract for Codex runtime:",
    "After the required KB and code-inspection commands have run, return exactly one JSON object and no prose.",
    'Use {"findings":[]} when there are no concrete exploitable findings.',
    "Each finding must use this shape:",
    '{"ruleId":"carlini-threat-hunt/<short-id>","filePath":"relative/path","startLine":123,"severity":"ERROR|WARNING|INFO","message":"concise finding","confidence":"HIGH|MEDIUM|LOW","subcategory":["vuln"],"likelihood":"HIGH|MEDIUM|LOW","impact":"HIGH|MEDIUM|LOW","cwe":["CWE-..."],"evidence":"source-to-sink proof"}',
  ].join("\n");
}

function buildScanRunContext(ctx: ExecutionContext): RunContext | null {
  const dag = ctx.dag;
  if (!dag) return null;

  return {
    runId: dag.runId,
    repoRoot: dag.workRoot ?? dag.repoRoot,
    ...(dag.scanPath ? { scanPath: dag.scanPath } : {}),
    ...(dag.gitRoot ? { gitRoot: dag.gitRoot } : {}),
    repoName: dag.repoName,
    // report-worker does not read dbPath for scan:agent-activity, and scanner
    // adapters use the same empty-string fallback when the DB path is unknown.
    dbPath: "",
  };
}

function threatModelRoot(ctx: ExecutionContext): string {
  const dag = requireDag(ctx);
  return dag.workRoot ?? dag.scanPath ?? dag.repoRoot;
}

function threatModelDocumentFromUpstream(
  upstreamOutputs: ReadonlyMap<string, unknown>,
): ThreatModelDocument | null {
  const candidates = [
    upstreamOutputs.get("threat-model-randori"),
    upstreamOutputs.get("threat-model:threat-model-randori"),
  ];
  for (const candidate of candidates) {
    if (!isRecord(candidate)) continue;
    const document = candidate["document"];
    if (isRecord(document) && isRecord(document["dfd"]) && Array.isArray(document["threats"])) {
      return document as unknown as ThreatModelDocument;
    }
  }
  return null;
}

function resolveHuntThreatModel(ctx: ExecutionContext): ThreatModelDocument {
  const dag = requireDag(ctx);
  const fromUpstream = threatModelDocumentFromUpstream(dag.upstreamOutputs);
  if (fromUpstream) return fromUpstream;
  const root = threatModelRoot(ctx);
  const persistent = loadPersistentThreatModel(root);
  if (persistent) return persistent;
  throw new Error(
    `carlini-threat-hunt requires an existing .kuzushi/threat-model.json under ${root}. Run /use threat-model then run . first.`,
  );
}

async function publishScanActivity(
  ctx: ExecutionContext,
  runContext: RunContext,
  activity: AgentActivity,
): Promise<void> {
  try {
    await ctx.bus.publish(
      createEvent("scan:agent-activity", runContext.runId, {
        context: runContext,
        taskId: MODULE_ID,
        kind: activity.kind,
        ...(activity.toolName !== undefined ? { toolName: activity.toolName } : {}),
        ...(activity.toolInput !== undefined ? { toolInput: activity.toolInput } : {}),
        ...(activity.summary !== undefined ? { summary: activity.summary } : {}),
        ...(activity.elapsedSeconds !== undefined
          ? { elapsedSeconds: activity.elapsedSeconds }
          : {}),
      }),
    );
  } catch {
    // Best-effort activity stream — never fail the hunt on UI event issues.
  }
}

async function runActorHunt(
  actor: DfdNode,
  threats: StrideThreat[],
  flows: DfdFlow[],
  ctx: ExecutionContext,
  config: CarliniThreatHuntConfig,
  runIndex: number,
  totalRuns: number,
): Promise<FindingOutput> {
  ctx.signal?.throwIfAborted();
  const dag = requireDag(ctx);
  const scanScope = dag.scanPath ?? dag.workRoot ?? dag.repoRoot;
  const prompt = buildScopedPrompt(actor, threats, flows, scanScope, {
    missionOverride: config.promptOverride,
    promptContext: config.promptContext,
    debugInlineThreats: config.debugInlineThreats,
    attachmentsBlock: config.attachmentsBlock,
    kbPath: config.kbPath,
    threatKbSearchAvailable: runtimeSupportsCustomTools(ctx.runtime),
  });
  const effectivePrompt = runtimeSupportsStrictOutputSchema(ctx.runtime)
    ? prompt
    : `${prompt}\n\n${codexFinalJsonInstruction()}`;
  const tag = `[carlini-threat-hunt/${actor.name}#${runIndex}]`;

  // Link the tool's abort signal to a per-hunt AbortController so Ctrl+C
  // in the shell propagates into pi-ai's turn loop. Without this, a deep-
  // thinking Opus hunt keeps burning tokens after the operator aborts.
  const abortController = new AbortController();
  if (ctx.signal) {
    if (ctx.signal.aborted) abortController.abort();
    else ctx.signal.addEventListener("abort", () => abortController.abort(), { once: true });
  }

  // Per-actor activity stream:
  //   1) `carlini-threat-hunt:agent-activity` (fingerprinted rows for actor heartbeat)
  //   2) `scan:agent-activity` (task-level live storytelling in scan stage UI)
  const fingerprint = buildActorFingerprint(actor, runIndex);
  const scanRunContext = buildScanRunContext(ctx);
  const activityCallback: AgentActivityCallback | undefined =
    ctx.reportAgentActivity || scanRunContext
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
          if (scanRunContext) {
            await publishScanActivity(ctx, scanRunContext, activity);
          }
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
  const startedTools = new Map<string, string>();
  const customTools =
    config.kbPath && runtimeSupportsCustomTools(ctx.runtime)
      ? [
          createThreatKbSearchTool({
            kbPath: config.kbPath,
            defaultLimit: config.kbTopK,
            maxChunkChars: config.kbMaxChunkChars,
          }),
        ]
      : [];

  try {
    for await (const message of ctx.runtime.query({
      prompt: effectivePrompt,
      options: {
        cwd: scanScope,
        model: config.model,
        allowedTools: dedupeTools([
          ...readAllowedTools(ctx),
          ...customTools.map((tool) => tool.name),
        ]),
        customTools,
        permissionMode: "dontAsk",
        effort: config.effort,
        thinkingDisabled: config.thinkingDisabled,
        abortController,
        ...(runtimeSupportsStrictOutputSchema(ctx.runtime)
          ? {
              outputFormat: {
                type: "json_schema" as const,
                schema: FINDING_SCHEMA,
                strict: true,
                retryInvalidStructuredOutput: 2,
              },
            }
          : {}),
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
      if (message.type === "tool-call-start") {
        startedTools.set(message.toolUseId, message.toolName);
        await activityCallback?.({
          kind: "tool-start",
          toolName: message.toolName,
        });
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
      if (message.type === "tool-result") {
        const toolName = startedTools.get(message.toolUseId) ?? message.toolUseId;
        const trimmed = message.content.trim();
        await activityCallback?.({
          kind: "tool-complete",
          toolName,
          summary: message.isError
            ? "tool result errored"
            : trimmed.length > 180
              ? `${trimmed.slice(0, 177)}...`
              : trimmed || "tool result returned",
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
  // Stamp the per-actor fingerprint on each finding so `selectFindings` can
  // carry it through to the final `Finding[]` (ActorTranscriptView reads it
  // to synthesize ★ Finding rows for one actor without re-parsing strings).
  const findingsWithActor = parsed.findings.map((f) => ({
    ...f,
    actorFingerprint: fingerprint,
  }));
  return { findings: findingsWithActor, costUsd };
}

/**
 * One-line summary for the `⎿  <output>` line under the tool header on
 * completion. Prefer the first non-empty line of `result.output` (from
 * `runSingleTaskPipeline`, which already includes findings + cost — so
 * re-appending them would produce "complete: 22 findings · 22 findings").
 * Only synthesize from `data.stats` when `output` is empty (early exits,
 * no-external-entities path, abort before first log line).
 */
function formatCarliniThreatHuntSummary(result: ToolResult): string {
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

export const carliniThreatHuntTool = defineDagTool<
  "carlini-threat-hunt",
  ScanOpts | Record<string, unknown>,
  Finding[]
>({
  name: "carlini-threat-hunt:run",
  displayName: "Carlini Threat Hunt",
  description:
    "Inspired by Nicholas Carlini's [un]prompted talk on parallel scoped agents. Not affiliated with or endorsed by Nicholas Carlini. Hunts STRIDE threats end-to-end with one scoped LLM agent per DFD threat actor.",
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
      kbTopK: {
        type: "integer",
        default: 8,
        description: "Default number of threat-model KB chunks returned by ThreatKbSearch.",
      },
      kbMaxChunkChars: {
        type: "integer",
        default: 1200,
        description: "Maximum characters returned per ThreatKbSearch chunk.",
      },
      kbSearchMode: {
        type: "string",
        enum: ["hybrid", "fts"],
        default: "hybrid",
        description: "Threat KB search mode. hybrid currently falls back to SQLite FTS.",
      },
      promptContext: {
        type: "string",
        enum: ["actor-flows", "actor-flows-threat-titles"],
        default: "actor-flows",
        description: "How much graph context to inline in actor prompts.",
      },
      debugInlineThreats: {
        type: "boolean",
        default: false,
        description: "Inline full threat details for prompt debugging.",
        "x-advanced": true,
      },
      model: {
        type: "string",
        default: DEFAULT_CARLINI_THREAT_HUNT_MODEL,
        description: "Model override for this hunt run.",
      },
      effort: {
        type: "string",
        enum: ["low", "medium", "high", "max", "xhigh", "extra-high", "xtra-high"],
        default: DEFAULT_CARLINI_THREAT_HUNT_EFFORT,
        description:
          "Reasoning effort. extra-high/xtra-high normalize to xhigh; max remains available for models that support it.",
      },
      thinking: {
        type: "boolean",
        default: true,
        description: "Enable extended thinking for actor agents.",
      },
      CARLINI_THREAT_HUNT_PROMPT: {
        type: "string",
        description:
          "Override the carlini-threat-hunt actor system prompt. Accepts inline text or a path to .md/.txt.",
        "x-advanced": true,
      },
      resume: {
        type: ["boolean", "string"],
        description: "Resume the latest checkpoint or a specific run id.",
      },
    },
    required: ["target"],
  },
  runLifecycle: {
    persistence: "pipeline-checkpoint",
    resume: "checkpoint",
    liveControl: "pause-resume",
    pipelineTasks: ["carlini-threat-hunt:run"],
    pipelineContext: "none",
  },
  formatInput(input) {
    const p = input as Record<string, unknown> | undefined;
    const target = typeof p?.["target"] === "string" ? (p["target"] as string) : null;
    const actors = typeof p?.["maxActors"] === "number" ? (p["maxActors"] as number) : null;
    if (target && actors) return `${target} · ${actors} actors`;
    return target ?? null;
  },
  renderResult(result) {
    return formatCarliniThreatHuntSummary(result);
  },
  dag: {
    outputKind: "findings",
    dependsOn: [],
    triageAgentConfig,
  },
  async run(input, ctx) {
    ctx.signal?.throwIfAborted();

    // Steps surfaced in `ModuleRunView`. Mutated in place; emitted on every
    // transition. Idempotent — the renderer is no-op when no run is active.
    const steps: Array<{
      id: string;
      title: string;
      status: "pending" | "running" | "done" | "error";
      count?: string;
    }> = [
      { id: "boot", title: "load threat model", status: "running" },
      { id: "kb", title: "prepare threat-model KB", status: "pending" },
      { id: "enumerate", title: "enumerate actors", status: "pending" },
      { id: "spawn", title: "spawn actor agents", status: "pending" },
      { id: "merge", title: "merge findings", status: "pending" },
    ];
    const emit = (): void => ctx.uiStore?.setModuleRunSteps?.(steps.slice());
    const setStep = (
      id: string,
      patch: Partial<{ status: "pending" | "running" | "done" | "error"; count: string }>,
    ): void => {
      const ix = steps.findIndex((s) => s.id === id);
      if (ix < 0) return;
      steps[ix] = { ...steps[ix]!, ...patch };
      emit();
    };
    emit();

    const config = await resolveConfig(input, ctx);
    ctx.reportActivity?.("reading threat model");
    const dag = requireDag(ctx);
    const document = resolveHuntThreatModel(ctx);
    const { prioritized, allActors } = actorsFromDocument(document);
    setStep("boot", { status: "done" });

    setStep("kb", { status: "running" });
    const kb = ensureThreatModelKbIndex({
      repoRoot: threatModelRoot(ctx),
      document,
    });
    ctx.reportActivity?.(
      `${kb.rebuilt ? "indexed" : "reusing"} threat-model KB (${kb.stats.chunks} chunks)`,
    );
    setStep("kb", {
      status: "done",
      count: `${kb.stats.chunks} chunks · ${kb.rebuilt ? "rebuilt" : "current"}`,
    });
    const activeConfig: CarliniThreatHuntConfig = { ...config, kbPath: kb.path };

    if (allActors.length === 0) {
      log.info("[carlini-threat-hunt] No external entities in threat model DFD — skipping");
      setStep("enumerate", { status: "done", count: "0 actors" });
      setStep("spawn", { status: "done", count: "skipped" });
      setStep("merge", { status: "done", count: "0 findings" });
      return attachTaskOutputMeta([], { costUsd: 0 }) as Finding[];
    }

    // Prefer actors with HIGH/CRITICAL linked threats; fall back to all actors only when
    // the threat model has no threat-to-actor links at all.
    const actorsToHunt: ActorWithThreats[] =
      prioritized.length > 0
        ? prioritized
        : allActors.map((a) => ({ actor: a, threats: [], flows: [] }));

    const capped = actorsToHunt.slice(0, activeConfig.maxActors);
    const totalRuns = capped.length * activeConfig.runsPerActor;
    setStep("enumerate", {
      status: "done",
      count: `${capped.length} actor${capped.length === 1 ? "" : "s"}`,
    });
    log.info(
      `[carlini-threat-hunt] Spawning ${totalRuns} hunts (${capped.length} actors x ${activeConfig.runsPerActor} runs, from ${allActors.length} external entities)`,
    );
    ctx.reportActivity?.(
      `queuing ${capped.length} actor${capped.length === 1 ? "" : "s"} × ${activeConfig.runsPerActor} run${activeConfig.runsPerActor === 1 ? "" : "s"}`,
    );
    setStep("spawn", { status: "running", count: `0/${totalRuns}` });

    // Build all hunt tasks, then execute with bounded concurrency.
    const huntTasks: Array<() => Promise<FindingOutput>> = [];
    let runIndex = 0;
    for (const { actor, threats, flows } of capped) {
      for (let i = 0; i < activeConfig.runsPerActor; i++) {
        const myRunIndex = runIndex++;
        huntTasks.push(() =>
          runActorHunt(actor, threats, flows, ctx, activeConfig, myRunIndex, totalRuns).catch(
            (err) => {
              log.error(
                `[carlini-threat-hunt/${actor.name}#${myRunIndex}] Error: ${toErrorMessage(err)}`,
              );
              return { findings: [], costUsd: 0 } as FindingOutput;
            },
          ),
        );
      }
    }

    const maxConcurrent = Math.min(totalRuns, activeConfig.maxConcurrentHunts);
    const totalBatches = Math.ceil(huntTasks.length / maxConcurrent);
    const results: FindingOutput[] = [];
    let completed = 0;
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
      completed += batchResults.length;
      setStep("spawn", { count: `${completed}/${totalRuns}` });
    }
    setStep("spawn", { status: "done", count: `${completed}/${totalRuns}` });

    // Merge all findings, dedup via selectFindings
    setStep("merge", { status: "running" });
    const merged: FindingOutput = {
      findings: results.flatMap((r) => r.findings),
      costUsd: results.reduce((sum, r) => sum + (r.costUsd ?? 0), 0),
    };

    const findings = selectFindings(
      merged,
      dag.scanPath ?? dag.workRoot ?? dag.repoRoot,
      dag.repoName,
      "HEAD",
      "carlini-threat-hunt",
      activeConfig.maxFindings,
    );
    setStep("merge", {
      status: "done",
      count: `${findings.length} finding${findings.length === 1 ? "" : "s"}`,
    });
    ctx.uiStore?.patchModuleRun?.({ costUsd: merged.costUsd ?? 0 });

    return attachTaskOutputMeta(findings, { costUsd: merged.costUsd ?? 0 }) as Finding[];
  },
});

export function createCarliniThreatHuntModule(): CopilotModule {
  // Knowledge-base verbs (`attach` / `attachments` / `detach` / `reparse`)
  // are registered through the shared factory. Operators stage incident
  // postmortems, runtime/SIEM logs, prior findings, intel briefs, etc.;
  // `resolveConfig` reads them at run time and threads the rendered block
  // into every per-actor prompt via `buildScopedPrompt`.
  const attachmentTools = createAttachmentTools(
    "carlini-threat-hunt",
    CARLINI_THREAT_HUNT_KIND_SPEC,
    {
      adapter: carliniThreatHuntAttachmentAdapter(),
    },
  );
  return defineModule({
    id: "carlini-threat-hunt",
    // M1: keep legacy `threat-hunt` ids resolvable. Operators with old
    // taskConfig keys, /use threat-hunt verbs, or persisted resume metadata
    // continue to work after the rename.
    legacyIds: ["threat-hunt"],
    displayName: "Carlini Threat Hunt",
    category: "offense",
    version: "0.17.2",
    description: "Hunts threats from the active threat-model document via parallel scoped agents.",
    longDescription:
      "Inspired by Nicholas Carlini's [un]prompted talk on parallel scoped agents — " +
      "not affiliated with or endorsed by Nicholas Carlini. " +
      "Attach reference material (incidents, runtime logs, prior findings) with `attach`.",
    rank: "good",
    references: [{ type: "URL", value: "https://unprompted.ai/" }],
    notes: {
      stability: ["stable"],
      reliability: ["variable-recall"],
      sideEffects: ["costs LLM tokens"],
    },
    requires: [
      { kind: "snapshot", moduleId: "context", field: "appModel" },
      { kind: "snapshot", moduleId: "threat-model", field: "threatModel" },
    ],
    tools: [carliniThreatHuntTool, ...attachmentTools],
  });
}

// Exported for testing (mirrors the old `__carliniThreatHuntInternals` surface)
export const __carliniThreatHuntInternals = {
  extractActors: (m: ReadonlyMap<string, unknown>) => extractActorsWithThreats(m).allActors,
  buildPrompt,
  buildScopedPrompt,
  buildActorFingerprint,
  renderReferences,
  resolveConfig,
  runActorHunt,
};
