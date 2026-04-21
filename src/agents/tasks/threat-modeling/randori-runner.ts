/**
 * Randori PASTA runner — executes the @kuzushi/randori-plugin via a Claude Code
 * subprocess across the S1-S4 stages plus narrative synthesis, reads the
 * resulting artifacts from disk, and converts them into Kuzushi's
 * ThreatModelDocument + Finding[] representation.
 *
 * Shared by the `threat-model-randori` pipeline task and the `randori:pasta`
 * tool exposed by the core Randori module.
 */

import { createHash } from "node:crypto";
import path from "node:path";
import { summarizeInput } from "../../../agent-runtime/tool-summary.js";
import type { AgentMessage, AgentRuntime } from "../../../agent-runtime/types.js";
import { createLogger } from "../../../logger.js";
import { scoreFindingMetadata } from "../../../scanners/scoring.js";
import type { Finding } from "../../../scanners/types.js";
import { toErrorMessage } from "../../../utils.js";
import { forwardSubAgentMessage } from "../forward-subagent-output.js";
import { convertRandoriToThreatModel } from "./randori-adapter.js";
import {
  mergeRandoriStageOutputs,
  type RandoriArtifacts,
  readRandoriArtifacts,
} from "./randori-artifacts.js";
import type { StrideThreat, ThreatModelDocument } from "./types.js";

export type RandoriStage = "s1" | "s2" | "s3" | "s4";

const log = createLogger({ stage: "randori-runner" });

const IMPACT_TO_SEVERITY: Record<string, string> = {
  critical: "ERROR",
  high: "ERROR",
  medium: "WARNING",
  low: "INFO",
};

// ---------------------------------------------------------------------------
// Prompt builders
// ---------------------------------------------------------------------------

export function buildScopePrompt(maxElements: number, outputDir: string): string {
  return [
    "You are running a PASTA threat model analysis on the current repository.",
    "",
    "Run stages: s1, s2, s3",
    "",
    `Write the output JSON to the ${outputDir}/ directory:`,
    "- Stage S1: Write pasta-s1.json (business objectives and security requirements)",
    "- Stage S2: Write pasta-s2.json (technical scope — components, actors, data flows)",
    "- Stage S3: Write pasta-s3.json (DFD, trust boundaries, entry points) and dfd.mmd",
    "",
    `Include up to ${maxElements} DFD elements in the technical scope.`,
    "",
    "Explore the codebase thoroughly using Glob, Grep, and Read.",
    "Ground every DFD element in actual code, not theoretical architecture.",
  ].join("\n");
}

export function buildNarrativePrompt(outputDir: string): string {
  return [
    "You are synthesising the narrative layer of a PASTA threat model.",
    "",
    `Read the prior stage outputs from ${outputDir}/pasta-s1.json, pasta-s2.json, pasta-s3.json,`,
    `and pasta-s4.json. Inspect the actual source files they reference to ground every claim.`,
    "",
    `Write ${outputDir}/pasta-narrative.json with this exact shape (snake_case):`,
    "{",
    '  "overview": "<1-3 paragraphs describing what the application does at runtime,',
    '                 where it runs, what it exposes, and the primary trust context>",',
    '  "input_categories": {',
    '    "attacker_controlled": ["<item with file:line citation>", ...],',
    '    "operator_controlled": ["<item>", ...],',
    '    "developer_controlled": ["<item>", ...],',
    '    "external_services": ["<item>", ...],',
    '    "sandbox_boundary": ["<item>", ...],',
    '    "assumptions": ["<item>", ...]',
    "  },",
    '  "attacker_stories": [',
    "    {",
    '      "title": "<short, action-oriented title>",',
    '      "narrative": "<2-4 sentences: who the attacker is, what they do, what they gain>",',
    '      "mitigation": "<how it is mitigated today or what SHOULD mitigate it>",',
    '      "threat_ids": ["<StrideThreat.id from pasta-s4.json, if linked>"]',
    "    },",
    "    ... (3-6 stories)",
    "  ],",
    '  "criticality_buckets": {',
    '    "critical": ["<1-3 concrete examples of critical-severity issues for THIS app>"],',
    '    "high":     ["<1-3 concrete examples>"],',
    '    "medium":   ["<1-3 concrete examples>"],',
    '    "low":      ["<1-3 concrete examples>"]',
    "  },",
    '  "out_of_scope": ["<class of issue that does not apply to this app, with reason>", ...]',
    "}",
    "",
    "Hard requirements:",
    "- Every `input_categories` item MUST cite a file path (ideally file:line).",
    "- `attacker_stories` MUST reference concrete attackers and concrete outcomes (no hand-waving).",
    "- Criticality examples MUST match THIS application's surface (not generic web-app examples",
    "  unless the app is a web app).",
    "- `out_of_scope` MUST state WHY each class does not apply.",
    "- Return ONLY the JSON object — no prose before or after.",
  ].join("\n");
}

export function buildNarrativeRetryPrompt(outputDir: string, reasons: string[]): string {
  return [
    `Your previous attempt to write ${outputDir}/pasta-narrative.json does not meet the schema requirements:`,
    ...reasons.map((r) => `- ${r}`),
    "",
    "Re-read the S1-S4 artifacts and the source files they reference, then rewrite",
    `${outputDir}/pasta-narrative.json with the full schema populated. Hard requirements:`,
    "- overview: 1-3 paragraphs grounded in actual runtime behaviour.",
    "- input_categories: every category that applies MUST list at least one item with file:line.",
    "- attacker_stories: 3-6 concrete scenarios with titles, narratives, mitigations.",
    "- criticality_buckets: examples specific to THIS application, not generic.",
    "- out_of_scope: list classes that do not apply, with the reason each does not apply.",
    "",
    "Return ONLY by writing the JSON file — no prose output.",
  ].join("\n");
}

export function buildStridePrompt(
  maxThreats: number,
  outputDir: string,
  previousModel?: ThreatModelDocument | null,
): string {
  const preamble: string[] = [];
  if (previousModel) {
    preamble.push(
      "The following threat model was generated in a previous scan. Use it as a starting point:",
      "- Preserve threats that are still relevant to the current code.",
      "- Remove threats that no longer apply (deleted code, fixed vulnerabilities).",
      "- Add new threats for new code or changed attack surface.",
      "- Preserve any userAnnotations, confirmedMitigations, and dismissedThreats from the previous model.",
      "",
      "Previous threat model:",
      JSON.stringify(previousModel, null, 2),
      "",
    );
  }
  return [
    ...preamble,
    "You are running Stage S4 of a PASTA threat model analysis.",
    "",
    `Read the prior stage outputs from ${outputDir}/pasta-s1.json, pasta-s2.json, pasta-s3.json, and dfd.mmd.`,
    "These describe the application's business context, technical scope, and data flow diagram.",
    "",
    `Write ${outputDir}/pasta-s4.json with STRIDE threat scenarios grounded in code evidence.`,
    "",
    "CRITICAL requirements for S4 threat scenarios:",
    "- Every threat MUST have evidence_anchors with file_path, start_line, description",
    "- Use STRIDE categories: spoofing, tampering, repudiation, information-disclosure, denial-of-service, elevation-of-privilege",
    "- Include probability (0-1) and impact (critical/high/medium/low)",
    "- Map to MITRE ATT&CK technique IDs where applicable",
    "- Include OWASP category mapping (e.g., A01, A03)",
    `- Identify up to ${maxThreats} distinct threat scenarios across all STRIDE categories`,
    "",
    "Use the DFD elements and trust boundaries from S3 to identify attack surfaces.",
    "Read the actual source files referenced in the DFD to ground threats in real code.",
    "Focus on the highest-impact threats first.",
    "",
    "If this application is a CLI tool, build system, or security scanner that processes external",
    "repositories or files, also model these threat scenarios:",
    "- Repository content as attacker-controlled input (malicious file names, symlinks, configs)",
    "- Build-time execution (autobuild, postinstall scripts, custom rules/plugins loaded from repo)",
    "- LLM/AI prompt injection via repository content influencing tool behavior or tool invocation",
    "- Path traversal via symlinks or relative paths in repo content escaping the project root",
    "- Subprocess invocation with repo-derived metadata (names, paths) as unsanitized arguments",
  ].join("\n");
}

// ---------------------------------------------------------------------------
// Narrative validation
// ---------------------------------------------------------------------------

/**
 * Assess an already-written pasta-narrative.json and return a list of
 * human-readable reasons it falls short of the schema's hard requirements.
 * An empty array means the artifact is acceptable. Used to decide whether
 * Phase 3 needs a retry pass.
 */
export function assessNarrativeArtifact(narrative: unknown): string[] {
  const reasons: string[] = [];
  if (!narrative || typeof narrative !== "object" || Array.isArray(narrative)) {
    reasons.push("pasta-narrative.json is missing or is not a JSON object");
    return reasons;
  }
  const record = narrative as Record<string, unknown>;

  const overview = record["overview"];
  if (typeof overview !== "string" || overview.trim().length < 40) {
    reasons.push('"overview" must be a substantive paragraph (got empty or too short)');
  }

  const inputCategories = record["input_categories"] ?? record["inputCategories"];
  if (!inputCategories || typeof inputCategories !== "object" || Array.isArray(inputCategories)) {
    reasons.push('"input_categories" must be an object with attacker/operator/developer lists');
  } else {
    const cats = inputCategories as Record<string, unknown>;
    const required = ["attacker_controlled", "operator_controlled", "developer_controlled"];
    const empty = required.filter((key) => {
      const arr = cats[key] ?? cats[toCamel(key)];
      return !Array.isArray(arr) || arr.length === 0;
    });
    if (empty.length > 0) {
      reasons.push(
        `"input_categories" is missing entries for: ${empty.join(", ")} (each must list at least one item)`,
      );
    }
  }

  const stories = record["attacker_stories"] ?? record["attackerStories"];
  if (!Array.isArray(stories) || stories.length < 1) {
    reasons.push('"attacker_stories" must contain 3-6 concrete attacker scenarios (got none)');
  }

  const outOfScope = record["out_of_scope"] ?? record["outOfScope"];
  if (!Array.isArray(outOfScope) || outOfScope.length === 0) {
    reasons.push(
      '"out_of_scope" must list at least one class of issue that does not apply to this app',
    );
  }

  return reasons;
}

function toCamel(snake: string): string {
  return snake.replace(/_([a-z])/g, (_, c) => c.toUpperCase());
}

// ---------------------------------------------------------------------------
// Finding conversion
// ---------------------------------------------------------------------------

export function threatsToFindings(
  threats: StrideThreat[],
  repoRoot: string,
  repoName: string,
  threshold: string,
): Finding[] {
  const thresholdSet = new Set<string>();
  if (threshold === "low") thresholdSet.add("low").add("medium").add("high").add("critical");
  else if (threshold === "medium") thresholdSet.add("medium").add("high").add("critical");
  else if (threshold === "high") thresholdSet.add("high").add("critical");
  else thresholdSet.add("critical");

  const deduped = new Map<string, Finding>();
  let syntheticIndex = 0;
  for (const threat of threats) {
    if (!thresholdSet.has(threat.impact)) continue;
    syntheticIndex += 1;

    const primary =
      threat.affectedFiles.length > 0
        ? {
            filePath: normalizeFilePath(repoRoot, threat.affectedFiles[0].filePath),
            startLine: threat.affectedFiles[0].startLine,
          }
        : { filePath: ".", startLine: syntheticIndex };
    const severity = IMPACT_TO_SEVERITY[threat.impact] || "WARNING";
    const cweList = threat.relatedCwe;
    const cweSegment = cweList.length > 0 ? `/${cweList[0]}` : "";
    const fingerprint = computeFingerprint(repoName, threat);

    const finding: Finding = {
      taskId: "threat-model-randori",
      fingerprint,
      ruleId: `threat-model/${threat.category}${cweSegment}`,
      filePath: primary.filePath,
      startLine: primary.startLine,
      severity,
      message: `[STRIDE/${threat.category}] ${threat.title}: ${threat.description}`,
      evidence: [
        `Attack vector: ${threat.attackVector}`,
        threat.missingMitigations.length > 0
          ? `Missing mitigations: ${threat.missingMitigations.join(", ")}`
          : "",
        ...(threat.evidenceAnchors ?? []).map(
          (a) => `Evidence: ${a.filePath}:${a.startLine} — ${a.description}`,
        ),
      ]
        .filter(Boolean)
        .join(". "),
      scannerConfidence:
        threat.likelihood === "high" ? "HIGH" : threat.likelihood === "medium" ? "MEDIUM" : "LOW",
      subcategory: ["vuln"],
      likelihood: threat.likelihood.toUpperCase(),
      impact: threat.impact === "critical" || threat.impact === "high" ? "HIGH" : "MEDIUM",
      cwe: cweList,
      score: scoreFindingMetadata({
        severity,
        likelihood: threat.likelihood.toUpperCase(),
        impact: threat.impact === "critical" || threat.impact === "high" ? "HIGH" : "MEDIUM",
        subcategory: ["vuln"],
      }),
    };

    const existing = deduped.get(fingerprint);
    if (!existing || finding.score > existing.score) {
      deduped.set(fingerprint, finding);
    }
  }

  return [...deduped.values()];
}

function computeFingerprint(repoName: string, threat: StrideThreat): string {
  const cwes = [...threat.relatedCwe].sort().join(",");
  const files = threat.affectedFiles
    .map((f) => `${f.filePath}:${f.startLine}`)
    .sort()
    .join(",");
  const source = [
    repoName,
    "threat-model-randori",
    threat.category,
    cwes,
    files,
    threat.title,
  ].join("|");
  return createHash("sha256").update(source).digest("hex");
}

function normalizeFilePath(repoRoot: string, filePath: string): string {
  if (!path.isAbsolute(filePath)) return filePath;
  const relative = path.relative(repoRoot, filePath);
  if (relative.startsWith("..")) return filePath;
  return relative || filePath;
}

// ---------------------------------------------------------------------------
// Streaming activity extraction
// ---------------------------------------------------------------------------

const ACTIVITY_MAX = 80;

function truncate(text: string, max: number): string {
  if (text.length <= max) return text;
  return `${text.slice(0, max - 1)}…`;
}

/**
 * Extract short human-readable activity lines from a runtime message so the
 * shell's progress rail sees forward motion while the plugin's LLM churns on
 * S1/S2/S3. Returns one entry per `tool_use` block in an assistant message
 * and a single line for tool summaries; `tool-progress` ticks and `result`
 * envelopes are ignored (too noisy / handled separately for cost).
 */
export function describeRuntimeMessage(message: AgentMessage): string[] {
  if (message.type === "assistant") {
    const blocks = Array.isArray(message.content) ? message.content : [];
    const out: string[] = [];
    for (const block of blocks) {
      if (block?.["type"] !== "tool_use") continue;
      const name = typeof block["name"] === "string" ? block["name"] : "tool";
      // Delegate hint extraction to the shared helper so new aliases
      // (e.g. file_path / filePath for Read, pattern for Glob/Grep)
      // get picked up consistently. Without this, valid LLM tool
      // calls surface as bare "Read" / "Grep" activity lines.
      const hint = summarizeInput(block["input"]);
      out.push(hint ? `${name} · ${hint}` : name);
    }
    return out;
  }
  if (message.type === "tool-summary") {
    const summary = typeof message.summary === "string" ? message.summary.trim() : "";
    if (!summary) return [];
    const firstLine = summary.split("\n")[0]?.trim() ?? "";
    if (!firstLine) return [];
    return [truncate(firstLine, ACTIVITY_MAX)];
  }
  return [];
}

export interface RandoriRunnerParams {
  runtime: AgentRuntime;
  repoRoot: string;
  repoName: string;
  pluginPath: string;
  model: string;
  allowedTools: string[];
  stages: ReadonlyArray<RandoriStage | string>;
  /** Relative-to-repoRoot output directory for pasta-*.json artifacts. */
  artifactDir: string;
  maxElements: number;
  maxThreats: number;
  emitFindings: boolean;
  findingThreshold: "low" | "medium" | "high" | "critical" | string;
  previousModel?: ThreatModelDocument | null;
  signal?: AbortSignal;
  logTag?: string;
  /**
   * Called at the start of each phase with a short human-readable label
   * ("phase 1 (S1-S3 scope)", "phase 2 (S4 threats)", "phase 3 (narrative)").
   * Lets the calling task surface sub-progress on the shell spinner so the
   * operator can tell phase-2 LLM-call-in-flight from a hang.
   */
  onPhase?: (phase: string) => void;
  /**
   * Finer-grained sub-step description — "now reading s4 artifacts", "now
   * writing narrative draft", etc. Feeds the rolling activity tail in the
   * shell so a 3–5 minute phase doesn't look like a frozen label.
   */
  onActivity?: (description: string) => void;
  /**
   * Sub-agent output sink — fires once per Claude Code tool_use block the
   * PASTA subprocess performs. Typically `ctx.reportOutput` so the
   * operator sees "Read(src/api/admin.ts)" etc. live under the `⏺`
   * header while S1-S4 runs.
   */
  onOutput?: (line: string) => void;
}

export interface RandoriRunnerResult {
  document: ThreatModelDocument;
  findings: Finding[];
  artifacts: RandoriArtifacts;
  costUsd: number;
  /** True when no usable stage artifacts were produced and an empty document was returned. */
  empty: boolean;
}

/**
 * Run the Randori PASTA analysis — scope (S1-S3), STRIDE threats (S4), and
 * narrative synthesis — then read and convert the resulting artifacts.
 *
 * Always returns a result; an empty `ThreatModelDocument` with `empty: true`
 * when no usable stage artifacts were produced (matches the pre-refactor
 * fallback behaviour).
 */
export async function runRandoriPasta(params: RandoriRunnerParams): Promise<RandoriRunnerResult> {
  const tag = params.logTag ?? "[randori]";
  params.signal?.throwIfAborted();

  // Forward the caller's abort signal into each phase's runtime.query via
  // an owned AbortController. Without this the Claude Code subprocess
  // keeps streaming (and billing) after Ctrl+C.
  const abortController = new AbortController();
  if (params.signal) {
    if (params.signal.aborted) abortController.abort();
    else {
      params.signal.addEventListener("abort", () => abortController.abort(), { once: true });
    }
  }

  const baseOpts = {
    cwd: params.repoRoot,
    model: params.model,
    allowedTools: params.allowedTools,
    permissionMode: "dontAsk" as const,
    plugins: [{ type: "local" as const, path: params.pluginPath }],
    abortController,
  };

  let costUsd = 0;

  // Max consecutive failures of the same tool before we consider the
  // phase wedged and abort it. The sub-Claude retries in a tight loop on
  // validation errors ("filePath" vs "file_path", content too long, etc.)
  // and without a cap it burns 20+ minutes before we ever see the result.
  const MAX_CONSECUTIVE_TOOL_FAILURES = 3;

  // Runs one plugin query to completion, accumulating cost and forwarding
  // every meaningful streaming message as an `onActivity` pulse. Without this
  // the shell sees a single phase label, then ~5 minutes of silence until
  // the `result` envelope — long enough for `ToolRunningStatus`'s 15s
  // staleness watchdog to show a misleading `waiting…` chip.
  const runPhase = async (prompt: string, phaseTag: string): Promise<void> => {
    params.signal?.throwIfAborted();
    // tool_use_id → tool_name; needed so when a tool_result comes back
    // (keyed only by tool_use_id) we can identify WHICH tool failed.
    const toolNames = new Map<string, string>();
    // Per-tool consecutive-failure counter. Reset when the same tool
    // succeeds or a different tool runs. Cross-tool alternation won't
    // trip the cap — only a stuck retry loop on a single tool.
    let lastFailedTool: string | null = null;
    let consecutiveFailures = 0;
    try {
      for await (const message of params.runtime.query({ prompt, options: baseOpts })) {
        // Respect aborts eagerly — the abortController in baseOpts is
        // linked to params.signal, so the SDK will eventually stop, but
        // bailing here returns control to the shell immediately.
        if (params.signal?.aborted) break;
        // Record tool_use_id → tool_name for upcoming tool_result lookups.
        if (message.type === "assistant" && Array.isArray(message.content)) {
          for (const block of message.content as Array<Record<string, unknown>>) {
            if (block?.["type"] !== "tool_use") continue;
            const id = typeof block["id"] === "string" ? block["id"] : "";
            const name = typeof block["name"] === "string" ? block["name"] : "tool";
            if (id) toolNames.set(id, name);
          }
        }
        // Detect retry loops on "Validation failed for tool X" / any
        // tool failure. After MAX consecutive failures from the same tool
        // we abort this phase so the operator isn't stuck watching an
        // infinite loop — the next phase (or enclosing task) gets whatever
        // partial artifacts S1-S3 produced.
        if (message.type === "tool-result") {
          const toolName = toolNames.get(message.toolUseId) ?? "tool";
          if (message.isError) {
            if (lastFailedTool === toolName) consecutiveFailures += 1;
            else {
              lastFailedTool = toolName;
              consecutiveFailures = 1;
            }
            const firstLine =
              message.content
                .split(/\r?\n/)
                .find((l) => l.trim().length > 0)
                ?.trim() ?? "";
            const summary = firstLine ? firstLine.slice(0, 80) : "tool error";
            const pulse = `${toolName} failed (${consecutiveFailures}/${MAX_CONSECUTIVE_TOOL_FAILURES}): ${summary}`;
            log.warn(`${phaseTag} ${pulse}`);
            params.onActivity?.(pulse);
            if (consecutiveFailures >= MAX_CONSECUTIVE_TOOL_FAILURES) {
              const abortMsg = `aborting phase after ${consecutiveFailures} ${toolName} failures`;
              log.warn(`${phaseTag} ${abortMsg}`);
              params.onActivity?.(abortMsg);
              abortController.abort();
              break;
            }
          } else {
            // Any successful tool result clears the retry counter.
            lastFailedTool = null;
            consecutiveFailures = 0;
          }
        }
        // Forward the sub-agent's per-action stream (tool_use headers,
        // tool-progress heartbeats) to the ephemeral live-tail sink so
        // operators see what PASTA is doing right now under the `⏺`
        // header. Independent of `onActivity` because output lines are
        // live-only — they never land in scrollback.
        forwardSubAgentMessage(message, params.onOutput);
        if (message.type === "result" && typeof message.totalCostUsd === "number") {
          costUsd += message.totalCostUsd;
        }
        if (params.onActivity) {
          for (const line of describeRuntimeMessage(message)) {
            params.onActivity(line);
          }
        }
      }
    } catch (error) {
      if (params.signal?.aborted) throw error;
      log.warn(`${phaseTag} error: ${toErrorMessage(error)}`);
    }
  };

  const hasS4 = params.stages.includes("s4");
  const scopeStages = hasS4 ? params.stages.filter((s) => s !== "s4") : params.stages;

  // ── Phase 1: S1-S3 (scope, tech decomposition, DFD) ──
  if (scopeStages.length > 0) {
    log.info(`${tag} Phase 1: running stages ${scopeStages.join(",")}`);
    params.onPhase?.(`phase 1 (${scopeStages.join("/").toUpperCase()} scope)`);
    params.onActivity?.(`scoping ${scopeStages.join(", ")}`);
    await runPhase(buildScopePrompt(params.maxElements, params.artifactDir), `${tag} Phase 1`);
  }

  // ── Phase 2: S4 (STRIDE threat scenarios with evidence) ──
  if (hasS4) {
    params.signal?.throwIfAborted();
    const scopeArtifacts = readRandoriArtifacts(params.repoRoot, params.artifactDir);
    if (Object.keys(scopeArtifacts).length > 0) {
      log.info(`${tag} Phase 2: running stage s4 (STRIDE threats)`);
      params.onPhase?.("phase 2 (S4 threats)");
      params.onActivity?.("enumerating STRIDE threats");
      await runPhase(
        buildStridePrompt(params.maxThreats, params.artifactDir, params.previousModel),
        `${tag} Phase 2 (S4)`,
      );
    } else {
      log.warn(`${tag} Skipping S4 — no scope artifacts from S1-S3`);
    }
  }

  // ── Phase 3: narrative synthesis ──
  if (hasS4) {
    params.signal?.throwIfAborted();
    const postS4 = readRandoriArtifacts(params.repoRoot, params.artifactDir);
    const haveStageOutputs = postS4.s2Scope || postS4.s3Decomposition || postS4.s4Threats;
    if (haveStageOutputs) {
      log.info(`${tag} Phase 3: synthesising narrative layer`);
      params.onPhase?.("phase 3 (narrative)");
      params.onActivity?.("drafting attacker narrative");
      await runPhase(buildNarrativePrompt(params.artifactDir), `${tag} Phase 3 (narrative)`);

      // Retry once if the artifact is missing or incomplete.
      params.signal?.throwIfAborted();
      const narrativeAfter = readRandoriArtifacts(params.repoRoot, params.artifactDir).narrative;
      const narrativeIssues = assessNarrativeArtifact(narrativeAfter);
      if (narrativeIssues.length > 0) {
        log.warn(
          `${tag} Phase 3 narrative incomplete (${narrativeIssues.length} issue(s)); retrying once`,
        );
        params.onPhase?.("phase 3 (narrative retry)");
        params.onActivity?.(`retrying narrative (${narrativeIssues.length} issue(s))`);
        await runPhase(
          buildNarrativeRetryPrompt(params.artifactDir, narrativeIssues),
          `${tag} Phase 3 retry`,
        );
      }
    } else {
      log.warn(`${tag} Skipping narrative synthesis — no stage artifacts`);
    }
  }

  // ── Collect ──
  const artifacts = readRandoriArtifacts(params.repoRoot, params.artifactDir);
  const merged = mergeRandoriStageOutputs(artifacts);

  if (!merged) {
    log.warn(`${tag} Randori produced no usable artifacts — returning empty threat model`);
    const empty: ThreatModelDocument = {
      version: "1.0",
      dfd: { elements: [], trustBoundaries: [] },
      threats: [],
      summary: {
        total: 0,
        bySeverity: {},
        byCategory: {} as ThreatModelDocument["summary"]["byCategory"],
      },
    };
    return { document: empty, findings: [], artifacts, costUsd, empty: true };
  }

  const document = convertRandoriToThreatModel(merged);
  if (!document) {
    throw new Error(`${tag} Failed to convert Randori output to ThreatModelDocument`);
  }

  log.info(
    `${tag} Converted ${document.threats.length} threats, ${document.dfd.elements.length} DFD elements`,
  );

  const findings = params.emitFindings
    ? threatsToFindings(document.threats, params.repoRoot, params.repoName, params.findingThreshold)
    : [];

  return { document, findings, artifacts, costUsd, empty: false };
}
