import { existsSync, readFileSync } from "node:fs";
import { readFile, writeFile } from "node:fs/promises";
import { createHash } from "node:crypto";
import path from "node:path";
import type { AgentRuntime } from "../../../agent-runtime/types.js";
import { runStructuredSessionQuery } from "../../../agent-runtime/execution.js";
import { writeBatchFile, cleanupBatchFiles } from "../../../agent-runtime/batch-files.js";
import { withRetry } from "../../../retry.js";
import { attachTaskOutputMeta } from "../../../task-output-meta.js";
import type { ScanOpts } from "../../../types.js";
import { isRecord, toErrorMessage } from "../../../utils.js";
import type { AgentTask } from "../../types.js";
import {
  countCandidateCsvRecords,
  isCsvRecordBlank,
  normalizeCandidateMarker,
  parseCsvRecords,
} from "./csv.js";
import {
  TAINT_ANALYSIS_PASSES,
  resolveTaintAnalysisConfig,
  type ExtractionDegradation,
  type TaintAnalysisCandidate,
  type TaintAnalysisLabelOutput,
  type TaintAnalysisLanguage,
  type TaintAnalysisLabelsDocument,
  type TaintAnalysisPassDefinition,
  type TaintAnalysisPassEntry,
  type TaintAnalysisPassId,
  type TaintAnalysisPreflightOutput,
} from "./types.js";
import type { TiPriorCwe, TiPriorDocument } from "./ti-prior.js";

export const SINK_DENY_LIST: Record<TaintAnalysisLanguage, Set<string>> = {
  go: new Set([
    "Sprintf", "Fprintf", "Printf", "Errorf",
    "Fatalf", "Panicf", "Logf", "Warnf", "Infof", "Debugf", "Tracef",
    "Sprint", "Fprint", "Print", "Sprintln", "Fprintln", "Println",
    "Warnw", "Infow", "Debugw",
    "String", "Error", "GoString", "Format",
  ]),
  python: new Set([
    "format", "join", "print",
    "debug", "info", "warning", "error", "critical", "exception",
    "repr", "str", "__str__", "__repr__", "encode", "decode",
  ]),
  java: new Set([
    "format", "printf",
    "log", "fine", "finer", "finest", "info", "warning", "severe",
    "debug", "warn", "error", "trace", "valueOf",
    "toString", "hashCode", "equals", "getClass", "getName",
  ]),
  javascript: new Set([
    "log", "warn", "error", "info", "debug", "trace", "format",
    "toString", "valueOf", "JSON.stringify", "String", "Number", "Boolean",
  ]),
  csharp: new Set([
    "Format",
    "LogDebug", "LogInformation", "LogWarning", "LogError", "LogCritical",
    "Debug", "Information", "Warning", "Error", "Fatal",
    "ToString", "GetType", "GetHashCode", "Equals",
  ]),
};

export const FRAMEWORK_SANITIZER_CATALOG: Record<TaintAnalysisLanguage, string[]> = {
  go: [
    "html.EscapeString", "url.QueryEscape", "url.PathEscape",
    "filepath.Clean", "filepath.Base", "strconv.Quote",
    "template.HTMLEscapeString", "template.JSEscapeString",
  ],
  python: [
    "escape", "mark_safe", "bleach.clean", "bleach.linkify",
    "html.escape", "markupsafe.escape", "Markup.escape",
    "urllib.parse.quote", "shlex.quote",
    "django.utils.html.escape", "django.utils.http.urlencode",
  ],
  java: [
    "HtmlUtils.htmlEscape", "StringEscapeUtils.escapeHtml4",
    "StringEscapeUtils.escapeXml", "URLEncoder.encode",
    "ESAPI.encoder().encodeForHTML", "Jsoup.clean",
    "PreparedStatement.setString", "PreparedStatement.setInt",
  ],
  javascript: [
    "encodeURIComponent", "encodeURI",
    "DOMPurify.sanitize", "sanitizeHtml",
    "escape", "validator.escape", "xss",
    "helmet", "csurf",
  ],
  csharp: [
    "HtmlEncoder.Encode", "UrlEncoder.Encode", "JavaScriptEncoder.Encode",
    "HttpUtility.HtmlEncode", "HttpUtility.UrlEncode",
    "AntiXssEncoder.HtmlEncode",
    "WebUtility.HtmlEncode", "WebUtility.UrlEncode",
  ],
};

interface TaintModelIntentEntry {
  pattern_intent: string;
  confidence: number;
  ti_basis: string;
  sink_focus?: string;
  examples?: string[];
}

interface TaintModelCwe {
  cwe: string;
  sources: TaintModelIntentEntry[];
  sinks: TaintModelIntentEntry[];
  sanitizers: TaintModelIntentEntry[];
  propagators: TaintModelIntentEntry[];
  notes: string[];
}

interface TaintModelDocument {
  version: string;
  generatedAt: string;
  language: string;
  framework: string | null;
  cwes: TaintModelCwe[];
}

/**
 * Lightweight schema for bulk sink triage — just id + relevant boolean.
 * Used in Phase 1 to cheaply pre-filter sinks before detailed labeling.
 */
const TRIAGE_RESPONSE_SCHEMA = {
  type: "object",
  additionalProperties: false,
  required: ["entries"],
  properties: {
    entries: {
      type: "array",
      items: {
        type: "object",
        additionalProperties: false,
        required: ["id", "relevant"],
        properties: {
          id: { type: "string" },
          relevant: { type: "boolean" },
        },
      },
    },
  },
} as const;

const LABEL_RESPONSE_SCHEMA = {
  type: "object",
  additionalProperties: false,
  required: ["entries"],
  properties: {
    entries: {
      type: "array",
      items: {
        type: "object",
        additionalProperties: false,
        required: ["id", "role", "classification", "confidence", "rationale"],
        properties: {
          id: { type: "string" },
          role: { type: "string", enum: ["source", "sink", "sanitizer", "summary", "none"] },
          classification: { type: "string", enum: ["tp", "fp", "candidate", "unknown"] },
          confidence: { type: "number", minimum: 0, maximum: 1 },
          rationale: { type: "string" },
          evidence: {
            type: "array",
            items: { type: "string" },
          },
        },
      },
    },
  },
} as const;

interface LabelResponseEntry {
  id: string;
  role: TaintAnalysisPassEntry["role"];
  classification: TaintAnalysisPassEntry["classification"];
  confidence: number;
  rationale: string;
  evidence?: string[];
}

interface LabelResponse {
  entries: LabelResponseEntry[];
}

export const LABEL_CHECKPOINT_VERSION = 2;
export const LABEL_PARSER_VERSION = 2;

interface LabelPassCheckpointV2 {
  version: typeof LABEL_CHECKPOINT_VERSION;
  parserVersion: typeof LABEL_PARSER_VERSION;
  passId: TaintAnalysisPassId;
  language: TaintAnalysisLanguage;
  candidateFingerprint: string;
  generatedAt: string;
  entries: TaintAnalysisPassEntry[];
}

type LabelCheckpointFormat = "v2" | "legacy";

type LoadPassCheckpointResult =
  | {
    hit: true;
    format: LabelCheckpointFormat;
    entries: TaintAnalysisPassEntry[];
    deniedCount: number;
    needsRewrite: boolean;
  }
  | {
    hit: false;
    reason: string;
  };

/**
 * Taint Analysis Step 3 task: LLM labeling + checkpoint payload generation.
 */
export const taintAnalysisLabelTask: AgentTask<ScanOpts, TaintAnalysisLabelOutput> = {
  id: "taint-analysis-label",
  displayName: "Taint Analysis Label",
  outputKind: "custom",
  dependsOn: ["taint-analysis-preflight"],
  async run(_input, context): Promise<TaintAnalysisLabelOutput> {
    const cfg = resolveTaintAnalysisConfig(context.config);
    const preflight = asPreflightOutput(context.upstreamOutputs.get("taint-analysis-preflight"));
    if (!preflight) {
      throw new Error("taint-analysis-label requires upstream output from taint-analysis-preflight");
    }

    process.stderr.write(`[taint-analysis-label] Starting labeling task...\n`);
    const allCandidates = await loadCandidates(
      preflight.extraction.sourcesCsvPath,
      preflight.extraction.sinksCsvPath,
    );
    const extractionCounts = summarizeExtractionCounts(preflight, allCandidates);
    assertExtractionCountConsistency(extractionCounts, preflight.workspaceDir);
    emitExtractionQualityDiagnostics(extractionCounts);
    assertExtractionQualityThresholds(extractionCounts, preflight.workspaceDir);
    const candidateFingerprint = computeCandidatesFingerprint(allCandidates);

    // ── Signature dedup: label unique signatures, propagate to instances ──
    const { representatives, signatureMap } = deduplicateBySig(allCandidates);
    process.stderr.write(
      `[taint-analysis-label] Dedup: ${allCandidates.length} instances -> ${representatives.length} unique signatures (${((1 - representatives.length / allCandidates.length) * 100).toFixed(0)}% reduction)\n`,
    );

    // Enrich only representative candidates with code snippets
    await enrichCandidateSnippets(representatives, context.repoRoot);
    process.stderr.write(`[taint-analysis-label] Loaded ${allCandidates.length} candidates (${preflight.extraction.sourcesRowCount} sources, ${preflight.extraction.sinksRowCount} sinks)\n`);
    const sourceStatus = resolveSourceAvailability(preflight, allCandidates);
    const noSourcesExtracted = sourceStatus.noSourcesExtracted;
    if (noSourcesExtracted) {
      process.stderr.write(
        `[taint-analysis-label] No source candidates extracted (rows=${preflight.extraction.sourcesRowCount}, parsed=${sourceStatus.parsedSourceCount}); skipping labeling.\n`,
      );
    }

    const tiPrior = await loadTiPrior(preflight.tiPriorJsonPath);
    const references = noSourcesExtracted
      ? ""
      : await loadReferenceContent(preflight.referenceFiles);
    const runtime = noSourcesExtracted
      ? null
      : context.runtime;

    const labelsByPass = new Map<number, TaintAnalysisPassEntry[]>();
    let totalCostUsd = 0;
    if (noSourcesExtracted) {
      for (const passId of preflight.passes) {
        const checkpointPath = path.join(preflight.workspaceDir, "labels", `labels_raw_pass${passId}.json`);
        labelsByPass.set(passId, []);
        await writePassCheckpointV2(
          checkpointPath,
          passId,
          preflight.language,
          candidateFingerprint,
          [],
        );
      }
    } else {
      // ── Optimization: label sources once, share across all passes ──
      // Use deduplicated representatives for labeling, propagate to all instances later
      const sourceCandidates = representatives.filter((c) => c.candidateKind === "source_candidate");
      const sinkCandidates = representatives.filter((c) => c.candidateKind === "sink_candidate");

      process.stderr.write(`[taint-analysis-label] Split (deduped): ${sourceCandidates.length} sources, ${sinkCandidates.length} sinks\n`);

      const sourceLabels = await labelSourcesOnce(
        runtime!,
        sourceCandidates,
        references,
        cfg,
        context.repoRoot,
        preflight.language,
        preflight.framework,
      );
      totalCostUsd += sourceLabels.costUsd;

      for (const passId of preflight.passes) {
        const passDef = TAINT_ANALYSIS_PASSES.find((pass) => pass.passId === passId);
        if (!passDef || !runtime) {
          continue;
        }

        const checkpointPath = path.join(preflight.workspaceDir, "labels", `labels_raw_pass${passId}.json`);
        const cached = loadPassCheckpoint({
          checkpointPath,
          passId,
          language: preflight.language,
          candidates: allCandidates,
          candidateFingerprint,
        });
        if (cached.hit) {
          process.stderr.write(`[taint-analysis-label] Pass ${passId} (${passDef.focus}): loaded ${cached.entries.length} entries from ${cached.format} checkpoint\n`);
          if (cached.deniedCount > 0) {
            process.stderr.write(
              `[taint-analysis-label]   Deny-list reclassified ${cached.deniedCount} formatting/logging sink(s) as non-sinks during checkpoint load\n`,
            );
          }
          labelsByPass.set(passId, cached.entries);
          if (cached.needsRewrite) {
            await writePassCheckpointV2(
              checkpointPath,
              passId,
              preflight.language,
              candidateFingerprint,
              cached.entries,
            );
            process.stderr.write(
              `[taint-analysis-label] Pass ${passId} (${passDef.focus}): rewrote checkpoint to v${LABEL_CHECKPOINT_VERSION}\n`,
            );
          }
          continue;
        }

        process.stderr.write(`[taint-analysis-label] Pass ${passId} (${passDef.focus}): checkpoint miss (${cached.reason})\n`);

        // ── Optimization: two-phase sink triage ──
        // Phase 1: cheap bulk pre-filter — which sinks are plausibly relevant to this CWE?
        const { relevantIds: relevantSinkIds, costUsd: triageCostUsd } = await triageSinkRelevance(
          runtime,
          sinkCandidates,
          passDef,
          context.repoRoot,
          cfg.labelingModel,
        );
        totalCostUsd += triageCostUsd;

        // Filter sinks to only those that survived triage (fallback: all sinks if triage returned nothing)
        const filteredSinks = relevantSinkIds.size > 0
          ? sinkCandidates.filter((c) => relevantSinkIds.has(c.id))
          : sinkCandidates;

        // Combine pre-labeled sources with filtered sinks for detailed labeling
        const passCandidates = [...sourceCandidates, ...filteredSinks];
        process.stderr.write(`[taint-analysis-label] Labeling pass ${passId} (${passDef.focus}): ${passCandidates.length} candidates (${sourceCandidates.length} sources + ${filteredSinks.length} sinks)...\n`);

        // Phase 2: detailed labeling on filtered candidates
        try {
          const passEntries = await labelPass(
            runtime,
            passDef,
            passCandidates,
            references,
            tiPrior,
            {
              ...cfg,
              workspaceDir: preflight.workspaceDir,
            },
            context.repoRoot,
            preflight.language,
            preflight.framework,
          );

          // Store only deduped representative entries — no expansion back to 51K instances.
          // Downstream groupCallables() already deduplicates, so it works unchanged.
          const dedupedEntries: TaintAnalysisPassEntry[] = [];
          const passEntryById = new Map(passEntries.entries.map((e) => [e.id, e]));

          // Add labeled sinks from this pass
          for (const rep of filteredSinks) {
            const entry = passEntryById.get(rep.id);
            if (entry) dedupedEntries.push(entry);
          }
          // Add source labels (from source-once labeling or this pass)
          for (const rep of sourceCandidates) {
            const entry = passEntryById.get(rep.id);
            if (entry) {
              dedupedEntries.push(entry);
            } else {
              const srcLabel = sourceLabels.entries.get(rep.id);
              dedupedEntries.push(normalizePassEntry(rep, srcLabel));
            }
          }

          labelsByPass.set(passId, dedupedEntries);
          totalCostUsd += passEntries.costUsd;
          process.stderr.write(`[taint-analysis-label] Pass ${passId} complete: ${dedupedEntries.length} entries (deduped)\n`);

          await writePassCheckpointV2(
            checkpointPath,
            passId,
            preflight.language,
            candidateFingerprint,
            passEntries.entries,
          );
        } catch (passError) {
          // A single pass failure (e.g. malformed JSON from the LLM) should not kill
          // all previously completed passes. Log the error and continue with empty
          // entries for this pass — the run stage will simply skip it.
          const msg = passError instanceof Error ? passError.message : String(passError);
          process.stderr.write(`[taint-analysis-label] Pass ${passId} (${passDef.focus}) failed (non-fatal): ${msg}\n`);
          labelsByPass.set(passId, []);
        }
      }
    }

    // ── Cross-pass label sharing: merge highest-confidence classifications ──
    if (!noSourcesExtracted) {
      mergeCrossPassLabels(labelsByPass);
    }

    const generatedAt = new Date().toISOString();
    const labels: TaintAnalysisLabelsDocument = {
      version: "1.0.0",
      metadata: {
        run_id: context.runId,
        generated_at: generatedAt,
        language: preflight.language,
        framework: preflight.framework,
        model: cfg.labelingModel,
        project: context.repoName,
        notes: [
          "Generated by Kuzushi taint-analysis-label task.",
          "Labels generated by Kuzushi taint-analysis-label task.",
          `internal.label_checkpoint_version=${LABEL_CHECKPOINT_VERSION}`,
          `internal.label_parser_version=${LABEL_PARSER_VERSION}`,
          ...(noSourcesExtracted
            ? [
              `Labeling skipped because source extraction returned zero source candidates (${preflight.extraction.sourcesRowCount} rows).`,
            ]
            : []),
        ],
      },
      passes: preflight.passes
        .map((passId) => {
          const passDef = TAINT_ANALYSIS_PASSES.find((pass) => pass.passId === passId);
          if (!passDef) {
            return null;
          }

          return {
            pass_id: passDef.passId,
            focus: passDef.focus,
            cwes: [...passDef.cwes],
            entries: labelsByPass.get(passId) ?? [],
          };
        })
        .filter((pass): pass is NonNullable<typeof pass> => Boolean(pass)),
    };

    const validationError = validateLabelsDocument(labels);
    if (validationError) {
      throw new Error(`Generated labels.json failed validation: ${validationError}`);
    }

    const labelsPath = path.join(preflight.workspaceDir, "labels", "labels.json");
    await writeFile(labelsPath, JSON.stringify(labels, null, 2), "utf-8");
    const taintModel = buildTaintModelDocument(labels, tiPrior);
    const taintModelPath = path.join(preflight.workspaceDir, "labels", "TAINT_MODEL.json");
    await writeFile(taintModelPath, JSON.stringify(taintModel, null, 2), "utf-8");
    process.stderr.write(`[taint-analysis-label] Labels and taint model written\n`);

    const { labelCounts, reviewSummary } = summarizeLabels(labels, cfg.labelingConfidenceThreshold);

    await writeFile(
      path.join(preflight.workspaceDir, "labels", "label_stats.md"),
      reviewSummary,
      "utf-8",
    );

    return attachTaskOutputMeta({
      taintAnalysisPath: preflight.taintAnalysisPath,
      workspaceDir: preflight.workspaceDir,
      dbPath: preflight.dbPath,
      codeqlBinary: preflight.codeqlBinary,
      codeqlVersion: preflight.codeqlVersion,
      codeqlApiProfileId: preflight.codeqlApiProfileId,
      language: preflight.language,
      framework: preflight.framework,
      passes: preflight.passes,
      tiPriorMarkdownPath: preflight.tiPriorMarkdownPath,
      tiPriorJsonPath: preflight.tiPriorJsonPath,
      tiPriorDegraded: preflight.tiPriorDegraded,
      extractionDegradation: preflight.extractionDegradation,
      diffScope: preflight.diffScope,
      labelsPath,
      labels,
      taintModelPath,
      reviewSummary,
      labelCounts,
    }, { costUsd: totalCostUsd });
  },
};

async function labelPass(
  runtime: AgentRuntime,
  passDef: TaintAnalysisPassDefinition,
  candidates: TaintAnalysisCandidate[],
  references: string,
  tiPrior: TiPriorDocument | null,
  cfg: ReturnType<typeof resolveTaintAnalysisConfig>,
  repoRoot: string,
  language: TaintAnalysisPreflightOutput["language"],
  framework: string | null,
): Promise<{ entries: TaintAnalysisPassEntry[]; costUsd: number }> {
  const byCandidateId = new Map<string, LabelResponseEntry>();
  const batches = chunk(candidates, cfg.labelingBatchSize);
  let totalCostUsd = 0;
  process.stderr.write(`[taint-analysis-label]   ${batches.length} batch(es) of up to ${cfg.labelingBatchSize} candidates\n`);

  // Session path: reuse a single subprocess for all batches in this pass
  const session = runtime.createSession?.({
    cwd: repoRoot,
    model: cfg.labelingModel,
    allowedTools: ["Read", "Grep", "Glob"],
    permissionMode: "dontAsk",
    outputFormat: {
      type: "json_schema",
      schema: LABEL_RESPONSE_SCHEMA as unknown as Record<string, unknown>,
      strict: true,
      retryInvalidStructuredOutput: 2,
    },
    systemPromptPrefix: buildLabelSystemPrompt(passDef, references, tiPrior, language, framework),
  });

  const runId = session ? crypto.randomUUID() : "";

  try {
    for (let batchIdx = 0; batchIdx < batches.length; batchIdx++) {
      const batch = batches[batchIdx];
      process.stderr.write(`[taint-analysis-label]   Batch ${batchIdx + 1}/${batches.length}: querying LLM with ${batch.length} candidates...\n`);

      let initial: { response: LabelResponse; costUsd: number };

      if (session) {
        const candidatePayload = batch.map((c) => ({
          id: c.id,
          candidate_kind: c.candidateKind,
          callable: c.callable,
          flow_kind: c.flowKind,
          arg_index: c.argIndex,
          receiver_hint: c.receiverHint ?? null,
          module_hint: c.moduleHint ?? null,
          location: { file: c.locationFile, line: c.locationLine },
          snippet: c.snippet ?? "",
        }));
        const batchFile = writeBatchFile(repoRoot, runId, `label-pass${passDef.passId}`, batchIdx, candidatePayload);
        const turnPrompt = `Read ${batchFile} and classify each candidate. Return JSON with your assessment.`;
        const result = await withRetry(
          () => runStructuredSessionQuery(session, turnPrompt),
          { maxRetries: 3, backoffMs: 5_000, multiplier: 2 },
        );
        const parsed = parseLabelResponse(result.structuredOutput ?? result.resultText);
        initial = { response: parsed, costUsd: result.costUsd };
      } else {
        // Fallback: spawn a new subprocess per batch (pi-ai runtime)
        const prompt = buildLabelPrompt(passDef, batch, references, tiPrior, language, framework, false);
        initial = await withRetry(
          () => queryLabelBatch(runtime, prompt, repoRoot, cfg.labelingModel),
          { maxRetries: 3, backoffMs: 5_000, multiplier: 2 },
        );
      }
      totalCostUsd += initial.costUsd;

      process.stderr.write(`[taint-analysis-label]   Batch ${batchIdx + 1}/${batches.length}: LLM returned ${initial.response.entries.length} entries\n`);
      for (const entry of initial.response.entries) {
        byCandidateId.set(entry.id, entry);
      }

      const lowConfidenceIds = initial.response.entries
        .filter((entry) => entry.confidence < cfg.labelingConfidenceThreshold)
        .map((entry) => entry.id);

      if (lowConfidenceIds.length > 0) {
        process.stderr.write(`[taint-analysis-label]   Batch ${batchIdx + 1}/${batches.length}: retrying ${lowConfidenceIds.length} low-confidence entries...\n`);
        const lowConfidenceCandidates = batch.filter((candidate) => lowConfidenceIds.includes(candidate.id));

        let retry: { response: LabelResponse; costUsd: number };

        if (session) {
          const retryPayload = lowConfidenceCandidates.map((c) => ({
            id: c.id,
            candidate_kind: c.candidateKind,
            callable: c.callable,
            flow_kind: c.flowKind,
            arg_index: c.argIndex,
            receiver_hint: c.receiverHint ?? null,
            module_hint: c.moduleHint ?? null,
            location: { file: c.locationFile, line: c.locationLine },
            snippet: c.snippet ?? "",
          }));
          const retryFile = writeBatchFile(repoRoot, runId, `label-pass${passDef.passId}-retry`, batchIdx, retryPayload);
          const retryTurnPrompt = `This is a retry pass for low-confidence items. Re-evaluate carefully with stricter confidence calibration. Read ${retryFile} and classify each candidate. Return JSON with your assessment.`;
          const result = await withRetry(
            () => runStructuredSessionQuery(session, retryTurnPrompt),
            { maxRetries: 3, backoffMs: 5_000, multiplier: 2 },
          );
          const parsed = parseLabelResponse(result.structuredOutput ?? result.resultText);
          retry = { response: parsed, costUsd: result.costUsd };
        } else {
          const retryPrompt = buildLabelPrompt(passDef, lowConfidenceCandidates, references, tiPrior, language, framework, true);
          retry = await withRetry(
            () => queryLabelBatch(runtime, retryPrompt, repoRoot, cfg.labelingModel),
            { maxRetries: 3, backoffMs: 5_000, multiplier: 2 },
          );
        }
        totalCostUsd += retry.costUsd;
        for (const entry of retry.response.entries) {
          byCandidateId.set(entry.id, entry);
        }
      }
    }
  } finally {
    await session?.close();
    if (runId) cleanupBatchFiles(repoRoot, runId);
  }

  const entries = candidates.map((candidate) => {
    const entry = byCandidateId.get(candidate.id);
    return normalizePassEntry(candidate, entry);
  });

  const validated = applySinkDenyList(entries, language);
  const deniedCount = entries.filter((entry) => entry.role === "sink").length
    - validated.filter((entry) => entry.role === "sink").length;
  if (deniedCount > 0) {
    process.stderr.write(
      `[taint-analysis-label]   Deny-list reclassified ${deniedCount} formatting/logging sink(s) as non-sinks during fresh labeling\n`,
    );
  }

  return {
    entries: validated,
    costUsd: totalCostUsd,
  };
}

/**
 * Label all source candidates once in a CWE-agnostic pass.
 * Sources (HTTP params, env vars, file reads) are universal — they don't
 * change by CWE class, so we label them once and reuse across all passes.
 */
async function labelSourcesOnce(
  runtime: AgentRuntime,
  sourceCandidates: TaintAnalysisCandidate[],
  references: string,
  cfg: ReturnType<typeof resolveTaintAnalysisConfig>,
  repoRoot: string,
  language: TaintAnalysisPreflightOutput["language"],
  framework: string | null,
): Promise<{ entries: Map<string, LabelResponseEntry>; costUsd: number }> {
  const byCandidateId = new Map<string, LabelResponseEntry>();
  if (sourceCandidates.length === 0) {
    return { entries: byCandidateId, costUsd: 0 };
  }

  const batches = chunk(sourceCandidates, cfg.labelingBatchSize);
  let totalCostUsd = 0;

  process.stderr.write(`[taint-analysis-label] Labeling ${sourceCandidates.length} sources once (${batches.length} batch(es))...\n`);

  const sourceSystemPrompt = [
    "You are a taint analysis source labeling agent.",
    "Return JSON only. Do not include markdown or narrative text.",
    "Classify each candidate as a data source (user-controlled input), sanitizer, or none.",
    "This is CWE-agnostic — focus on whether data is user-controllable, not on specific vulnerability types.",
    "",
    "Output JSON schema:",
    JSON.stringify(LABEL_RESPONSE_SCHEMA),
    "",
    "Labeling rubric:",
    "- role: source|sanitizer|none",
    "- classification: tp|fp|candidate|unknown",
    "- confidence: number in [0,1]",
    "",
    `Known sanitizer functions for ${language}:`,
    JSON.stringify(FRAMEWORK_SANITIZER_CATALOG[language as TaintAnalysisLanguage] ?? [], null, 2),
    "",
    `Language: ${language}${framework ? `, Framework: ${framework}` : ""}`,
    "",
    "References (trimmed):",
    references,
  ].join("\n");

  // Session path: reuse a single subprocess for all source batches
  const session = runtime.createSession?.({
    cwd: repoRoot,
    model: cfg.labelingModel,
    allowedTools: ["Read", "Grep", "Glob"],
    permissionMode: "dontAsk",
    outputFormat: {
      type: "json_schema",
      schema: LABEL_RESPONSE_SCHEMA as unknown as Record<string, unknown>,
      strict: true,
      retryInvalidStructuredOutput: 2,
    },
    systemPromptPrefix: sourceSystemPrompt,
  });

  const runId = session ? crypto.randomUUID() : "";

  try {
    for (let batchIdx = 0; batchIdx < batches.length; batchIdx++) {
      const batch = batches[batchIdx];
      const candidatePayload = batch.map((c) => ({
        id: c.id,
        candidate_kind: c.candidateKind,
        callable: c.callable,
        flow_kind: c.flowKind,
        arg_index: c.argIndex,
        receiver_hint: c.receiverHint ?? null,
        module_hint: c.moduleHint ?? null,
        location: { file: c.locationFile, line: c.locationLine },
        snippet: c.snippet ?? "",
      }));

      let result: { response: LabelResponse; costUsd: number };

      if (session) {
        const batchFile = writeBatchFile(repoRoot, runId, "label-sources", batchIdx, candidatePayload);
        const turnPrompt = `Read ${batchFile} and classify each candidate. Return JSON with your assessment.`;
        const sessionResult = await withRetry(
          () => runStructuredSessionQuery(session, turnPrompt),
          { maxRetries: 3, backoffMs: 5_000, multiplier: 2 },
        );
        const parsed = parseLabelResponse(sessionResult.structuredOutput ?? sessionResult.resultText);
        result = { response: parsed, costUsd: sessionResult.costUsd };
      } else {
        // Fallback: spawn a new subprocess per batch (pi-ai runtime)
        const prompt = [
          sourceSystemPrompt,
          "",
          "Candidates:",
          JSON.stringify(candidatePayload, null, 2),
        ].join("\n");
        result = await withRetry(
          () => queryLabelBatch(runtime, prompt, repoRoot, cfg.labelingModel),
          { maxRetries: 3, backoffMs: 5_000, multiplier: 2 },
        );
      }
      totalCostUsd += result.costUsd;

      for (const entry of result.response.entries) {
        byCandidateId.set(entry.id, entry);
      }

      if ((batchIdx + 1) % 50 === 0 || batchIdx === batches.length - 1) {
        process.stderr.write(`[taint-analysis-label]   Source labeling: ${batchIdx + 1}/${batches.length} batches done\n`);
      }
    }
  } finally {
    await session?.close();
    if (runId) cleanupBatchFiles(repoRoot, runId);
  }

  process.stderr.write(`[taint-analysis-label] Source labeling complete: ${byCandidateId.size} entries\n`);
  return { entries: byCandidateId, costUsd: totalCostUsd };
}

const TRIAGE_BATCH_SIZE = 300;

/**
 * Cheap bulk pre-filter: send sink callables (minimal context) to LLM and
 * ask which are plausibly relevant to a given CWE class. Returns the set
 * of candidate IDs that survived triage.
 *
 * Language-agnostic — the LLM determines relevance based on callable names
 * and CWE semantics, not regex patterns.
 */
async function triageSinkRelevance(
  runtime: AgentRuntime,
  sinkCandidates: TaintAnalysisCandidate[],
  passDef: TaintAnalysisPassDefinition,
  repoRoot: string,
  model: string,
): Promise<{ relevantIds: Set<string>; costUsd: number }> {
  const relevantIds = new Set<string>();
  if (sinkCandidates.length === 0) {
    return { relevantIds, costUsd: 0 };
  }

  const batches = chunk(sinkCandidates, TRIAGE_BATCH_SIZE);
  let totalCostUsd = 0;

  process.stderr.write(`[taint-analysis-label]   Sink triage for ${passDef.focus}: ${sinkCandidates.length} sinks in ${batches.length} batch(es)...\n`);

  const systemPrompt = [
    `You are a taint analysis triage agent. For CWE ${passDef.cwes.join("/")} (${passDef.focus}):`,
    "Mark each callable as relevant (true) or skip (false).",
    "A callable is relevant ONLY if it could plausibly be a security-sensitive sink for this CWE class.",
    "Be inclusive — when in doubt, mark as relevant. The goal is to filter out obvious non-sinks (logging, formatting, type conversion, string building).",
    "",
    "Return JSON only:",
    JSON.stringify(TRIAGE_RESPONSE_SCHEMA),
  ].join("\n");

  // Session path: reuse a single subprocess for all batches
  const session = runtime.createSession?.({
    cwd: repoRoot,
    model,
    allowedTools: ["Read"],
    permissionMode: "dontAsk",
    outputFormat: {
      type: "json_schema",
      schema: TRIAGE_RESPONSE_SCHEMA as unknown as Record<string, unknown>,
      strict: true,
      retryInvalidStructuredOutput: 1,
    },
    systemPromptPrefix: systemPrompt,
  });

  const runId = session ? crypto.randomUUID() : "";

  try {
    for (let batchIdx = 0; batchIdx < batches.length; batchIdx++) {
      const batch = batches[batchIdx];
      // Compact payload — only callable name and module, no snippets or file paths
      const compactPayload = batch.map((c) => ({
        id: c.id,
        callable: c.callable,
        module_hint: c.moduleHint ?? null,
        receiver_hint: c.receiverHint ?? null,
      }));

      let rawResult: unknown;
      let rawText = "";
      let costUsd = 0;

      if (session) {
        // Write batch data to a file the subprocess can read
        const batchFile = writeBatchFile(repoRoot, runId, "triage-sink", batchIdx, compactPayload);
        const turnPrompt = `Read ${batchFile} and classify each candidate. Return JSON with your assessment.`;

        const result = await runStructuredSessionQuery(session, turnPrompt);
        costUsd = result.costUsd;
        rawText = result.resultText;
        rawResult = result.structuredOutput;
      } else {
        // Fallback: spawn a new subprocess per batch (pi-ai runtime)
        const prompt = [
          systemPrompt,
          "",
          "Candidates:",
          JSON.stringify(compactPayload, null, 2),
        ].join("\n");

        for await (const message of runtime.query({
          prompt,
          options: {
            cwd: repoRoot,
            model,
            allowedTools: [],
            permissionMode: "dontAsk",
            outputFormat: {
              type: "json_schema",
              schema: TRIAGE_RESPONSE_SCHEMA as unknown as Record<string, unknown>,
              strict: true,
              retryInvalidStructuredOutput: 1,
            },
          },
        })) {
          if (message.type !== "result") continue;
          if (typeof message.totalCostUsd === "number" && Number.isFinite(message.totalCostUsd)) {
            costUsd = message.totalCostUsd;
          }
          if ("result" in message) {
            rawText = message.result;
            rawResult = message.structuredOutput;
          }
        }
      }

      totalCostUsd += costUsd;

      // Parse triage response
      const parsed = parseTriageResponse(rawResult ?? rawText);
      for (const entry of parsed.entries) {
        if (entry.relevant) {
          relevantIds.add(entry.id);
        }
      }

      if ((batchIdx + 1) % 20 === 0 || batchIdx === batches.length - 1) {
        process.stderr.write(`[taint-analysis-label]   Sink triage: ${batchIdx + 1}/${batches.length} batches, ${relevantIds.size} relevant so far\n`);
      }
    }
  } finally {
    await session?.close();
    if (runId) cleanupBatchFiles(repoRoot, runId);
  }

  process.stderr.write(`[taint-analysis-label]   Sink triage complete: ${relevantIds.size}/${sinkCandidates.length} sinks relevant to ${passDef.focus}\n`);
  return { relevantIds, costUsd: totalCostUsd };
}

function parseTriageResponse(value: unknown): { entries: Array<{ id: string; relevant: boolean }> } {
  if (isRecord(value) && Array.isArray(value["entries"])) {
    return {
      entries: value["entries"]
        .filter((e): e is Record<string, unknown> => isRecord(e) && typeof e["id"] === "string")
        .map((e) => ({ id: String(e["id"]), relevant: e["relevant"] === true })),
    };
  }

  if (typeof value === "string") {
    try {
      const parsed = JSON.parse(extractJson(value));
      return parseTriageResponse(parsed);
    } catch {
      // If triage parsing fails, mark all as relevant (safe fallback)
      return { entries: [] };
    }
  }

  return { entries: [] };
}

async function queryLabelBatch(
  runtime: AgentRuntime,
  prompt: string,
  repoRoot: string,
  model: string,
): Promise<{ response: LabelResponse; costUsd: number }> {
  let rawResult: unknown;
  let rawText = "";
  let resultError: string | null = null;
  let resultErrorSubtype: string | null = null;
  let costUsd = 0;

  for await (const message of runtime.query({
    prompt,
    options: {
      cwd: repoRoot,
      model,
      allowedTools: ["Read", "Grep", "Glob"],
      permissionMode: "dontAsk",
      outputFormat: {
        type: "json_schema",
        schema: LABEL_RESPONSE_SCHEMA as unknown as Record<string, unknown>,
        strict: true,
        retryInvalidStructuredOutput: 2,
      },
    },
  })) {
    if (message.type !== "result") {
      continue;
    }

    if (typeof message.totalCostUsd === "number" && Number.isFinite(message.totalCostUsd)) {
      costUsd = message.totalCostUsd;
    }

    if ("result" in message) {
      rawText = message.result;
      rawResult = message.structuredOutput;
      continue;
    }

    resultErrorSubtype = message.subtype;
    resultError = ("errors" in message ? message.errors.join("; ") : "") || message.subtype;
  }

  if (resultError) {
    const withSubtype = resultErrorSubtype
      ? ` (${resultErrorSubtype})`
      : "";
    throw new Error(`Taint analysis labeling runtime failed${withSubtype}: ${resultError}`);
  }

  const parsed = parseLabelResponse(rawResult ?? rawText);
  return {
    response: parsed,
    costUsd,
  };
}

function parseLabelResponse(value: unknown): LabelResponse {
  if (isRecord(value) && Array.isArray(value["entries"])) {
    return {
      entries: value["entries"]
        .map((entry) => normalizeLabelResponseEntry(entry))
        .filter((entry): entry is LabelResponseEntry => Boolean(entry)),
    };
  }

  if (typeof value === "string") {
    try {
      const parsed = JSON.parse(extractJson(value));
      return parseLabelResponse(parsed);
    } catch (error) {
      throw new Error(`Could not parse taint analysis label response JSON: ${toErrorMessage(error)}`);
    }
  }

  throw new Error("Unexpected taint analysis label response shape");
}

function normalizeLabelResponseEntry(value: unknown): LabelResponseEntry | null {
  if (!isRecord(value)) {
    return null;
  }

  const id = asString(value["id"]);
  const role = asRole(value["role"]);
  const classification = asClassification(value["classification"]);
  const confidence = clamp(Number(value["confidence"]));
  const rationale = asString(value["rationale"]);

  if (!id || !role || !classification || !rationale) {
    return null;
  }

  const evidence = Array.isArray(value["evidence"])
    ? value["evidence"].map((item) => String(item).trim()).filter(Boolean)
    : undefined;

  return {
    id,
    role,
    classification,
    confidence,
    rationale,
    evidence,
  };
}

function normalizePassEntry(candidate: TaintAnalysisCandidate, entry: LabelResponseEntry | undefined): TaintAnalysisPassEntry {
  return {
    id: candidate.id,
    role: entry?.role ?? (candidate.candidateKind === "sink_candidate" ? "sink" : "source"),
    classification: entry?.classification ?? "candidate",
    confidence: entry?.confidence ?? 0.5,
    signature: {
      package: null,
      module: candidate.moduleHint ?? null,
      type: candidate.receiverHint ?? null,
      callable: candidate.callable,
      arg_index: candidate.argIndex,
      flow_kind: candidate.flowKind,
    },
    location: {
      file: candidate.locationFile,
      line: candidate.locationLine,
    },
    rationale: entry?.rationale ?? "Generated fallback label from extraction metadata.",
    evidence: entry?.evidence,
  };
}

function applySinkDenyList(
  entries: TaintAnalysisPassEntry[],
  language: TaintAnalysisLanguage,
): TaintAnalysisPassEntry[] {
  const denySet = SINK_DENY_LIST[language];
  if (!denySet || denySet.size === 0) {
    return entries;
  }

  return entries.map((entry) => {
    if (entry.role !== "sink") {
      return entry;
    }

    const callable = entry.signature.callable.trim();
    const callableParts = callable
      .split(/[.:#]/)
      .map((part) => part.trim())
      .filter(Boolean);
    const basename = callableParts.at(-1) ?? callable;

    if (!denySet.has(callable) && !denySet.has(basename)) {
      return entry;
    }

    const baseRationale = entry.rationale.trim() || "Deny-list override.";
    return {
      ...entry,
      role: "none",
      classification: "fp",
      rationale: `${baseRationale} [Overridden: ${callable} is a formatting/logging function, not a security-sensitive sink.]`,
    };
  });
}

/**
 * Cross-pass label sharing: for each candidate, propagate the highest-confidence
 * classification across all passes. If a function was labeled as a source in pass 1
 * with confidence 0.9, it should also be available as a source in pass 3.
 */
function mergeCrossPassLabels(labelsByPass: Map<number, TaintAnalysisPassEntry[]>): void {
  // Build a merged index: candidateId -> best entry per role
  const bestByCandidate = new Map<string, TaintAnalysisPassEntry>();

  for (const entries of labelsByPass.values()) {
    for (const entry of entries) {
      if (entry.role === "none" || entry.classification === "fp") {
        continue;
      }
      const existing = bestByCandidate.get(entry.id);
      if (!existing || entry.confidence > existing.confidence) {
        bestByCandidate.set(entry.id, entry);
      }
    }
  }

  // Apply merged labels back to each pass
  for (const entries of labelsByPass.values()) {
    for (let i = 0; i < entries.length; i++) {
      const entry = entries[i];
      const best = bestByCandidate.get(entry.id);
      if (!best) {
        continue;
      }
      // If this pass has a lower-confidence or "none" label, upgrade it
      if (
        (entry.role === "none" || entry.classification === "fp" || entry.confidence < best.confidence)
        && best.role !== "none"
        && best.classification !== "fp"
      ) {
        entries[i] = {
          ...entry,
          role: best.role,
          classification: best.classification,
          confidence: best.confidence,
          rationale: `${entry.rationale} [Cross-pass upgrade from ${best.role}@${best.confidence.toFixed(2)}]`,
        };
      }
    }
  }

  const upgradedCount = [...labelsByPass.values()]
    .flat()
    .filter((e) => e.rationale.includes("[Cross-pass upgrade"))
    .length;
  if (upgradedCount > 0) {
    process.stderr.write(
      `[taint-analysis-label] Cross-pass label sharing: upgraded ${upgradedCount} entries across passes\n`,
    );
  }
}

/**
 * Snippet enrichment: read source files and attach 5-10 lines of code context
 * around each candidate's location. This dramatically improves labeling accuracy
 * by giving the LLM actual code to examine rather than just function names.
 */
async function enrichCandidateSnippets(
  candidates: TaintAnalysisCandidate[],
  repoRoot: string,
): Promise<void> {
  // Group candidates by file to minimize file reads
  const byFile = new Map<string, TaintAnalysisCandidate[]>();
  for (const candidate of candidates) {
    if (candidate.snippet) continue; // Already has a snippet
    const filePath = candidate.locationFile;
    if (!filePath) continue;
    const group = byFile.get(filePath) ?? [];
    group.push(candidate);
    byFile.set(filePath, group);
  }

  let enrichedCount = 0;
  for (const [relativeFile, fileCandidates] of byFile) {
    const absolutePath = path.isAbsolute(relativeFile)
      ? relativeFile
      : path.join(repoRoot, relativeFile);
    let lines: string[];
    try {
      const content = await readFile(absolutePath, "utf-8");
      lines = content.split("\n");
    } catch {
      continue; // File not readable, skip
    }

    for (const candidate of fileCandidates) {
      const line = candidate.locationLine;
      if (line < 1 || line > lines.length) continue;
      const start = Math.max(0, line - 4); // 3 lines before
      const end = Math.min(lines.length, line + 6); // 6 lines after
      const snippet = lines.slice(start, end).join("\n").trim();
      if (snippet) {
        candidate.snippet = snippet;
        enrichedCount++;
      }
    }
  }

  if (enrichedCount > 0) {
    process.stderr.write(
      `[taint-analysis-label] Snippet enrichment: added code context to ${enrichedCount} candidates\n`,
    );
  }
}

/**
 * Extract the static system prompt portion of the label prompt.
 * Used as `systemPromptPrefix` when creating a session so the
 * per-batch turn only needs to reference the batch file path.
 */
function buildLabelSystemPrompt(
  passDef: TaintAnalysisPassDefinition,
  references: string,
  tiPrior: TiPriorDocument | null,
  language: string,
  framework: string | null,
): string {
  const passTiPrior = selectTiPriorForPass(passDef, tiPrior);

  return [
    "You are a taint analysis labeling agent for one CWE-focused pass.",
    "Return JSON only. Do not include markdown or narrative text.",
    "Classify each candidate conservatively and include concise rationale.",
    "",
    "Output JSON schema:",
    JSON.stringify(LABEL_RESPONSE_SCHEMA),
    "",
    "Labeling rubric:",
    "- role: source|sink|sanitizer|summary|none",
    "- classification: tp|fp|candidate|unknown",
    "- confidence: number in [0,1]",
    "",
    "Sink classification constraints (hard rules):",
    "- A sink MUST be a function that performs a security-sensitive action: executing commands, querying databases, making network requests, writing to filesystems, evaluating code, rendering templates, constructing LDAP filters, or setting HTTP headers/redirects.",
    "- String formatting functions (Sprintf, Errorf, String.format, etc.) are NOT sinks - they produce strings but do not execute, query, or transmit anything.",
    "- Logging functions (log.Printf, logger.info, console.log, etc.) are NOT injection sinks for command/SQL/SSRF/LDAP injection passes.",
    "- If a candidate is a formatting or logging function, classify it as role=none, classification=fp.",
    "",
    `Known sanitizer functions for ${language} (classify as role=sanitizer when encountered):`,
    JSON.stringify(FRAMEWORK_SANITIZER_CATALOG[language as TaintAnalysisLanguage] ?? [], null, 2),
    "",
    "Threat-intelligence prior (use as weighting guidance, not as proof):",
    JSON.stringify(passTiPrior, null, 2),
    "",
    "Pass context:",
    JSON.stringify({
      pass_id: passDef.passId,
      pass_key: passDef.passKey,
      focus: passDef.focus,
      cwes: passDef.cwes,
      language,
      framework,
    }, null, 2),
    "",
    "References (trimmed):",
    references,
  ].join("\n");
}

function buildLabelPrompt(
  passDef: TaintAnalysisPassDefinition,
  candidates: TaintAnalysisCandidate[],
  references: string,
  tiPrior: TiPriorDocument | null,
  language: string,
  framework: string | null,
  retryOnly: boolean,
): string {
  const candidatePayload = candidates.map((candidate) => ({
    id: candidate.id,
    candidate_kind: candidate.candidateKind,
    callable: candidate.callable,
    flow_kind: candidate.flowKind,
    arg_index: candidate.argIndex,
    receiver_hint: candidate.receiverHint ?? null,
    module_hint: candidate.moduleHint ?? null,
    location: {
      file: candidate.locationFile,
      line: candidate.locationLine,
    },
    snippet: candidate.snippet ?? "",
  }));

  const passTiPrior = selectTiPriorForPass(passDef, tiPrior);

  return [
    "You are a taint analysis labeling agent for one CWE-focused pass.",
    "Return JSON only. Do not include markdown or narrative text.",
    retryOnly
      ? "This is a retry pass for low-confidence items. Re-evaluate carefully with stricter confidence calibration."
      : "Classify each candidate conservatively and include concise rationale.",
    "",
    "Output JSON schema:",
    JSON.stringify(LABEL_RESPONSE_SCHEMA),
    "",
    "Labeling rubric:",
    "- role: source|sink|sanitizer|summary|none",
    "- classification: tp|fp|candidate|unknown",
    "- confidence: number in [0,1]",
    "",
    "Sink classification constraints (hard rules):",
    "- A sink MUST be a function that performs a security-sensitive action: executing commands, querying databases, making network requests, writing to filesystems, evaluating code, rendering templates, constructing LDAP filters, or setting HTTP headers/redirects.",
    "- String formatting functions (Sprintf, Errorf, String.format, etc.) are NOT sinks - they produce strings but do not execute, query, or transmit anything.",
    "- Logging functions (log.Printf, logger.info, console.log, etc.) are NOT injection sinks for command/SQL/SSRF/LDAP injection passes.",
    "- If a candidate is a formatting or logging function, classify it as role=none, classification=fp.",
    "",
    `Known sanitizer functions for ${language} (classify as role=sanitizer when encountered):`,
    JSON.stringify(FRAMEWORK_SANITIZER_CATALOG[language as TaintAnalysisLanguage] ?? [], null, 2),
    "",
    "Threat-intelligence prior (use as weighting guidance, not as proof):",
    JSON.stringify(passTiPrior, null, 2),
    "",
    "Pass context:",
    JSON.stringify({
      pass_id: passDef.passId,
      pass_key: passDef.passKey,
      focus: passDef.focus,
      cwes: passDef.cwes,
      language,
      framework,
    }, null, 2),
    "",
    "Candidates:",
    JSON.stringify(candidatePayload, null, 2),
    "",
    "References (trimmed):",
    references,
  ].join("\n");
}

async function loadReferenceContent(referenceFiles: string[]): Promise<string> {
  const sections: string[] = [];

  for (const referenceFile of referenceFiles) {
    try {
      const content = await readFile(referenceFile, "utf-8");
      const trimmed = content.trim();
      if (!trimmed) {
        continue;
      }

      sections.push(`## ${path.basename(referenceFile)}\n${trimTo(trimmed, 8000)}`);
    } catch {
      // Best-effort reference loading.
    }
  }

  return sections.join("\n\n");
}

async function loadTiPrior(tiPriorJsonPath: string): Promise<TiPriorDocument | null> {
  if (!tiPriorJsonPath) {
    return null;
  }

  try {
    const raw = await readFile(tiPriorJsonPath, "utf-8");
    const parsed = JSON.parse(raw);
    if (!isRecord(parsed) || !Array.isArray(parsed["cwes"])) {
      return null;
    }
    return parsed as unknown as TiPriorDocument;
  } catch {
    return null;
  }
}

function selectTiPriorForPass(
  passDef: TaintAnalysisPassDefinition,
  tiPrior: TiPriorDocument | null,
): TiPriorCwe[] {
  if (!tiPrior) {
    return [];
  }

  const target = new Set(passDef.cwes.map((cwe) => normalizeCweId(cwe)));
  return tiPrior.cwes.filter((entry) => target.has(normalizeCweId(entry.cwe)));
}

interface LoadPassCheckpointArgs {
  checkpointPath: string;
  passId: TaintAnalysisPassId;
  language: TaintAnalysisLanguage;
  candidates: TaintAnalysisCandidate[];
  candidateFingerprint: string;
}

function loadPassCheckpoint({
  checkpointPath,
  passId,
  language,
  candidates,
  candidateFingerprint,
}: LoadPassCheckpointArgs): LoadPassCheckpointResult {
  if (!existsSync(checkpointPath)) {
    return { hit: false, reason: "missing checkpoint file" };
  }

  const computedFingerprint = computeCandidatesFingerprint(candidates);
  if (computedFingerprint !== candidateFingerprint) {
    return { hit: false, reason: "internal candidate fingerprint mismatch" };
  }

  let parsed: unknown;
  try {
    const raw = readFileSync(checkpointPath, "utf-8");
    parsed = JSON.parse(raw);
  } catch {
    return { hit: false, reason: "checkpoint parse error" };
  }

  if (Array.isArray(parsed)) {
    return loadLegacyPassCheckpoint(parsed, language, candidateFingerprint);
  }

  if (!isRecord(parsed)) {
    return { hit: false, reason: "checkpoint root is not an object or array" };
  }

  const version = Number(parsed["version"]);
  if (!Number.isFinite(version) || version !== LABEL_CHECKPOINT_VERSION) {
    return { hit: false, reason: `version mismatch (found ${String(parsed["version"])})` };
  }

  const parserVersion = Number(parsed["parserVersion"]);
  if (!Number.isFinite(parserVersion) || parserVersion !== LABEL_PARSER_VERSION) {
    return { hit: false, reason: `parser version mismatch (expected ${LABEL_PARSER_VERSION}, found ${String(parsed["parserVersion"]) || "unknown"})` };
  }

  const parsedPassId = Number(parsed["passId"]);
  if (!Number.isFinite(parsedPassId) || parsedPassId !== passId) {
    return { hit: false, reason: `pass mismatch (expected ${passId}, found ${String(parsed["passId"])})` };
  }

  const parsedLanguage = asString(parsed["language"]).trim();
  if (parsedLanguage !== language) {
    return { hit: false, reason: `language mismatch (expected ${language}, found ${parsedLanguage || "unknown"})` };
  }

  const storedFingerprint = asString(parsed["candidateFingerprint"]).trim();
  if (!storedFingerprint || storedFingerprint !== candidateFingerprint) {
    return {
      hit: false,
      reason: `fingerprint mismatch (parserVersion=${parserVersion})`,
    };
  }

  const entries = parseCheckpointEntries(parsed["entries"]);
  if (!entries) {
    return { hit: false, reason: "shape invalid" };
  }

  const validated = applySinkDenyList(entries, language);
  const deniedCount = entries.filter((entry) => entry.role === "sink").length
    - validated.filter((entry) => entry.role === "sink").length;
  return {
    hit: true,
    format: "v2",
    entries: validated,
    deniedCount,
    needsRewrite: deniedCount > 0,
  };
}

function loadLegacyPassCheckpoint(
  value: unknown[],
  language: TaintAnalysisLanguage,
  candidateFingerprint: string,
): LoadPassCheckpointResult {
  const entries = parseCheckpointEntries(value);
  if (!entries) {
    return { hit: false, reason: "shape invalid" };
  }

  const entriesFingerprint = computeEntriesFingerprint(entries);
  if (entriesFingerprint !== candidateFingerprint) {
    return { hit: false, reason: `legacy fingerprint mismatch (parserVersion=legacy-unknown, expected=${LABEL_PARSER_VERSION})` };
  }

  const validated = applySinkDenyList(entries, language);
  const deniedCount = entries.filter((entry) => entry.role === "sink").length
    - validated.filter((entry) => entry.role === "sink").length;
  return {
    hit: true,
    format: "legacy",
    entries: validated,
    deniedCount,
    needsRewrite: true,
  };
}

function parseCheckpointEntries(value: unknown): TaintAnalysisPassEntry[] | null {
  if (!Array.isArray(value)) {
    return null;
  }

  const entries: TaintAnalysisPassEntry[] = [];
  for (const item of value) {
    const entry = parseCheckpointEntry(item);
    if (!entry) {
      return null;
    }
    entries.push(entry);
  }

  return entries;
}

function parseCheckpointEntry(value: unknown): TaintAnalysisPassEntry | null {
  if (!isRecord(value)) {
    return null;
  }

  const id = asString(value["id"]).trim();
  const role = asRole(value["role"]);
  const classification = asClassification(value["classification"]);
  const confidence = clamp(Number(value["confidence"]));
  const rationale = asString(value["rationale"]).trim();
  if (!id || !role || !classification || !rationale) {
    return null;
  }

  const signature = value["signature"];
  if (!isRecord(signature)) {
    return null;
  }
  const callable = asString(signature["callable"]).trim();
  const flowKind = asFlowKind(signature["flow_kind"]);
  if (!callable || !flowKind) {
    return null;
  }

  const location = value["location"];
  if (!isRecord(location)) {
    return null;
  }
  const locationFile = asString(location["file"]).trim();
  const locationLine = Number(location["line"]);
  if (!locationFile || !Number.isFinite(locationLine) || locationLine < 1) {
    return null;
  }

  let evidence: string[] | undefined;
  if (value["evidence"] != null) {
    if (!Array.isArray(value["evidence"])) {
      return null;
    }
    evidence = value["evidence"].map((item) => String(item).trim()).filter(Boolean);
  }

  return {
    id,
    role,
    classification,
    confidence,
    signature: {
      package: asOptionalString(signature["package"]),
      module: asOptionalString(signature["module"]),
      type: asOptionalString(signature["type"]),
      callable,
      arg_index: asNullableIndex(signature["arg_index"]),
      flow_kind: flowKind,
    },
    location: {
      file: locationFile,
      line: Math.floor(locationLine),
    },
    rationale,
    evidence,
  };
}

async function writePassCheckpointV2(
  checkpointPath: string,
  passId: TaintAnalysisPassId,
  language: TaintAnalysisLanguage,
  candidateFingerprint: string,
  entries: TaintAnalysisPassEntry[],
): Promise<void> {
  const payload: LabelPassCheckpointV2 = {
    version: LABEL_CHECKPOINT_VERSION,
    parserVersion: LABEL_PARSER_VERSION,
    passId,
    language,
    candidateFingerprint,
    generatedAt: new Date().toISOString(),
    entries,
  };
  await writeFile(checkpointPath, JSON.stringify(payload, null, 2), "utf-8");
}

function canonicalizeCandidateForFingerprint(candidate: TaintAnalysisCandidate): string {
  return [
    normalizeFingerprintField(candidate.id),
    normalizeFingerprintField(candidate.candidateKind),
    normalizeFingerprintField(candidate.callable),
    normalizeFingerprintField(candidate.moduleHint),
    normalizeFingerprintField(candidate.receiverHint),
    normalizeFingerprintNumber(candidate.argIndex),
    normalizeFingerprintField(candidate.flowKind),
    normalizeFingerprintField(candidate.locationFile),
    normalizeFingerprintNumber(candidate.locationLine),
  ].join("|");
}

function canonicalizeEntryForFingerprint(entry: TaintAnalysisPassEntry): string {
  return [
    normalizeFingerprintField(entry.id),
    inferCandidateKindFromEntryId(entry.id),
    normalizeFingerprintField(entry.signature.callable),
    normalizeFingerprintField(entry.signature.module),
    normalizeFingerprintField(entry.signature.type),
    normalizeFingerprintNumber(entry.signature.arg_index),
    normalizeFingerprintField(entry.signature.flow_kind),
    normalizeFingerprintField(entry.location.file),
    normalizeFingerprintNumber(entry.location.line),
  ].join("|");
}

function computeCandidatesFingerprint(candidates: TaintAnalysisCandidate[]): string {
  const canonical = candidates
    .map(canonicalizeCandidateForFingerprint)
    .sort()
    .join("\n");
  return sha256Hex(canonical);
}

function computeEntriesFingerprint(entries: TaintAnalysisPassEntry[]): string {
  const canonical = entries
    .map(canonicalizeEntryForFingerprint)
    .sort()
    .join("\n");
  return sha256Hex(canonical);
}

function inferCandidateKindFromEntryId(entryId: string): string {
  const normalized = entryId.trim();
  if (normalized.startsWith("src-")) {
    return "source_candidate";
  }
  if (normalized.startsWith("sink-")) {
    return "sink_candidate";
  }
  return "<unknown>";
}

function normalizeFingerprintField(value: unknown): string {
  if (value == null) {
    return "<null>";
  }

  const trimmed = String(value).trim();
  return trimmed || "<null>";
}

function normalizeFingerprintNumber(value: unknown): string {
  if (typeof value !== "number" || !Number.isFinite(value)) {
    return "<null>";
  }

  return String(Math.floor(value));
}

function sha256Hex(value: string): string {
  return createHash("sha256").update(value).digest("hex");
}

async function loadCandidates(sourcesCsvPath: string, sinksCsvPath: string): Promise<TaintAnalysisCandidate[]> {
  const sources = await parseCsvCandidates(sourcesCsvPath, "source_candidate");
  const sinks = await parseCsvCandidates(sinksCsvPath, "sink_candidate");
  return [...sources, ...sinks];
}

function resolveSourceAvailability(
  preflight: TaintAnalysisPreflightOutput,
  candidates: TaintAnalysisCandidate[],
): {
  parsedSourceCount: number;
  noSourcesExtracted: boolean;
} {
  const parsedSourceCount = candidates
    .filter((candidate) => candidate.candidateKind === "source_candidate")
    .length;
  return {
    parsedSourceCount,
    noSourcesExtracted: preflight.extraction.sourcesRowCount <= 0 || parsedSourceCount <= 0,
  };
}

interface ExtractionCountSummary {
  expectedSources: number;
  expectedSinks: number;
  parsedSources: number;
  parsedSinks: number;
  expectedTotal: number;
  parsedTotal: number;
  sourceParsedRatio: number;
  sinkParsedRatio: number;
  parsedTotalRatio: number;
  unknownFlowCount: number;
  lineOneCount: number;
  unknownFlowRatio: number;
  lineOneRatio: number;
}

function summarizeExtractionCounts(
  preflight: TaintAnalysisPreflightOutput,
  candidates: TaintAnalysisCandidate[],
): ExtractionCountSummary {
  const expectedSources = Math.max(0, Math.floor(preflight.extraction.sourcesRowCount));
  const expectedSinks = Math.max(0, Math.floor(preflight.extraction.sinksRowCount));
  const parsedSources = candidates.filter((candidate) => candidate.candidateKind === "source_candidate").length;
  const parsedSinks = candidates.filter((candidate) => candidate.candidateKind === "sink_candidate").length;
  const expectedTotal = expectedSources + expectedSinks;
  const parsedTotal = parsedSources + parsedSinks;
  const unknownFlowCount = candidates.filter((candidate) => candidate.flowKind === "unknown").length;
  const lineOneCount = candidates.filter((candidate) => candidate.locationLine === 1).length;

  return {
    expectedSources,
    expectedSinks,
    parsedSources,
    parsedSinks,
    expectedTotal,
    parsedTotal,
    sourceParsedRatio: ratio(parsedSources, expectedSources),
    sinkParsedRatio: ratio(parsedSinks, expectedSinks),
    parsedTotalRatio: ratio(parsedTotal, expectedTotal),
    unknownFlowCount,
    lineOneCount,
    unknownFlowRatio: parsedTotal > 0 ? unknownFlowCount / parsedTotal : 0,
    lineOneRatio: parsedTotal > 0 ? lineOneCount / parsedTotal : 0,
  };
}

function assertExtractionCountConsistency(
  summary: ExtractionCountSummary,
  workspaceDir: string,
): void {
  const sourceMismatch = summary.parsedSources !== summary.expectedSources;
  const sinkMismatch = summary.parsedSinks !== summary.expectedSinks;
  if (!sourceMismatch && !sinkMismatch) {
    return;
  }

  throw new Error(
    [
      "[taint-analysis-label] Candidate parse mismatch with preflight extraction counts.",
      `sources expected=${summary.expectedSources} parsed=${summary.parsedSources}; sinks expected=${summary.expectedSinks} parsed=${summary.parsedSinks}.`,
      `This usually indicates malformed CSV records or stale extraction artifacts in ${workspaceDir}/extraction.`,
      "Remediation: delete the workspace extraction/labels artifacts and rerun taint-analysis preflight + label.",
    ].join(" "),
  );
}

function emitExtractionQualityDiagnostics(summary: ExtractionCountSummary): void {
  process.stderr.write(
    `[taint-analysis-label] Extraction quality: parsed_ratio=${summary.parsedTotalRatio.toFixed(3)} source_ratio=${summary.sourceParsedRatio.toFixed(3)} sink_ratio=${summary.sinkParsedRatio.toFixed(3)} unknown_flow_ratio=${summary.unknownFlowRatio.toFixed(3)} line_one_ratio=${summary.lineOneRatio.toFixed(3)}\n`,
  );

  if (summary.unknownFlowRatio >= 0.9) {
    process.stderr.write(
      `[taint-analysis-label] Warning: ${summary.unknownFlowCount}/${summary.parsedTotal} candidates have flow_kind=unknown; extraction metadata may be degraded\n`,
    );
  }

  if (summary.lineOneRatio >= 0.9) {
    process.stderr.write(
      `[taint-analysis-label] Warning: ${summary.lineOneCount}/${summary.parsedTotal} candidates resolve to line=1; extraction metadata may be degraded\n`,
    );
  }
}

function assertExtractionQualityThresholds(summary: ExtractionCountSummary, workspaceDir: string): void {
  const minSampleSize = 50;
  if (summary.parsedTotal < minSampleSize) {
    return;
  }

  const hardFailRatio = 0.97;
  if (summary.unknownFlowRatio >= hardFailRatio || summary.lineOneRatio >= hardFailRatio) {
    throw new Error(
      [
        "[taint-analysis-label] Extraction metadata collapsed (hard quality gate).",
        `unknown_flow_ratio=${summary.unknownFlowRatio.toFixed(3)} line_one_ratio=${summary.lineOneRatio.toFixed(3)} parsed_total=${summary.parsedTotal}.`,
        `Artifacts under ${workspaceDir}/extraction are not trustworthy for labeling.`,
        "Remediation: regenerate extraction outputs and verify the extraction query preserves flow_kind/line metadata.",
      ].join(" "),
    );
  }
}

function ratio(numerator: number, denominator: number): number {
  if (denominator <= 0) {
    return numerator <= 0 ? 1 : 0;
  }
  return numerator / denominator;
}

async function parseCsvCandidates(
  csvPath: string,
  fallbackKind: TaintAnalysisCandidate["candidateKind"],
): Promise<TaintAnalysisCandidate[]> {
  const csvContent = await readFile(csvPath, "utf-8");
  const records = parseCsvRecords(csvContent);

  const out: TaintAnalysisCandidate[] = [];
  let counter = 0;

  for (const cols of records) {
    if (cols.length < 2 || isCsvRecordBlank(cols)) {
      continue;
    }

    const marker = normalizeCandidateMarker(cols[1]);
    if (!marker) {
      continue;
    }

    counter += 1;

    const candidateKind = marker ?? fallbackKind;

    const callable = sanitizeString(cols[2]) || "unknown";
    const flowKind = parseFlowKind(cols[3]);
    const receiverHint = parseKeyValue(cols[4], "receiver");
    const moduleHint = parseKeyValue(cols[5], "module");
    const argIndex = parseArgIndex(cols[6]);
    const locationLine = parseLine(cols[7]);
    const locationFile = moduleHint || "unknown";
    const snippet = sanitizeString(cols[0]);

    out.push({
      id: `${candidateKind === "source_candidate" ? "src" : "sink"}-${counter}`,
      candidateKind,
      callable,
      flowKind,
      receiverHint,
      moduleHint,
      argIndex,
      locationFile,
      locationLine,
      snippet: snippet || undefined,
    });
  }

  return out;
}

export function buildTaintModelDocument(
  labels: TaintAnalysisLabelsDocument,
  tiPrior: TiPriorDocument | null,
): TaintModelDocument {
  const cwes: TaintModelCwe[] = [];

  for (const pass of labels.passes) {
    const tiForPass = (tiPrior?.cwes ?? []).filter((entry) => pass.cwes.some((cwe) => normalizeCweId(cwe) === normalizeCweId(entry.cwe)));
    const tiBasisText = tiForPass.length > 0
      ? tiForPass.map((entry) => `${entry.cwe} weight=${entry.tiWeight} refs=${entry.references.length}`).join("; ")
      : "No live TI references available for this pass";
    const tiWeight = tiForPass.some((entry) => entry.tiWeight === "HIGH")
      ? "HIGH"
      : tiForPass.some((entry) => entry.tiWeight === "MEDIUM")
        ? "MEDIUM"
        : "LOW";
    const confidenceBoost = tiWeight === "HIGH" ? 0.1 : tiWeight === "MEDIUM" ? 0.05 : 0;

    const sources = pass.entries
      .filter((entry) => entry.role === "source" && entry.classification !== "fp")
      .map((entry) => ({
        pattern_intent: describeEntryIntent(entry),
        confidence: clampConfidence(entry.confidence + confidenceBoost),
        ti_basis: tiBasisText,
        examples: [`${entry.location.file}:${entry.location.line}`],
      }));

    const sinks = pass.entries
      .filter((entry) => entry.role === "sink" && entry.classification !== "fp")
      .map((entry) => ({
        pattern_intent: describeEntryIntent(entry),
        sink_focus: describeSinkFocus(entry),
        confidence: clampConfidence(entry.confidence + confidenceBoost),
        ti_basis: tiBasisText,
        examples: [`${entry.location.file}:${entry.location.line}`],
      }));

    const sanitizers = pass.entries
      .filter((entry) => entry.role === "sanitizer" && entry.classification !== "fp")
      .map((entry) => ({
        pattern_intent: describeEntryIntent(entry),
        confidence: clampConfidence(entry.confidence + confidenceBoost),
        ti_basis: tiBasisText,
        examples: [`${entry.location.file}:${entry.location.line}`],
      }));

    const propagators = pass.entries
      .filter((entry) => entry.role === "summary" && entry.classification !== "fp")
      .map((entry) => ({
        pattern_intent: describeEntryIntent(entry),
        confidence: clampConfidence(entry.confidence + confidenceBoost),
        ti_basis: tiBasisText,
        examples: [`${entry.location.file}:${entry.location.line}`],
      }));

    for (const cwe of pass.cwes) {
      cwes.push({
        cwe: normalizeCweId(cwe),
        sources,
        sinks,
        sanitizers,
        propagators,
        notes: [
          `Generated from pass ${pass.pass_id} (${pass.focus}).`,
          tiPrior?.degraded
            ? "TI prior degraded; live threat-intel sources were partially unavailable."
            : "TI prior sourced from live KEV/NVD lookups.",
        ],
      });
    }
  }

  return {
    version: "1.0.0",
    generatedAt: new Date().toISOString(),
    language: labels.metadata.language,
    framework: labels.metadata.framework,
    cwes,
  };
}

function describeEntryIntent(entry: TaintAnalysisPassEntry): string {
  const callable = entry.signature.callable || "unknown";
  const flow = entry.signature.flow_kind || "unknown";
  if (entry.role === "source") {
    return `Treat ${callable} (${flow}) as a taint source boundary.`;
  }
  if (entry.role === "sink") {
    return `Treat ${callable} (${flow}) as a dangerous sink for pass-specific flows.`;
  }
  if (entry.role === "sanitizer") {
    return `Treat ${callable} (${flow}) as a barrier/sanitizer candidate.`;
  }
  return `Treat ${callable} (${flow}) as a propagator/summary edge.`;
}

function describeSinkFocus(entry: TaintAnalysisPassEntry): string {
  if (entry.signature.arg_index != null) {
    return `argument[${entry.signature.arg_index}]`;
  }
  return entry.signature.flow_kind || "unknown";
}

function normalizeCweId(value: string): string {
  const digits = value.replace(/[^0-9]/g, "");
  const numeric = Number.parseInt(digits, 10);
  if (!Number.isFinite(numeric)) {
    return "CWE-000";
  }
  return `CWE-${numeric}`;
}

function clampConfidence(value: number): number {
  if (!Number.isFinite(value)) {
    return 0;
  }
  return Math.max(0, Math.min(1, value));
}

function summarizeLabels(
  labels: TaintAnalysisLabelsDocument,
  confidenceThreshold: number,
): { labelCounts: Record<string, number>; reviewSummary: string } {
  const counts: Record<string, number> = {};
  const sourceFrequency = new Map<string, number>();
  const sinkFrequency = new Map<string, number>();
  let lowConfidence = 0;

  for (const pass of labels.passes) {
    for (const entry of pass.entries) {
      const key = `pass${pass.pass_id}.${entry.role}`;
      counts[key] = (counts[key] ?? 0) + 1;

      if (entry.confidence < confidenceThreshold) {
        lowConfidence += 1;
      }

      if (entry.role === "source") {
        sourceFrequency.set(entry.signature.callable, (sourceFrequency.get(entry.signature.callable) ?? 0) + 1);
      }

      if (entry.role === "sink") {
        sinkFrequency.set(entry.signature.callable, (sinkFrequency.get(entry.signature.callable) ?? 0) + 1);
      }
    }
  }

  const byPassLines = labels.passes.map((pass) => {
    const passCounts = ["source", "sink", "sanitizer", "summary", "none"]
      .map((role) => `${role}:${counts[`pass${pass.pass_id}.${role}`] ?? 0}`)
      .join(" ");
    return `- pass ${pass.pass_id} (${pass.focus}): ${passCounts}`;
  });

  const topSources = topItems(sourceFrequency, 5)
    .map(([name, count]) => `${name}(${count})`)
    .join(", ") || "none";
  const topSinks = topItems(sinkFrequency, 5)
    .map(([name, count]) => `${name}(${count})`)
    .join(", ") || "none";

  const reviewSummary = [
    "> **Advisory only** — this report is for human review. No pipeline stage gates on approval.",
    "",
    "# Taint Analysis checkpoint summary",
    "",
    "## Label counts by pass/role",
    ...byPassLines,
    "",
    `- top sinks: ${topSinks}`,
    `- top sources: ${topSources}`,
    `- low-confidence entries (<${confidenceThreshold.toFixed(2)}): ${lowConfidence}`,
  ].join("\n");

  return {
    labelCounts: counts,
    reviewSummary,
  };
}

function topItems(map: Map<string, number>, maxItems: number): Array<[string, number]> {
  return [...map.entries()]
    .sort((a, b) => b[1] - a[1])
    .slice(0, maxItems);
}

function validateLabelsDocument(labels: TaintAnalysisLabelsDocument): string | null {
  if (!labels.version || !/^v?[0-9]+\.[0-9]+(\.[0-9]+)?$/.test(labels.version)) {
    return "version must match semantic format (for example 1.0.0)";
  }

  if (!labels.metadata.run_id || !labels.metadata.project || !labels.metadata.model) {
    return "metadata.run_id, metadata.project, and metadata.model are required";
  }

  if (!Array.isArray(labels.passes) || labels.passes.length === 0) {
    return "passes must include at least one pass";
  }

  for (const pass of labels.passes) {
    if (!Number.isInteger(pass.pass_id) || pass.pass_id < 1 || pass.pass_id > 13) {
      return `invalid pass_id: ${String(pass.pass_id)}`;
    }

    if (!Array.isArray(pass.entries)) {
      return `pass ${pass.pass_id} entries must be an array`;
    }

    for (const entry of pass.entries) {
      if (!entry.id || !entry.signature.callable || !entry.location.file || entry.location.line < 1) {
        return `invalid entry in pass ${pass.pass_id}: missing id/signature/location`;
      }

      if (entry.confidence < 0 || entry.confidence > 1) {
        return `invalid confidence in pass ${pass.pass_id} for entry ${entry.id}`;
      }
    }
  }

  return null;
}

function asPreflightOutput(value: unknown): TaintAnalysisPreflightOutput | null {
  if (!isRecord(value) || !isRecord(value["extraction"])) {
    return null;
  }

  const extraction = value["extraction"];

  const output: TaintAnalysisPreflightOutput = {
    taintAnalysisPath: asString(value["taintAnalysisPath"]),
    workspaceDir: asString(value["workspaceDir"]),
    dbPath: asString(value["dbPath"]),
    codeqlBinary: asString(value["codeqlBinary"]),
    codeqlVersion: asString(value["codeqlVersion"]),
    codeqlApiProfileId: asString(value["codeqlApiProfileId"]),
    language: asString(value["language"]) as TaintAnalysisPreflightOutput["language"],
    framework: asOptionalString(value["framework"]),
    referenceFiles: asStringArray(value["referenceFiles"]),
    passes: asPassArray(value["passes"]),
    tiPriorMarkdownPath: asString(value["tiPriorMarkdownPath"]),
    tiPriorJsonPath: asString(value["tiPriorJsonPath"]),
    tiPriorDegraded: asBoolean(value["tiPriorDegraded"]),
    extraction: {
      sourcesQueryPath: asString(extraction["sourcesQueryPath"]),
      sinksQueryPath: asString(extraction["sinksQueryPath"]),
      sourcesCsvPath: asString(extraction["sourcesCsvPath"]),
      sinksCsvPath: asString(extraction["sinksCsvPath"]),
      sourcesRowCount: asNumber(extraction["sourcesRowCount"]),
      sinksRowCount: asNumber(extraction["sinksRowCount"]),
    },
    extractionDegradation: asExtractionDegradation(value["extractionDegradation"]),
  };

  if (
    !output.taintAnalysisPath
    || !output.workspaceDir
    || !output.dbPath
    || !output.codeqlBinary
    || !output.codeqlVersion
    || !output.codeqlApiProfileId
    || !output.language
    || !output.tiPriorMarkdownPath
    || !output.tiPriorJsonPath
    || !output.extraction.sourcesCsvPath
    || !output.extraction.sinksCsvPath
  ) {
    return null;
  }

  return output;
}

function extractJson(value: string): string {
  const fenced = value.match(/```(?:json)?\s*\n?([\s\S]*?)\n?```/);
  if (fenced) {
    return fenced[1].trim();
  }

  const first = value.indexOf("{");
  const last = value.lastIndexOf("}");
  if (first >= 0 && last > first) {
    return value.slice(first, last + 1);
  }

  return value;
}

function parseFlowKind(value: string | undefined): TaintAnalysisCandidate["flowKind"] {
  const normalized = parseKeyValue(value, "flow_kind")?.toLowerCase() ?? "unknown";
  const canonical = normalized === "arg"
    ? "argument"
    : normalized === "parameter"
      ? "param"
      : normalized === "result" || normalized === "ret"
        ? "return"
        : normalized;
  if (
    canonical === "param"
    || canonical === "argument"
    || canonical === "return"
    || canonical === "receiver"
    || canonical === "field"
  ) {
    return canonical;
  }

  return "unknown";
}

function asFlowKind(value: unknown): TaintAnalysisCandidate["flowKind"] | null {
  const normalized = String(value ?? "").trim().toLowerCase();
  const canonical = normalized === "arg"
    ? "argument"
    : normalized === "parameter"
      ? "param"
      : normalized === "result" || normalized === "ret"
        ? "return"
        : normalized;
  if (
    canonical === "param"
    || canonical === "argument"
    || canonical === "return"
    || canonical === "receiver"
    || canonical === "field"
    || canonical === "unknown"
  ) {
    return canonical;
  }

  return null;
}

function parseArgIndex(value: string | undefined): number | null {
  const raw = parseKeyValue(value, "arg_index") ?? "";
  const numeric = Number(raw);
  if (!Number.isFinite(numeric) || numeric < 0) {
    return null;
  }

  return Math.floor(numeric);
}

function asNullableIndex(value: unknown): number | null {
  if (value == null || value === "") {
    return null;
  }

  const numeric = Number(value);
  if (!Number.isFinite(numeric) || numeric < 0) {
    return null;
  }

  return Math.floor(numeric);
}

function parseLine(value: string | undefined): number {
  const raw = parseKeyValue(value, "line") ?? value ?? "";
  const numeric = Number(raw);
  if (!Number.isFinite(numeric) || numeric < 1) {
    return 1;
  }

  return Math.floor(numeric);
}

function parseKeyValue(value: string | undefined, prefix: string): string | undefined {
  if (!value) {
    return undefined;
  }

  const trimmed = value.trim();
  if (trimmed.startsWith(`${prefix}=`)) {
    return trimmed.slice(prefix.length + 1).trim() || undefined;
  }

  return trimmed || undefined;
}

function sanitizeString(value: string | undefined): string {
  return (value ?? "").trim();
}

function asRole(value: unknown): LabelResponseEntry["role"] | null {
  const normalized = String(value ?? "").trim();
  if (
    normalized === "source"
    || normalized === "sink"
    || normalized === "sanitizer"
    || normalized === "summary"
    || normalized === "none"
  ) {
    return normalized;
  }

  return null;
}

function asClassification(value: unknown): LabelResponseEntry["classification"] | null {
  const normalized = String(value ?? "").trim();
  if (normalized === "tp" || normalized === "fp" || normalized === "candidate" || normalized === "unknown") {
    return normalized;
  }

  return null;
}

function asString(value: unknown): string {
  return typeof value === "string" ? value : "";
}

function asOptionalString(value: unknown): string | null {
  if (value == null) {
    return null;
  }

  if (typeof value === "string") {
    const trimmed = value.trim();
    return trimmed || null;
  }

  return null;
}

function asStringArray(value: unknown): string[] {
  if (!Array.isArray(value)) {
    return [];
  }

  return value
    .map((item) => String(item).trim())
    .filter(Boolean);
}

function asPassArray(value: unknown): TaintAnalysisPassId[] {
  if (!Array.isArray(value)) {
    return [];
  }

  const out: TaintAnalysisPassId[] = [];
  for (const item of value) {
    const numeric = Number(item);
    if (numeric >= 1 && numeric <= 13) {
      out.push(Math.floor(numeric) as TaintAnalysisPassId);
    }
  }

  return out;
}

function asNumber(value: unknown): number {
  const numeric = Number(value);
  if (!Number.isFinite(numeric)) {
    return 0;
  }

  return numeric;
}

function asBoolean(value: unknown): boolean {
  return value === true;
}

function asExtractionDegradation(value: unknown): ExtractionDegradation {
  if (isRecord(value) && typeof value["status"] === "string" && Array.isArray(value["reasons"])) {
    const status = value["status"];
    if (status === "ok" || status === "degraded" || status === "failed") {
      return { status, reasons: value["reasons"].filter((r): r is string => typeof r === "string") as ExtractionDegradation["reasons"] };
    }
  }
  return { status: "ok", reasons: [] };
}

function trimTo(value: string, maxLength: number): string {
  if (value.length <= maxLength) {
    return value;
  }

  return `${value.slice(0, maxLength)}\n\n[truncated]`;
}

function clamp(value: number): number {
  if (!Number.isFinite(value)) {
    return 0;
  }

  return Math.max(0, Math.min(1, value));
}

/**
 * Build a signature key from candidate properties that identify equivalent
 * callables. All instances sharing the same key will receive the same label.
 *
 * Keyed by (candidateKind, callable) only — the callable name determines
 * whether something is a source/sink/sanitizer regardless of which module
 * or receiver it appears in. This aggressive dedup reduces 51K instances
 * to ~120 unique callables.
 */
function candidateSignatureKey(c: TaintAnalysisCandidate): string {
  return `${c.candidateKind}\0${c.callable}`;
}

/**
 * Group candidates by signature and pick one representative per group.
 * Returns the representative list (for labeling) and a map from signature
 * key -> representative candidate ID (for propagation).
 */
function deduplicateBySig(candidates: TaintAnalysisCandidate[]): {
  representatives: TaintAnalysisCandidate[];
  signatureMap: Map<string, string>;
} {
  const seen = new Map<string, TaintAnalysisCandidate>();
  const signatureMap = new Map<string, string>();

  for (const candidate of candidates) {
    const key = candidateSignatureKey(candidate);
    if (!seen.has(key)) {
      seen.set(key, candidate);
    }
    // Map every instance's signature to its representative's ID
    signatureMap.set(key, seen.get(key)!.id);
  }

  return {
    representatives: [...seen.values()],
    signatureMap,
  };
}

function chunk<T>(values: T[], size: number): T[][] {
  const out: T[][] = [];
  const normalizedSize = Math.max(1, Math.floor(size));

  for (let idx = 0; idx < values.length; idx += normalizedSize) {
    out.push(values.slice(idx, idx + normalizedSize));
  }

  return out;
}

export const __taintAnalysisLabelInternals = {
  LABEL_CHECKPOINT_VERSION,
  LABEL_PARSER_VERSION,
  buildLabelPrompt,
  applySinkDenyList,
  loadPassCheckpoint,
  writePassCheckpointV2,
  canonicalizeCandidateForFingerprint,
  canonicalizeEntryForFingerprint,
  computeCandidatesFingerprint,
  computeEntriesFingerprint,
  resolveSourceAvailability,
  parseCsvCandidates,
  countCandidateCsvRecords,
  summarizeLabels,
  validateLabelsDocument,
  buildTaintModelDocument,
};
