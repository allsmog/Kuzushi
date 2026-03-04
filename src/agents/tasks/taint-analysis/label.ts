import { existsSync, readFileSync } from "node:fs";
import { readFile, writeFile } from "node:fs/promises";
import path from "node:path";
import { getAgentRuntime } from "../../../agent-runtime/index.js";
import type { AgentRuntime } from "../../../agent-runtime/types.js";
import { withRetry } from "../../../retry.js";
import type { ScanOpts } from "../../../types.js";
import { isRecord, toErrorMessage } from "../../../utils.js";
import type { AgentTask } from "../../types.js";
import {
  TAINT_ANALYSIS_PASSES,
  resolveTaintAnalysisConfig,
  type TaintAnalysisCandidate,
  type TaintAnalysisLabelOutput,
  type TaintAnalysisLabelsDocument,
  type TaintAnalysisPassDefinition,
  type TaintAnalysisPassEntry,
  type TaintAnalysisPassId,
  type TaintAnalysisPreflightOutput,
} from "./types.js";
import type { TiPriorCwe, TiPriorDocument } from "./ti-prior.js";

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
      : getAgentRuntime();

    const labelsByPass = new Map<number, TaintAnalysisPassEntry[]>();
    if (noSourcesExtracted) {
      for (const passId of preflight.passes) {
        labelsByPass.set(passId, []);
        await writeFile(
          path.join(preflight.workspaceDir, "labels", `labels_raw_pass${passId}.json`),
          "[]",
          "utf-8",
        );
      }
    } else {
      for (const passId of preflight.passes) {
        const passDef = TAINT_ANALYSIS_PASSES.find((pass) => pass.passId === passId);
        if (!passDef || !runtime) {
          continue;
        }

        const checkpointPath = path.join(preflight.workspaceDir, "labels", `labels_raw_pass${passId}.json`);
        const cached = loadPassCheckpoint(checkpointPath, allCandidates.length);
        if (cached) {
          process.stderr.write(`[taint-analysis-label] Pass ${passId} (${passDef.focus}): loaded ${cached.length} entries from checkpoint\n`);
          labelsByPass.set(passId, cached);
          continue;
        }

        process.stderr.write(`[taint-analysis-label] Labeling pass ${passId} (${passDef.focus})...\n`);
        const passEntries = await labelPass(
          runtime,
          passDef,
          allCandidates,
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

        labelsByPass.set(passId, passEntries);
        process.stderr.write(`[taint-analysis-label] Pass ${passId} complete: ${passEntries.length} entries labeled\n`);

        await writeFile(
          checkpointPath,
          JSON.stringify(passEntries, null, 2),
          "utf-8",
        );
      }
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

    return {
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
      labelsPath,
      labels,
      taintModelPath,
      reviewSummary,
      labelCounts,
    };
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
): Promise<TaintAnalysisPassEntry[]> {
  const byCandidateId = new Map<string, LabelResponseEntry>();
  const batches = chunk(candidates, cfg.labelingBatchSize);
  process.stderr.write(`[taint-analysis-label]   ${batches.length} batch(es) of up to ${cfg.labelingBatchSize} candidates\n`);

  for (let batchIdx = 0; batchIdx < batches.length; batchIdx++) {
    const batch = batches[batchIdx];
    process.stderr.write(`[taint-analysis-label]   Batch ${batchIdx + 1}/${batches.length}: querying LLM with ${batch.length} candidates...\n`);
    const prompt = buildLabelPrompt(passDef, batch, references, tiPrior, language, framework, false);
    const initial = await withRetry(
      () => queryLabelBatch(runtime, prompt, repoRoot, cfg.labelingModel),
      { maxRetries: 3, backoffMs: 5_000, multiplier: 2 },
    );

    process.stderr.write(`[taint-analysis-label]   Batch ${batchIdx + 1}/${batches.length}: LLM returned ${initial.entries.length} entries\n`);
    for (const entry of initial.entries) {
      byCandidateId.set(entry.id, entry);
    }

    const lowConfidenceIds = initial.entries
      .filter((entry) => entry.confidence < cfg.labelingConfidenceThreshold)
      .map((entry) => entry.id);

    if (lowConfidenceIds.length > 0) {
      process.stderr.write(`[taint-analysis-label]   Batch ${batchIdx + 1}/${batches.length}: retrying ${lowConfidenceIds.length} low-confidence entries...\n`);
      const lowConfidenceCandidates = batch.filter((candidate) => lowConfidenceIds.includes(candidate.id));
      const retryPrompt = buildLabelPrompt(passDef, lowConfidenceCandidates, references, tiPrior, language, framework, true);
      const retry = await withRetry(
        () => queryLabelBatch(runtime, retryPrompt, repoRoot, cfg.labelingModel),
        { maxRetries: 3, backoffMs: 5_000, multiplier: 2 },
      );
      for (const entry of retry.entries) {
        byCandidateId.set(entry.id, entry);
      }
    }
  }

  return candidates.map((candidate) => {
    const entry = byCandidateId.get(candidate.id);
    return normalizePassEntry(candidate, entry);
  });
}

async function queryLabelBatch(
  runtime: AgentRuntime,
  prompt: string,
  repoRoot: string,
  model: string,
): Promise<LabelResponse> {
  let rawResult: unknown;
  let rawText = "";
  let resultError: string | null = null;
  let resultErrorSubtype: string | null = null;

  for await (const message of runtime.query({
    prompt,
    options: {
      cwd: repoRoot,
      model,
      maxTurns: undefined,
      allowedTools: [],
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
  return parsed;
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

  return { entries: [] };
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

function loadPassCheckpoint(
  checkpointPath: string,
  expectedCount: number,
): TaintAnalysisPassEntry[] | null {
  if (!existsSync(checkpointPath)) {
    return null;
  }

  try {
    const raw = readFileSync(checkpointPath, "utf-8");
    const parsed: unknown = JSON.parse(raw);
    if (!Array.isArray(parsed) || parsed.length !== expectedCount) {
      return null;
    }

    // Quick structural check on the first entry.
    const first = parsed[0];
    if (!isRecord(first) || typeof first["id"] !== "string" || !isRecord(first["signature"])) {
      return null;
    }

    return parsed as TaintAnalysisPassEntry[];
  } catch {
    return null;
  }
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

async function parseCsvCandidates(
  csvPath: string,
  fallbackKind: TaintAnalysisCandidate["candidateKind"],
): Promise<TaintAnalysisCandidate[]> {
  const csvContent = await readFile(csvPath, "utf-8");
  const lines = csvContent
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter(Boolean);

  const out: TaintAnalysisCandidate[] = [];
  let counter = 0;

  for (const line of lines) {
    const cols = parseCsvLine(line);
    if (cols.length < 2) {
      continue;
    }

    const marker = cols[1]?.toLowerCase();
    if (marker !== "source_candidate" && marker !== "sink_candidate") {
      continue;
    }

    counter += 1;

    const candidateKind = marker === "source_candidate" || marker === "sink_candidate"
      ? marker
      : fallbackKind;

    const callable = sanitizeString(cols[2]) || "unknown";
    const flowKind = parseFlowKind(cols[3]);
    const receiverHint = parseKeyValue(cols[4], "receiver");
    const moduleHint = parseKeyValue(cols[5], "module");
    const argIndex = parseArgIndex(cols[6]);
    const locationLine = parseLine(cols[7]);
    const locationFile = moduleHint || "unknown";

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

function parseCsvLine(line: string): string[] {
  const out: string[] = [];
  let current = "";
  let inQuotes = false;

  for (let idx = 0; idx < line.length; idx += 1) {
    const char = line[idx];

    if (char === '"') {
      const next = line[idx + 1];
      if (inQuotes && next === '"') {
        current += '"';
        idx += 1;
        continue;
      }

      inQuotes = !inQuotes;
      continue;
    }

    if (char === "," && !inQuotes) {
      out.push(current);
      current = "";
      continue;
    }

    current += char;
  }

  out.push(current);
  return out;
}

function parseFlowKind(value: string | undefined): TaintAnalysisCandidate["flowKind"] {
  const normalized = parseKeyValue(value, "flow_kind")?.toLowerCase() ?? "unknown";
  if (
    normalized === "param"
    || normalized === "argument"
    || normalized === "return"
    || normalized === "receiver"
    || normalized === "field"
  ) {
    return normalized;
  }

  return "unknown";
}

function parseArgIndex(value: string | undefined): number | null {
  const raw = parseKeyValue(value, "arg_index") ?? "";
  const numeric = Number(raw);
  if (!Number.isFinite(numeric) || numeric < 0) {
    return null;
  }

  return Math.floor(numeric);
}

function parseLine(value: string | undefined): number {
  const numeric = Number(value);
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

function chunk<T>(values: T[], size: number): T[][] {
  const out: T[][] = [];
  const normalizedSize = Math.max(1, Math.floor(size));

  for (let idx = 0; idx < values.length; idx += normalizedSize) {
    out.push(values.slice(idx, idx + normalizedSize));
  }

  return out;
}

export const __taintAnalysisLabelInternals = {
  buildLabelPrompt,
  resolveSourceAvailability,
  parseCsvCandidates,
  summarizeLabels,
  validateLabelsDocument,
  buildTaintModelDocument,
};
