import { type ExecFileException, execFile } from "node:child_process";
import { existsSync } from "node:fs";
import { mkdir, readdir, readFile, rm, writeFile } from "node:fs/promises";
import path from "node:path";
import { promisify } from "node:util";
import {
  resolveDefaultReadOnlyTools,
  runStructuredAgentQuery,
} from "../../../agent-runtime/execution.js";
import type { AgentRuntime } from "../../../agent-runtime/types.js";
import { createSimpleTextIndexProvider } from "../../../analysis-support/index.js";
import { getLogger } from "../../../logger.js";
import { coerceRepoContext } from "../../../repo-context.js";
import { resolveCodeQLBinary } from "../../../scanners/resolve-codeql.js";
import { ensureDatabase, withCodeQLDatabase } from "../../../scanners/run-codeql.js";
import { attachTaskOutputMeta } from "../../../task-output-meta.js";
import type { ScanOpts } from "../../../types.js";
import { isRecord, toErrorMessage } from "../../../utils.js";
import type { AgentTask } from "../../types.js";
import {
  CodeqlProfileDetectionError,
  detectWorkingProfile,
  resolveCodeqlVersion,
} from "./codeql-compat.js";
import {
  countCandidateCsvRecords,
  isCsvRecordBlank,
  normalizeCandidateMarker,
  parseCsvRecords,
  toCsvRow,
} from "./csv.js";
import { generateExtractionQuery, hasBodyPlaceholders } from "./extraction-agent.js";
import { groundCallableTargets } from "./grounding.js";
import { buildTiPriorArtifacts } from "./ti-prior.js";
import {
  DEFAULT_TAINT_ANALYSIS_TASK_CONFIG,
  type DiffScope,
  type ExtractionDegradation,
  type ExtractionDegradationReason,
  mapFrameworkToReference,
  normalizeTaintAnalysisLanguage,
  resolveContextAwarePasses,
  resolveTaintAnalysisConfig,
  TAINT_ANALYSIS_PASSES,
  type TaintAnalysisLanguage,
  type TaintAnalysisPassId,
  type TaintAnalysisPreflightOutput,
  type TaintAnalysisTaskConfig,
} from "./types.js";

interface ExtractionAgentContext {
  referenceFiles: string[];
  taintAnalysisPath: string;
  model: string;
  runtime: AgentRuntime;
  repoRoot: string;
  workspaceDir: string;
  codeqlBinary: string;
  dbPath: string;
  codeqlApiProfileId: string;
  dataFlowImport: string;
  taintTrackingImport: string;
}

const execFileAsync = promisify(execFile);

const REQUIRED_TAINT_ANALYSIS_PATHS = ["WORKFLOW.md", "references", "assets", "scripts"];

const WORKSPACE_SUBDIRS = [
  "exploration",
  "extraction",
  "labels",
  "libraries",
  "queries",
  "results",
  "report",
];
const log = getLogger("taint-analysis-preflight");

interface FrameworkCandidate {
  id: string;
  score: number;
  evidence: string[];
}

interface ExtractionCompileAttempt {
  attempted: boolean;
  generatedQuery: boolean;
  compileOk: boolean | null;
  compileErrorExcerpt: string | null;
}

interface ExtractionQueryDiagnostic {
  kind: "source" | "sink";
  language: TaintAnalysisLanguage;
  templatePath: string;
  templateExists: boolean;
  templateHadBodyPlaceholders: boolean;
  selectedQuerySource: "deterministic-template" | "agent-initial" | "agent-retry" | "unavailable";
  fallbackUsed: boolean;
  fallbackReason: string | null;
  fallbackDetail: string | null;
  initialAttempt: ExtractionCompileAttempt;
  retryAttempt: ExtractionCompileAttempt;
}

interface ExtractionDiagnosticsDocument {
  generatedAt: string;
  language: TaintAnalysisLanguage;
  counts: {
    sources: number;
    sinks: number;
    sourcesDecodedRows?: number;
    sinksDecodedRows?: number;
    agenticSupplementSources?: number;
    agenticSupplementSinks?: number;
  };
  diagnostics: ExtractionQueryDiagnostic[];
}

interface RenderExtractionTemplateResult {
  query: string | null;
  diagnostic: ExtractionQueryDiagnostic;
  costUsd: number;
}

interface ExtractionSupplementCandidate {
  candidateKind: "source_candidate" | "sink_candidate";
  callable: string;
  flowKind: "param" | "arg" | "return" | "receiver" | "field" | "unknown";
  receiverHint: string;
  argIndex: number | null;
  rationale: string;
}

const EXTRACTION_SUPPLEMENT_SCHEMA = {
  type: "object",
  additionalProperties: false,
  required: ["candidates"],
  properties: {
    candidates: {
      type: "array",
      items: {
        type: "object",
        additionalProperties: false,
        required: [
          "candidateKind",
          "callable",
          "flowKind",
          "receiverHint",
          "argIndex",
          "rationale",
        ],
        properties: {
          candidateKind: { type: "string", enum: ["source_candidate", "sink_candidate"] },
          callable: { type: "string" },
          flowKind: {
            type: "string",
            enum: ["param", "arg", "return", "receiver", "field", "unknown"],
          },
          receiverHint: { type: "string" },
          argIndex: { type: ["integer", "null"] },
          rationale: { type: "string" },
        },
      },
    },
  },
} as const;

interface DiscoverExtractionSupplementsArgs {
  language: TaintAnalysisLanguage;
  framework: string | null;
  repoRoot: string;
  model: string;
  runtime: AgentRuntime;
  sourcesRowCount: number;
  sinksRowCount: number;
}

async function discoverExtractionSupplements(
  args: DiscoverExtractionSupplementsArgs,
): Promise<{ candidates: ExtractionSupplementCandidate[]; costUsd: number }> {
  const { language, framework, repoRoot, model, runtime, sourcesRowCount, sinksRowCount } = args;

  const coverageNote =
    sourcesRowCount < 5 || sinksRowCount < 5
      ? `\n\nNOTE: The main extraction found very few results (${sourcesRowCount} sources, ${sinksRowCount} sinks). ` +
        `This means CodeQL's type resolution may be incomplete — extra discovery is especially important.`
      : `\n\nThe main extraction found ${sourcesRowCount} sources and ${sinksRowCount} sinks.`;

  const prompt = `You are a security-focused code analysis agent. Your job is to identify additional **taint sources** and **taint sinks** in this ${language} codebase${framework ? ` (${framework} framework)` : ""} that automated CodeQL extraction may have missed.
${coverageNote}

## What to look for

**Sources** (entry points where attacker-controlled data enters):
- HTTP handler parameters, request body/query/header readers
- gRPC handler parameters, proto message field reads
- Environment variable reads (os.Getenv, os.LookupEnv, etc.)
- Message queue consumers, event handler parameters
- File/stdin readers in CLI tools
- Database reads that serve as secondary sources

**Sinks** (dangerous operations where tainted data should not reach):
- SQL execution: raw query builders, exec/query methods
- Command execution: os/exec, subprocess calls
- File writes: open/create with user-controlled paths
- Template rendering with user data
- Network requests with user-controlled URLs (SSRF)
- Deserialization of untrusted data

## Instructions

1. Use Grep and Glob to explore the codebase and find functions matching the patterns above
2. Focus on framework-specific patterns and project-specific wrappers
3. For each candidate, determine the flow kind and argument semantics
4. Return your findings as structured JSON

For each candidate provide:
- candidateKind: "source_candidate" or "sink_candidate"
- callable: the function/method name
- flowKind: how data flows ("param", "arg", "return", "receiver", "field", "unknown")
- receiverHint: the package/module/type qualifier
- argIndex: the specific argument index (null if not applicable)
- rationale: brief explanation of why this is a source/sink`;

  const result = await runStructuredAgentQuery({
    prompt,
    cwd: repoRoot,
    model,
    allowedTools: resolveDefaultReadOnlyTools(runtime),
    runtimeOptions: { runtime },
    schema: EXTRACTION_SUPPLEMENT_SCHEMA as Record<string, unknown>,
    strict: true,
    retryInvalidStructuredOutput: 2,
  });

  if (result.executionError) {
    throw new Error(`Extraction supplement discovery agent error: ${result.executionError}`);
  }

  const parsed = result.structuredOutput as { candidates?: unknown[] } | null;
  if (!parsed || !Array.isArray(parsed.candidates)) {
    return { candidates: [], costUsd: result.costUsd };
  }

  const validFlowKinds = new Set(["param", "arg", "return", "receiver", "field", "unknown"]);
  const candidates: ExtractionSupplementCandidate[] = [];
  for (const item of parsed.candidates) {
    if (!isRecord(item)) continue;
    const callable = typeof item["callable"] === "string" ? item["callable"].trim() : "";
    if (!callable) continue;
    const candidateKind = item["candidateKind"];
    if (candidateKind !== "source_candidate" && candidateKind !== "sink_candidate") continue;
    const flowKind = typeof item["flowKind"] === "string" ? item["flowKind"] : "unknown";
    candidates.push({
      candidateKind,
      callable,
      flowKind: validFlowKinds.has(flowKind)
        ? (flowKind as ExtractionSupplementCandidate["flowKind"])
        : "unknown",
      receiverHint: typeof item["receiverHint"] === "string" ? item["receiverHint"] : "",
      argIndex:
        typeof item["argIndex"] === "number" && Number.isInteger(item["argIndex"])
          ? item["argIndex"]
          : null,
      rationale: typeof item["rationale"] === "string" ? item["rationale"] : "",
    });
  }

  return { candidates, costUsd: result.costUsd };
}

function supplementCandidatesToCsvRows(candidates: ExtractionSupplementCandidate[]): {
  sourceRows: string[];
  sinkRows: string[];
} {
  const sourceRows: string[] = [];
  const sinkRows: string[] = [];
  for (const c of candidates) {
    const row = toCsvRow([
      "[agentic-supplement]",
      c.candidateKind,
      c.callable,
      `flow_kind=${c.flowKind}`,
      c.receiverHint,
      `module=${c.receiverHint}`,
      `arg_index=${c.argIndex ?? -1}`,
      "line=0",
    ]);
    if (c.candidateKind === "source_candidate") {
      sourceRows.push(row);
    } else {
      sinkRows.push(row);
    }
  }
  return { sourceRows, sinkRows };
}

/**
 * Taint Analysis Step 0-2 task: deterministic pre-flight + candidate extraction.
 */
export const taintAnalysisPreflightTask: AgentTask<ScanOpts, TaintAnalysisPreflightOutput> = {
  id: "taint-analysis-preflight",
  displayName: "Taint Analysis Pre-flight",
  outputKind: "custom",
  dependsOn: ["context-gatherer"],
  async run(_input, context): Promise<TaintAnalysisPreflightOutput> {
    const cfg = resolveTaintAnalysisConfig(context.config);
    const repoContext = coerceRepoContext(context.upstreamOutputs.get("context-gatherer"));
    const originalPassCount = cfg.passes.length;
    cfg.passes = resolveContextAwarePasses(repoContext, cfg.passes);
    if (cfg.passes.length < originalPassCount) {
      process.stderr.write(
        `[taint-analysis-preflight] Context-aware pass filtering: ${originalPassCount} → ${cfg.passes.length} passes [${cfg.passes.join(", ")}]\n`,
      );
    }
    const taintAnalysisPath = toAbsolutePath(context.repoRoot, cfg.taintAnalysisPath);
    await validateTaintAnalysisPath(taintAnalysisPath);

    const workspaceDir = resolveWorkspaceDir(context.repoRoot, cfg.workspaceDir);
    await initializeWorkspace(workspaceDir);

    const codeqlBinary = cfg.codeqlBinary
      ? toAbsolutePath(context.repoRoot, cfg.codeqlBinary)
      : await resolveCodeQLBinary();

    const { dbPath, language: detectedLanguage } = await ensureDatabase(
      context.repoRoot,
      codeqlBinary,
      {
        dbPath: cfg.dbPath,
      },
    );

    const language = normalizeTaintAnalysisLanguage(detectedLanguage);
    const framework = await detectPrimaryFramework(
      context.repoRoot,
      context.upstreamOutputs.get("context-gatherer"),
    );
    const referenceFiles = await resolveReferenceFiles(taintAnalysisPath, language, framework);
    const extractionModelSelection = resolveExtractionModel(cfg);
    if (extractionModelSelection.usedLabelingFallback) {
      process.stderr.write(
        `[taint-analysis-preflight] extractionModel not configured; using labelingModel (${cfg.labelingModel}) for extraction\n`,
      );
    }
    const extractionModel = extractionModelSelection.model;

    await writeQlpack(workspaceDir, language);
    await runCodeql(codeqlBinary, ["pack", "install"], workspaceDir);

    const codeqlVersion = await resolveCodeqlVersion(codeqlBinary);
    let profileDetection: Awaited<ReturnType<typeof detectWorkingProfile>>;
    try {
      profileDetection = await detectWorkingProfile({
        language,
        codeqlBinary,
        workspaceDir,
        codeqlApiProfile: cfg.codeqlApiProfile,
        codeqlProfileFallbacks: cfg.codeqlProfileFallbacks,
        probeTimeoutMs: cfg.codeqlProbeTimeoutMs,
      });
    } catch (error) {
      const tried = error instanceof CodeqlProfileDetectionError ? error.tried : [];
      await writeCodeqlCompatibility(
        workspaceDir,
        language,
        codeqlVersion,
        cfg,
        tried,
        null,
        toErrorMessage(error),
      );
      throw error;
    }
    const codeqlProfile = profileDetection.selected;
    const codeqlApiProfileId = codeqlProfile.id;

    await writeCodeqlCompatibility(
      workspaceDir,
      language,
      codeqlVersion,
      cfg,
      profileDetection.tried,
      codeqlProfile.id,
      undefined,
    );

    await writeManifestAndDetection(
      workspaceDir,
      dbPath,
      language,
      framework,
      referenceFiles,
      cfg,
      extractionModel,
      codeqlVersion,
      codeqlApiProfileId,
    );

    const explorationDir = path.join(workspaceDir, "exploration");
    let diffScope: DiffScope | undefined;
    if (cfg.taintDiffBase) {
      diffScope = await buildDiffScope(
        context.repoRoot,
        cfg.taintDiffBase,
        cfg.taintDiffMode ?? "delta",
        cfg.passes,
      );
      await writeFile(
        path.join(explorationDir, "diff_scope.json"),
        JSON.stringify(
          {
            generatedAt: new Date().toISOString(),
            ...diffScope,
          },
          null,
          2,
        ),
        "utf-8",
      );
      process.stderr.write(
        `[taint-analysis-preflight] Diff-aware scope: base=${diffScope.base} mode=${diffScope.mode} changed_files=${diffScope.changedFiles.length} fell_back_to_full=${diffScope.fellBackToFull}${diffScope.fallbackReason ? ` reason=${diffScope.fallbackReason}` : ""}\n`,
      );
    }
    const tiPriorMarkdownPath = path.join(explorationDir, "TI_PRIOR.md");
    const tiPriorJsonPath = path.join(explorationDir, "ti_prior.json");
    const selectedPasses = TAINT_ANALYSIS_PASSES.filter((pass) => cfg.passes.includes(pass.passId));
    const tiPriorArtifacts = await buildTiPriorArtifacts({
      passes: selectedPasses,
      timeoutMs: cfg.tiTimeoutMs ?? 15_000,
    });
    await writeFile(tiPriorMarkdownPath, tiPriorArtifacts.markdown, "utf-8");
    await writeFile(tiPriorJsonPath, JSON.stringify(tiPriorArtifacts.document, null, 2), "utf-8");

    const extractionDir = path.join(workspaceDir, "extraction");
    const sourcesQueryPath = path.join(extractionDir, "sources.ql");
    const sinksQueryPath = path.join(extractionDir, "sinks.ql");

    const sourcesTemplatePath = path.join(
      taintAnalysisPath,
      "assets",
      "extraction",
      `${language}_sources.ql.tmpl`,
    );
    const sinksTemplatePath = path.join(
      taintAnalysisPath,
      "assets",
      "extraction",
      `${language}_sinks.ql.tmpl`,
    );

    const agentCtx: ExtractionAgentContext = {
      referenceFiles,
      taintAnalysisPath,
      model: extractionModel,
      runtime: context.runtime,
      repoRoot: context.repoRoot,
      workspaceDir,
      codeqlBinary,
      dbPath,
      codeqlApiProfileId,
      dataFlowImport: codeqlProfile.dataFlowImport,
      taintTrackingImport: codeqlProfile.taintTrackingImport,
    };

    const sourcesQueryResult = await renderExtractionTemplateWithDiagnostic(
      sourcesTemplatePath,
      language,
      "source",
      agentCtx,
    );
    const sinksQueryResult = await renderExtractionTemplateWithDiagnostic(
      sinksTemplatePath,
      language,
      "sink",
      agentCtx,
    );
    let extractionCostUsd = sourcesQueryResult.costUsd + sinksQueryResult.costUsd;
    const sourcesBqrsPath = path.join(extractionDir, "sources.bqrs");
    const sinksBqrsPath = path.join(extractionDir, "sinks.bqrs");
    const sourcesCsvPath = path.join(extractionDir, "sources.csv");
    const sinksCsvPath = path.join(extractionDir, "sinks.csv");

    if (!sourcesQueryResult.query || !sinksQueryResult.query) {
      const extractionDegradation = computeExtractionDegradation(
        [sourcesQueryResult.diagnostic, sinksQueryResult.diagnostic],
        0,
        0,
        language,
        framework,
      );

      await writeExtractionDiagnostics(
        path.join(explorationDir, "extraction_diagnostics.json"),
        language,
        {
          sources: 0,
          sinks: 0,
          sourcesDecodedRows: 0,
          sinksDecodedRows: 0,
          agenticSupplementSources: 0,
          agenticSupplementSinks: 0,
        },
        [sourcesQueryResult.diagnostic, sinksQueryResult.diagnostic],
      );

      process.stderr.write(
        `[taint-analysis-preflight] Extraction unavailable; taint analysis will stop before labeling (${extractionDegradation.reasons.join(", ") || "unknown_reason"}).\n`,
      );

      return attachTaskOutputMeta(
        {
          taintAnalysisPath,
          workspaceDir,
          dbPath,
          codeqlBinary,
          codeqlVersion,
          codeqlApiProfileId,
          language,
          framework,
          referenceFiles,
          passes: cfg.passes,
          tiPriorMarkdownPath,
          tiPriorJsonPath,
          tiPriorDegraded: tiPriorArtifacts.document.degraded,
          extraction: {
            sourcesQueryPath,
            sinksQueryPath,
            sourcesCsvPath,
            sinksCsvPath,
            sourcesRowCount: 0,
            sinksRowCount: 0,
          },
          extractionDegradation,
          diffScope,
        },
        { costUsd: extractionCostUsd },
      );
    }

    await writeFile(sourcesQueryPath, sourcesQueryResult.query, "utf-8");
    await writeFile(sinksQueryPath, sinksQueryResult.query, "utf-8");

    process.stderr.write(`[taint-analysis-preflight] Running CodeQL query: sources.ql...\n`);
    await runCodeql(
      codeqlBinary,
      withResources(
        ["query", "run", sourcesQueryPath, "--database", dbPath, "--output", sourcesBqrsPath],
        cfg,
      ),
      workspaceDir,
    );

    process.stderr.write(`[taint-analysis-preflight] Running CodeQL query: sinks.ql...\n`);
    await runCodeql(
      codeqlBinary,
      withResources(
        ["query", "run", sinksQueryPath, "--database", dbPath, "--output", sinksBqrsPath],
        cfg,
      ),
      workspaceDir,
    );

    process.stderr.write(`[taint-analysis-preflight] Decoding BQRS results...\n`);
    await runCodeql(
      codeqlBinary,
      ["bqrs", "decode", sourcesBqrsPath, "--format=csv", `--output=${sourcesCsvPath}`],
      workspaceDir,
    );

    await runCodeql(
      codeqlBinary,
      ["bqrs", "decode", sinksBqrsPath, "--format=csv", `--output=${sinksCsvPath}`],
      workspaceDir,
    );

    const sourcesDecodedRows = await countCsvCandidateRows(sourcesCsvPath, "source_candidate");
    const sinksDecodedRows = await countCsvCandidateRows(sinksCsvPath, "sink_candidate");

    let agenticSupplementSources = 0;
    let agenticSupplementSinks = 0;
    if (!cfg.extractionSupplementsDisabled) {
      try {
        const supplementResult = await discoverExtractionSupplements({
          language,
          framework,
          repoRoot: context.repoRoot,
          model: extractionModel,
          runtime: context.runtime,
          sourcesRowCount: sourcesDecodedRows,
          sinksRowCount: sinksDecodedRows,
        });
        extractionCostUsd += supplementResult.costUsd;
        const groundedCandidates = cfg.groundingEnabled
          ? await groundCallableTargets(context.repoRoot, supplementResult.candidates)
          : supplementResult.candidates.map((candidate) => ({
              item: candidate,
              grounding: {
                status: "weak" as const,
                reasons: ["grounding_disabled"],
                matchCount: 0,
                evidence: [],
              },
            }));
        const acceptedCandidates = groundedCandidates
          .filter((candidate) => candidate.grounding.status !== "invalid")
          .map((candidate) => candidate.item);
        const csvRows = supplementCandidatesToCsvRows(acceptedCandidates);
        agenticSupplementSources = csvRows.sourceRows.length;
        agenticSupplementSinks = csvRows.sinkRows.length;

        await writeFile(
          path.join(extractionDir, "extraction_supplements.json"),
          JSON.stringify(
            {
              generatedAt: new Date().toISOString(),
              language,
              framework,
              costUsd: supplementResult.costUsd,
              candidates: acceptedCandidates,
              droppedCandidates: groundedCandidates
                .filter((candidate) => candidate.grounding.status === "invalid")
                .map((candidate) => candidate.item),
              grounding: groundedCandidates.map((candidate) => ({
                ...candidate.item,
                grounding: candidate.grounding,
              })),
            },
            null,
            2,
          ),
          "utf-8",
        );

        if (csvRows.sourceRows.length > 0) {
          const existing = existsSync(sourcesCsvPath)
            ? await readFile(sourcesCsvPath, "utf-8")
            : "";
          const existingKeys = new Set(
            parseCsvRecords(existing)
              .filter((r) => !isCsvRecordBlank(r))
              .map((r) => r.join("\u001F")),
          );
          const newRows = csvRows.sourceRows.filter((row) => {
            const parsed = parseCsvRecords(row);
            return parsed.length > 0 && !existingKeys.has(parsed[0].join("\u001F"));
          });
          if (newRows.length > 0) {
            const suffix = newRows.join("\n") + "\n";
            await writeFile(sourcesCsvPath, existing.trimEnd() + "\n" + suffix, "utf-8");
          }
        }

        if (csvRows.sinkRows.length > 0) {
          const existing = existsSync(sinksCsvPath) ? await readFile(sinksCsvPath, "utf-8") : "";
          const existingKeys = new Set(
            parseCsvRecords(existing)
              .filter((r) => !isCsvRecordBlank(r))
              .map((r) => r.join("\u001F")),
          );
          const newRows = csvRows.sinkRows.filter((row) => {
            const parsed = parseCsvRecords(row);
            return parsed.length > 0 && !existingKeys.has(parsed[0].join("\u001F"));
          });
          if (newRows.length > 0) {
            const suffix = newRows.join("\n") + "\n";
            await writeFile(sinksCsvPath, existing.trimEnd() + "\n" + suffix, "utf-8");
          }
        }

        process.stderr.write(
          `[taint-analysis-preflight] Agentic extraction supplements: sources=${agenticSupplementSources} sinks=${agenticSupplementSinks}\n`,
        );
      } catch (error) {
        process.stderr.write(
          `[taint-analysis-preflight] Extraction supplement discovery failed (non-fatal): ${toErrorMessage(error)}\n`,
        );
      }
    }

    const sourcesRowCount = await countCsvRows(sourcesCsvPath);
    const sinksRowCount = await countCsvRows(sinksCsvPath);
    process.stderr.write(
      `[taint-analysis-preflight] Extraction complete: ${sourcesRowCount} sources, ${sinksRowCount} sinks\n`,
    );

    if (
      language === "go" &&
      framework &&
      isGrpcOrProtoFramework(framework) &&
      sourcesRowCount < 5
    ) {
      process.stderr.write(
        `[taint-analysis-preflight] WARNING: Detected Go gRPC service but found ${sourcesRowCount} sources.\n` +
          `  CodeQL may have incomplete type resolution. Agentic extraction supplements may provide additional coverage.\n`,
      );
    }

    await writeExtractionDiagnostics(
      path.join(explorationDir, "extraction_diagnostics.json"),
      language,
      {
        sources: sourcesRowCount,
        sinks: sinksRowCount,
        sourcesDecodedRows,
        sinksDecodedRows,
        agenticSupplementSources,
        agenticSupplementSinks,
      },
      [sourcesQueryResult.diagnostic, sinksQueryResult.diagnostic],
    );

    const extractionDegradation = computeExtractionDegradation(
      [sourcesQueryResult.diagnostic, sinksQueryResult.diagnostic],
      sourcesRowCount,
      sinksRowCount,
      language,
      framework,
    );

    if (tiPriorArtifacts.document.degraded) {
      process.stderr.write(
        "[taint-analysis-preflight] TI Prior data is degraded; threat intelligence coverage may be incomplete.\n",
      );
    }

    return attachTaskOutputMeta(
      {
        taintAnalysisPath,
        workspaceDir,
        dbPath,
        codeqlBinary,
        codeqlVersion,
        codeqlApiProfileId,
        language,
        framework,
        referenceFiles,
        passes: cfg.passes,
        tiPriorMarkdownPath,
        tiPriorJsonPath,
        tiPriorDegraded: tiPriorArtifacts.document.degraded,
        extraction: {
          sourcesQueryPath,
          sinksQueryPath,
          sourcesCsvPath,
          sinksCsvPath,
          sourcesRowCount,
          sinksRowCount,
        },
        extractionDegradation,
        diffScope,
      },
      { costUsd: extractionCostUsd },
    );
  },
};

async function buildDiffScope(
  repoRoot: string,
  taintDiffBase: string,
  mode: "delta" | "baseline",
  enabledPasses: TaintAnalysisPassId[],
): Promise<DiffScope> {
  try {
    const index = await createSimpleTextIndexProvider(repoRoot);
    const diffSlice = await index.getDiffSlice(taintDiffBase);

    if (diffSlice.changedFiles.length === 0) {
      process.stderr.write(
        `[taint-analysis-preflight] Diff slice returned 0 changed files; falling back to full analysis\n`,
      );
      return {
        base: diffSlice.base,
        changedFiles: [],
        mode,
        affectedPassIds: [...enabledPasses],
        fellBackToFull: true,
        fallbackReason: "no_changed_files",
      };
    }

    // At preflight time, labels are not yet available so we conservatively
    // assume all enabled passes may be affected by the diff.  The analyze
    // task narrows this set once label data is available.
    return {
      base: diffSlice.base,
      changedFiles: diffSlice.changedFiles,
      mode,
      affectedPassIds: [...enabledPasses],
      fellBackToFull: false,
    };
  } catch (error) {
    process.stderr.write(
      `[taint-analysis-preflight] getDiffSlice failed: ${toErrorMessage(error)}; falling back to full analysis\n`,
    );
    return {
      base: taintDiffBase,
      changedFiles: [],
      mode,
      affectedPassIds: [...enabledPasses],
      fellBackToFull: true,
      fallbackReason: `getDiffSlice_error: ${toErrorMessage(error)}`,
    };
  }
}

function withResources(args: string[], cfg: TaintAnalysisTaskConfig): string[] {
  const out = [...args];
  if (cfg.threads && cfg.threads > 0) {
    out.push(`--threads=${cfg.threads}`);
  }
  if (cfg.ram && cfg.ram > 0) {
    out.push(`--ram=${cfg.ram}`);
  }
  return out;
}

async function validateTaintAnalysisPath(taintAnalysisPath: string): Promise<void> {
  if (!existsSync(taintAnalysisPath)) {
    throw new Error(`Taint analysis path does not exist: ${taintAnalysisPath}`);
  }

  for (const rel of REQUIRED_TAINT_ANALYSIS_PATHS) {
    const abs = path.join(taintAnalysisPath, rel);
    if (!existsSync(abs)) {
      throw new Error(`Invalid taint analysis path. Missing required path: ${abs}`);
    }
  }
}

async function initializeWorkspace(workspaceDir: string): Promise<void> {
  await mkdir(workspaceDir, { recursive: true });
  for (const dir of WORKSPACE_SUBDIRS) {
    await mkdir(path.join(workspaceDir, dir), { recursive: true });
  }
}

async function writeQlpack(workspaceDir: string, language: TaintAnalysisLanguage): Promise<void> {
  const qlpack = [
    "name: iris/generated",
    "version: 0.0.1",
    "dependencies:",
    `  codeql/${language}-all: "*"`,
    "",
  ].join("\n");

  await writeFile(path.join(workspaceDir, "qlpack.yml"), qlpack, "utf-8");
}

async function writeManifestAndDetection(
  workspaceDir: string,
  dbPath: string,
  language: TaintAnalysisLanguage,
  framework: string | null,
  referenceFiles: string[],
  cfg: TaintAnalysisTaskConfig,
  extractionModel: string,
  codeqlVersion: string,
  codeqlApiProfileId: string,
): Promise<void> {
  const generatedAt = new Date().toISOString();
  const manifestPath = path.join(workspaceDir, "exploration", "run_manifest.json");
  const detectionPath = path.join(workspaceDir, "exploration", "detection.json");

  await writeFile(
    manifestPath,
    JSON.stringify(
      {
        timestamp: generatedAt,
        dbPath,
        language,
        selectedPasses: cfg.passes,
        model: extractionModel,
        extractionModel,
        labelingModel: cfg.labelingModel,
        codeqlVersion,
        codeqlApiProfileId,
      },
      null,
      2,
    ),
    "utf-8",
  );

  await writeFile(
    detectionPath,
    JSON.stringify(
      {
        language,
        framework,
        referenceFiles,
        generatedAt,
      },
      null,
      2,
    ),
    "utf-8",
  );
}

async function writeCodeqlCompatibility(
  workspaceDir: string,
  language: TaintAnalysisLanguage,
  codeqlVersion: string,
  cfg: TaintAnalysisTaskConfig,
  tried: Array<{ id: string; ok: boolean; error?: string }>,
  selectedProfileId: string | null,
  failureReason?: string,
): Promise<void> {
  const compatPath = path.join(workspaceDir, "exploration", "codeql_compat.json");
  const generatedAt = new Date().toISOString();
  await writeFile(
    compatPath,
    JSON.stringify(
      {
        generatedAt,
        language,
        codeqlVersion,
        requestedProfile: cfg.codeqlApiProfile ?? "auto",
        profileFallbacks: cfg.codeqlProfileFallbacks ?? true,
        probeTimeoutMs: cfg.codeqlProbeTimeoutMs ?? 20_000,
        selectedProfileId,
        triedProfiles: tried,
        ...(failureReason ? { failureReason } : {}),
      },
      null,
      2,
    ),
    "utf-8",
  );
}

async function writeExtractionDiagnostics(
  diagnosticsPath: string,
  language: TaintAnalysisLanguage,
  counts: ExtractionDiagnosticsDocument["counts"],
  diagnostics: ExtractionQueryDiagnostic[],
): Promise<void> {
  const document: ExtractionDiagnosticsDocument = {
    generatedAt: new Date().toISOString(),
    language,
    counts,
    diagnostics,
  };
  await writeFile(diagnosticsPath, JSON.stringify(document, null, 2), "utf-8");
}

function computeExtractionDegradation(
  diagnostics: ExtractionQueryDiagnostic[],
  sourcesRowCount: number,
  sinksRowCount: number,
  language?: TaintAnalysisLanguage,
  framework?: string | null,
): ExtractionDegradation {
  const reasons: ExtractionDegradationReason[] = [];

  for (const diag of diagnostics) {
    if (diag.selectedQuerySource === "unavailable") {
      reasons.push(
        diag.kind === "source" ? "sources_extraction_unavailable" : "sinks_extraction_unavailable",
      );
    }
    if (
      diag.fallbackReason?.includes("agent_returned_no_query") ||
      diag.fallbackReason?.includes("retry_returned_no_query")
    ) {
      reasons.push(
        diag.kind === "source"
          ? "sources_agent_returned_no_query"
          : "sinks_agent_returned_no_query",
      );
    }
  }

  if (sourcesRowCount <= 0) {
    reasons.push("zero_usable_sources");
  }
  if (sinksRowCount <= 0) {
    reasons.push("zero_usable_sinks");
  }

  if (
    language === "go" &&
    framework &&
    isGrpcOrProtoFramework(framework) &&
    sourcesRowCount < 5 &&
    sourcesRowCount > 0
  ) {
    reasons.push("low_source_count_for_framework");
  }

  let status: ExtractionDegradation["status"];
  if (reasons.length === 0) {
    status = "ok";
  } else if (sourcesRowCount <= 0 && sinksRowCount <= 0) {
    status = "failed";
  } else {
    status = "degraded";
  }

  return { status, reasons };
}

async function detectPrimaryFramework(
  repoRoot: string,
  contextGathererOutput: unknown,
): Promise<string | null> {
  const fromContext = inferFrameworkFromContext(contextGathererOutput);
  if (fromContext) {
    return fromContext;
  }

  const candidates = await detectFrameworkCandidates(repoRoot);
  if (candidates.length === 0) {
    return null;
  }

  const primary = candidates.find((candidate) => candidate.score >= 0.75);
  if (primary) {
    return primary.id;
  }

  const secondary = candidates.find((candidate) => candidate.score >= 0.5);
  if (secondary) {
    return secondary.id;
  }

  return candidates[0]?.id ?? null;
}

function inferFrameworkFromContext(contextGathererOutput: unknown): string | null {
  if (!isRecord(contextGathererOutput)) {
    return null;
  }

  const frameworks = contextGathererOutput["frameworks"];
  if (!Array.isArray(frameworks)) {
    return null;
  }

  for (const value of frameworks) {
    if (typeof value !== "string") {
      continue;
    }

    const mapped = mapFrameworkToReference(value);
    if (mapped) {
      return mapped;
    }
  }

  return null;
}

async function detectFrameworkCandidates(repoRoot: string): Promise<FrameworkCandidate[]> {
  const candidates = new Map<string, FrameworkCandidate>();
  const add = (framework: string, score: number, evidence: string): void => {
    const existing = candidates.get(framework);
    if (existing) {
      existing.score += score;
      existing.evidence.push(evidence);
      return;
    }

    candidates.set(framework, {
      id: framework,
      score,
      evidence: [evidence],
    });
  };

  const packageJson = await readText(path.join(repoRoot, "package.json"));
  if (packageJson.includes('"express"')) add("express", 0.45, "package.json dependency: express");

  const requirements = await readText(path.join(repoRoot, "requirements.txt"));
  const pyproject = await readText(path.join(repoRoot, "pyproject.toml"));
  const pythonCombined = `${requirements}\n${pyproject}`.toLowerCase();
  if (pythonCombined.includes("fastapi")) add("fastapi", 0.45, "python dependency: fastapi");
  if (pythonCombined.includes("django")) add("django", 0.45, "python dependency: django");
  if (pythonCombined.includes("flask")) add("flask", 0.45, "python dependency: flask");

  const goMod = await readText(path.join(repoRoot, "go.mod"));
  if (goMod.includes("github.com/gin-gonic/gin")) add("gin", 0.45, "go.mod dependency: gin");
  if (goMod.includes("github.com/labstack/echo")) add("echo", 0.45, "go.mod dependency: echo");

  const pom = await readText(path.join(repoRoot, "pom.xml"));
  const gradle = await readText(path.join(repoRoot, "build.gradle"));
  const gradleKts = await readText(path.join(repoRoot, "build.gradle.kts"));
  const javaCombined = `${pom}\n${gradle}\n${gradleKts}`.toLowerCase();
  if (javaCombined.includes("spring")) add("spring", 0.45, "java manifest contains spring");

  const csproj = await readAnyCsproj(repoRoot);
  const programCs = await readText(path.join(repoRoot, "Program.cs"));
  const aspNetText = `${csproj}\n${programCs}`.toLowerCase();
  if (aspNetText.includes("aspnetcore") || aspNetText.includes("webapplication.createbuilder")) {
    add("aspnet", 0.45, "ASP.NET Core marker");
  }

  const out = [...candidates.values()]
    .map((candidate) => ({
      ...candidate,
      score: Math.max(0, Math.min(1, candidate.score)),
    }))
    .sort((a, b) => b.score - a.score);

  return out;
}

async function resolveReferenceFiles(
  taintAnalysisPath: string,
  language: TaintAnalysisLanguage,
  framework: string | null,
): Promise<string[]> {
  const files: string[] = [];
  const patternsPath = path.join(taintAnalysisPath, "references", "patterns.md");
  const languagePath = path.join(taintAnalysisPath, "references", `${language}.md`);

  if (existsSync(patternsPath)) {
    files.push(patternsPath);
  }

  if (existsSync(languagePath)) {
    files.push(languagePath);
  }

  if (framework) {
    const frameworkPath = path.join(taintAnalysisPath, "references", `${framework}.md`);
    if (existsSync(frameworkPath)) {
      files.push(frameworkPath);
    }
  }

  return files;
}

async function renderExtractionTemplate(
  templatePath: string,
  language: TaintAnalysisLanguage,
  kind: "source" | "sink",
  agentCtx?: ExtractionAgentContext,
): Promise<string | null> {
  const result = await renderExtractionTemplateWithDiagnostic(
    templatePath,
    language,
    kind,
    agentCtx,
  );
  return result.query;
}

async function renderExtractionTemplateWithDiagnostic(
  templatePath: string,
  language: TaintAnalysisLanguage,
  kind: "source" | "sink",
  agentCtx?: ExtractionAgentContext,
): Promise<RenderExtractionTemplateResult> {
  let template = "";
  let costUsd = 0;
  const templateExists = existsSync(templatePath);
  if (templateExists) {
    template = await readFile(templatePath, "utf-8");
  }
  const templateHadBodyPlaceholders = hasBodyPlaceholders(template, kind);
  const diagnostic: ExtractionQueryDiagnostic = {
    kind,
    language,
    templatePath,
    templateExists,
    templateHadBodyPlaceholders,
    selectedQuerySource: "unavailable",
    fallbackUsed: false,
    fallbackReason: null,
    fallbackDetail: null,
    initialAttempt: createEmptyCompileAttempt(),
    retryAttempt: createEmptyCompileAttempt(),
  };

  if (!template) {
    return withoutGeneratedQuery(diagnostic, "missing_template", null, costUsd);
  }

  // Kind-specific gate: only templates with unresolved body placeholders need
  // the agent path. Python templates (which have hardcoded predicates) skip this.
  if (templateHadBodyPlaceholders) {
    if (agentCtx) {
      try {
        log.info({ language, kind }, `Running extraction agent for ${language}/${kind}`);
        diagnostic.initialAttempt.attempted = true;
        const generated = await generateExtractionQuery({
          language,
          kind,
          template,
          ...agentCtx,
        });
        costUsd += generated.costUsd;
        if (generated.query) {
          diagnostic.initialAttempt.generatedQuery = true;
          log.info(
            { language, kind, queryLength: generated.query.length },
            `Extraction agent succeeded for ${language}/${kind}`,
          );
          const compileResult = await tryCompileQuery(generated.query, agentCtx);
          diagnostic.initialAttempt.compileOk = compileResult.ok;
          diagnostic.initialAttempt.compileErrorExcerpt = compileResult.errorExcerpt ?? null;
          if (compileResult.ok) {
            diagnostic.selectedQuerySource = "agent-initial";
            return {
              query: generated.query,
              diagnostic,
              costUsd,
            };
          }
          log.warn(
            { language, kind },
            `Generated query failed compile check for ${language}/${kind}; retrying without cache`,
          );
          diagnostic.fallbackReason = "initial_compile_failed";
          diagnostic.fallbackDetail = compileResult.errorExcerpt ?? null;
          await clearExtractionCache(agentCtx.workspaceDir, language, kind);
        } else {
          diagnostic.initialAttempt.generatedQuery = false;
          diagnostic.initialAttempt.compileOk = null;
          diagnostic.fallbackReason = "agent_returned_no_query";
          log.warn(
            { language, kind },
            `Extraction agent returned no query for ${language}/${kind}; retrying without cache`,
          );
        }

        diagnostic.retryAttempt.attempted = true;
        const regenerated = await generateExtractionQuery({
          language,
          kind,
          template,
          ...agentCtx,
          disableCacheRead: true,
        });
        costUsd += regenerated.costUsd;
        if (regenerated.query) {
          diagnostic.retryAttempt.generatedQuery = true;
          log.info(
            { language, kind, queryLength: regenerated.query.length },
            `Extraction agent retry succeeded for ${language}/${kind}`,
          );
          const compileResult = await tryCompileQuery(regenerated.query, agentCtx);
          diagnostic.retryAttempt.compileOk = compileResult.ok;
          diagnostic.retryAttempt.compileErrorExcerpt = compileResult.errorExcerpt ?? null;
          if (compileResult.ok) {
            diagnostic.selectedQuerySource = "agent-retry";
            diagnostic.fallbackUsed = false;
            diagnostic.fallbackReason = null;
            diagnostic.fallbackDetail = null;
            return {
              query: regenerated.query,
              diagnostic,
              costUsd,
            };
          }
          log.warn(
            { language, kind },
            `Retry query failed compile check for ${language}/${kind}; extraction unavailable`,
          );
          diagnostic.fallbackReason = "retry_compile_failed";
          diagnostic.fallbackDetail = compileResult.errorExcerpt ?? null;
        } else {
          diagnostic.retryAttempt.generatedQuery = false;
          diagnostic.retryAttempt.compileOk = null;
          diagnostic.fallbackReason = "retry_returned_no_query";
          log.warn(
            { language, kind },
            `Extraction agent retry returned no query for ${language}/${kind}; extraction unavailable`,
          );
        }
        await clearExtractionCache(agentCtx.workspaceDir, language, kind);
      } catch (error) {
        diagnostic.fallbackReason = "agent_exception";
        diagnostic.fallbackDetail = toErrorMessage(error);
        process.stderr.write(
          `[taint-analysis-preflight] Agent extraction failed for ${language}/${kind}; extraction unavailable: ${toErrorMessage(error)}\n`,
        );
      }
    } else {
      diagnostic.fallbackReason = "body_placeholders_without_agent_ctx";
    }
    return withoutGeneratedQuery(
      diagnostic,
      diagnostic.fallbackReason ?? "agent_path_exhausted",
      diagnostic.fallbackDetail,
      costUsd,
    );
  }

  const rendered = template
    .replaceAll("{{QUERY_NAME}}", `Taint Analysis ${capitalize(kind)} candidate extraction`)
    .replaceAll("{{QUERY_DESCRIPTION}}", `Extract ${kind} candidates for taint analysis labeling.`)
    .replaceAll("{{QUERY_ID}}", `taint-analysis/extraction/${kind}`)
    .replaceAll("{{LANGUAGE_IMPORTS}}", `import ${language}`)
    .replaceAll("{{HELPER_PREDICATES}}", "")
    .replaceAll(`{{${kind.toUpperCase()}_CLAUSES}}`, "")
    .replaceAll("{{SELECT_NODE}}", '"n/a"')
    .replaceAll("{{SELECT_CALLABLE}}", '"unknown"')
    .replaceAll("{{SELECT_FLOW_KIND}}", '"flow_kind=unknown"')
    .replaceAll("{{SELECT_RECEIVER}}", '"receiver="')
    .replaceAll("{{SELECT_MODULE}}", '"module="')
    .replaceAll("{{SELECT_ARG_INDEX}}", '"arg_index=-1"')
    .replaceAll("{{SELECT_LINE}}", "1");

  if (rendered.includes("{{")) {
    return withoutGeneratedQuery(diagnostic, "unresolved_placeholders_after_render", null, costUsd);
  }

  diagnostic.selectedQuerySource = "deterministic-template";
  diagnostic.fallbackUsed = false;
  return {
    query: rendered,
    diagnostic,
    costUsd,
  };
}

function createEmptyCompileAttempt(): ExtractionCompileAttempt {
  return {
    attempted: false,
    generatedQuery: false,
    compileOk: null,
    compileErrorExcerpt: null,
  };
}

function withoutGeneratedQuery(
  diagnostic: ExtractionQueryDiagnostic,
  reason: string,
  detail: string | null = null,
  costUsd = 0,
): RenderExtractionTemplateResult {
  diagnostic.selectedQuerySource = "unavailable";
  diagnostic.fallbackUsed = false;
  diagnostic.fallbackReason = reason;
  diagnostic.fallbackDetail = detail;
  return {
    query: null,
    diagnostic,
    costUsd,
  };
}

async function clearExtractionCache(
  workspaceDir: string,
  language: TaintAnalysisLanguage,
  kind: "source" | "sink",
): Promise<void> {
  const cachePath = path.join(workspaceDir, "extraction", `.cache-${language}-${kind}.ql`);
  try {
    await rm(cachePath, { force: true });
  } catch {
    // Best-effort cache cleanup.
  }
}

async function tryCompileQuery(
  query: string,
  ctx: ExtractionAgentContext,
): Promise<{ ok: true; errorExcerpt: null } | { ok: false; errorExcerpt: string }> {
  const tmpQueryPath = path.join(ctx.workspaceDir, "extraction", "_compile_check.ql");
  try {
    await writeFile(tmpQueryPath, query, "utf-8");
    await execFileAsync(
      ctx.codeqlBinary,
      ["query", "compile", tmpQueryPath, "--search-path", ctx.workspaceDir],
      {
        cwd: ctx.workspaceDir,
        encoding: "utf-8",
        maxBuffer: 32 * 1024 * 1024,
      },
    );
    return { ok: true, errorExcerpt: null };
  } catch (error) {
    const err = error as ExecFileException & { stderr?: string };
    const excerpt = err.stderr?.trim().split("\n").slice(0, 5).join("; ") || toErrorMessage(error);
    process.stderr.write(`[taint-analysis-preflight] Compile check failed: ${excerpt}\n`);
    return { ok: false, errorExcerpt: excerpt };
  }
}

async function runCodeql(codeqlBinary: string, args: string[], cwd: string): Promise<void> {
  // Extract --database path from args to serialize access via the operation queue.
  const dbFlagIndex = args.indexOf("--database");
  const dbPath = dbFlagIndex !== -1 ? args[dbFlagIndex + 1] : undefined;

  const exec = async () => {
    try {
      // Using execFile (not exec) with array args — safe from shell injection.
      await execFileAsync(codeqlBinary, args, {
        cwd,
        encoding: "utf-8",
        maxBuffer: 64 * 1024 * 1024,
      });
    } catch (error) {
      const err = error as ExecFileException & { stderr?: string; stdout?: string };
      const details = err.stderr?.trim() || err.stdout?.trim() || toErrorMessage(error);
      throw new Error(`CodeQL command failed: ${codeqlBinary} ${args.join(" ")}\n${details}`);
    }
  };

  if (dbPath) {
    await withCodeQLDatabase(dbPath, exec);
  } else {
    await exec();
  }
}

function isGrpcOrProtoFramework(framework: string): boolean {
  const normalized = framework.trim().toLowerCase();
  return (
    normalized.includes("grpc") || normalized.includes("proto") || normalized.includes("protobuf")
  );
}

function escapeQllString(value: string): string {
  return value.replaceAll("\\", "\\\\").replaceAll('"', '\\"');
}

async function countCsvCandidateRows(
  filePath: string,
  candidateKind: "source_candidate" | "sink_candidate",
): Promise<number> {
  if (!existsSync(filePath)) {
    return 0;
  }
  const content = await readFile(filePath, "utf-8");
  return countCandidateCsvRecords(content, candidateKind);
}

interface MergeCandidateCsvResult {
  primaryRows: number;
  supplementRows: number;
  addedRows: number;
  mergedRows: number;
}

async function mergeCandidateCsvFiles(
  primaryPath: string,
  supplementPath: string,
  candidateKind: "source_candidate" | "sink_candidate",
): Promise<MergeCandidateCsvResult> {
  if (!existsSync(primaryPath) || !existsSync(supplementPath)) {
    const primaryRows = await countCsvCandidateRows(primaryPath, candidateKind);
    const supplementRows = await countCsvCandidateRows(supplementPath, candidateKind);
    return {
      primaryRows,
      supplementRows,
      addedRows: 0,
      mergedRows: primaryRows,
    };
  }

  const [primaryContent, supplementContent] = await Promise.all([
    readFile(primaryPath, "utf-8"),
    readFile(supplementPath, "utf-8"),
  ]);
  const primaryRecords = parseCsvRecords(primaryContent);
  const supplementRecords = parseCsvRecords(supplementContent);

  const findHeader = (records: string[][]): string[] | undefined =>
    records.find((record) => {
      if (isCsvRecordBlank(record)) {
        return false;
      }
      return normalizeCandidateMarker(record[1]) == null;
    });
  const primaryHeader = findHeader(primaryRecords);
  const supplementHeader = findHeader(supplementRecords);
  const header = primaryHeader ?? supplementHeader ?? [];

  const collect = (records: string[][]): string[][] =>
    records
      .filter((record) => !isCsvRecordBlank(record))
      .filter((record) => normalizeCandidateMarker(record[1]) === candidateKind);

  const primaryData = collect(primaryRecords);
  const supplementData = collect(supplementRecords);
  const seen = new Set(primaryData.map((record) => record.join("\u001F")));
  const mergedData = [...primaryData];
  let addedRows = 0;

  for (const record of supplementData) {
    const key = record.join("\u001F");
    if (seen.has(key)) {
      continue;
    }
    seen.add(key);
    mergedData.push(record);
    addedRows += 1;
  }

  const lines: string[] = [];
  if (header.length > 0) {
    lines.push(toCsvRow(header));
  }
  for (const row of mergedData) {
    lines.push(toCsvRow(row));
  }
  await writeFile(primaryPath, `${lines.join("\n")}${lines.length > 0 ? "\n" : ""}`, "utf-8");

  return {
    primaryRows: primaryData.length,
    supplementRows: supplementData.length,
    addedRows,
    mergedRows: mergedData.length,
  };
}

async function countCsvRows(filePath: string): Promise<number> {
  if (!existsSync(filePath)) {
    return 0;
  }

  const content = await readFile(filePath, "utf-8");
  const sourceCount = countCandidateCsvRecords(content, "source_candidate");
  const sinkCount = countCandidateCsvRecords(content, "sink_candidate");
  return sourceCount + sinkCount;
}

async function readText(filePath: string): Promise<string> {
  try {
    return await readFile(filePath, "utf-8");
  } catch {
    return "";
  }
}

async function readAnyCsproj(repoRoot: string): Promise<string> {
  try {
    const entries = await readdir(repoRoot);
    const csproj = entries.find((entry) => entry.endsWith(".csproj"));
    if (!csproj) {
      return "";
    }

    return await readText(path.join(repoRoot, csproj));
  } catch {
    return "";
  }
}

function capitalize(value: string): string {
  return value.length === 0 ? value : value[0].toUpperCase() + value.slice(1);
}

function resolveExtractionModel(cfg: TaintAnalysisTaskConfig): {
  model: string;
  usedLabelingFallback: boolean;
} {
  if (cfg.extractionModel) {
    return {
      model: cfg.extractionModel,
      usedLabelingFallback: false,
    };
  }

  return {
    model: cfg.labelingModel,
    usedLabelingFallback: true,
  };
}

function toAbsolutePath(repoRoot: string, candidate: string): string {
  if (path.isAbsolute(candidate)) {
    return path.normalize(candidate);
  }

  return path.resolve(repoRoot, candidate);
}

export function resolveWorkspaceDir(repoRoot: string, workspaceDir: string): string {
  const absoluteRepoRoot = path.resolve(repoRoot);
  const resolvedWorkspace = toAbsolutePath(absoluteRepoRoot, workspaceDir);
  if (isWithinRoot(absoluteRepoRoot, resolvedWorkspace)) {
    return resolvedWorkspace;
  }

  const fallbackWorkspace = toAbsolutePath(
    absoluteRepoRoot,
    DEFAULT_TAINT_ANALYSIS_TASK_CONFIG.workspaceDir,
  );
  log.warn(
    { workspaceDir, fallbackWorkspace },
    "Ignoring workspaceDir outside repo root; using fallback workspace",
  );
  return fallbackWorkspace;
}

function isWithinRoot(rootPath: string, candidatePath: string): boolean {
  const relative = path.relative(path.resolve(rootPath), path.resolve(candidatePath));
  return relative === "" || (!relative.startsWith("..") && !path.isAbsolute(relative));
}

export const __taintAnalysisPreflightInternals = {
  detectPrimaryFramework,
  renderExtractionTemplate,
  renderExtractionTemplateWithDiagnostic,
  resolveReferenceFiles,
  resolveWorkspaceDir,
  initializeWorkspace,
  writeManifestAndDetection,
  writeCodeqlCompatibility,
  writeExtractionDiagnostics,
  resolveExtractionModel,
  computeExtractionDegradation,
  isGrpcOrProtoFramework,
};
