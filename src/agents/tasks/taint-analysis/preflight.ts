import { execFile, type ExecFileException } from "node:child_process";
import { existsSync } from "node:fs";
import { mkdir, readFile, readdir, rm, writeFile } from "node:fs/promises";
import path from "node:path";
import { promisify } from "node:util";
import { ensureDatabase } from "../../../scanners/run-codeql.js";
import { resolveCodeQLBinary } from "../../../scanners/resolve-codeql.js";
import type { ScanOpts } from "../../../types.js";
import { isRecord, toErrorMessage } from "../../../utils.js";
import type { AgentTask } from "../../types.js";
import {
  generateExtractionQuery,
  hasBodyPlaceholders,
} from "./extraction-agent.js";
import {
  countCandidateCsvRecords,
  isCsvRecordBlank,
  normalizeCandidateMarker,
  parseCsvRecords,
  toCsvRow,
} from "./csv.js";
import {
  CodeqlProfileDetectionError,
  detectWorkingProfile,
  resolveCodeqlVersion,
} from "./codeql-compat.js";
import {
  DEFAULT_TAINT_ANALYSIS_TASK_CONFIG,
  TAINT_ANALYSIS_PASSES,
  mapFrameworkToReference,
  normalizeTaintAnalysisLanguage,
  resolveTaintAnalysisConfig,
  type TaintAnalysisLanguage,
  type TaintAnalysisPreflightOutput,
  type TaintAnalysisTaskConfig,
} from "./types.js";
import { buildTiPriorArtifacts } from "./ti-prior.js";

interface ExtractionAgentContext {
  referenceFiles: string[];
  taintAnalysisPath: string;
  model: string;
  repoRoot: string;
  workspaceDir: string;
  codeqlBinary: string;
  dbPath: string;
  codeqlApiProfileId: string;
  dataFlowImport: string;
  taintTrackingImport: string;
}

const execFileAsync = promisify(execFile);

const REQUIRED_TAINT_ANALYSIS_PATHS = [
  "WORKFLOW.md",
  "references",
  "assets",
  "scripts",
];

const WORKSPACE_SUBDIRS = [
  "exploration",
  "extraction",
  "labels",
  "libraries",
  "queries",
  "results",
  "report",
];

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
  selectedQuerySource: "deterministic-template" | "agent-initial" | "agent-retry" | "fallback";
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
    sinksSupplementRows?: number;
    sinksSupplementAddedRows?: number;
  };
  diagnostics: ExtractionQueryDiagnostic[];
}

interface RenderExtractionTemplateResult {
  query: string;
  diagnostic: ExtractionQueryDiagnostic;
}

interface DeterministicSinkSupplementSpec {
  kind: "function" | "method";
  packagePath: string;
  callable: string;
  argIndex: number;
  receiverHint: string;
  receivers?: string[];
}

const DETERMINISTIC_SINK_SUPPLEMENTS: Record<TaintAnalysisLanguage, DeterministicSinkSupplementSpec[]> = {
  go: [
    {
      kind: "function",
      packagePath: "github.com/volatiletech/sqlboiler/v4/queries",
      callable: "Raw",
      argIndex: 0,
      receiverHint: "queries",
    },
    {
      kind: "function",
      packagePath: "github.com/volatiletech/sqlboiler/queries",
      callable: "Raw",
      argIndex: 0,
      receiverHint: "queries",
    },
    {
      kind: "function",
      packagePath: "github.com/volatiletech/sqlboiler/v4/queries/qm",
      callable: "SQL",
      argIndex: 0,
      receiverHint: "qm",
    },
    {
      kind: "function",
      packagePath: "github.com/volatiletech/sqlboiler/queries/qm",
      callable: "SQL",
      argIndex: 0,
      receiverHint: "qm",
    },
    {
      kind: "function",
      packagePath: "github.com/volatiletech/sqlboiler/v4/queries/qm",
      callable: "From",
      argIndex: 0,
      receiverHint: "qm",
    },
    {
      kind: "function",
      packagePath: "github.com/volatiletech/sqlboiler/queries/qm",
      callable: "From",
      argIndex: 0,
      receiverHint: "qm",
    },
    {
      kind: "method",
      packagePath: "database/sql",
      callable: "Exec",
      argIndex: 0,
      receiverHint: "database/sql",
      receivers: ["DB", "Tx", "Stmt", "Conn"],
    },
    {
      kind: "method",
      packagePath: "database/sql",
      callable: "ExecContext",
      argIndex: 1,
      receiverHint: "database/sql",
      receivers: ["DB", "Tx", "Stmt", "Conn"],
    },
    {
      kind: "method",
      packagePath: "database/sql",
      callable: "QueryRow",
      argIndex: 0,
      receiverHint: "database/sql",
      receivers: ["DB", "Tx", "Stmt", "Conn"],
    },
  ],
  python: [],
  java: [],
  javascript: [],
  csharp: [],
};

/**
 * Taint Analysis Step 0-2 task: deterministic pre-flight + candidate extraction.
 */
export const taintAnalysisPreflightTask: AgentTask<ScanOpts, TaintAnalysisPreflightOutput> = {
  id: "taint-analysis-preflight",
  displayName: "Taint Analysis Pre-flight",
  outputKind: "custom",
  // Soft dependency: consume context-gatherer output when available, but do not require it.
  // This keeps taint analysis usable even when context gathering is disabled.
  dependsOn: [],
  async run(_input, context): Promise<TaintAnalysisPreflightOutput> {
    const cfg = resolveTaintAnalysisConfig(context.config);
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
    const framework = await detectPrimaryFramework(context.repoRoot, context.upstreamOutputs.get("context-gatherer"));
    const referenceFiles = await resolveReferenceFiles(taintAnalysisPath, language, framework);
    const extractionModelSelection = resolveExtractionModel(cfg);
    if (extractionModelSelection.usedLabelingFallback) {
      process.stderr.write(
        `[taint-analysis-preflight] extractionModel not configured; using labelingModel (${cfg.labelingModel}) for extraction\n`,
      );
    }
    const extractionModel = extractionModelSelection.model;

    await writeQlpack(workspaceDir, language);
    await runCodeql(
      codeqlBinary,
      ["pack", "install"],
      workspaceDir,
    );

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
      const tried = error instanceof CodeqlProfileDetectionError
        ? error.tried
        : [];
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

    const sourcesTemplatePath = path.join(taintAnalysisPath, "assets", "extraction", `${language}_sources.ql.tmpl`);
    const sinksTemplatePath = path.join(taintAnalysisPath, "assets", "extraction", `${language}_sinks.ql.tmpl`);

    const agentCtx: ExtractionAgentContext = {
      referenceFiles,
      taintAnalysisPath,
      model: extractionModel,
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
    const sinkSupplementQuery = renderDeterministicSinkSupplementQuery(language);

    await writeFile(sourcesQueryPath, sourcesQueryResult.query, "utf-8");
    await writeFile(sinksQueryPath, sinksQueryResult.query, "utf-8");
    const sinksSupplementQueryPath = path.join(extractionDir, "sinks_supplement.ql");
    if (sinkSupplementQuery) {
      await writeFile(sinksSupplementQueryPath, sinkSupplementQuery, "utf-8");
      process.stderr.write(
        `[taint-analysis-preflight] Appended deterministic sink supplement coverage for ${language}\n`,
      );
    }

    const sourcesBqrsPath = path.join(extractionDir, "sources.bqrs");
    const sinksBqrsPath = path.join(extractionDir, "sinks.bqrs");
    const sinksSupplementBqrsPath = path.join(extractionDir, "sinks_supplement.bqrs");
    const sourcesCsvPath = path.join(extractionDir, "sources.csv");
    const sinksCsvPath = path.join(extractionDir, "sinks.csv");
    const sinksSupplementCsvPath = path.join(extractionDir, "sinks_supplement.csv");

    process.stderr.write(`[taint-analysis-preflight] Running CodeQL query: sources.ql...\n`);
    await runCodeql(
      codeqlBinary,
      withResources([
        "query",
        "run",
        sourcesQueryPath,
        "--database",
        dbPath,
        "--output",
        sourcesBqrsPath,
      ], cfg),
      workspaceDir,
    );

    process.stderr.write(`[taint-analysis-preflight] Running CodeQL query: sinks.ql...\n`);
    await runCodeql(
      codeqlBinary,
      withResources([
        "query",
        "run",
        sinksQueryPath,
        "--database",
        dbPath,
        "--output",
        sinksBqrsPath,
      ], cfg),
      workspaceDir,
    );

    if (sinkSupplementQuery) {
      process.stderr.write(`[taint-analysis-preflight] Running CodeQL query: sinks_supplement.ql...\n`);
      await runCodeql(
        codeqlBinary,
        withResources([
          "query",
          "run",
          sinksSupplementQueryPath,
          "--database",
          dbPath,
          "--output",
          sinksSupplementBqrsPath,
        ], cfg),
        workspaceDir,
      );
    }

    process.stderr.write(`[taint-analysis-preflight] Decoding BQRS results...\n`);
    await runCodeql(
      codeqlBinary,
      [
        "bqrs",
        "decode",
        sourcesBqrsPath,
        "--format=csv",
        `--output=${sourcesCsvPath}`,
      ],
      workspaceDir,
    );

    await runCodeql(
      codeqlBinary,
      [
        "bqrs",
        "decode",
        sinksBqrsPath,
        "--format=csv",
        `--output=${sinksCsvPath}`,
      ],
      workspaceDir,
    );

    if (sinkSupplementQuery) {
      await runCodeql(
        codeqlBinary,
        [
          "bqrs",
          "decode",
          sinksSupplementBqrsPath,
          "--format=csv",
          `--output=${sinksSupplementCsvPath}`,
        ],
        workspaceDir,
      );
    }

    const sourcesDecodedRows = await countCsvCandidateRows(sourcesCsvPath, "source_candidate");
    const sinksDecodedRows = await countCsvCandidateRows(sinksCsvPath, "sink_candidate");
    let sinksSupplementRows = 0;
    let sinksSupplementAddedRows = 0;
    if (sinkSupplementQuery) {
      const merged = await mergeCandidateCsvFiles(
        sinksCsvPath,
        sinksSupplementCsvPath,
        "sink_candidate",
      );
      sinksSupplementRows = merged.supplementRows;
      sinksSupplementAddedRows = merged.addedRows;
      process.stderr.write(
        `[taint-analysis-preflight] Deterministic sink supplements: decoded=${sinksSupplementRows} added=${sinksSupplementAddedRows} merged_total=${merged.mergedRows}\n`,
      );
    }

    const sourcesRowCount = await countCsvRows(sourcesCsvPath);
    const sinksRowCount = await countCsvRows(sinksCsvPath);
    process.stderr.write(`[taint-analysis-preflight] Extraction complete: ${sourcesRowCount} sources, ${sinksRowCount} sinks\n`);
    await writeExtractionDiagnostics(
      path.join(explorationDir, "extraction_diagnostics.json"),
      language,
      {
        sources: sourcesRowCount,
        sinks: sinksRowCount,
        sourcesDecodedRows,
        sinksDecodedRows,
        sinksSupplementRows,
        sinksSupplementAddedRows,
      },
      [sourcesQueryResult.diagnostic, sinksQueryResult.diagnostic],
    );

    return {
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
    };
  },
};

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
    `  codeql/${language}-all: \"*\"`,
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
    JSON.stringify({
      timestamp: generatedAt,
      dbPath,
      language,
      selectedPasses: cfg.passes,
      model: extractionModel,
      extractionModel,
      labelingModel: cfg.labelingModel,
      codeqlVersion,
      codeqlApiProfileId,
    }, null, 2),
    "utf-8",
  );

  await writeFile(
    detectionPath,
    JSON.stringify({
      language,
      framework,
      referenceFiles,
      generatedAt,
    }, null, 2),
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
    JSON.stringify({
      generatedAt,
      language,
      codeqlVersion,
      requestedProfile: cfg.codeqlApiProfile ?? "auto",
      profileFallbacks: cfg.codeqlProfileFallbacks ?? true,
      probeTimeoutMs: cfg.codeqlProbeTimeoutMs ?? 20_000,
      selectedProfileId,
      triedProfiles: tried,
      ...(failureReason ? { failureReason } : {}),
    }, null, 2),
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
  if (packageJson.includes("\"express\"")) add("express", 0.45, "package.json dependency: express");

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
): Promise<string> {
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
    selectedQuerySource: "fallback",
    fallbackUsed: false,
    fallbackReason: null,
    fallbackDetail: null,
    initialAttempt: createEmptyCompileAttempt(),
    retryAttempt: createEmptyCompileAttempt(),
  };

  if (!template) {
    return withFallback(diagnostic, language, kind, "missing_template");
  }

  // Kind-specific gate: only templates with unresolved body placeholders need
  // the agent path. Python templates (which have hardcoded predicates) skip this.
  if (templateHadBodyPlaceholders) {
    if (agentCtx) {
      try {
        process.stderr.write(`[taint-analysis-preflight] Running extraction agent for ${language}/${kind}...\n`);
        diagnostic.initialAttempt.attempted = true;
        const generated = await generateExtractionQuery({
          language,
          kind,
          template,
          ...agentCtx,
        });
        if (generated) {
          diagnostic.initialAttempt.generatedQuery = true;
          process.stderr.write(`[taint-analysis-preflight] Extraction agent succeeded for ${language}/${kind} (${generated.length} chars)\n`);
          const compileResult = await tryCompileQuery(generated, agentCtx);
          diagnostic.initialAttempt.compileOk = compileResult.ok;
          diagnostic.initialAttempt.compileErrorExcerpt = compileResult.errorExcerpt ?? null;
          if (compileResult.ok) {
            diagnostic.selectedQuerySource = "agent-initial";
            return {
              query: generated,
              diagnostic,
            };
          }
          process.stderr.write(
            `[taint-analysis-preflight] Generated query failed compile check for ${language}/${kind}; retrying without cache\n`,
          );
          diagnostic.fallbackReason = "initial_compile_failed";
          diagnostic.fallbackDetail = compileResult.errorExcerpt ?? null;
          await clearExtractionCache(agentCtx.workspaceDir, language, kind);
        } else {
          diagnostic.initialAttempt.generatedQuery = false;
          diagnostic.initialAttempt.compileOk = null;
          diagnostic.fallbackReason = "agent_returned_no_query";
          process.stderr.write(
            `[taint-analysis-preflight] Extraction agent returned no query for ${language}/${kind}; retrying without cache\n`,
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
        if (regenerated) {
          diagnostic.retryAttempt.generatedQuery = true;
          process.stderr.write(
            `[taint-analysis-preflight] Extraction agent retry succeeded for ${language}/${kind} (${regenerated.length} chars)\n`,
          );
          const compileResult = await tryCompileQuery(regenerated, agentCtx);
          diagnostic.retryAttempt.compileOk = compileResult.ok;
          diagnostic.retryAttempt.compileErrorExcerpt = compileResult.errorExcerpt ?? null;
          if (compileResult.ok) {
            diagnostic.selectedQuerySource = "agent-retry";
            diagnostic.fallbackUsed = false;
            diagnostic.fallbackReason = null;
            diagnostic.fallbackDetail = null;
            return {
              query: regenerated,
              diagnostic,
            };
          }
          process.stderr.write(
            `[taint-analysis-preflight] Retry query failed compile check for ${language}/${kind}, using fallback\n`,
          );
          diagnostic.fallbackReason = "retry_compile_failed";
          diagnostic.fallbackDetail = compileResult.errorExcerpt ?? null;
        } else {
          diagnostic.retryAttempt.generatedQuery = false;
          diagnostic.retryAttempt.compileOk = null;
          diagnostic.fallbackReason = "retry_returned_no_query";
          process.stderr.write(
            `[taint-analysis-preflight] Extraction agent retry returned no query for ${language}/${kind}, using fallback\n`,
          );
        }
        await clearExtractionCache(agentCtx.workspaceDir, language, kind);
      } catch (error) {
        diagnostic.fallbackReason = "agent_exception";
        diagnostic.fallbackDetail = toErrorMessage(error);
        process.stderr.write(
          `[taint-analysis-preflight] Agent extraction failed for ${language}/${kind}, using fallback: ${toErrorMessage(error)}\n`,
        );
      }
    } else {
      diagnostic.fallbackReason = "body_placeholders_without_agent_ctx";
    }
    return withFallback(
      diagnostic,
      language,
      kind,
      diagnostic.fallbackReason ?? "agent_path_exhausted",
      diagnostic.fallbackDetail,
    );
  }

  const rendered = template
    .replaceAll("{{QUERY_NAME}}", `Taint Analysis ${capitalize(kind)} candidate extraction`)
    .replaceAll("{{QUERY_DESCRIPTION}}", `Extract ${kind} candidates for taint analysis labeling.`)
    .replaceAll("{{QUERY_ID}}", `taint-analysis/extraction/${kind}`)
    .replaceAll("{{LANGUAGE_IMPORTS}}", `import ${language}`)
    .replaceAll("{{HELPER_PREDICATES}}", "")
    .replaceAll(`{{${kind.toUpperCase()}_CLAUSES}}`, "")
    .replaceAll("{{SELECT_NODE}}", "\"n/a\"")
    .replaceAll("{{SELECT_CALLABLE}}", "\"unknown\"")
    .replaceAll("{{SELECT_FLOW_KIND}}", "\"flow_kind=unknown\"")
    .replaceAll("{{SELECT_RECEIVER}}", "\"receiver=\"")
    .replaceAll("{{SELECT_MODULE}}", "\"module=\"")
    .replaceAll("{{SELECT_ARG_INDEX}}", "\"arg_index=-1\"")
    .replaceAll("{{SELECT_LINE}}", "1");

  if (rendered.includes("{{")) {
    return withFallback(diagnostic, language, kind, "unresolved_placeholders_after_render");
  }

  diagnostic.selectedQuerySource = "deterministic-template";
  diagnostic.fallbackUsed = false;
  return {
    query: rendered,
    diagnostic,
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

function withFallback(
  diagnostic: ExtractionQueryDiagnostic,
  language: TaintAnalysisLanguage,
  kind: "source" | "sink",
  reason: string,
  detail: string | null = null,
): RenderExtractionTemplateResult {
  diagnostic.selectedQuerySource = "fallback";
  diagnostic.fallbackUsed = true;
  diagnostic.fallbackReason = reason;
  diagnostic.fallbackDetail = detail;
  return {
    query: fallbackExtractionQuery(language, kind),
    diagnostic,
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

function fallbackExtractionQuery(language: TaintAnalysisLanguage, kind: "source" | "sink"): string {
  const candidateKind = kind === "source" ? "source_candidate" : "sink_candidate";
  return [
    "/**",
    ` * @name Taint Analysis ${capitalize(kind)} candidate extraction`,
    " * @description Deterministic fallback extraction query generated by Kuzushi.",
    " * @kind problem",
    ` * @id taint-analysis/extraction/fallback-${kind}`,
    " * @problem.severity recommendation",
    " */",
    "",
    `import ${language}`,
    "",
    "from DataFlow::Node marker",
    "where 1 = 0",
    "select",
    "  marker,",
    `  \"${candidateKind}\",`,
    "  \"unknown\",",
    "  \"flow_kind=unknown\",",
    "  \"receiver=\",",
    "  \"module=\",",
    "  \"arg_index=-1\",",
    "  1",
    "",
  ].join("\n");
}

async function tryCompileQuery(
  query: string,
  ctx: ExtractionAgentContext,
): Promise<{ ok: true; errorExcerpt: null } | { ok: false; errorExcerpt: string }> {
  const tmpQueryPath = path.join(ctx.workspaceDir, "extraction", "_compile_check.ql");
  try {
    await writeFile(tmpQueryPath, query, "utf-8");
    await execFileAsync(ctx.codeqlBinary, [
      "query", "compile",
      tmpQueryPath,
      "--search-path", ctx.workspaceDir,
    ], {
      cwd: ctx.workspaceDir,
      encoding: "utf-8",
      maxBuffer: 8 * 1024 * 1024,
    });
    return { ok: true, errorExcerpt: null };
  } catch (error) {
    const err = error as ExecFileException & { stderr?: string };
    const excerpt = err.stderr?.trim().split("\n").slice(0, 5).join("; ") || toErrorMessage(error);
    process.stderr.write(`[taint-analysis-preflight] Compile check failed: ${excerpt}\n`);
    return { ok: false, errorExcerpt: excerpt };
  }
}

async function runCodeql(codeqlBinary: string, args: string[], cwd: string): Promise<void> {
  try {
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
}

function renderDeterministicSinkSupplementQuery(language: TaintAnalysisLanguage): string | null {
  const specs = DETERMINISTIC_SINK_SUPPLEMENTS[language];
  if (!specs || specs.length === 0) {
    return null;
  }

  if (language !== "go") {
    return null;
  }

  const clauses = specs.map((spec) => renderGoSinkSupplementClause(spec)).join("\n  or\n");
  return [
    "/**",
    " * @name Taint Analysis Sink Candidate Extraction Supplement",
    " * @description Deterministic supplemental sink extraction coverage.",
    " * @kind problem",
    ` * @id taint-analysis/extraction/sinks-supplement-${language}`,
    " * @problem.severity recommendation",
    " */",
    "",
    "import go",
    "import semmle.go.dataflow.DataFlow",
    "",
    "private predicate deterministicSinkCandidate(",
    "  DataFlow::Node node, string callable, string flowKind,",
    "  string receiverHint, string modulePath, int argIndex, int line",
    ") {",
    `  ${clauses}`,
    "}",
    "",
    "from",
    "  DataFlow::Node node, string callable, string flowKind,",
    "  string receiverHint, string modulePath, int argIndex, int line",
    "where",
    "  deterministicSinkCandidate(node, callable, flowKind, receiverHint, modulePath, argIndex, line)",
    "select",
    "  node,",
    "  \"sink_candidate\",",
    "  callable,",
    "  \"flow_kind=\" + flowKind,",
    "  receiverHint,",
    "  \"module=\" + modulePath,",
    "  \"arg_index=\" + argIndex.toString(),",
    "  \"line=\" + line.toString()",
    "",
  ].join("\n");
}

function renderGoSinkSupplementClause(spec: DeterministicSinkSupplementSpec): string {
  const escapedPackage = escapeQllString(spec.packagePath);
  const escapedCallable = escapeQllString(spec.callable);
  const escapedReceiverHint = escapeQllString(`receiver=${spec.receiverHint}`);
  if (spec.kind === "method") {
    const receivers = (spec.receivers ?? [])
      .map((receiver) => `m.hasQualifiedName("${escapedPackage}", "${escapeQllString(receiver)}", "${escapedCallable}")`)
      .join("\n      or ");
    return [
      "exists(DataFlow::CallNode call, Method m |",
      "      m = call.getTarget() and",
      "      (",
      `        ${receivers}`,
      "      ) and",
      `      node = call.getArgument(${spec.argIndex}) and`,
      `      callable = \"${escapedCallable}\" and`,
      "      flowKind = \"arg\" and",
      `      receiverHint = \"${escapedReceiverHint}\" and`,
      "      modulePath = call.getFile().getRelativePath() and",
      `      argIndex = ${spec.argIndex} and`,
      "      line = call.getStartLine()",
      "    )",
    ].join("\n");
  }

  return [
    "exists(DataFlow::CallNode call |",
    `      call.getTarget().hasQualifiedName("${escapedPackage}", "${escapedCallable}") and`,
    `      node = call.getArgument(${spec.argIndex}) and`,
    `      callable = \"${escapedCallable}\" and`,
    "      flowKind = \"arg\" and",
    `      receiverHint = \"${escapedReceiverHint}\" and`,
    "      modulePath = call.getFile().getRelativePath() and",
    `      argIndex = ${spec.argIndex} and`,
    "      line = call.getStartLine()",
    "    )",
  ].join("\n");
}

function escapeQllString(value: string): string {
  return value.replaceAll("\\", "\\\\").replaceAll("\"", "\\\"");
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

  const findHeader = (records: string[][]): string[] | undefined => records.find((record) => {
    if (isCsvRecordBlank(record)) {
      return false;
    }
    return normalizeCandidateMarker(record[1]) == null;
  });
  const primaryHeader = findHeader(primaryRecords);
  const supplementHeader = findHeader(supplementRecords);
  const header = primaryHeader ?? supplementHeader ?? [];

  const collect = (records: string[][]): string[][] => records
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
  return value.length === 0
    ? value
    : value[0].toUpperCase() + value.slice(1);
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

  const fallbackWorkspace = toAbsolutePath(absoluteRepoRoot, DEFAULT_TAINT_ANALYSIS_TASK_CONFIG.workspaceDir);
  process.stderr.write(
    `[taint-analysis-preflight] Ignoring workspaceDir outside repo root: ${workspaceDir}; using ${fallbackWorkspace}\n`,
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
};
