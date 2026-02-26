import { execFile, type ExecFileException } from "node:child_process";
import { existsSync } from "node:fs";
import { mkdir, readFile, readdir, writeFile } from "node:fs/promises";
import path from "node:path";
import { promisify } from "node:util";
import { ensureDatabase } from "../../scanners/run-codeql.js";
import { resolveCodeQLBinary } from "../../scanners/resolve-codeql.js";
import type { ScanOpts } from "../../types.js";
import { isRecord, toErrorMessage } from "../../utils.js";
import type { AgentTask } from "../types.js";
import {
  generateExtractionQuery,
  hasBodyPlaceholders,
} from "./augur-extraction-agent.js";
import {
  DEFAULT_AUGUR_TASK_CONFIG,
  mapFrameworkToReference,
  normalizeAugurLanguage,
  resolveAugurConfig,
  type AugurLanguage,
  type AugurPreflightOutput,
  type AugurTaskConfig,
} from "./augur-types.js";

interface ExtractionAgentContext {
  referenceFiles: string[];
  augurPath: string;
  model: string;
  repoRoot: string;
  workspaceDir: string;
  codeqlBinary: string;
  dbPath: string;
}

const execFileAsync = promisify(execFile);

const REQUIRED_AUGUR_PATHS = [
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

/**
 * Augur Step 0-2 task: deterministic pre-flight + candidate extraction.
 */
export const augurPreflightTask: AgentTask<ScanOpts, AugurPreflightOutput> = {
  id: "augur-preflight",
  displayName: "Augur Pre-flight",
  outputKind: "custom",
  // Soft dependency: consume context-gatherer output when available, but do not require it.
  // This keeps Augur usable even when context gathering is disabled.
  dependsOn: [],
  async run(_input, context): Promise<AugurPreflightOutput> {
    const cfg = resolveAugurConfig(context.config);
    const augurPath = toAbsolutePath(context.repoRoot, cfg.augurPath);
    await validateAugurPath(augurPath);

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

    const language = normalizeAugurLanguage(detectedLanguage);
    const framework = await detectPrimaryFramework(context.repoRoot, context.upstreamOutputs.get("context-gatherer"));
    const referenceFiles = await resolveReferenceFiles(augurPath, language, framework);
    const extractionModel = cfg.extractionModel || cfg.labelingModel;

    await writeQlpack(workspaceDir, language);
    await runCodeql(
      codeqlBinary,
      ["pack", "install"],
      workspaceDir,
    );

    await writeManifestAndDetection(
      workspaceDir,
      dbPath,
      language,
      framework,
      referenceFiles,
      cfg,
      extractionModel,
    );

    const extractionDir = path.join(workspaceDir, "extraction");
    const sourcesQueryPath = path.join(extractionDir, "sources.ql");
    const sinksQueryPath = path.join(extractionDir, "sinks.ql");

    const sourcesTemplatePath = path.join(augurPath, "assets", "extraction", `${language}_sources.ql.tmpl`);
    const sinksTemplatePath = path.join(augurPath, "assets", "extraction", `${language}_sinks.ql.tmpl`);

    const agentCtx: ExtractionAgentContext = {
      referenceFiles,
      augurPath,
      model: extractionModel,
      repoRoot: context.repoRoot,
      workspaceDir,
      codeqlBinary,
      dbPath,
    };

    const sourcesQuery = await renderExtractionTemplate(
      sourcesTemplatePath,
      language,
      "source",
      agentCtx,
    );
    const sinksQuery = await renderExtractionTemplate(
      sinksTemplatePath,
      language,
      "sink",
      agentCtx,
    );

    await writeFile(sourcesQueryPath, sourcesQuery, "utf-8");
    await writeFile(sinksQueryPath, sinksQuery, "utf-8");

    const sourcesBqrsPath = path.join(extractionDir, "sources.bqrs");
    const sinksBqrsPath = path.join(extractionDir, "sinks.bqrs");
    const sourcesCsvPath = path.join(extractionDir, "sources.csv");
    const sinksCsvPath = path.join(extractionDir, "sinks.csv");

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

    const sourcesRowCount = await countCsvRows(sourcesCsvPath);
    const sinksRowCount = await countCsvRows(sinksCsvPath);

    return {
      augurPath,
      workspaceDir,
      dbPath,
      codeqlBinary,
      language,
      framework,
      referenceFiles,
      passes: cfg.passes,
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

function withResources(args: string[], cfg: AugurTaskConfig): string[] {
  const out = [...args];
  if (cfg.threads && cfg.threads > 0) {
    out.push(`--threads=${cfg.threads}`);
  }
  if (cfg.ram && cfg.ram > 0) {
    out.push(`--ram=${cfg.ram}`);
  }
  return out;
}

async function validateAugurPath(augurPath: string): Promise<void> {
  if (!existsSync(augurPath)) {
    throw new Error(`Augur path does not exist: ${augurPath}`);
  }

  for (const rel of REQUIRED_AUGUR_PATHS) {
    const abs = path.join(augurPath, rel);
    if (!existsSync(abs)) {
      throw new Error(`Invalid Augur path. Missing required path: ${abs}`);
    }
  }
}

async function initializeWorkspace(workspaceDir: string): Promise<void> {
  await mkdir(workspaceDir, { recursive: true });
  for (const dir of WORKSPACE_SUBDIRS) {
    await mkdir(path.join(workspaceDir, dir), { recursive: true });
  }
}

async function writeQlpack(workspaceDir: string, language: AugurLanguage): Promise<void> {
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
  language: AugurLanguage,
  framework: string | null,
  referenceFiles: string[],
  cfg: AugurTaskConfig,
  extractionModel: string,
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
  augurPath: string,
  language: AugurLanguage,
  framework: string | null,
): Promise<string[]> {
  const files: string[] = [];
  const patternsPath = path.join(augurPath, "references", "patterns.md");
  const languagePath = path.join(augurPath, "references", `${language}.md`);

  if (existsSync(patternsPath)) {
    files.push(patternsPath);
  }

  if (existsSync(languagePath)) {
    files.push(languagePath);
  }

  if (framework) {
    const frameworkPath = path.join(augurPath, "references", `${framework}.md`);
    if (existsSync(frameworkPath)) {
      files.push(frameworkPath);
    }
  }

  return files;
}

async function renderExtractionTemplate(
  templatePath: string,
  language: AugurLanguage,
  kind: "source" | "sink",
  agentCtx?: ExtractionAgentContext,
): Promise<string> {
  let template = "";
  if (existsSync(templatePath)) {
    template = await readFile(templatePath, "utf-8");
  }

  if (!template) {
    return fallbackExtractionQuery(language, kind);
  }

  // Kind-specific gate: only templates with unresolved body placeholders need
  // the agent path. Python templates (which have hardcoded predicates) skip this.
  if (hasBodyPlaceholders(template, kind)) {
    if (agentCtx) {
      try {
        const generated = await generateExtractionQuery({
          language,
          kind,
          template,
          ...agentCtx,
        });
        if (generated) {
          return generated;
        }
      } catch (error) {
        process.stderr.write(
          `[augur-preflight] Agent extraction failed for ${language}/${kind}, using fallback: ${toErrorMessage(error)}\n`,
        );
      }
    }
    return fallbackExtractionQuery(language, kind);
  }

  const rendered = template
    .replaceAll("{{QUERY_NAME}}", `Augur ${capitalize(kind)} candidate extraction`)
    .replaceAll("{{QUERY_DESCRIPTION}}", `Extract ${kind} candidates for Augur labeling.`)
    .replaceAll("{{QUERY_ID}}", `augur/extraction/${kind}`)
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
    return fallbackExtractionQuery(language, kind);
  }

  return rendered;
}

function fallbackExtractionQuery(language: AugurLanguage, kind: "source" | "sink"): string {
  const candidateKind = kind === "source" ? "source_candidate" : "sink_candidate";
  return [
    "/**",
    ` * @name Augur ${capitalize(kind)} candidate extraction`,
    " * @description Deterministic fallback extraction query generated by Kuzushi.",
    " * @kind problem",
    ` * @id augur/extraction/fallback-${kind}`,
    " * @problem.severity recommendation",
    " */",
    "",
    `import ${language}`,
    "",
    "from string marker",
    "where false",
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

async function countCsvRows(filePath: string): Promise<number> {
  if (!existsSync(filePath)) {
    return 0;
  }

  const content = await readFile(filePath, "utf-8");
  const lines = content
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter(Boolean);

  if (lines.length <= 1) {
    return 0;
  }

  return lines.length - 1;
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

  const fallbackWorkspace = toAbsolutePath(absoluteRepoRoot, DEFAULT_AUGUR_TASK_CONFIG.workspaceDir);
  process.stderr.write(
    `[augur-preflight] Ignoring workspaceDir outside repo root: ${workspaceDir}; using ${fallbackWorkspace}\n`,
  );
  return fallbackWorkspace;
}

function isWithinRoot(rootPath: string, candidatePath: string): boolean {
  const relative = path.relative(path.resolve(rootPath), path.resolve(candidatePath));
  return relative === "" || (!relative.startsWith("..") && !path.isAbsolute(relative));
}

export const __augurPreflightInternals = {
  detectPrimaryFramework,
  renderExtractionTemplate,
  resolveReferenceFiles,
  resolveWorkspaceDir,
  initializeWorkspace,
  writeManifestAndDetection,
};
