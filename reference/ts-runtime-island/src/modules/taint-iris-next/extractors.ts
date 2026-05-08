import { spawn } from "node:child_process";
import {
  type Dirent,
  existsSync,
  mkdirSync,
  readdirSync,
  readFileSync,
  statSync,
  writeFileSync,
} from "node:fs";
import os from "node:os";
import path from "node:path";
import { resolveCodeQLBinary } from "../../scanners/resolve-codeql.js";
import { runCodeQL, selectFindings } from "../../scanners/run-codeql.js";
import type { Finding } from "../../scanners/types.js";
import { isRecord, toErrorMessage } from "../../utils.js";
import type { ExecutionContext } from "../types.js";
import type {
  TaintIrisNextCweCatalogEntry,
  TaintIrisNextStructuralQuery,
} from "./cwe-reference.js";
import {
  applyLinkedStoriesToEvidence,
  buildCandidatesFromEvidence,
  determineEvidenceOutcome,
  inferLabeledSpecsFromCandidates,
  linkTaintCandidates,
  summarizeCountsByCwe,
  trackForCatalogEntry,
  trackForTaintClass,
} from "./evidence-tools.js";
import type {
  TaintIrisNextEvidence,
  TaintIrisNextEvidenceConfidence,
  TaintIrisNextEvidenceResult,
  TaintIrisNextPlan,
} from "./types.js";

const RG_IGNORE_GLOBS = [
  "!.git/**",
  "!.kuzushi/**",
  "!node_modules/**",
  "!vendor/**",
  "!dist/**",
  "!build/**",
  "!coverage/**",
  "!.next/**",
  "!.turbo/**",
  "!target/**",
  "!__pycache__/**",
  "!test/**",
  "!tests/**",
  "!**/test/**",
  "!**/tests/**",
  "!**/*_test.py",
  "!**/*.test.ts",
  "!**/*.spec.ts",
];

const LANGUAGE_BY_EXTENSION = new Map<string, string>([
  [".c", "c"],
  [".cc", "cpp"],
  [".cpp", "cpp"],
  [".cs", "csharp"],
  [".go", "go"],
  [".h", "c"],
  [".hpp", "cpp"],
  [".java", "java"],
  [".js", "javascript"],
  [".jsx", "javascript"],
  [".php", "php"],
  [".py", "python"],
  [".rb", "ruby"],
  [".rs", "rust"],
  [".ts", "typescript"],
  [".tsx", "typescript"],
]);

const FALLBACK_IGNORED_DIRECTORIES = new Set([
  ".git",
  ".kuzushi",
  "node_modules",
  "vendor",
  "dist",
  "build",
  "coverage",
  ".next",
  ".turbo",
  "target",
  "__pycache__",
]);

type StructuralSearchResult = {
  code: number | null;
  stdout: string;
  stderr: string;
  error?: string;
  warnings?: string[];
};

const PYTHON_CODEQL_PREDICATE_CHUNK_SIZE = 8;
const AST_GREP_QUERY_TIMEOUT_MS = 5_000;
const AST_GREP_LANGUAGES = new Set(["javascript", "typescript", "python", "ruby", "rust"]);

export async function extractTaintIrisNextEvidence(
  plan: TaintIrisNextPlan,
  ctx: ExecutionContext,
): Promise<TaintIrisNextEvidenceResult> {
  const structural = await runStructuralExtractor(plan, ctx);
  if (plan.backend.selected !== "codeql" && !plan.backend.corroborateWithCodeql) return structural;

  const codeql = await runCodeqlEvidenceExtractor(plan, ctx);
  const merged = {
    backend: plan.backend.selected,
    tool: codeql.evidence.length > 0 ? "codeql" : structural.tool,
    evidence: mergeEvidence(structural.evidence, codeql.evidence, plan.caps.maxEvidencePerCwe),
    queryCount: structural.queryCount + codeql.queryCount,
    warnings: [...structural.warnings, ...codeql.warnings],
  } satisfies Parameters<typeof finalizeEvidenceResult>[1];
  return finalizeEvidenceResult(
    plan,
    codeql.artifacts ? { ...merged, artifacts: codeql.artifacts } : merged,
  );
}

export async function runStructuralExtractor(
  plan: TaintIrisNextPlan,
  ctx: ExecutionContext,
): Promise<TaintIrisNextEvidenceResult> {
  const evidence: TaintIrisNextEvidence[] = [];
  const warnings = [...plan.backend.warnings];
  if (!plan.threatModelStatus.ok) {
    warnings.push(
      `threat-model-empty: ${plan.threatModelStatus.reason}; using broad deterministic CWE ranking`,
    );
  }
  const seen = new Set<string>();
  const perCweRoleCount = new Map<string, number>();
  const structuralBudget = {
    astGrepRemaining: Math.min(4, Math.max(1, plan.caps.maxCatalogEntries)),
  };

  for (const query of plan.structuralQueries) {
    if (roleCount(perCweRoleCount, query.cwe, query.role) >= plan.caps.maxEvidencePerCwe) {
      continue;
    }
    if (ctx.signal?.aborted) break;

    const matches = await runStructuralQuery(query, plan, ctx.signal, warnings, structuralBudget);
    const matchedFiles = new Set<string>();
    for (const parsed of matches) {
      if (roleCount(perCweRoleCount, query.cwe, query.role) >= plan.caps.maxEvidencePerCwe) {
        break;
      }
      if (!matchedFiles.has(parsed.filePath) && matchedFiles.size >= plan.caps.maxFilesPerQuery) {
        continue;
      }
      matchedFiles.add(parsed.filePath);

      const language = parsed.language ?? languageForPath(parsed.filePath);
      if (!shouldKeepEvidenceLanguage(language, plan.languages)) continue;

      const item: TaintIrisNextEvidence = {
        cwe: query.cwe,
        taintClass: query.taintClass,
        track: trackForTaintClass(query.taintClass),
        role: query.role,
        pattern: query.pattern,
        filePath: parsed.filePath,
        line: parsed.line,
        snippet: parsed.snippet,
        language,
        confidence: confidenceForRole(query.role),
        catalogSignal: parsed.catalogSignal ?? `${query.role}: ${query.pattern}`,
        evidenceLevel: "candidate",
        source: "structural",
        ...(parsed.callExpression ? { callExpression: parsed.callExpression } : {}),
      };
      if (!shouldKeepStructuralEvidence(item)) continue;

      const key = `${query.cwe}:${query.role}:${parsed.filePath}:${parsed.line}:${query.pattern}`;
      if (seen.has(key)) continue;
      seen.add(key);
      incrementRoleCount(perCweRoleCount, query.cwe, query.role);
      evidence.push(item);
    }
  }

  return finalizeEvidenceResult(plan, {
    backend: "structural",
    tool: plan.backend.structuralTool,
    evidence,
    queryCount: plan.structuralQueries.length,
    warnings,
  });
}

export async function runCodeqlEvidenceExtractor(
  plan: TaintIrisNextPlan,
  ctx: ExecutionContext,
): Promise<TaintIrisNextEvidenceResult> {
  const warnings: string[] = [];
  const dbPath = plan.backend.codeqlDbPath;
  if (!dbPath) {
    return finalizeEvidenceResult(plan, {
      backend: "codeql",
      tool: "codeql",
      evidence: [],
      queryCount: 0,
      warnings: ["backend=codeql selected, but no existing CodeQL DB path was resolved"],
    });
  }
  if (!existsSync(dbPath)) {
    return finalizeEvidenceResult(plan, {
      backend: "codeql",
      tool: "codeql",
      evidence: [],
      queryCount: 0,
      warnings: [`CodeQL DB path does not exist: ${dbPath}`],
    });
  }

  let codeqlBin: string;
  try {
    codeqlBin = resolveConfiguredCodeqlBinary(ctx) ?? (await resolveCodeQLBinary());
  } catch (error) {
    return finalizeEvidenceResult(plan, {
      backend: "codeql",
      tool: "codeql",
      evidence: [],
      queryCount: 0,
      warnings: [
        `CodeQL DB found at ${dbPath}, but CodeQL CLI is unavailable; using structural evidence only. ${toErrorMessage(error)}`,
      ],
    });
  }

  const language = detectCodeqlDatabaseLanguage(dbPath, plan.languages);
  const allQueries = buildCodeqlCatalogQueries(plan, language);
  const corroborationOnly = plan.backend.selected !== "codeql";
  const queries = corroborationOnly ? allQueries.slice(0, 2) : allQueries;
  if (corroborationOnly && allQueries.length > queries.length) {
    warnings.push(
      `CodeQL corroboration capped at ${queries.length}/${allQueries.length} generated taint queries; use backend=codeql for the full heavy path.`,
    );
  }
  if (queries.length === 0) {
    return finalizeEvidenceResult(plan, {
      backend: "codeql",
      tool: "codeql",
      evidence: [],
      queryCount: 0,
      artifacts: {
        codeqlLanguage: language,
        codeqlCompileStatus: "not-run",
      },
      warnings: [
        language === "python"
          ? `CodeQL DB found for ${language}, but no taint-track catalog entries had enough source/sink specs for path generation; control CWEs use guard/context analysis.`
          : `CodeQL DB found for ${language}, but the bounded IRIS Next CodeQL adapter does not support that language yet; using structural evidence only.`,
      ],
    });
  }

  const workspaceDir = resolveCodeqlArtifactDir(plan, ctx, language);
  const queryPaths = queries.map((query) => path.join(workspaceDir, query.fileName));
  const artifacts = {
    codeqlLanguage: language,
    codeqlQueryPath: queryPaths[0]!,
    codeqlQueryPaths: queryPaths,
    codeqlCompileStatus: "not-run" as const,
    codeqlQueryStatuses: [] as NonNullable<
      TaintIrisNextEvidenceResult["artifacts"]
    >["codeqlQueryStatuses"],
  };
  let compilePassedCount = 0;
  const evidence: TaintIrisNextEvidence[] = [];
  try {
    mkdirSync(workspaceDir, { recursive: true });
    writeFileSync(
      path.join(workspaceDir, "qlpack.yml"),
      [
        "name: kuzushi/taint-iris-next-generated",
        "version: 0.0.0",
        "libraryPathDependencies:",
        `  - ${codeqlPackDependencyForLanguage(language)}`,
        "",
      ].join("\n"),
      "utf8",
    );
    for (const query of queries) {
      if (ctx.signal?.aborted) break;
      const queryPath = path.join(workspaceDir, query.fileName);
      writeFileSync(queryPath, query.query, "utf8");
      const compileTimeoutMs = corroborationOnly
        ? 10_000
        : Math.min(30_000, plan.caps.codeqlAnalyzeTimeoutMs);
      const compile = await compileCodeqlQuery(
        codeqlBin,
        queryPath,
        workspaceDir,
        ctx.signal,
        compileTimeoutMs,
      );
      if (!compile.ok) {
        const warning = `Generated ${language} CodeQL query for ${query.cwe} failed validation at ${queryPath}; skipped. ${compile.stderr || compile.stdout || "compile failed"}`;
        artifacts.codeqlQueryStatuses?.push({
          cwe: query.cwe,
          queryPath,
          compileStatus: "failed",
          analyzeStatus: "not-run",
          evidenceRows: 0,
          warning,
        });
        warnings.push(warning);
        continue;
      }
      compilePassedCount += 1;
      try {
        const before = evidence.length;
        const sarif = await runCodeQL(dbPath, codeqlBin, queryPath, {
          threads: 1,
          timeoutMs: plan.caps.codeqlAnalyzeTimeoutMs,
          ...resolveCodeqlPackOptions(),
        });
        const findings = selectFindings(sarif, path.basename(plan.repoRoot), "HEAD");
        evidence.push(...codeqlFindingsToEvidence(findings, plan));
        artifacts.codeqlQueryStatuses?.push({
          cwe: query.cwe,
          queryPath,
          compileStatus: "passed",
          analyzeStatus: "passed",
          evidenceRows: evidence.length - before,
        });
      } catch (error) {
        const warning = `CodeQL read-only analysis failed for ${query.cwe} at ${queryPath}; skipped. ${toErrorMessage(error)}`;
        artifacts.codeqlQueryStatuses?.push({
          cwe: query.cwe,
          queryPath,
          compileStatus: "passed",
          analyzeStatus: "failed",
          evidenceRows: 0,
          warning,
        });
        warnings.push(warning);
      }
    }
    return finalizeEvidenceResult(plan, {
      backend: "codeql",
      tool: "codeql",
      evidence,
      queryCount: queries.length,
      artifacts: {
        ...artifacts,
        codeqlCompileStatus: compilePassedCount > 0 ? "passed" : "failed",
      },
      warnings,
    });
  } catch (error) {
    return finalizeEvidenceResult(plan, {
      backend: "codeql",
      tool: "codeql",
      evidence: [],
      queryCount: queries.length,
      artifacts: {
        ...artifacts,
        codeqlCompileStatus: compilePassedCount > 0 ? "passed" : "failed",
      },
      warnings: [
        `CodeQL read-only analysis failed for ${language} in ${workspaceDir}; using structural evidence only. ${toErrorMessage(error)}`,
      ],
    });
  }
}

export function buildCodeqlCatalogQuery(plan: TaintIrisNextPlan, language: string): string | null {
  if (language === "python") return buildCodeqlCatalogQueries(plan, language)[0]?.query ?? null;
  if (language !== "javascript") return null;
  const clauses = buildCodeqlCandidateClauses(plan);
  if (clauses.length === 0) return null;
  return [
    "/**",
    " * @name Taint IRIS Next bounded catalog candidates",
    " * @description Bounded source/sink call candidates generated from the ranked Taint IRIS Next CWE catalog.",
    " * @kind problem",
    " * @problem.severity recommendation",
    " * @precision low",
    " * @id js/taint-iris-next/catalog-candidate",
    " */",
    "import javascript",
    "",
    "from CallExpr call, string callee, string cwe, string signal",
    "where",
    "  callee = call.getCallee().toString() and",
    "  (",
    clauses.map((clause) => `    ${clause}`).join("\n    or\n"),
    "  )",
    'select call, "Taint IRIS Next " + cwe + " catalog signal " + signal + " at call " + callee',
    "",
  ].join("\n");
}

export function buildCodeqlCatalogQueries(
  plan: TaintIrisNextPlan,
  language: string,
): Array<{ cwe: string; fileName: string; query: string }> {
  if (language !== "python") {
    const query = buildCodeqlCatalogQuery(plan, language);
    return query ? [{ cwe: "catalog", fileName: "iris-next-candidates.ql", query }] : [];
  }
  const queries: Array<{ cwe: string; fileName: string; query: string }> = [];
  for (const entry of plan.catalog) {
    if (trackForCatalogEntry(entry) !== "taint") continue;
    const query = buildPythonCodeqlCatalogQueryForEntry(plan, entry);
    if (!query) continue;
    queries.push({
      cwe: entry.cwe,
      fileName: `iris-next-${entry.cwe.toLowerCase()}.ql`,
      query,
    });
  }
  return queries;
}

function buildPythonCodeqlCatalogQueryForEntry(
  plan: TaintIrisNextPlan,
  entry: TaintIrisNextCweCatalogEntry,
): string | null {
  const sourceClauses = buildPythonSourceSpecClauses(plan, entry);
  const sinkClauses = buildPythonSinkSpecClauses(plan, entry);
  const sanitizerClauses = buildPythonSanitizerSpecClauses(plan, entry);
  if (sourceClauses.length === 0 || sinkClauses.length === 0) return null;
  const scopePredicate = renderPythonScanScopePredicate(plan);
  const sourcePredicate = renderChunkedPredicate(
    "irisSourceSpec",
    "string cwe, string signal",
    "cwe, signal",
    sourceClauses,
    PYTHON_CODEQL_PREDICATE_CHUNK_SIZE,
  );
  const sinkPredicate = renderChunkedPredicate(
    "irisSinkSpec",
    "string cwe, string signal, string token",
    "cwe, signal, token",
    sinkClauses,
    PYTHON_CODEQL_PREDICATE_CHUNK_SIZE,
  );
  const sanitizerPredicate =
    sanitizerClauses.length > 0
      ? renderChunkedPredicate(
          "irisSanitizerSpec",
          "string cwe, string signal, string token",
          "cwe, signal, token",
          sanitizerClauses,
          PYTHON_CODEQL_PREDICATE_CHUNK_SIZE,
        )
      : [
          "private predicate irisSanitizerSpec(string cwe, string signal, string token) {",
          "  none()",
          "}",
        ].join("\n");

  return [
    "/**",
    ` * @name Taint IRIS Next Python ${entry.cwe} taint paths`,
    ` * @description IRIS-style per-CWE Python source-to-sink paths for ${entry.name}.`,
    " * @kind path-problem",
    " * @problem.severity recommendation",
    " * @precision low",
    ` * @id py/taint-iris-next/${entry.cwe.toLowerCase()}-taint-path`,
    " * @tags security",
    " */",
    "import python",
    "import semmle.python.dataflow.new.DataFlow",
    "import semmle.python.dataflow.new.TaintTracking",
    "import semmle.python.dataflow.new.RemoteFlowSources",
    "",
    scopePredicate,
    "",
    sourcePredicate,
    "",
    sinkPredicate,
    "",
    sanitizerPredicate,
    "",
    "private predicate irisSourceNode(DataFlow::Node node, string cwe, string signal) {",
    "  node instanceof RemoteFlowSource and irisSourceSpec(cwe, signal)",
    "}",
    "",
    "private predicate irisSinkNode(DataFlow::Node node, string cwe, string signal) {",
    "  exists(DataFlow::CallCfgNode call, string token |",
    "    (node = call or node = call.getArg(_)) and",
    "    irisSinkSpec(cwe, signal, token) and",
    '    (call.getFunction().toString().matches("%" + token + "%") or call.toString().matches("%" + token + "%"))',
    "  )",
    "}",
    "",
    "private predicate irisSanitizerNode(DataFlow::Node node) {",
    "  exists(DataFlow::CallCfgNode call, string cwe, string signal, string token |",
    "    (node = call or node = call.getArg(_)) and",
    "    irisSanitizerSpec(cwe, signal, token) and",
    '    (call.getFunction().toString().matches("%" + token + "%") or call.toString().matches("%" + token + "%"))',
    "  )",
    "}",
    "",
    "private module IrisNextPythonConfig implements DataFlow::ConfigSig {",
    "  predicate isSource(DataFlow::Node source) { irisSourceNode(source, _, _) and irisInScanScope(source) }",
    "  predicate isSink(DataFlow::Node sink) { irisSinkNode(sink, _, _) and irisInScanScope(sink) }",
    "  predicate isBarrier(DataFlow::Node node) { irisSanitizerNode(node) }",
    "  predicate observeDiffInformedIncrementalMode() { any() }",
    "}",
    "",
    "module IrisNextPythonFlow = TaintTracking::Global<IrisNextPythonConfig>;",
    "import IrisNextPythonFlow::PathGraph",
    "",
    "from IrisNextPythonFlow::PathNode source, IrisNextPythonFlow::PathNode sink, string cwe, string sourceSignal, string sinkSignal",
    "where",
    "  IrisNextPythonFlow::flowPath(source, sink) and",
    "  irisSourceNode(source.getNode(), cwe, sourceSignal) and",
    "  irisSinkNode(sink.getNode(), cwe, sinkSignal) and",
    "  irisInScanScope(sink.getNode())",
    'select sink.getNode(), source, sink, "Taint IRIS Next " + cwe + " path from $@ to sink catalog signal " + sinkSignal + ".", source.getNode(), sourceSignal',
    "",
  ].join("\n");
}

export function codeqlFindingsToEvidence(
  findings: readonly Finding[],
  plan: TaintIrisNextPlan,
): TaintIrisNextEvidence[] {
  const evidence: TaintIrisNextEvidence[] = [];
  const seen = new Set<string>();
  const perCweCount = new Map<string, number>();

  for (const finding of findings) {
    if (!findingHasScanRootEvidence(finding, plan)) continue;
    const catalogEntries = matchFindingCatalogEntries(finding, plan.catalog);
    for (const entry of catalogEntries) {
      if ((perCweCount.get(entry.cwe) ?? 0) >= plan.caps.maxEvidencePerCwe) continue;
      const irisMessage = parseIrisNextCodeqlMessage(finding.message);

      const steps =
        finding.taintPath && finding.taintPath.length > 0
          ? finding.taintPath
          : [
              {
                filePath: finding.filePath,
                line: finding.startLine,
                message: finding.message,
                snippet: finding.evidence ?? undefined,
              },
            ];

      for (const [index, step] of steps.entries()) {
        if ((perCweCount.get(entry.cwe) ?? 0) >= plan.caps.maxEvidencePerCwe) break;
        const normalizedStepPath = normalizePath(plan.repoRoot, step.filePath);
        if (!isPathInPlanScanRoot(plan, normalizedStepPath)) continue;
        const role = roleForCodeqlStep(index, steps.length);
        const key = `${entry.cwe}:${role}:${step.filePath}:${step.line}:${finding.ruleId}`;
        if (seen.has(key)) continue;
        seen.add(key);
        perCweCount.set(entry.cwe, (perCweCount.get(entry.cwe) ?? 0) + 1);
        evidence.push({
          cwe: entry.cwe,
          taintClass: entry.taintClass,
          track: trackForCatalogEntry(entry),
          role,
          pattern: finding.ruleId,
          filePath: normalizedStepPath,
          line: Math.max(1, step.line),
          snippet: step.snippet ?? step.message ?? finding.message,
          language: languageForPath(step.filePath),
          confidence: confidenceForCodeqlFinding(finding),
          catalogSignal: irisMessage
            ? `codeql: ${irisMessage.cwe} source=${irisMessage.sourceSignal} sink=${irisMessage.sinkSignal}`
            : `codeql: ${finding.ruleId}`,
          evidenceLevel: "path",
          source: "codeql",
        });
      }
    }
  }

  return evidence;
}

function finalizeEvidenceResult(
  plan: TaintIrisNextPlan,
  base: {
    backend: TaintIrisNextEvidenceResult["backend"];
    tool: TaintIrisNextEvidenceResult["tool"];
    evidence: readonly TaintIrisNextEvidence[];
    queryCount: number;
    warnings: readonly string[];
    artifacts?: TaintIrisNextEvidenceResult["artifacts"];
  },
): TaintIrisNextEvidenceResult {
  const candidateSeedEvidence = addImplicitSourceEvidence(
    plan,
    filterNoisyStructuralEvidence(
      enrichEvidenceWithLocalContext(
        plan,
        base.evidence.map((item) => ({
          ...item,
          evidenceLevel: item.evidenceLevel ?? "candidate",
        })),
      ),
    ),
  );
  const candidates = buildCandidatesFromEvidence(plan, candidateSeedEvidence);
  const linkedStories = linkTaintCandidates(candidates);
  const evidence = applyLinkedStoriesToEvidence(candidateSeedEvidence, linkedStories);
  const labeledSpecs = inferLabeledSpecsFromCandidates(plan, candidates);
  const outcome =
    base.backend === "codeql" &&
    !evidence.some((item) => item.evidenceLevel === "path") &&
    base.artifacts?.codeqlCompileStatus === "passed"
      ? "backend-no-paths"
      : determineEvidenceOutcome(evidence, base.warnings);
  const result = {
    backend: base.backend,
    tool: base.tool,
    evidence,
    candidates,
    linkedStories,
    labeledSpecs,
    queryCount: base.queryCount,
    candidateCounts: summarizeCountsByCwe(candidates),
    labeledSpecCounts: summarizeCountsByCwe(labeledSpecs),
    linkedStoryCount: linkedStories.length,
    backendPathCount: evidence.filter((item) => item.evidenceLevel === "path").length,
    structuralEngine: plan.backend.structuralTool,
    triageSummary: { finding: 0, candidate: 0, rejected: 0 },
    outcome,
    legacyComparisonStatus: "not-compared",
    warnings: [...base.warnings],
  } satisfies Omit<TaintIrisNextEvidenceResult, "artifacts">;
  return base.artifacts ? { ...result, artifacts: base.artifacts } : result;
}

interface StructuralMatch {
  filePath: string;
  line: number;
  snippet: string;
  language?: string;
  catalogSignal?: string;
  callExpression?: string;
}

interface SourceFileContext {
  absolutePath: string;
  lines: string[];
}

interface PythonScopeContext {
  name: string;
  line: number;
  snippet: string;
  params: string[];
}

function enrichEvidenceWithLocalContext(
  plan: TaintIrisNextPlan,
  evidence: readonly TaintIrisNextEvidence[],
): TaintIrisNextEvidence[] {
  const fileCache = new Map<string, SourceFileContext | undefined>();
  return evidence.map((item) => {
    const file = loadSourceFileContext(plan, item.filePath, fileCache);
    if (!file || item.language !== "python") return item;
    const scope = findPythonScope(file, item.line);
    const nearbySanitizers = scope ? findNearbyPythonSanitizers(file, scope, item.line) : [];
    return {
      ...item,
      ...(scope ? { enclosingSymbol: scope.name } : {}),
      ...(nearbySanitizers.length > 0 ? { nearbySanitizers } : {}),
    };
  });
}

function addImplicitSourceEvidence(
  plan: TaintIrisNextPlan,
  evidence: readonly TaintIrisNextEvidence[],
): TaintIrisNextEvidence[] {
  const out: TaintIrisNextEvidence[] = [...evidence];
  const fileCache = new Map<string, SourceFileContext | undefined>();
  const seen = new Set(
    out.map((item) => `${item.cwe}:${item.role}:${item.filePath}:${item.line}:${item.pattern}`),
  );

  for (const sink of evidence) {
    if (sink.role !== "sink") continue;
    if (sink.track === "control" || trackForTaintClass(sink.taintClass) === "control") continue;
    if (sink.language !== "python") continue;
    if (!isActionablePythonTaintSink(sink)) continue;

    const file = loadSourceFileContext(plan, sink.filePath, fileCache);
    if (!file) continue;
    const scope = findPythonScope(file, sink.line);
    if (!scope || scope.params.length === 0) continue;

    const sourceParams = scope.params
      .filter((param) => isLikelyUntrustedPythonParam(param, sink))
      .sort((left, right) => comparePythonSourceParamsForSink(left, right, sink))
      .slice(0, 2);
    for (const param of sourceParams) {
      if (hasSourceForScope(out, sink, scope, param)) continue;
      const pattern = `implicit-param:${param}`;
      const key = `${sink.cwe}:source:${sink.filePath}:${scope.line}:${pattern}`;
      if (seen.has(key)) continue;
      seen.add(key);
      out.push({
        cwe: sink.cwe,
        taintClass: sink.taintClass,
        track: "taint",
        role: "source",
        pattern,
        filePath: sink.filePath,
        line: scope.line,
        snippet: scope.snippet,
        language: sink.language,
        confidence: "medium",
        catalogSignal: `source: implicit function parameter ${param} near ${sink.catalogSignal}`,
        evidenceLevel: "candidate",
        source: "structural",
        enclosingSymbol: scope.name,
        assignedVariable: param,
      });
    }
  }

  return out;
}

function filterNoisyStructuralEvidence(
  evidence: readonly TaintIrisNextEvidence[],
): TaintIrisNextEvidence[] {
  return evidence.filter(shouldKeepStructuralEvidence);
}

function shouldKeepStructuralEvidence(item: TaintIrisNextEvidence): boolean {
  if (item.source === "codeql") return true;
  if (item.role !== "sink") return true;
  if (item.language !== "python") return true;
  if (item.track === "control" || trackForTaintClass(item.taintClass) === "control") return true;
  return isActionablePythonTaintSink(item);
}

function hasSourceForScope(
  evidence: readonly TaintIrisNextEvidence[],
  sink: TaintIrisNextEvidence,
  scope: PythonScopeContext,
  param: string,
): boolean {
  const paramRegex = new RegExp(`\\b${escapeRegex(param)}\\b`, "u");
  return evidence.some(
    (item) =>
      item.cwe === sink.cwe &&
      item.role === "source" &&
      item.filePath === sink.filePath &&
      item.enclosingSymbol === scope.name &&
      (paramRegex.test(item.snippet) || item.assignedVariable === param),
  );
}

function loadSourceFileContext(
  plan: TaintIrisNextPlan,
  filePath: string,
  cache: Map<string, SourceFileContext | undefined>,
): SourceFileContext | undefined {
  const absolutePath = path.isAbsolute(filePath) ? filePath : path.join(plan.repoRoot, filePath);
  if (cache.has(absolutePath)) return cache.get(absolutePath);
  try {
    const stat = statSync(absolutePath);
    if (!stat.isFile() || stat.size > 2_000_000) {
      cache.set(absolutePath, undefined);
      return undefined;
    }
    const context = {
      absolutePath,
      lines: readFileSync(absolutePath, "utf8").split(/\r?\n/u),
    };
    cache.set(absolutePath, context);
    return context;
  } catch {
    cache.set(absolutePath, undefined);
    return undefined;
  }
}

function findPythonScope(file: SourceFileContext, line: number): PythonScopeContext | undefined {
  const targetIndex = Math.max(0, Math.min(file.lines.length - 1, line - 1));
  const targetLine = file.lines[targetIndex] ?? "";
  for (let index = targetIndex; index >= 0; index -= 1) {
    const def = parsePythonDefAt(file, index);
    if (!def) continue;
    const indent = def.indent;
    if (index !== targetIndex && targetLine.trim() && countIndent(targetLine) <= indent) {
      return undefined;
    }
    return {
      name: def.name,
      line: index + 1,
      snippet: def.snippet,
      params: def.params,
    };
  }
  return undefined;
}

function parsePythonDefAt(
  file: SourceFileContext,
  index: number,
): { name: string; indent: number; snippet: string; params: string[] } | undefined {
  const current = file.lines[index] ?? "";
  const start = current.match(/^(\s*)(?:async\s+def|def)\s+([A-Za-z_][\w]*)\s*\((.*)$/u);
  if (!start) return undefined;
  const headerLines = [current.trim()];
  for (let next = index + 1; next < Math.min(file.lines.length, index + 8); next += 1) {
    if (headerLines.join(" ").includes("):")) break;
    headerLines.push((file.lines[next] ?? "").trim());
  }
  const header = headerLines.join(" ");
  const paramsMatch = header.match(/\((.*)\)\s*:/u);
  return {
    name: start[2]!,
    indent: countIndent(start[1] ?? ""),
    snippet: header,
    params: parsePythonParams(paramsMatch?.[1] ?? ""),
  };
}

function parsePythonParams(raw: string): string[] {
  return raw
    .split(",")
    .map((part) =>
      part
        .trim()
        .replace(/=.*/u, "")
        .replace(/:.*/u, "")
        .replace(/^[*/]+/u, "")
        .trim(),
    )
    .filter((param) => /^[A-Za-z_][\w]*$/u.test(param))
    .filter((param) => param !== "self" && param !== "cls");
}

function findNearbyPythonSanitizers(
  file: SourceFileContext,
  scope: PythonScopeContext,
  line: number,
): string[] {
  const targetIndex = Math.max(0, line - 1);
  const start = Math.max(scope.line - 1, targetIndex - 20);
  const end = Math.min(file.lines.length, targetIndex + 20);
  const sanitizers = new Set<string>();
  for (let index = start; index < end; index += 1) {
    const text = file.lines[index]?.trim() ?? "";
    const match = text.match(
      /\b(validate|sanitize|escape|quote|allowlist|normpath|resolve|safe_load)\b/iu,
    );
    if (match?.[1]) sanitizers.add(match[1]);
  }
  return [...sanitizers].slice(0, 5);
}

function isActionablePythonTaintSink(item: TaintIrisNextEvidence): boolean {
  const text = item.snippet.trim();
  if (!text || text.startsWith("#")) return false;
  if (/^(?:from\s+\S+\s+import|import\s+|def\s+|async\s+def\s+|class\s+)/u.test(text)) {
    return false;
  }
  if (/getLogger|get_logger/u.test(text)) return false;
  if (/"""|'''/u.test(text) && !/[A-Za-z_][\w.]*\s*\(/u.test(text)) return false;

  const taintClass = item.taintClass;
  if (taintClass === "command-injection" || taintClass === "os-command-injection") {
    return /\b(?:subprocess\.(?:Popen|run|call|check_call|check_output)|Popen\s*\(|check_output\s*\(|os\.system\s*\(|docker\s+exec|shell\s*=|exec\(|popen\()/iu.test(
      text,
    );
  }
  if (taintClass === "sql-injection" || taintClass === "nosql-injection") {
    return (
      /\b(?:execute|query|raw|find_by_sql|aggregate|findOne)\s*\(/iu.test(text) ||
      /^\s*query\s*=/iu.test(text)
    );
  }
  if (taintClass === "ssrf") {
    return /\b(?:requests|httpx|urllib|aiohttp)\b.*\(/iu.test(text) || /\bfetch\s*\(/iu.test(text);
  }
  if (taintClass === "path-traversal" || taintClass === "external-file-control") {
    return /\b(?:open|send_file|Path|readFile|writeFile|rename|copy|unlink)\s*\(/iu.test(text);
  }
  if (taintClass === "deserialization") {
    return /\b(?:pickle\.loads?|yaml\.load|jsonpickle|marshal\.loads|ObjectInputStream|json\.loads)\s*\(/iu.test(
      text,
    );
  }
  if (taintClass === "xss") {
    return /\b(?:render|render_template|render_template_string|Template|html|send|Response)\b.*\(/iu.test(
      text,
    );
  }
  if (taintClass === "xxe") {
    return /\b(?:lxml|ElementTree|XMLParser|parse|fromstring)\s*\(/iu.test(text);
  }
  if (taintClass === "log-injection") {
    return /\b(?:logger|log)\.(?:debug|info|warning|error|exception|critical)\s*\(/iu.test(text);
  }
  if (taintClass === "open-redirect" || taintClass === "header-injection") {
    return /\b(?:redirect|RedirectResponse|setHeader|headers?\.|response\.headers)\b.*\(/iu.test(
      text,
    );
  }
  return /[A-Za-z_][\w.]*\s*\(/u.test(text);
}

function isLikelyUntrustedPythonParam(param: string, sink: TaintIrisNextEvidence): boolean {
  const normalized = param.toLowerCase();
  if (PYTHON_TRUSTED_PARAM_NAMES.has(normalized)) return false;
  if (new RegExp(`\\b${escapeRegex(param)}\\b`, "u").test(sink.snippet)) return true;
  return PYTHON_SOURCE_PARAM_RE.test(normalized);
}

function comparePythonSourceParamsForSink(
  left: string,
  right: string,
  sink: TaintIrisNextEvidence,
): number {
  return pythonSourceParamScore(right, sink) - pythonSourceParamScore(left, sink);
}

function pythonSourceParamScore(param: string, sink: TaintIrisNextEvidence): number {
  const normalized = param.toLowerCase();
  let score = 0;
  if (new RegExp(`\\b${escapeRegex(param)}\\b`, "u").test(sink.snippet)) score += 8;
  if (/(?:cmd|command|exec|shell)/u.test(normalized)) score += 6;
  if (/(?:url|uri|host|origin|callback)/u.test(normalized)) score += 5;
  if (/(?:path|file|filename)/u.test(normalized)) score += 5;
  if (/(?:query|sql|filter)/u.test(normalized)) score += 5;
  if (/(?:request|req|body|payload|event|message|input|data)/u.test(normalized)) score += 4;
  return score;
}

function countIndent(value: string): number {
  let count = 0;
  for (const char of value) {
    count += char === "\t" ? 4 : 1;
  }
  return count;
}

function escapeRegex(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/gu, "\\$&");
}

const PYTHON_SOURCE_PARAM_RE =
  /(?:arg|argv|body|callback|cmd|command|container|data|event|exec|file|filename|filter|header|host|input|key|message|name|option|origin|path|payload|query|request|req|sql|token|url|uri|user)/u;

const PYTHON_TRUSTED_PARAM_NAMES = new Set([
  "client",
  "conn",
  "connection",
  "cursor",
  "db",
  "logger",
  "session",
]);

async function runStructuralQuery(
  query: TaintIrisNextStructuralQuery,
  plan: TaintIrisNextPlan,
  signal: AbortSignal | undefined,
  warnings: string[],
  budget: { astGrepRemaining: number },
): Promise<StructuralMatch[]> {
  if (
    plan.backend.structuralTool === "ast-grep" &&
    query.role !== "source" &&
    budget.astGrepRemaining > 0
  ) {
    const matches = await runAstGrepQuery(query, plan, signal, warnings, budget);
    if (matches.length > 0) return matches;
  }

  const result = await runStructuralSearch(query.pattern, plan.scanRoot, plan.repoRoot, signal);
  if (result.error) {
    warnings.push(result.error);
    return [];
  }
  if (result.code !== 0 && result.code !== 1) {
    warnings.push(`rg exited ${result.code} for ${query.cwe} ${query.role}:${query.pattern}`);
    return [];
  }

  const matches = result.stdout.split(/\r?\n/u).flatMap((line) => {
    if (!line.trim()) return [];
    const parsed = parseRgLine(line, plan.repoRoot);
    return parsed ? [parsed] : [];
  });
  if (matches.length > 0 || query.role !== "source") return matches;

  const tokenMatches: StructuralMatch[] = [];
  const seen = new Set<string>();
  for (const token of fallbackSourceTokens(query.pattern)) {
    const tokenResult = await runStructuralSearch(token, plan.scanRoot, plan.repoRoot, signal);
    if (tokenResult.code !== 0 && tokenResult.code !== 1) continue;
    for (const line of tokenResult.stdout.split(/\r?\n/u)) {
      if (!line.trim()) continue;
      const parsed = parseRgLine(line, plan.repoRoot);
      if (!parsed) continue;
      const key = `${parsed.filePath}:${parsed.line}:${parsed.snippet}`;
      if (seen.has(key)) continue;
      seen.add(key);
      tokenMatches.push({
        ...parsed,
        catalogSignal: `${query.role}: ${query.pattern} [token:${token}]`,
      });
    }
  }
  return tokenMatches;
}

async function runAstGrepQuery(
  query: TaintIrisNextStructuralQuery,
  plan: TaintIrisNextPlan,
  signal: AbortSignal | undefined,
  warnings: string[],
  budget: { astGrepRemaining: number },
): Promise<StructuralMatch[]> {
  const command = resolveAstGrepCommand();
  if (!command) {
    warnings.push(
      "ast-grep requested for structural extraction, but ast-grep/sg is unavailable; using rg",
    );
    return [];
  }

  const patterns = buildAstGrepPatternsForQuery(query, plan.languages);
  const out: StructuralMatch[] = [];
  const seen = new Set<string>();
  for (const item of patterns) {
    if (signal?.aborted) break;
    if (budget.astGrepRemaining <= 0) break;
    budget.astGrepRemaining -= 1;
    const result = await runAstGrepPattern(command, item.language, item.pattern, plan, signal);
    if (result.error) {
      warnings.push(result.error);
      continue;
    }
    if (result.code !== 0 && result.code !== 1) {
      warnings.push(
        `ast-grep exited ${result.code} for ${query.cwe} ${item.language}:${item.pattern}`,
      );
      continue;
    }
    const parsed = astGrepJsonToStructuralMatches(
      result.stdout,
      plan.repoRoot,
      `${query.role}: ${query.pattern} [ast-grep:${item.pattern}]`,
    );
    for (const match of parsed) {
      const key = `${match.filePath}:${match.line}:${match.snippet}`;
      if (seen.has(key)) continue;
      seen.add(key);
      out.push(match);
    }
  }
  return out;
}

export function buildAstGrepPatternsForQuery(
  query: TaintIrisNextStructuralQuery,
  languageHints: readonly string[],
): Array<{ language: string; pattern: string }> {
  const token = normalizeAstGrepToken(query.pattern);
  if (!token) return [];
  const languages = resolveAstGrepLanguages(query.languages, languageHints);
  const patterns = new Set<string>();
  for (const language of languages) {
    for (const pattern of patternsForLanguage(language, token)) {
      patterns.add(`${language}\u0000${pattern}`);
    }
  }
  return [...patterns].map((item) => {
    const [language, pattern] = item.split("\u0000");
    return { language: language!, pattern: pattern! };
  });
}

export function astGrepJsonToStructuralMatches(
  stdout: string,
  repoRoot: string,
  catalogSignal?: string,
): StructuralMatch[] {
  const trimmed = stdout.trim();
  if (!trimmed) return [];
  let parsed: unknown;
  try {
    parsed = trimmed.startsWith("[")
      ? (JSON.parse(trimmed) as unknown)
      : trimmed
          .split(/\r?\n/u)
          .filter(Boolean)
          .map((line) => JSON.parse(line) as unknown);
  } catch {
    return [];
  }
  const rows = Array.isArray(parsed) ? parsed : [parsed];
  return rows.flatMap((row) => {
    if (!isRecord(row)) return [];
    const file = typeof row["file"] === "string" ? row["file"] : "";
    const range = isRecord(row["range"]) ? row["range"] : undefined;
    const start = range && isRecord(range["start"]) ? range["start"] : undefined;
    const rawLine = Number(start?.["line"]);
    const snippet =
      typeof row["lines"] === "string"
        ? row["lines"].trim()
        : typeof row["text"] === "string"
          ? row["text"].trim()
          : "";
    if (!file || !Number.isFinite(rawLine) || !snippet) return [];
    const rawLanguage = typeof row["language"] === "string" ? row["language"] : undefined;
    return [
      {
        filePath: normalizePath(repoRoot, file),
        line: Math.max(1, Math.floor(rawLine) + 1),
        snippet,
        ...(rawLanguage ? { language: normalizeAstGrepLanguage(rawLanguage) } : {}),
        ...(catalogSignal ? { catalogSignal } : {}),
        callExpression: typeof row["text"] === "string" ? row["text"].trim() : snippet,
      },
    ];
  });
}

function runAstGrepPattern(
  command: string,
  language: string,
  pattern: string,
  plan: TaintIrisNextPlan,
  signal: AbortSignal | undefined,
): Promise<{ code: number | null; stdout: string; stderr: string; error?: string }> {
  const args = [
    "run",
    "--pattern",
    pattern,
    "--lang",
    language,
    "--json=compact",
    ...AST_GREP_IGNORE_GLOBS.flatMap((glob) => ["--globs", glob]),
    plan.scanRoot,
  ];

  return new Promise((resolve) => {
    const child = spawn(command, args, { cwd: plan.repoRoot, signal });
    const stdout: Buffer[] = [];
    const stderr: Buffer[] = [];
    let timedOut = false;
    const timer = setTimeout(() => {
      timedOut = true;
      child.kill("SIGTERM");
    }, AST_GREP_QUERY_TIMEOUT_MS);
    child.stdout.on("data", (chunk: Buffer) => stdout.push(chunk));
    child.stderr.on("data", (chunk: Buffer) => stderr.push(chunk));
    child.on("error", (error) => {
      clearTimeout(timer);
      resolve({
        code: null,
        stdout: Buffer.concat(stdout).toString("utf8"),
        stderr: Buffer.concat(stderr).toString("utf8"),
        error: `ast-grep unavailable for structural extraction: ${error.message}`,
      });
    });
    child.on("close", (code) => {
      clearTimeout(timer);
      resolve({
        code,
        stdout: Buffer.concat(stdout).toString("utf8"),
        stderr: timedOut
          ? `ast-grep query timed out after ${AST_GREP_QUERY_TIMEOUT_MS}ms`
          : Buffer.concat(stderr).toString("utf8"),
        ...(timedOut
          ? { error: `ast-grep query timed out after ${AST_GREP_QUERY_TIMEOUT_MS}ms` }
          : {}),
      });
    });
  });
}

const AST_GREP_IGNORE_GLOBS = [
  "!**/.git/**",
  "!**/.kuzushi/**",
  "!**/node_modules/**",
  "!**/vendor/**",
  "!**/dist/**",
  "!**/build/**",
  "!**/coverage/**",
  "!**/.next/**",
  "!**/.turbo/**",
  "!**/target/**",
  "!**/__pycache__/**",
  "!**/test/**",
  "!**/tests/**",
  "!**/*_test.py",
  "!**/*.test.ts",
  "!**/*.spec.ts",
];

function resolveAstGrepCommand(): string | undefined {
  return resolveExecutableFromPath("ast-grep") ?? resolveExecutableFromPath("sg");
}

function resolveExecutableFromPath(command: string): string | undefined {
  for (const dir of (process.env.PATH ?? "").split(path.delimiter)) {
    if (!dir) continue;
    const candidate = path.join(dir, command);
    try {
      const stat = statSync(candidate);
      if (stat.isFile()) return candidate;
    } catch {
      // Continue scanning PATH.
    }
  }
  return undefined;
}

function resolveAstGrepLanguages(
  queryLanguages: readonly string[],
  languageHints: readonly string[],
): string[] {
  const languages = new Set<string>();
  const normalizedHints = languageHints
    .map(normalizeAstGrepLanguage)
    .filter((language) => AST_GREP_LANGUAGES.has(language));
  const sourceLanguages =
    queryLanguages.some((language) => normalizeAstGrepLanguage(language) === "any") &&
    normalizedHints.length > 0
      ? normalizedHints
      : [...queryLanguages, ...languageHints];

  for (const language of sourceLanguages) {
    const normalized = normalizeAstGrepLanguage(language);
    if (normalized === "any") {
      for (const supported of AST_GREP_LANGUAGES) languages.add(supported);
    } else if (AST_GREP_LANGUAGES.has(normalized)) {
      languages.add(normalized);
    }
  }
  if (languages.size === 0) {
    for (const supported of AST_GREP_LANGUAGES) languages.add(supported);
  }
  return [...languages].sort();
}

function patternsForLanguage(language: string, token: string): string[] {
  const callToken = token.includes(".") ? token : token.replace(/[^A-Za-z0-9_$]/gu, "");
  if (!callToken || /^\d/u.test(callToken)) return [];
  if (language === "python") {
    return [`${callToken}($$$ARGS)`, `$RECEIVER.${callToken}($$$ARGS)`];
  }
  if (language === "ruby") {
    return [`${callToken}($$$ARGS)`, `${callToken} $$$ARGS`, `$RECEIVER.${callToken}($$$ARGS)`];
  }
  if (language === "rust") {
    return [
      `${callToken}($$$ARGS)`,
      `$RECEIVER.${callToken}($$$ARGS)`,
      `${callToken}::new($$$ARGS)`,
    ];
  }
  return [`${callToken}($$$ARGS)`, `$RECEIVER.${callToken}($$$ARGS)`, `new ${callToken}($$$ARGS)`];
}

function normalizeAstGrepToken(pattern: string): string | undefined {
  const trimmed = pattern.trim();
  if (trimmed.length < 3) return undefined;
  const call = trimmed.match(/^([A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)*)\s*\(/u);
  if (call?.[1]) return call[1];
  const bare = trimmed
    .replace(/[()[\]{}'"`]/gu, "")
    .replace(/::$/u, "")
    .trim();
  if (!/^[A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)?$/u.test(bare)) return undefined;
  return bare;
}

function normalizeAstGrepLanguage(language: string): string {
  const normalized = language.trim().toLowerCase();
  if (normalized === "js" || normalized === "jsx") return "javascript";
  if (normalized === "ts" || normalized === "tsx") return "typescript";
  if (normalized === "py") return "python";
  if (normalized === "rb") return "ruby";
  if (normalized === "rs") return "rust";
  return normalized;
}

function fallbackSourceTokens(pattern: string): string[] {
  const tokens = pattern
    .toLowerCase()
    .match(/[a-z_][a-z0-9_]{2,}/gu)
    ?.filter((token) => !SOURCE_TOKEN_STOPWORDS.has(token));
  return [...new Set(tokens ?? [])].slice(0, 3);
}

const SOURCE_TOKEN_STOPWORDS = new Set([
  "arg",
  "args",
  "body",
  "data",
  "field",
  "input",
  "parameter",
  "payload",
]);

function runRg(
  pattern: string,
  scanRoot: string,
  repoRoot: string,
  signal: AbortSignal | undefined,
): Promise<StructuralSearchResult> {
  const searchPath = relativeSearchPath(repoRoot, scanRoot);
  const args = [
    "--line-number",
    "--no-heading",
    "--color",
    "never",
    "--fixed-strings",
    ...RG_IGNORE_GLOBS.flatMap((glob) => ["--glob", glob]),
    "--",
    pattern,
    searchPath,
  ];

  return new Promise((resolve) => {
    const child = spawn("rg", args, { cwd: repoRoot, signal });
    const stdout: Buffer[] = [];
    const stderr: Buffer[] = [];
    child.stdout.on("data", (chunk: Buffer) => stdout.push(chunk));
    child.stderr.on("data", (chunk: Buffer) => stderr.push(chunk));
    child.on("error", (error) => {
      resolve({
        code: null,
        stdout: Buffer.concat(stdout).toString("utf8"),
        stderr: Buffer.concat(stderr).toString("utf8"),
        error: `rg unavailable for structural extraction: ${error.message}`,
      });
    });
    child.on("close", (code) => {
      resolve({
        code,
        stdout: Buffer.concat(stdout).toString("utf8"),
        stderr: Buffer.concat(stderr).toString("utf8"),
      });
    });
  });
}

async function runStructuralSearch(
  pattern: string,
  scanRoot: string,
  repoRoot: string,
  signal: AbortSignal | undefined,
): Promise<StructuralSearchResult> {
  const rgResult = await runRg(pattern, scanRoot, repoRoot, signal);
  if (!rgResult.error) return rgResult;
  const fallbackResult = runFilesystemSearch(pattern, scanRoot, repoRoot);
  return { ...fallbackResult, warnings: [rgResult.error] };
}

function runFilesystemSearch(
  pattern: string,
  scanRoot: string,
  repoRoot: string,
): StructuralSearchResult {
  const root = resolveSearchRoot(scanRoot, repoRoot);
  const stdout = collectSearchFiles(root)
    .flatMap((filePath) => searchTextFile(pattern, filePath, repoRoot))
    .join("\n");
  return { code: stdout ? 0 : 1, stdout, stderr: "" };
}

function resolveSearchRoot(scanRoot: string, repoRoot: string): string {
  return path.isAbsolute(scanRoot) ? scanRoot : path.resolve(repoRoot, scanRoot);
}

function collectSearchFiles(root: string): string[] {
  const files: string[] = [];
  visitSearchDirectory(root, files);
  return files;
}

function visitSearchDirectory(directory: string, files: string[]): void {
  let entries: Dirent[];
  try {
    entries = readdirSync(directory, { withFileTypes: true });
  } catch {
    return;
  }
  for (const entry of entries) {
    const entryPath = path.join(directory, entry.name);
    if (entry.isDirectory() && shouldSearchDirectory(entry.name)) {
      visitSearchDirectory(entryPath, files);
    } else if (entry.isFile()) {
      files.push(entryPath);
    }
  }
}

function shouldSearchDirectory(name: string): boolean {
  return !FALLBACK_IGNORED_DIRECTORIES.has(name);
}

function searchTextFile(pattern: string, filePath: string, repoRoot: string): string[] {
  let body: string;
  try {
    body = readFileSync(filePath, "utf8");
  } catch {
    return [];
  }
  if (body.includes("\u0000")) return [];
  const relativePath = normalizePath(repoRoot, filePath);
  return body
    .split(/\r?\n/u)
    .flatMap((line, index) =>
      line.includes(pattern) ? [`${relativePath}:${index + 1}:${line}`] : [],
    );
}

function mergeEvidence(
  structural: readonly TaintIrisNextEvidence[],
  codeql: readonly TaintIrisNextEvidence[],
  maxEvidencePerCwe: number,
): TaintIrisNextEvidence[] {
  const merged: TaintIrisNextEvidence[] = [];
  const seen = new Set<string>();
  const perCweRoleCount = new Map<string, number>();

  for (const item of [...codeql, ...structural]) {
    if (roleCount(perCweRoleCount, item.cwe, item.role) >= maxEvidencePerCwe) continue;
    const key = `${item.cwe}:${item.role}:${item.filePath}:${item.line}:${item.pattern}`;
    if (seen.has(key)) continue;
    seen.add(key);
    incrementRoleCount(perCweRoleCount, item.cwe, item.role);
    merged.push(item);
  }

  return merged;
}

function roleCount(
  counts: ReadonlyMap<string, number>,
  cwe: string,
  role: TaintIrisNextEvidence["role"],
): number {
  return counts.get(`${cwe}:${role}`) ?? 0;
}

function incrementRoleCount(
  counts: Map<string, number>,
  cwe: string,
  role: TaintIrisNextEvidence["role"],
): void {
  const key = `${cwe}:${role}`;
  counts.set(key, (counts.get(key) ?? 0) + 1);
}

function resolveConfiguredCodeqlBinary(ctx: ExecutionContext): string | undefined {
  const codeqlConfig = ctx.config.taskConfig?.["codeql"];
  if (!isRecord(codeqlConfig)) return undefined;
  const binary = codeqlConfig["binary"];
  return typeof binary === "string" && binary.trim() ? binary.trim() : undefined;
}

function resolveCodeqlArtifactDir(
  plan: TaintIrisNextPlan,
  ctx: ExecutionContext,
  language: string,
): string {
  const runId = resolveRunArtifactId(ctx);
  const segment = sanitizePathSegment(`${language}-${runId}`);
  const root = path.join(plan.repoRoot, ".kuzushi", "runs", sanitizePathSegment(runId));
  return path.join(root, "taint-iris-next", segment);
}

function resolveRunArtifactId(ctx: ExecutionContext): string {
  if (ctx.dag?.runId) return ctx.dag.runId;
  if (ctx.workspaceId) return `workspace-${ctx.workspaceId}`;
  const toolName = ctx.tool?.name ? sanitizePathSegment(ctx.tool.name) : "tool";
  return `${toolName}-${Date.now().toString(36)}`;
}

function codeqlPackDependencyForLanguage(language: string): string {
  if (language === "python") return "codeql/python-all";
  if (language === "javascript") return "codeql/javascript-all";
  return `codeql/${language}-all`;
}

function compileCodeqlQuery(
  codeqlBin: string,
  queryPath: string,
  workspaceDir: string,
  signal: AbortSignal | undefined,
  timeoutMs: number,
): Promise<{ ok: boolean; stdout: string; stderr: string }> {
  const packOptions = resolveCodeqlPackOptions();
  const searchPath = [workspaceDir, packOptions.searchPath].filter(Boolean).join(path.delimiter);
  const args = ["query", "compile", queryPath, `--search-path=${searchPath}`];
  if (packOptions.additionalPacks) args.push(`--additional-packs=${packOptions.additionalPacks}`);
  return new Promise((resolve) => {
    const child = spawn(codeqlBin, args, { signal, detached: true });
    const stdout: Buffer[] = [];
    const stderr: Buffer[] = [];
    let timedOut = false;
    let forceTimer: NodeJS.Timeout | undefined;
    const timer = setTimeout(() => {
      timedOut = true;
      killProcessGroup(child.pid, "SIGTERM");
      forceTimer = setTimeout(() => killProcessGroup(child.pid, "SIGKILL"), 2_000);
    }, timeoutMs);
    child.stdout.on("data", (chunk: Buffer) => stdout.push(chunk));
    child.stderr.on("data", (chunk: Buffer) => stderr.push(chunk));
    child.on("error", (error) => {
      clearTimeout(timer);
      if (forceTimer) clearTimeout(forceTimer);
      resolve({ ok: false, stdout: Buffer.concat(stdout).toString("utf8"), stderr: error.message });
    });
    child.on("close", (code) => {
      clearTimeout(timer);
      if (forceTimer) clearTimeout(forceTimer);
      resolve({
        ok: code === 0 && !timedOut,
        stdout: Buffer.concat(stdout).toString("utf8"),
        stderr: timedOut
          ? `CodeQL query compile timed out after ${timeoutMs}ms`
          : Buffer.concat(stderr).toString("utf8"),
      });
    });
  });
}

function killProcessGroup(pid: number | undefined, signal: NodeJS.Signals): void {
  if (!pid) return;
  try {
    process.kill(-pid, signal);
  } catch {
    try {
      process.kill(pid, signal);
    } catch {
      // Process already exited.
    }
  }
}

function resolveCodeqlPackOptions(): { searchPath?: string; additionalPacks?: string } {
  const additionalPacks = resolveCodeqlInstalledPackPaths();
  if (additionalPacks) return { additionalPacks };
  const searchPath = resolveCodeqlPackSearchPath();
  return searchPath ? { searchPath } : {};
}

function resolveCodeqlPackSearchPath(): string | undefined {
  const packagesPath = path.join(os.homedir(), ".codeql", "packages");
  return existsSync(packagesPath) ? packagesPath : undefined;
}

function resolveCodeqlInstalledPackPaths(): string | undefined {
  const root = path.join(os.homedir(), ".codeql", "packages", "codeql");
  if (!existsSync(root)) return undefined;
  const latestByPack: string[] = [];
  for (const packName of readdirSync(root)) {
    const packRoot = path.join(root, packName);
    if (!existsSync(packRoot)) continue;
    const versions = readdirSync(packRoot)
      .filter((entry) => existsSync(path.join(packRoot, entry, "qlpack.yml")))
      .sort(compareVersionDesc);
    const latest = versions[0];
    if (latest) latestByPack.push(path.join(packRoot, latest));
  }
  return latestByPack.length > 0 ? latestByPack.join(path.delimiter) : undefined;
}

function compareVersionDesc(left: string, right: string): number {
  const leftParts = left.split(".").map((part) => Number.parseInt(part, 10) || 0);
  const rightParts = right.split(".").map((part) => Number.parseInt(part, 10) || 0);
  for (let index = 0; index < Math.max(leftParts.length, rightParts.length); index += 1) {
    const delta = (rightParts[index] ?? 0) - (leftParts[index] ?? 0);
    if (delta !== 0) return delta;
  }
  return right.localeCompare(left);
}

function detectCodeqlDatabaseLanguage(dbPath: string, languageHints: readonly string[]): string {
  const metadataPath = path.join(dbPath, "codeql-database.yml");
  if (existsSync(metadataPath)) {
    const metadata = readFileSync(metadataPath, "utf8");
    const match = metadata.match(/^\s*primaryLanguage:\s*([^\s#]+)/imu);
    if (match?.[1]) return normalizeCodeqlLanguage(match[1]);
  }

  for (const language of languageHints) {
    const normalized = normalizeCodeqlLanguage(language);
    if (normalized !== "unknown") return normalized;
  }

  return "javascript";
}

function normalizeCodeqlLanguage(language: string): string {
  const normalized = language.trim().toLowerCase();
  if (normalized === "javascript" || normalized === "typescript" || normalized === "js") {
    return "javascript";
  }
  if (normalized === "python" || normalized === "py") return "python";
  if (normalized === "ruby" || normalized === "rb") return "ruby";
  if (normalized === "java") return "java";
  if (normalized === "go" || normalized === "golang") return "go";
  if (normalized === "csharp" || normalized === "c#") return "csharp";
  if (normalized === "cpp" || normalized === "c++" || normalized === "c") return "cpp";
  if (normalized === "rust" || normalized === "rs") return "rust";
  if (normalized === "swift") return "swift";
  return "unknown";
}

function buildPythonSourceSpecClauses(
  plan: TaintIrisNextPlan,
  entry: TaintIrisNextCweCatalogEntry,
): string[] {
  const signals = collectPythonSignals(plan, entry, "source");
  return signals.map((signal) => `(cwe = ${qlString(entry.cwe)} and signal = ${qlString(signal)})`);
}

function buildPythonSinkSpecClauses(
  plan: TaintIrisNextPlan,
  entry: TaintIrisNextCweCatalogEntry,
): string[] {
  return collectPythonSignals(plan, entry, "sink").flatMap((signal) => {
    const token = normalizeCodeqlPatternToken(signal);
    if (!token) return [];
    return [
      `(cwe = ${qlString(entry.cwe)} and signal = ${qlString(signal)} and token = ${qlString(token)})`,
    ];
  });
}

function buildPythonSanitizerSpecClauses(
  plan: TaintIrisNextPlan,
  entry: TaintIrisNextCweCatalogEntry,
): string[] {
  return collectPythonSignals(plan, entry, "sanitizer").flatMap((signal) => {
    const token = normalizeCodeqlPatternToken(signal);
    if (!token) return [];
    return [
      `(cwe = ${qlString(entry.cwe)} and signal = ${qlString(signal)} and token = ${qlString(token)})`,
    ];
  });
}

function collectPythonSignals(
  plan: TaintIrisNextPlan,
  entry: TaintIrisNextCweCatalogEntry,
  role: "source" | "sink" | "sanitizer",
): string[] {
  const signals = new Set<string>();
  const catalogSignals =
    role === "source"
      ? entry.sourceSignals
      : role === "sink"
        ? entry.sinkSignals
        : entry.sanitizerSignals;
  for (const signal of catalogSignals) addSignal(signals, signal);
  for (const query of plan.structuralQueries) {
    if (query.cwe !== entry.cwe || query.role !== role) continue;
    addSignal(signals, query.pattern);
  }
  return [...signals].slice(0, Math.max(1, plan.caps.maxSpecsPerCwe));
}

function addSignal(signals: Set<string>, signal: string): void {
  const trimmed = signal.trim();
  if (trimmed.length >= 2) signals.add(trimmed);
}

function renderChunkedPredicate(
  name: string,
  signature: string,
  callArgs: string,
  clauses: readonly string[],
  maxClausesPerChunk: number,
): string {
  const chunkSize = Math.max(1, maxClausesPerChunk);
  const chunks: string[][] = [];
  for (let index = 0; index < clauses.length; index += chunkSize) {
    chunks.push(clauses.slice(index, index + chunkSize));
  }
  const lines: string[] = [];
  for (const [index, chunk] of chunks.entries()) {
    lines.push(`private predicate ${name}Chunk${index}(${signature}) {`);
    lines.push(chunk.map((clause) => `  ${clause}`).join("\n  or\n"));
    lines.push("}");
    lines.push("");
  }
  lines.push(`private predicate ${name}(${signature}) {`);
  lines.push(chunks.map((_, index) => `  ${name}Chunk${index}(${callArgs})`).join("\n  or\n"));
  lines.push("}");
  return lines.join("\n");
}

function renderPythonScanScopePredicate(plan: TaintIrisNextPlan): string {
  const searchPath = relativeSearchPath(plan.repoRoot, plan.scanRoot).replace(/\\/gu, "/");
  if (searchPath === ".") {
    return [
      "private predicate irisInScanScope(DataFlow::Node node) {",
      "  exists(node.getLocation().getFile().getRelativePath())",
      "}",
    ].join("\n");
  }
  const prefix = searchPath.endsWith("/") ? searchPath : `${searchPath}/`;
  return [
    "private predicate irisInScanScope(DataFlow::Node node) {",
    `  node.getLocation().getFile().getRelativePath().matches(${qlString(`${prefix}%`)})`,
    "}",
  ].join("\n");
}

function buildCodeqlCandidateClauses(plan: TaintIrisNextPlan): string[] {
  const clauses: string[] = [];
  const seen = new Set<string>();
  for (const query of plan.structuralQueries) {
    if (query.role !== "sink" && query.role !== "structural") continue;
    const token = normalizeCodeqlPatternToken(query.pattern);
    if (!token) continue;
    const key = `${query.cwe}:${token.toLowerCase()}`;
    if (seen.has(key)) continue;
    seen.add(key);
    clauses.push(
      `(cwe = ${qlString(query.cwe)} and signal = ${qlString(query.pattern)} and (callee.matches(${qlString(`%${token}%`)}) or call.toString().matches(${qlString(`%${token}%`)})))`,
    );
    if (clauses.length >= 80) break;
  }
  return clauses;
}

function normalizeCodeqlPatternToken(pattern: string): string | null {
  const trimmed = pattern.trim();
  if (trimmed.length < 3) return null;
  const cleaned = trimmed
    .replace(/[()[\]{}'"`]/gu, "")
    .replace(/^\.+/u, "")
    .replace(/\.+$/u, "");
  if (cleaned.length < 3 || /\s/u.test(cleaned)) return null;
  if (!/^[\w$./:-]+$/u.test(cleaned)) return null;
  return cleaned;
}

function qlString(value: string): string {
  return `"${value.replace(/\\/gu, "\\\\").replace(/"/gu, '\\"')}"`;
}

function sanitizePathSegment(value: string): string {
  return value.replace(/[^a-zA-Z0-9._-]/gu, "_").slice(0, 80) || "adhoc";
}

function matchFindingCatalogEntries(
  finding: Finding,
  catalog: readonly TaintIrisNextCweCatalogEntry[],
): TaintIrisNextCweCatalogEntry[] {
  const cwes = new Set(finding.cwe.map((cwe) => cwe.toUpperCase()));
  const direct = catalog.filter((entry) => cwes.has(entry.cwe));
  if (direct.length > 0) return direct;

  const haystack = [
    finding.ruleId,
    finding.message,
    finding.evidence ?? "",
    ...(finding.taintPath ?? []).map((step) => `${step.message ?? ""} ${step.snippet ?? ""}`),
  ]
    .join(" ")
    .toLowerCase();

  return catalog.filter((entry) => {
    if (haystack.includes(entry.cwe.toLowerCase())) return true;
    if (haystack.includes(entry.taintClass.toLowerCase())) return true;
    if (haystack.includes(entry.name.toLowerCase())) return true;
    return [...entry.sinkSignals, ...entry.sourceSignals].some((signal) => {
      const normalized = signal.toLowerCase();
      return normalized.length >= 4 && haystack.includes(normalized);
    });
  });
}

function roleForCodeqlStep(index: number, total: number): TaintIrisNextEvidence["role"] {
  if (total <= 1) return "sink";
  if (index === 0) return "source";
  if (index === total - 1) return "sink";
  return "structural";
}

function parseIrisNextCodeqlMessage(
  message: string,
): { cwe: string; sourceSignal: string; sinkSignal: string } | undefined {
  const match = message.match(
    /Taint IRIS Next (CWE-\d+) path from .*? to sink catalog signal ([^.]+)\./iu,
  );
  if (!match?.[1] || !match?.[2]) return undefined;
  return {
    cwe: match[1].toUpperCase(),
    sourceSignal: "codeql-path-source",
    sinkSignal: match[2].trim(),
  };
}

function findingHasScanRootEvidence(finding: Finding, plan: TaintIrisNextPlan): boolean {
  if (isPathInPlanScanRoot(plan, normalizePath(plan.repoRoot, finding.filePath))) return true;
  return (finding.taintPath ?? []).some((step) =>
    isPathInPlanScanRoot(plan, normalizePath(plan.repoRoot, step.filePath)),
  );
}

function isPathInPlanScanRoot(plan: TaintIrisNextPlan, filePath: string): boolean {
  const searchPath = relativeSearchPath(plan.repoRoot, plan.scanRoot).replace(/\\/gu, "/");
  if (searchPath === ".") return true;
  const normalized = filePath.replace(/\\/gu, "/").replace(/^\.\//u, "");
  return normalized === searchPath || normalized.startsWith(`${searchPath}/`);
}

function confidenceForCodeqlFinding(finding: Finding): TaintIrisNextEvidenceConfidence {
  if (finding.scannerConfidence === "HIGH") return "high";
  if (finding.scannerConfidence === "MEDIUM") return "medium";
  return "low";
}

function relativeSearchPath(repoRoot: string, scanRoot: string): string {
  if (!path.isAbsolute(scanRoot)) return scanRoot;
  const rel = path.relative(repoRoot, scanRoot);
  if (!rel) return ".";
  return rel.startsWith("..") ? scanRoot : rel;
}

function parseRgLine(
  line: string,
  repoRoot: string,
): { filePath: string; line: number; snippet: string } | undefined {
  const first = line.indexOf(":");
  if (first < 0) return undefined;
  const second = line.indexOf(":", first + 1);
  if (second < 0) return undefined;
  const rawPath = line.slice(0, first);
  const lineNumber = Number.parseInt(line.slice(first + 1, second), 10);
  const snippet = line.slice(second + 1).trim();
  if (!rawPath || !Number.isFinite(lineNumber)) return undefined;

  return {
    filePath: normalizePath(repoRoot, rawPath),
    line: Math.max(1, lineNumber),
    snippet,
  };
}

function normalizePath(repoRoot: string, filePath: string): string {
  if (filePath.startsWith(`.${path.sep}`)) return filePath.slice(2);
  if (!path.isAbsolute(filePath)) return filePath;
  const rel = path.relative(repoRoot, filePath);
  return rel.startsWith("..") ? filePath : rel || filePath;
}

function languageForPath(filePath: string): string {
  return LANGUAGE_BY_EXTENSION.get(path.extname(filePath).toLowerCase()) ?? "unknown";
}

function shouldKeepEvidenceLanguage(language: string, planLanguages: readonly string[]): boolean {
  const normalized = normalizeEvidenceLanguage(language);
  if (normalized === "unknown") return false;
  const planSet = new Set(
    planLanguages.map(normalizeEvidenceLanguage).filter((item) => item !== "unknown"),
  );
  if (planSet.size === 0) return true;
  if (planSet.has(normalized)) return true;
  if (normalized === "javascript" && planSet.has("typescript")) return true;
  if (normalized === "typescript" && planSet.has("javascript")) return true;
  return false;
}

function normalizeEvidenceLanguage(language: string): string {
  const normalized = language.trim().toLowerCase();
  if (normalized === "js" || normalized === "jsx") return "javascript";
  if (normalized === "ts" || normalized === "tsx") return "typescript";
  if (normalized === "py") return "python";
  if (normalized === "rb") return "ruby";
  if (normalized === "rs") return "rust";
  return normalized || "unknown";
}

function confidenceForRole(role: string): TaintIrisNextEvidenceConfidence {
  if (role === "sink") return "medium";
  if (role === "source") return "medium";
  return "low";
}
