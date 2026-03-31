import { execFile, type ExecFileException } from "node:child_process";
import { existsSync } from "node:fs";
import { readdir, readFile, writeFile } from "node:fs/promises";
import path from "node:path";
import { promisify } from "node:util";
import type { AgentRuntime } from "../../../agent-runtime/types.js";
import { getLogger } from "../../../logger.js";
import { formatTaintPathForPrompt } from "../../../findings/taint-path.js";
import { scoreFindingMetadata } from "../../../scanners/scoring.js";
import { selectFindings, type CodeQLSarifOutput } from "../../../scanners/run-codeql.js";
import type { Finding, TriageAgentConfig } from "../../../scanners/types.js";
import type { ScanOpts } from "../../../types.js";
import { getLatestCompletedRunFindings } from "../../../store.js";
import { isRecord, toErrorMessage } from "../../../utils.js";
import { resolveDefaultReadOnlyTools, runStructuredAgentQuery } from "../../../agent-runtime/execution.js";
import type { AgentTask } from "../../types.js";
import { groundCallableTargets, groundNamedHints } from "./grounding.js";
import {
  candidateProfiles,
  formatProfileDiagnostics,
  libraryImportsForProfile,
  profileById,
  queryImportsForProfile,
  type CodeqlProfile,
} from "./codeql-compat.js";
import {
  TAINT_ANALYSIS_PASS_IDS,
  TAINT_ANALYSIS_PASSES,
  resolveTaintAnalysisConfig,
  type ExtractionDegradation,
  type TaintAnalysisLabelOutput,
  type TaintAnalysisLabelsDocument,
  type TaintAnalysisLanguage,
  type TaintAnalysisPassEntry,
  type TaintAnalysisPassDefinition,
  type TaintAnalysisPassId,
  type TaintAnalysisPreflightOutput,
} from "./types.js";
import {
  extractPassId,
  mergeBaselineTaintFindings,
  narrowDiffScope,
} from "./diff-scope.js";

const execFileAsync = promisify(execFile);
const log = getLogger("taint-analysis-run");
const EXPECTED_LABEL_CHECKPOINT_VERSION = 2;
const EXPECTED_LABEL_PARSER_VERSION = 2;
const LABEL_CHECKPOINT_VERSION_NOTE_PREFIX = "internal.label_checkpoint_version=";
const LABEL_PARSER_VERSION_NOTE_PREFIX = "internal.label_parser_version=";

const SUMMARY_SUPPLEMENT_SCHEMA = {
  type: "object",
  additionalProperties: false,
  required: ["supplements"],
  properties: {
    supplements: {
      type: "array",
      items: {
        type: "object",
        additionalProperties: false,
        required: ["callable", "flowKind", "receiverHint", "argIndex", "rationale"],
        properties: {
          callable: { type: "string" },
          flowKind: { type: "string", enum: ["param", "argument", "return", "receiver", "field", "unknown"] },
          receiverHint: { type: ["string", "null"] },
          argIndex: { type: ["integer", "null"] },
          rationale: { type: "string" },
        },
      },
    },
  },
} as const;

interface DiscoverSummarySupplementsArgs {
  labels: TaintAnalysisLabelsDocument;
  language: TaintAnalysisLanguage;
  framework: string | null;
  extractionDegradation: ExtractionDegradation;
  repoRoot: string;
  model: string;
  runtime: AgentRuntime;
}

async function discoverSummarySupplements(
  args: DiscoverSummarySupplementsArgs,
): Promise<{ supplements: CallableInfo[]; costUsd: number }> {
  const { labels, language, framework, extractionDegradation, repoRoot, model, runtime } = args;

  const labelSummaryLines: string[] = [];
  for (const pass of labels.passes) {
    const sources = pass.entries.filter((e) => e.role === "source" && e.classification !== "fp");
    const sinks = pass.entries.filter((e) => e.role === "sink" && e.classification !== "fp");
    if (sources.length === 0 && sinks.length === 0) {
      continue;
    }
    labelSummaryLines.push(`## Pass ${pass.pass_id}: ${pass.focus}`);
    if (sources.length > 0) {
      labelSummaryLines.push(`Sources (${sources.length}):`);
      for (const s of sources.slice(0, 15)) {
        const mod = s.signature.module ?? s.signature.type ?? "";
        labelSummaryLines.push(`  - ${mod ? mod + "." : ""}${s.signature.callable} [${s.signature.flow_kind}]`);
      }
      if (sources.length > 15) {
        labelSummaryLines.push(`  ... and ${sources.length - 15} more`);
      }
    }
    if (sinks.length > 0) {
      labelSummaryLines.push(`Sinks (${sinks.length}):`);
      for (const s of sinks.slice(0, 15)) {
        const mod = s.signature.module ?? s.signature.type ?? "";
        labelSummaryLines.push(`  - ${mod ? mod + "." : ""}${s.signature.callable} [${s.signature.flow_kind}]`);
      }
      if (sinks.length > 15) {
        labelSummaryLines.push(`  ... and ${sinks.length - 15} more`);
      }
    }
  }

  const degradationNote = extractionDegradation.status !== "ok"
    ? `\n\nNOTE: Extraction was degraded (${extractionDegradation.reasons.join(", ")}). ` +
      `This means CodeQL's type resolution may be incomplete — taint flow gaps are more likely. ` +
      `Pay extra attention to utility wrappers, format functions, and type converters that bridge data flow.`
    : "";

  const prompt = `You are a security-focused code analysis agent. Your job is to identify **intermediate functions** in this ${language} codebase${framework ? ` (${framework} framework)` : ""} that propagate taint but are NOT already labeled as sources or sinks.

These are functions like:
- Utility wrappers (string formatting, encoding, conversion)
- Proto getters / setters
- Serialization/deserialization helpers
- Builder pattern methods (e.g. strings.Builder.WriteString → receiver)
- Type conversion functions (e.g. strconv.Itoa, fmt.Sprintf)
- Internal helper functions that pass user data through
- Async/callback boundaries that propagate taint:
  - Go: goroutine closures capturing tainted variables, channel send/receive
  - JavaScript/TypeScript: Promise.then/catch callbacks, async/await chains, EventEmitter handlers
  - Python: asyncio coroutine parameters, callback functions passed to async APIs
  - Java: CompletableFuture.thenApply/thenAccept, Callable/Runnable lambdas, ExecutorService submissions
- Data structure operations that propagate taint:
  - Map/dict lookups, array/list indexing, struct/object field access
  - JSON marshaling/unmarshaling, protobuf serialization
  - ORM model field access (e.g. model.field, rows.Scan)

${degradationNote}

## Labeled Sources and Sinks

${labelSummaryLines.join("\n")}

## Instructions

1. Use Grep and Glob to explore the codebase and find functions that are called between sources and sinks
2. Focus on functions that take tainted data as input and produce tainted data as output
3. Look for common patterns: format functions, type converters, proto getters, serializers, wrapper functions
4. For each function found, determine the flow kind and argument/return semantics
5. Return ONLY functions NOT already in the labeled sources/sinks above
6. Return your findings as structured JSON

For each supplement provide:
- callable: the function name (basename only for methods)
- flowKind: how taint flows ("return" if input→result, "receiver" if input→receiver, "argument" if input→specific arg)
- receiverHint: the package/module/type qualifier (null if unknown)
- argIndex: the specific argument index for the output if flowKind is "argument", null otherwise
- rationale: brief explanation of why this bridges taint flow`;

  const result = await runStructuredAgentQuery({
    prompt,
    cwd: repoRoot,
    model,
    allowedTools: resolveDefaultReadOnlyTools(runtime),
    runtimeOptions: { runtime },
    schema: SUMMARY_SUPPLEMENT_SCHEMA as Record<string, unknown>,
    strict: true,
    retryInvalidStructuredOutput: 2,
  });

  if (result.executionError) {
    throw new Error(`Summary supplement discovery agent error: ${result.executionError}`);
  }

  const parsed = result.structuredOutput as { supplements?: unknown[] } | null;
  if (!parsed || !Array.isArray(parsed.supplements)) {
    return { supplements: [], costUsd: result.costUsd };
  }

  const supplements: CallableInfo[] = [];
  for (const item of parsed.supplements) {
    if (!isRecord(item)) {
      continue;
    }
    const callable = typeof item["callable"] === "string" ? item["callable"].trim() : "";
    if (!callable) {
      continue;
    }
    const flowKind = typeof item["flowKind"] === "string" ? item["flowKind"] : "unknown";
    const validFlowKinds = new Set(["param", "argument", "return", "receiver", "field", "unknown"]);
    supplements.push({
      callable,
      flowKind: validFlowKinds.has(flowKind) ? flowKind as CallableInfo["flowKind"] : "unknown",
      receiverHint: typeof item["receiverHint"] === "string" ? item["receiverHint"] : null,
      argIndex: typeof item["argIndex"] === "number" && Number.isInteger(item["argIndex"]) ? item["argIndex"] : null,
    });
  }

  return { supplements, costUsd: result.costUsd };
}

interface CallableInfo {
  callable: string;
  flowKind: "param" | "argument" | "return" | "receiver" | "field" | "unknown";
  receiverHint: string | null;
  argIndex: number | null;
}

interface RenderingHints {
  variadicFormatFuncs: Set<string>;
  sqlQueryTextArg0Callables: Set<string>;
  stdlibPackages: Set<string>;
}

function defaultRenderingHints(): RenderingHints {
  return {
    variadicFormatFuncs: new Set(),
    sqlQueryTextArg0Callables: new Set(),
    stdlibPackages: new Set(),
  };
}

const RENDERING_HINTS_SCHEMA = {
  type: "object",
  additionalProperties: false,
  required: ["variadicFormatFuncs", "sqlQueryTextArg0Callables", "stdlibPackages"],
  properties: {
    variadicFormatFuncs: {
      type: "array",
      items: { type: "string" },
    },
    sqlQueryTextArg0Callables: {
      type: "array",
      items: { type: "string" },
    },
    stdlibPackages: {
      type: "array",
      items: { type: "string" },
    },
  },
} as const;

interface DiscoverRenderingHintsArgs {
  language: TaintAnalysisLanguage;
  framework: string | null;
  repoRoot: string;
  model: string;
  runtime: AgentRuntime;
  labeledCallables: string[];
}

async function discoverRenderingHints(
  args: DiscoverRenderingHintsArgs,
): Promise<{ hints: RenderingHints; costUsd: number }> {
  const { language, framework, repoRoot, model, runtime, labeledCallables } = args;

  const callableContext = labeledCallables.length > 0
    ? `\n\nLabeled callables in the codebase (for context):\n${labeledCallables.slice(0, 50).map((c) => `  - ${c}`).join("\n")}${labeledCallables.length > 50 ? `\n  ... and ${labeledCallables.length - 50} more` : ""}`
    : "";

  const prompt = `You are a code analysis agent. Analyze this ${language} codebase${framework ? ` (${framework} framework)` : ""} and identify rendering hints for CodeQL taint analysis query generation.
${callableContext}

## What to identify

1. **Variadic format functions**: Functions that accept a format string as the first argument followed by variadic arguments (like fmt.Sprintf, fmt.Fprintf, log.Printf, etc.). These need special argument handling in CodeQL queries — any argument should be considered tainted, not just argument 0.

2. **SQL query-text-arg0 callables**: Functions/methods where argument 0 is always a SQL query string (like Raw, From in query builder libraries). When the agent doesn't know which argument is the SQL text, these default to argument 0.

3. **Stdlib packages**: Standard library package names used in this codebase (like "fmt", "os", "net/http", "database/sql" for Go, or "os", "subprocess" for Python). These help distinguish between qualified name matching (package.Function) vs simple name matching.

## Instructions

1. Use Grep and Glob to scan the codebase for import statements, function calls, and library usage
2. Identify which variadic format functions, SQL builders, and stdlib packages are actually used
3. Return ONLY items that are actually present/imported in this codebase
4. Return your findings as structured JSON

Return:
- variadicFormatFuncs: array of function base names (e.g. ["Sprintf", "Fprintf", "Errorf"])
- sqlQueryTextArg0Callables: array of function base names (e.g. ["Raw", "From"])
- stdlibPackages: array of package paths (e.g. ["fmt", "os", "database/sql", "encoding/json"])`;

  const result = await runStructuredAgentQuery({
    prompt,
    cwd: repoRoot,
    model,
    allowedTools: resolveDefaultReadOnlyTools(runtime),
    runtimeOptions: { runtime },
    schema: RENDERING_HINTS_SCHEMA as Record<string, unknown>,
    strict: true,
    retryInvalidStructuredOutput: 2,
  });

  if (result.executionError) {
    throw new Error(`Rendering hints discovery agent error: ${result.executionError}`);
  }

  const parsed = result.structuredOutput as {
    variadicFormatFuncs?: unknown[];
    sqlQueryTextArg0Callables?: unknown[];
    stdlibPackages?: unknown[];
  } | null;

  const hints = defaultRenderingHints();
  if (parsed) {
    if (Array.isArray(parsed.variadicFormatFuncs)) {
      for (const item of parsed.variadicFormatFuncs) {
        if (typeof item === "string" && item.trim()) hints.variadicFormatFuncs.add(item.trim());
      }
    }
    if (Array.isArray(parsed.sqlQueryTextArg0Callables)) {
      for (const item of parsed.sqlQueryTextArg0Callables) {
        if (typeof item === "string" && item.trim()) hints.sqlQueryTextArg0Callables.add(item.trim());
      }
    }
    if (Array.isArray(parsed.stdlibPackages)) {
      for (const item of parsed.stdlibPackages) {
        if (typeof item === "string" && item.trim()) hints.stdlibPackages.add(item.trim());
      }
    }
  }

  return { hints, costUsd: result.costUsd };
}

interface RawFindingRecord {
  scanner: string;
  ruleId: string;
  filePath: string;
  startLine: number;
  severity: string;
  message: string;
  evidence?: string | null;
  cwe: string[];
  passId?: number;
  taintPath?: Finding["taintPath"];
  proofState?: Finding["proofState"];
  engineProvenance?: Finding["engineProvenance"];
}

/**
 * Taint Analysis Step 4-6 task: deterministic library/query generation + analysis + report filtering.
 */
export const taintAnalysisRunTask: AgentTask<ScanOpts, Finding[]> = {
  id: "taint-analysis-run",
  displayName: "Taint Analysis Run",
  outputKind: "findings",
  dependsOn: ["taint-analysis-label"],
  async run(_input, context): Promise<Finding[]> {
    process.stderr.write(`[taint-analysis-run] Starting taint analysis run...\n`);
    const cfg = resolveTaintAnalysisConfig(context.config);
    const labelOutput = asLabelOutput(context.upstreamOutputs.get("taint-analysis-label"));
    if (!labelOutput) {
      throw new Error("taint-analysis-run requires upstream output from taint-analysis-label");
    }

    const labels = labelOutput.labels ?? await loadLabelsFromDisk(labelOutput.labelsPath);
    process.stderr.write(`[taint-analysis-run] Loaded labels: ${labels.passes.length} passes\n`);
    enforceLabelArtifactCompatibility(labels);
    const resultsDir = path.join(labelOutput.workspaceDir, "results");
    const compatRecordPath = path.join(labelOutput.workspaceDir, "exploration", "codeql_compat.json");

    // --- Diff-aware pass narrowing ---
    let diffScope = narrowDiffScope(labelOutput.diffScope, labels);
    let cachedBaselineFindings: Finding[] = [];
    if (diffScope?.mode === "baseline" && !diffScope.fellBackToFull) {
      if (!context.db) {
        diffScope = {
          ...diffScope,
          fellBackToFull: true,
          fallbackReason: "baseline_cache_unavailable",
        };
        process.stderr.write(
          "[taint-analysis-run] Baseline mode requested but no findings database is attached to task context; falling back to full analysis\n",
        );
      } else {
        cachedBaselineFindings = getLatestCompletedRunFindings(
          context.db,
          resolveBaselineCacheRepoRoot(context),
        )
          .filter((finding) => finding.scanner === "taint-analysis-run");
        if (cachedBaselineFindings.length === 0) {
          diffScope = {
            ...diffScope,
            fellBackToFull: true,
            fallbackReason: "baseline_cache_missing",
          };
          process.stderr.write(
            "[taint-analysis-run] Baseline mode requested but no completed taint baseline was found; falling back to full analysis\n",
          );
        }
      }
    }

    if (diffScope) {
      process.stderr.write(
        `[taint-analysis-run] Diff-aware mode=${diffScope.mode} affected_passes=[${diffScope.affectedPassIds.join(",")}] fell_back_to_full=${diffScope.fellBackToFull}\n`,
      );
      await writeFile(
        path.join(resultsDir, "diff_scope_narrowed.json"),
        JSON.stringify({
          generatedAt: new Date().toISOString(),
          ...diffScope,
        }, null, 2),
        "utf-8",
      );
    }

    const enabledPasses = TAINT_ANALYSIS_PASSES.filter((passDef) => labelOutput.passes.includes(passDef.passId));
    if (enabledPasses.length === 0) {
      process.stderr.write(`[taint-analysis-run] No enabled passes, skipping\n`);
      return [];
    }
    process.stderr.write(`[taint-analysis-run] ${enabledPasses.length} enabled passes\n`);
    emitSinkCoverageDiagnostics(labels, enabledPasses);
    if (!hasUsableRoleForPasses(labels, enabledPasses, "source")) {
      await writeFile(
        path.join(resultsDir, "skip_reason.json"),
        JSON.stringify({
          reason: "no_sources",
          detail: "Skipping taint analysis run because no non-fp source labels were available for enabled passes.",
          enabledPasses: enabledPasses.map((pass) => pass.passId),
          generatedAt: new Date().toISOString(),
        }, null, 2),
        "utf-8",
      );
      return [];
    }

    const taintTemplatePath = path.join(labelOutput.taintAnalysisPath, "assets", "taint_query.ql.tmpl");
    const taintTemplate = await readFile(taintTemplatePath, "utf-8");

    let agenticSupplements: CallableInfo[] = [];
    if (!cfg.summarySupplementsDisabled) {
      try {
        const supplementResult = await discoverSummarySupplements({
          labels,
          language: labelOutput.language,
          framework: labelOutput.framework,
          extractionDegradation: labelOutput.extractionDegradation,
          repoRoot: context.repoRoot,
          model: cfg.labelingModel,
          runtime: context.runtime,
        });
        const groundedSupplements = cfg.groundingEnabled
          ? await groundCallableTargets(context.repoRoot, supplementResult.supplements)
          : supplementResult.supplements.map((supplement) => ({
            item: supplement,
            grounding: {
              status: "weak" as const,
              reasons: ["grounding_disabled"],
              matchCount: 0,
              evidence: [],
            },
          }));
        agenticSupplements = groundedSupplements
          .filter((supplement) => supplement.grounding.status !== "invalid")
          .map((supplement) => supplement.item);
        process.stderr.write(`[taint-analysis-run] Discovered ${agenticSupplements.length} summary supplement(s)\n`);
        await writeFile(
          path.join(resultsDir, "summary_supplements.json"),
          JSON.stringify({
            generatedAt: new Date().toISOString(),
            language: labelOutput.language,
            framework: labelOutput.framework,
            costUsd: supplementResult.costUsd,
            supplements: agenticSupplements,
            droppedSupplements: groundedSupplements
              .filter((supplement) => supplement.grounding.status === "invalid")
              .map((supplement) => supplement.item),
            grounding: groundedSupplements.map((supplement) => ({
              ...supplement.item,
              grounding: supplement.grounding,
            })),
          }, null, 2),
          "utf-8",
        );
      } catch (error) {
        process.stderr.write(`[taint-analysis-run] Summary supplement discovery failed (non-fatal): ${toErrorMessage(error)}\n`);
      }
    }

    let renderingHints: RenderingHints | undefined;
    if (!cfg.renderingHintsDisabled) {
      try {
        const labeledCallables: string[] = [];
        for (const pass of labels.passes) {
          for (const entry of pass.entries) {
            if (entry.classification !== "fp" && entry.signature.callable.trim()) {
              const mod = entry.signature.module ?? entry.signature.type ?? "";
              labeledCallables.push(mod ? `${mod}.${entry.signature.callable}` : entry.signature.callable);
            }
          }
        }
        const hintsResult = await discoverRenderingHints({
          language: labelOutput.language,
          framework: labelOutput.framework,
          repoRoot: context.repoRoot,
          model: cfg.labelingModel,
          runtime: context.runtime,
          labeledCallables,
        });
        if (cfg.groundingEnabled) {
          const [groundedVariadic, groundedSqlArg0, groundedStdlib] = await Promise.all([
            groundNamedHints(context.repoRoot, [...hintsResult.hints.variadicFormatFuncs]),
            groundNamedHints(context.repoRoot, [...hintsResult.hints.sqlQueryTextArg0Callables]),
            groundNamedHints(context.repoRoot, [...hintsResult.hints.stdlibPackages]),
          ]);
          renderingHints = {
            variadicFormatFuncs: new Set(
              groundedVariadic
                .filter((hint) => hint.grounding.status !== "invalid")
                .map((hint) => hint.name),
            ),
            sqlQueryTextArg0Callables: new Set(
              groundedSqlArg0
                .filter((hint) => hint.grounding.status !== "invalid")
                .map((hint) => hint.name),
            ),
            stdlibPackages: new Set(
              groundedStdlib
                .filter((hint) => hint.grounding.status !== "invalid")
                .map((hint) => hint.name),
            ),
          };
          await writeFile(
            path.join(resultsDir, "rendering_hints_grounding.json"),
            JSON.stringify({
              generatedAt: new Date().toISOString(),
              variadicFormatFuncs: groundedVariadic,
              sqlQueryTextArg0Callables: groundedSqlArg0,
              stdlibPackages: groundedStdlib,
            }, null, 2),
            "utf-8",
          );
        } else {
          renderingHints = hintsResult.hints;
        }
        process.stderr.write(
          `[taint-analysis-run] Discovered rendering hints: variadicFmt=${renderingHints.variadicFormatFuncs.size} sqlArg0=${renderingHints.sqlQueryTextArg0Callables.size} stdlib=${renderingHints.stdlibPackages.size}\n`,
        );
        await writeFile(
          path.join(resultsDir, "rendering_hints.json"),
          JSON.stringify({
            generatedAt: new Date().toISOString(),
            language: labelOutput.language,
            framework: labelOutput.framework,
            costUsd: hintsResult.costUsd,
            variadicFormatFuncs: [...renderingHints.variadicFormatFuncs],
            sqlQueryTextArg0Callables: [...renderingHints.sqlQueryTextArg0Callables],
            stdlibPackages: [...renderingHints.stdlibPackages],
          }, null, 2),
          "utf-8",
        );
      } catch (error) {
        process.stderr.write(`[taint-analysis-run] Rendering hints discovery failed (non-fatal): ${toErrorMessage(error)}\n`);
      }
    }

    process.stderr.write(`[taint-analysis-run] Rendering artifacts and compile-gating queries...\n`);
    const requestedProfile = cfg.codeqlApiProfile ?? "auto";
    const fallbackEnabled = requestedProfile === "auto"
      ? (cfg.codeqlProfileFallbacks ?? true)
      : false;
    const profileSelection = await selectProfileWithCompileGate({
      language: labelOutput.language,
      initialProfileId: labelOutput.codeqlApiProfileId,
      fallbackEnabled,
      tryProfile: async (profile) => {
        const passQueries = await renderArtifactsForProfile({
          labels,
          profile,
          taintTemplate,
          workspaceDir: labelOutput.workspaceDir,
          enabledPasses,
          agenticSupplements,
          renderingHints,
        });
        const compileError = await compilePassQueries(
          labelOutput.codeqlBinary,
          labelOutput.workspaceDir,
          passQueries,
        );
        return {
          passQueries,
          error: compileError,
        };
      },
    });

    if (!profileSelection.selected || !profileSelection.passQueries) {
      throw new Error(formatProfileDiagnostics({
        language: labelOutput.language,
        codeqlVersion: labelOutput.codeqlVersion,
        requestedProfile,
        selectedProfileId: labelOutput.codeqlApiProfileId,
        fallbackEnabled,
        compatRecordPath,
        tried: profileSelection.attempts,
      }));
    }

    const selectedProfile = profileSelection.selected;
    const passQueries = profileSelection.passQueries;
    process.stderr.write(`[taint-analysis-run] Profile selected: ${selectedProfile.id}, ${passQueries.length} queries to run\n`);
    await writeFile(
      path.join(resultsDir, "profile_used.json"),
      JSON.stringify({
        language: labelOutput.language,
        codeqlVersion: labelOutput.codeqlVersion,
        requestedProfile,
        preflightProfileId: labelOutput.codeqlApiProfileId,
        selectedProfileId: selectedProfile.id,
        dataFlowImport: selectedProfile.dataFlowImport,
        taintTrackingImport: selectedProfile.taintTrackingImport,
        fallbackEnabled,
        triedProfiles: profileSelection.attempts,
      }, null, 2),
      "utf-8",
    );

    let skippedByDiff = 0;
    for (let qi = 0; qi < passQueries.length; qi++) {
      const passQuery = passQueries[qi];

      // Skip passes unaffected by the diff when narrowing is active
      if (diffScope && !diffScope.fellBackToFull && !diffScope.affectedPassIds.includes(passQuery.passId)) {
        process.stderr.write(
          `[taint-analysis-run] Skipping query ${qi + 1}/${passQueries.length} (pass ${passQuery.passId}) — not affected by diff\n`,
        );
        skippedByDiff++;
        continue;
      }

      process.stderr.write(`[taint-analysis-run] Running query ${qi + 1}/${passQueries.length} (pass ${passQuery.passId})...\n`);
      await runCommand(
        labelOutput.codeqlBinary,
        withResources([
          "database",
          "analyze",
          labelOutput.dbPath,
          passQuery.queryPath,
          "--format=sarifv2.1.0",
          `--output=${passQuery.resultPath}`,
        ], cfg),
        labelOutput.workspaceDir,
      );
      process.stderr.write(`[taint-analysis-run] Query ${qi + 1}/${passQueries.length} complete\n`);
    }
    if (skippedByDiff > 0) {
      process.stderr.write(`[taint-analysis-run] Diff-aware analysis skipped ${skippedByDiff}/${passQueries.length} passes\n`);
    }

    // iris_report.md is a supplemental human-readable summary; SARIF-derived findings are the source of truth.
    const scriptPath = path.join(labelOutput.taintAnalysisPath, "scripts", "filter_and_report.py");
    const reportPath = path.join(labelOutput.workspaceDir, "report", "iris_report.md");

    if (existsSync(scriptPath)) {
      await runCommand(
        cfg.python3Binary,
        [
          scriptPath,
          "--input-dir",
          resultsDir,
          "--labels",
          labelOutput.labelsPath,
          "--output",
          reportPath,
        ],
        labelOutput.workspaceDir,
      );
    }

    process.stderr.write(`[taint-analysis-run] Collecting findings from SARIF results...\n`);
    const rawFindings = await collectRawFindings(resultsDir, labels);
    await writeFile(
      path.join(resultsDir, "findings.raw.json"),
      JSON.stringify({
        version: "1.0.0",
        generatedAt: new Date().toISOString(),
        findings: rawFindings,
      }, null, 2),
      "utf-8",
    );

    if (labelOutput.extractionDegradation.status !== "ok") {
      await writeFile(
        path.join(resultsDir, "extraction_degradation.json"),
        JSON.stringify(labelOutput.extractionDegradation, null, 2),
        "utf-8",
      );
    }

    let findings = await convertSarifToTaintAnalysisFindings(resultsDir, context.repoName, labels);

    // --- Diff-aware finding filtering ---
    if (diffScope && !diffScope.fellBackToFull) {
      const preFilterCount = findings.length;
      if (diffScope.mode === "delta") {
        // Delta mode: only emit findings whose filePath or any taintPath step
        // intersects the set of changed files.
        const changedSet = new Set(diffScope.changedFiles);
        findings = findings.filter((f) => {
          if (changedSet.has(f.filePath)) return true;
          if (f.taintPath?.some((step) => changedSet.has(step.filePath))) return true;
          return false;
        });
        process.stderr.write(
          `[taint-analysis-run] Delta-mode filtering: ${preFilterCount} -> ${findings.length} findings (${preFilterCount - findings.length} outside diff)\n`,
        );
      } else {
        findings = mergeBaselineTaintFindings(
          cachedBaselineFindings,
          findings,
          diffScope.affectedPassIds,
        );
        process.stderr.write(
          `[taint-analysis-run] Baseline mode: merged cached unaffected findings with ${diffScope.affectedPassIds.length} rerun pass(es), returning ${findings.length} findings\n`,
        );
      }
    }

    const capped = cfg.maxFindings ? findings.slice(0, cfg.maxFindings) : findings;
    process.stderr.write(`[taint-analysis-run] Complete: ${rawFindings.length} raw findings, ${capped.length} deduplicated findings\n`);
    return capped;
  },
  triageAgentConfig(finding, repoName): TriageAgentConfig {
    const taintPathSection = formatTaintPathForPrompt(finding.taintPath);
    return {
      prompt: [
        "You are a taint-analysis-focused security triage agent.",
        "The finding came from a neurosymbolic pipeline: deterministic extraction + LLM API labeling + CodeQL taint analysis.",
        "Use the evidence and full code path to confirm exploitability rather than trusting the label blindly.",
        "",
        "## Finding",
        `Repo: ${repoName}`,
        `Scanner: ${finding.scanner}`,
        `Rule: ${finding.ruleId}`,
        `File: ${finding.filePath}:${finding.startLine}`,
        `Severity: ${finding.severity}`,
        `Scanner Confidence: ${finding.scannerConfidence}`,
        `Likelihood: ${finding.likelihood}`,
        `Impact: ${finding.impact}`,
        `CWE: ${finding.cwe.join(", ") || "none"}`,
        `Message: ${finding.message}`,
        `Evidence: ${finding.evidence || "none"}`,
        `Fingerprint: ${finding.fingerprint}`,
        "",
        taintPathSection,
        "",
        "## Investigation instructions",
        "1. Validate that source and sink semantics match the reported CWE pass.",
        "2. For each taint-path step, check attacker control, inter-procedural reachability, and whether the hop is actually feasible.",
        "3. Check framework sanitization, validation, policy checks, and branch conditions that may block the path.",
        "4. If any hop is infeasible or sanitized, explain that explicitly and downgrade or reject the finding.",
        "5. If uncertain, return needs_review with conservative confidence and concrete missing evidence.",
        "",
        "## Output requirements",
        "Return ONLY a JSON object with:",
        "fingerprint, verdict(tp|fp|needs_review), confidence(0..1), rationale, verification_steps(array), fix_patch(string|null)",
        "Optional but preferred for taint analysis refinement: source{why,is_false_positive,evidence}, sink{why,is_false_positive,evidence},",
        "is_vulnerable(boolean), exploit_scenario(string), recommended_fix(string), rule_refinement_hint(string), triage_schema_version(string).",
      ].join("\n"),
    };
  },
};

function withResources(args: string[], cfg: ReturnType<typeof resolveTaintAnalysisConfig>): string[] {
  const out = [...args];
  if (cfg.threads && cfg.threads > 0) {
    out.push(`--threads=${cfg.threads}`);
  }
  if (cfg.ram && cfg.ram > 0) {
    out.push(`--ram=${cfg.ram}`);
  }
  return out;
}

async function loadLabelsFromDisk(labelsPath: string): Promise<TaintAnalysisLabelsDocument> {
  const raw = await readFile(labelsPath, "utf-8");
  const parsed = JSON.parse(raw);
  if (!isRecord(parsed) || !Array.isArray(parsed["passes"])) {
    throw new Error(`Invalid labels.json at ${labelsPath}`);
  }

  return parsed as unknown as TaintAnalysisLabelsDocument;
}

function enforceLabelArtifactCompatibility(labels: TaintAnalysisLabelsDocument): void {
  const notes = labels.metadata.notes ?? [];
  const checkpointVersion = parseVersionFromNotes(notes, LABEL_CHECKPOINT_VERSION_NOTE_PREFIX);
  const parserVersion = parseVersionFromNotes(notes, LABEL_PARSER_VERSION_NOTE_PREFIX);

  if (checkpointVersion == null || parserVersion == null) {
    process.stderr.write(
      `[taint-analysis-run] Warning: labels metadata does not include internal parser/checkpoint versions; stale-artifact verification is partial\n`,
    );
    return;
  }

  if (checkpointVersion !== EXPECTED_LABEL_CHECKPOINT_VERSION) {
    throw new Error(
      `[taint-analysis-run] Incompatible labels metadata: checkpoint version ${checkpointVersion} (expected ${EXPECTED_LABEL_CHECKPOINT_VERSION}). Regenerate taint-analysis labels/checkpoints.`,
    );
  }

  if (parserVersion !== EXPECTED_LABEL_PARSER_VERSION) {
    throw new Error(
      `[taint-analysis-run] Incompatible labels metadata: parser version ${parserVersion} (expected ${EXPECTED_LABEL_PARSER_VERSION}). Regenerate taint-analysis labels/checkpoints.`,
    );
  }
}

function parseVersionFromNotes(notes: string[], prefix: string): number | null {
  for (const note of notes) {
    const trimmed = note.trim();
    if (!trimmed.startsWith(prefix)) {
      continue;
    }
    const rawValue = trimmed.slice(prefix.length).trim();
    const parsed = Number(rawValue);
    if (Number.isFinite(parsed)) {
      return Math.floor(parsed);
    }
  }
  return null;
}

function emitSinkCoverageDiagnostics(
  labels: TaintAnalysisLabelsDocument,
  enabledPasses: TaintAnalysisPassDefinition[],
): void {
  const enabledSet = new Set(enabledPasses.map((pass) => pass.passId));
  for (const pass of labels.passes) {
    if (!enabledSet.has(pass.pass_id)) {
      continue;
    }
    const sinksBeforeFiltering = pass.entries.filter((entry) => entry.role === "sink").length;
    const sinksAfterFiltering = pass.entries.filter((entry) => entry.role === "sink" && entry.classification !== "fp").length;
    const uniqueCallables = new Set(
      pass.entries
        .filter((entry) => entry.role === "sink" && entry.classification !== "fp")
        .map((entry) => entry.signature.callable.trim())
        .filter(Boolean),
    ).size;
    process.stderr.write(
      `[taint-analysis-run] pass ${pass.pass_id} (${pass.focus}): sinks before_fp=${sinksBeforeFiltering} after_fp=${sinksAfterFiltering} unique_callables=${uniqueCallables}\n`,
    );
  }
}

function renderTaintAnalysisLibraries(
  labels: TaintAnalysisLabelsDocument,
  profile: CodeqlProfile,
  agenticSupplements?: CallableInfo[],
  renderingHints?: RenderingHints,
): {
  sources: string;
  sinks: string;
  sanitizers: string;
  summaries: string;
} {
  const languageImports = libraryImportsForProfile(profile);

  const sourceByPass = groupCallables(labels, "source");
  const sinkByPass = groupCallables(labels, "sink");
  const sanitizerByPass = groupCallables(labels, "sanitizer");

  const sources = renderMatcherLibrary(
    "MySources",
    "isSource",
    "node",
    sourceByPass,
    languageImports,
    profile,
    "source",
    renderingHints,
  );

  const sinks = renderMatcherLibrary(
    "MySinks",
    "isSink",
    "node",
    sinkByPass,
    languageImports,
    profile,
    "sink",
    renderingHints,
  );

  const sanitizers = renderMatcherLibrary(
    "MySanitizers",
    "isBarrier",
    "node",
    sanitizerByPass,
    languageImports,
    profile,
    "sanitizer",
    renderingHints,
  );

  const summaryByPass = groupCallables(labels, "summary");

  if (agenticSupplements && agenticSupplements.length > 0) {
    for (const passKey of [...summaryByPass.keys()]) {
      const existing = summaryByPass.get(passKey)!;
      const existingKeys = new Set(
        existing.map((c) => buildCallableVariantKey(c.callable, c.receiverHint, c.flowKind, c.argIndex)),
      );
      for (const supplement of agenticSupplements) {
        const key = buildCallableVariantKey(supplement.callable, supplement.receiverHint, supplement.flowKind, supplement.argIndex);
        if (!existingKeys.has(key)) {
          existing.push(supplement);
          existingKeys.add(key);
        }
      }
    }
    // Also add supplements to pass keys that exist in TAINT_ANALYSIS_PASSES but have no summary entries yet
    for (const passDef of TAINT_ANALYSIS_PASSES) {
      if (!summaryByPass.has(passDef.passKey)) {
        const supplements: CallableInfo[] = [];
        const seen = new Set<string>();
        for (const supplement of agenticSupplements) {
          const key = buildCallableVariantKey(supplement.callable, supplement.receiverHint, supplement.flowKind, supplement.argIndex);
          if (!seen.has(key)) {
            supplements.push(supplement);
            seen.add(key);
          }
        }
        summaryByPass.set(passDef.passKey, supplements);
      }
    }
  }

  const summaries = renderSummaryLibrary(summaryByPass, languageImports, profile, renderingHints);

  return {
    sources,
    sinks,
    sanitizers,
    summaries,
  };
}

function renderMatcherLibrary(
  moduleName: string,
  predicateName: string,
  nodeParamName: string,
  byPass: Map<string, CallableInfo[]>,
  languageImports: string,
  profile: CodeqlProfile,
  role: "source" | "sink" | "sanitizer",
  hints?: RenderingHints,
): string {
  const passClauses = TAINT_ANALYSIS_PASSES.map((passDef) => {
    const callables = byPass.get(passDef.passKey) ?? [];
    if (callables.length === 0) {
      return `    passKey = \"${passDef.passKey}\" and ${nodeParamName}.toString().regexpMatch(\"a^\")`;
    }

    const callableChecks = callables
      .map((info) => buildNodeCallableCheck(nodeParamName, info, profile, role, hints))
      .join("\n      or ");

    return [
      `    passKey = \"${passDef.passKey}\" and`,
      "    (",
      `      ${callableChecks}`,
      "    )",
    ].join("\n");
  }).join("\n    or\n");

  return [
    "/**",
    " * Generated by Kuzushi Taint Analysis integration.",
    " */",
    "",
    languageImports,
    "",
    `module ${moduleName} {`,
    `  predicate ${predicateName}(DataFlow::Node ${nodeParamName}, string passKey) {`,
    passClauses,
    "  }",
    "}",
    "",
  ].join("\n");
}

function groupCallables(labels: TaintAnalysisLabelsDocument, role: TaintAnalysisPassEntry["role"]): Map<string, CallableInfo[]> {
  const out = new Map<string, CallableInfo[]>();

  for (const pass of labels.passes) {
    const passDef = TAINT_ANALYSIS_PASSES.find((candidate) => candidate.passId === pass.pass_id);
    if (!passDef) {
      continue;
    }

    const seen = new Set<string>();
    const infos: CallableInfo[] = [];
    let skippedSynthetic = 0;

    for (const entry of pass.entries) {
      if (entry.role !== role || entry.classification === "fp") {
        continue;
      }

      const callable = entry.signature.callable.trim();
      if (!callable) {
        continue;
      }
      if (isSyntheticCallableName(callable)) {
        skippedSynthetic += 1;
        continue;
      }

      const receiverHint = entry.signature.type ?? entry.signature.module ?? null;
      const flowKind = entry.signature.flow_kind;
      const argIndex = entry.signature.arg_index ?? null;
      const variantKey = buildCallableVariantKey(callable, receiverHint, flowKind, argIndex);
      if (seen.has(variantKey)) {
        continue;
      }

      seen.add(variantKey);
      infos.push({
        callable,
        flowKind,
        receiverHint,
        argIndex,
      });
    }

    if (skippedSynthetic > 0) {
      log.info(
        {
          passId: pass.pass_id,
          focus: passDef.focus,
          skippedSynthetic,
          role,
        },
        `pass ${pass.pass_id} (${passDef.focus}): skipped ${skippedSynthetic} synthetic ${role} callable entr${skippedSynthetic === 1 ? "y" : "ies"}`,
      );
    }

    infos.sort(compareCallableInfo);
    out.set(passDef.passKey, infos);
  }

  return out;
}

function isSyntheticCallableName(callable: string): boolean {
  const trimmed = callable.trim();
  return trimmed.startsWith("<") && trimmed.endsWith(">");
}

function buildCallableVariantKey(
  callable: string,
  receiverHint: string | null,
  flowKind: CallableInfo["flowKind"],
  argIndex: number | null,
): string {
  return [
    callable,
    receiverHint ?? "<null>",
    flowKind,
    argIndex == null ? "<null>" : String(argIndex),
  ].join("|");
}

function compareCallableInfo(a: CallableInfo, b: CallableInfo): number {
  const byCallable = a.callable.localeCompare(b.callable);
  if (byCallable !== 0) {
    return byCallable;
  }
  const byReceiver = (a.receiverHint ?? "").localeCompare(b.receiverHint ?? "");
  if (byReceiver !== 0) {
    return byReceiver;
  }
  const byFlow = a.flowKind.localeCompare(b.flowKind);
  if (byFlow !== 0) {
    return byFlow;
  }
  return (a.argIndex ?? -1) - (b.argIndex ?? -1);
}

function renderTaintQuery(
  template: string,
  passDef: TaintAnalysisPassDefinition,
  profile: CodeqlProfile,
): string {
  const queryIdPrefix = languageQueryIdPrefix(profile.language);
  const extraTags = passDef.cwes
    .slice(1)
    .map((cwe) => ` *       external/cwe/cwe-${Number.parseInt(cwe, 10)}`)
    .join("\n");

  const rendered = template
    .replaceAll("import {{SOURCE_MODULE}}", "import libraries.MySources")
    .replaceAll("import {{SINK_MODULE}}", "import libraries.MySinks")
    .replaceAll("import {{SANITIZER_MODULE}}", "import libraries.MySanitizers")
    .replaceAll("import {{SUMMARY_MODULE}}", "import libraries.MySummaries")
    .replaceAll("{{QUERY_NAME}}", `Taint Analysis Pass ${passDef.passId} - ${passDef.focus}`)
    .replaceAll("{{QUERY_DESCRIPTION}}", `Detect tainted dataflow for ${passDef.focus}.`)
    .replaceAll("{{QUERY_ID}}", `${queryIdPrefix}/taint-analysis/pass${passDef.passId}-${passDef.passKey.replaceAll("_", "-")}`)
    .replaceAll("{{PRECISION}}", "medium")
    .replaceAll("{{CWE_PRIMARY}}", String(Number.parseInt(passDef.cwes[0] ?? "0", 10)))
    .replaceAll("{{EXTRA_TAGS}}", extraTags)
    .replaceAll("{{SOURCE_MODULE}}", "MySources")
    .replaceAll("{{SINK_MODULE}}", "MySinks")
    .replaceAll("{{SANITIZER_MODULE}}", "MySanitizers")
    .replaceAll("{{SUMMARY_MODULE}}", "MySummaries")
    .replaceAll("{{CONFIG_NAME}}", `Pass${passDef.passId}Config`)
    .replaceAll("{{FLOW_MODULE}}", `Pass${passDef.passId}Flow`)
    .replaceAll("{{PASS_KEY}}", passDef.passKey)
    .replaceAll("{{RESULT_MESSAGE}}", `Potential ${passDef.focus} flow detected.`)
    .replaceAll("{{LANGUAGE_IMPORTS}}", queryImportsForProfile(profile));

  if (rendered.includes("{{")) {
    throw new Error(
      `Taint analysis taint query template render failed for pass ${passDef.passId}: unresolved placeholders`,
    );
  }

  return rendered;
}

interface PassQueryArtifact {
  passId: TaintAnalysisPassId;
  queryPath: string;
  resultPath: string;
}

interface ProfileCompileAttempt {
  id: string;
  ok: boolean;
  error?: string;
}

async function renderArtifactsForProfile(args: {
  labels: TaintAnalysisLabelsDocument;
  profile: CodeqlProfile;
  taintTemplate: string;
  workspaceDir: string;
  enabledPasses: TaintAnalysisPassDefinition[];
  agenticSupplements?: CallableInfo[];
  renderingHints?: RenderingHints;
}): Promise<PassQueryArtifact[]> {
  const libraries = renderTaintAnalysisLibraries(args.labels, args.profile, args.agenticSupplements, args.renderingHints);
  const librariesDir = path.join(args.workspaceDir, "libraries");
  await writeFile(path.join(librariesDir, "MySources.qll"), libraries.sources, "utf-8");
  await writeFile(path.join(librariesDir, "MySinks.qll"), libraries.sinks, "utf-8");
  await writeFile(path.join(librariesDir, "MySanitizers.qll"), libraries.sanitizers, "utf-8");
  await writeFile(path.join(librariesDir, "MySummaries.qll"), libraries.summaries, "utf-8");

  const queriesDir = path.join(args.workspaceDir, "queries");
  const resultsDir = path.join(args.workspaceDir, "results");
  const passQueries: PassQueryArtifact[] = [];

  for (const passDef of args.enabledPasses) {
    const queryPath = path.join(queriesDir, queryFilename(passDef.passId, passDef.focus));
    const query = renderTaintQuery(args.taintTemplate, passDef, args.profile);
    await writeFile(queryPath, query, "utf-8");
    passQueries.push({
      passId: passDef.passId,
      queryPath,
      resultPath: path.join(resultsDir, `pass${passDef.passId}.sarif`),
    });
  }

  return passQueries;
}

async function compilePassQueries(
  codeqlBinary: string,
  workspaceDir: string,
  passQueries: PassQueryArtifact[],
): Promise<string | null> {
  for (const passQuery of passQueries) {
    try {
      await runCommand(
        codeqlBinary,
        ["query", "compile", passQuery.queryPath, "--search-path", workspaceDir],
        workspaceDir,
      );
    } catch (error) {
      return `pass${passQuery.passId}: ${firstErrorExcerpt(toErrorMessage(error))}`;
    }
  }

  return null;
}

async function selectProfileWithCompileGate(args: {
  language: TaintAnalysisPreflightOutput["language"];
  initialProfileId: string;
  fallbackEnabled: boolean;
  tryProfile: (
    profile: CodeqlProfile,
  ) => Promise<{ passQueries: PassQueryArtifact[]; error: string | null }>;
}): Promise<{
  selected: CodeqlProfile | null;
  passQueries: PassQueryArtifact[] | null;
  attempts: ProfileCompileAttempt[];
}> {
  const initialProfile = profileById(args.language, args.initialProfileId);
  if (!initialProfile) {
    const validIds = candidateProfiles(args.language).map((profile) => profile.id).join(", ");
    throw new Error(
      `Unknown CodeQL API profile '${args.initialProfileId}' for ${args.language}. Valid profiles: ${validIds}`,
    );
  }

  const orderedProfiles = [initialProfile];
  if (args.fallbackEnabled) {
    for (const profile of candidateProfiles(args.language)) {
      if (profile.id !== initialProfile.id) {
        orderedProfiles.push(profile);
      }
    }
  }

  const attempts: ProfileCompileAttempt[] = [];
  for (const profile of orderedProfiles) {
    const attempt = await args.tryProfile(profile);
    if (!attempt.error) {
      attempts.push({ id: profile.id, ok: true });
      return {
        selected: profile,
        passQueries: attempt.passQueries,
        attempts,
      };
    }

    attempts.push({
      id: profile.id,
      ok: false,
      error: attempt.error,
    });
  }

  return {
    selected: null,
    passQueries: null,
    attempts,
  };
}

function firstErrorExcerpt(value: string): string {
  const lines = value
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter(Boolean);

  if (lines.length === 0) {
    return "unknown error";
  }

  return lines.slice(0, 4).join(" | ");
}

async function runCommand(command: string, args: string[], cwd: string): Promise<void> {
  try {
    await execFileAsync(command, args, {
      cwd,
      encoding: "utf-8",
      maxBuffer: 64 * 1024 * 1024,
    });
  } catch (error) {
    const err = error as ExecFileException & { stderr?: string; stdout?: string };
    const details = err.stderr?.trim() || err.stdout?.trim() || toErrorMessage(error);
    throw new Error(`Command failed: ${command} ${args.join(" ")}\n${details}`);
  }
}

async function convertSarifToTaintAnalysisFindings(
  resultsDir: string,
  repoName: string,
  labels: TaintAnalysisLabelsDocument,
): Promise<Finding[]> {
  const files = (await readdir(resultsDir))
    .filter((name) => name.toLowerCase().endsWith(".sarif"))
    .sort();

  const deduped = new Map<string, Finding>();

  for (const fileName of files) {
    const passId = parsePassIdFromName(fileName);
    const passDef = passId
      ? TAINT_ANALYSIS_PASSES.find((pass) => pass.passId === passId)
      : undefined;

    const absolutePath = path.join(resultsDir, fileName);
    const content = await readFile(absolutePath, "utf-8");
    const parsed = JSON.parse(content);
    if (!isRecord(parsed) || !Array.isArray(parsed["runs"])) {
      continue;
    }

    const findings = selectFindings(
      { runs: parsed["runs"] as CodeQLSarifOutput["runs"] },
      repoName,
      "HEAD",
    );

    for (const finding of findings) {
      const augmented = augmentFinding(finding, passDef, labels);
      const existing = deduped.get(augmented.fingerprint);
      if (!existing || augmented.score > existing.score) {
        deduped.set(augmented.fingerprint, augmented);
      }
    }
  }

  return [...deduped.values()].sort((a, b) => b.score - a.score);
}

async function collectRawFindings(
  resultsDir: string,
  labels: TaintAnalysisLabelsDocument,
): Promise<RawFindingRecord[]> {
  const files = (await readdir(resultsDir))
    .filter((name) => name.toLowerCase().endsWith(".sarif"))
    .sort();

  const out: RawFindingRecord[] = [];
  for (const fileName of files) {
    const passId = parsePassIdFromName(fileName);
    const passDef = passId
      ? TAINT_ANALYSIS_PASSES.find((pass) => pass.passId === passId)
      : undefined;
    const absolutePath = path.join(resultsDir, fileName);
    const content = await readFile(absolutePath, "utf-8");
    const parsed = JSON.parse(content);
    if (!isRecord(parsed) || !Array.isArray(parsed["runs"])) {
      continue;
    }

    const findings = selectFindings(
      { runs: parsed["runs"] as CodeQLSarifOutput["runs"] },
      labels.metadata.project,
      "HEAD",
    );

    for (const finding of findings) {
      out.push({
        scanner: "taint-analysis-run",
        ruleId: finding.ruleId,
        filePath: finding.filePath,
        startLine: finding.startLine,
        severity: finding.severity,
        message: finding.message,
        evidence: finding.evidence,
        cwe: passDef ? passDef.cwes.map((cwe) => `CWE-${Number.parseInt(cwe, 10)}`) : finding.cwe,
        passId: passDef?.passId,
        taintPath: finding.taintPath,
        proofState: finding.proofState,
        engineProvenance: finding.engineProvenance,
      });
    }
  }

  return out;
}

function augmentFinding(
  finding: Finding,
  passDef: TaintAnalysisPassDefinition | undefined,
  labels: TaintAnalysisLabelsDocument,
): Finding {
  const labelPass = passDef
    ? labels.passes.find((pass) => pass.pass_id === passDef.passId)
    : undefined;

  const sourceCount = labelPass?.entries.filter((entry) => entry.role === "source").length ?? 0;
  const sinkCount = labelPass?.entries.filter((entry) => entry.role === "sink").length ?? 0;

  const passEvidence = passDef
    ? `Taint Analysis pass ${passDef.passId} (${passDef.focus}) | labeled sources=${sourceCount} sinks=${sinkCount}`
    : "Taint analysis pass metadata unavailable";

  const augmented: Finding = {
    ...finding,
    scanner: "taint-analysis-run",
    ruleId: passDef
      ? `taint-analysis/pass${passDef.passId}/${finding.ruleId}`
      : `taint-analysis/${finding.ruleId}`,
    message: passDef
      ? `[Taint Analysis ${passDef.focus}] ${finding.message}`
      : `[Taint Analysis] ${finding.message}`,
    evidence: finding.evidence
      ? `${finding.evidence} | ${passEvidence}`
      : passEvidence,
    cwe: passDef ? passDef.cwes.map((cwe) => `CWE-${Number.parseInt(cwe, 10)}`) : finding.cwe,
    proofState: finding.proofState ?? "symbolic_only",
    engineProvenance: [
      {
        kind: "taint-analysis",
        detail: passDef
          ? `CodeQL-backed taint-analysis pass ${passDef.passId} (${passDef.focus})`
          : "CodeQL-backed taint-analysis finding",
      },
      ...(finding.engineProvenance ?? []),
    ],
    score: scoreFindingMetadata({
      severity: finding.severity,
      likelihood: finding.likelihood,
      impact: finding.impact,
      subcategory: finding.subcategory,
    }),
  };

  return augmented;
}

function parsePassIdFromName(fileName: string): TaintAnalysisPassId | undefined {
  const match = fileName.toLowerCase().match(/pass\s*(\d+)/);
  if (!match) {
    return undefined;
  }

  const id = Number.parseInt(match[1], 10);
  if (!TAINT_ANALYSIS_PASS_IDS.has(id)) return undefined;
  return id as TaintAnalysisPassId;
}

function languageQueryIdPrefix(language: TaintAnalysisPreflightOutput["language"]): string {
  if (language === "python") return "py";
  if (language === "go") return "go";
  if (language === "java") return "java";
  if (language === "csharp") return "cs";
  return "js";
}

function queryFilename(passId: number, focus: string): string {
  const focusSlug = focus
    .replaceAll("/", "")
    .replaceAll(/\s+/g, "")
    .replaceAll("-", "");
  return `Pass${passId}_${focusSlug}.ql`;
}

function looksLikeGoPackage(hint: string, hints?: RenderingHints): boolean {
  return hint.includes("/") || (hints?.stdlibPackages.has(hint) ?? false);
}

const PLACEHOLDER_RECEIVER_HINTS = new Set(["N/A", "n/a", "none", "unknown", "proto", ""]);

/** Per-language CodeQL callable name matching. */
function buildCallableNameCheck(
  callable: string,
  language: TaintAnalysisLanguage,
  receiverHint: string | null,
  profile: CodeqlProfile,
  hints?: RenderingHints,
): string {
  const effectiveCallable = language === "go"
    ? callableBasename(callable)
    : callable;
  const escaped = escapeQllString(effectiveCallable);

  // If the profile provides a custom callee name pattern, use it.
  if (profile.calleeNamePattern) {
    return profile.calleeNamePattern.replaceAll("{NAME}", escaped);
  }

  if (receiverHint && !PLACEHOLDER_RECEIVER_HINTS.has(receiverHint)) {
    const hint = escapeQllString(receiverHint);
    switch (language) {
      case "go":
        if (looksLikeGoPackage(receiverHint, hints)) {
          return `call.getTarget().hasQualifiedName("${hint}", "${escaped}")`;
        }
        return `call.getTarget().getName() = "${escaped}"`;
      case "java":
        // Use type-qualified matching when receiver hint contains a package-like path
        if (receiverHint.includes(".")) {
          return `call.getCallee().getDeclaringType().hasQualifiedName("${hint.substring(0, hint.lastIndexOf("."))}", "${hint.substring(hint.lastIndexOf(".") + 1)}") and call.getCallee().getName() = "${escaped}"`;
        }
        return `call.getCallee().getDeclaringType().hasName("${hint}") and call.getCallee().getName() = "${escaped}"`;
      case "csharp":
        if (receiverHint.includes(".")) {
          return `call.getCallee().getDeclaringType().hasQualifiedName("${hint.substring(0, hint.lastIndexOf("."))}", "${hint.substring(hint.lastIndexOf(".") + 1)}") and call.getCallee().getName() = "${escaped}"`;
        }
        return `call.getCallee().getDeclaringType().hasName("${hint}") and call.getCallee().getName() = "${escaped}"`;
      case "python":
        // Python: use attribute access matching with module hint
        return `call.getFunction().toString().matches("%${hint}.${escaped}%")`;
      case "javascript":
        // JS: use receiver type matching when available
        return `call.getReceiver().toString().matches("%${hint}%") and call.getCalleeName() = "${escaped}"`;
    }
  }

  switch (language) {
    case "go":
      return `call.getTarget().getName() = "${escaped}"`;
    case "python":
      return `call.getFunction().toString().matches("%${escaped}%")`;
    case "javascript":
      return `call.getCalleeName() = "${escaped}"`;
    case "java":
    case "csharp":
      return `call.getCallee().getName() = "${escaped}"`;
  }
}

function callableBasename(callable: string): string {
  const trimmed = callable.trim();
  if (!trimmed) {
    return trimmed;
  }
  const pieces = trimmed
    .split(/[.:#]/)
    .map((part) => part.trim())
    .filter(Boolean);
  return pieces.at(-1) ?? trimmed;
}

function wrapCallExists(nameCheck: string, nodeCheck: string, profile: CodeqlProfile): string {
  const callType = profile.callNodeType ?? "DataFlow::CallNode";
  return [
    `exists(${callType} call |`,
    `        ${nameCheck} and`,
    `        ${nodeCheck}`,
    `      )`,
  ].join("\n");
}

function buildGoParamSourceCheck(nodeParamName: string, info: CallableInfo): string | null {
  if (info.argIndex == null || info.argIndex < 0) {
    return null;
  }

  const escapedCallable = escapeQllString(info.callable);
  return [
    "exists(Method m |",
    `        m.getName() = "${escapedCallable}" and`,
    `        m.getNumParameter() > ${info.argIndex} and`,
    `        ${nodeParamName}.asParameter() = m.getParameter(${info.argIndex})`,
    "      )",
  ].join("\n");
}

function buildNodeCallableCheck(
  nodeParamName: string,
  info: CallableInfo,
  profile: CodeqlProfile,
  role: "source" | "sink" | "sanitizer",
  hints?: RenderingHints,
): string {
  const language = profile.language;
  const nameCheck = buildCallableNameCheck(info.callable, language, info.receiverHint, profile, hints);

  const getArg = profile.getArgumentMethod ?? "getArgument";
  const getAnyArg = profile.getAnArgumentExpr ?? "call.getAnArgument()";
  const resultExpr = profile.callResultExpr ?? "call.getResult()";

  const callGetArg = (idx: number) => `call.${getArg}(${idx})`;

  if (role === "source") {
    if (language === "go" && info.flowKind === "param") {
      const paramCheck = buildGoParamSourceCheck(nodeParamName, info);
      if (paramCheck) {
        return paramCheck;
      }
    }

    let nodeExpr: string;
    if (info.argIndex != null && info.flowKind !== "return") {
      nodeExpr = callGetArg(info.argIndex);
    } else {
      nodeExpr = resultExpr;
    }
    return wrapCallExists(nameCheck, `${nodeParamName} = ${nodeExpr}`, profile);
  }

  if (role === "sink") {
    const callableName = language === "go"
      ? callableBasename(info.callable)
      : info.callable;
    let argExpr: string;
    if (info.argIndex != null) {
      const isVariadicFormat = info.argIndex === 0
        && (hints?.variadicFormatFuncs.has(callableName) ?? false);
      argExpr = isVariadicFormat
        ? getAnyArg
        : callGetArg(info.argIndex);
    } else if (language === "go" && (hints?.sqlQueryTextArg0Callables.has(callableName) ?? false)) {
      argExpr = callGetArg(0);
    } else {
      argExpr = getAnyArg;
    }
    return wrapCallExists(nameCheck, `${nodeParamName} = ${argExpr}`, profile);
  }

  // Sanitizer: match either return value or argument
  const argExpr = info.argIndex != null
    ? callGetArg(info.argIndex)
    : getAnyArg;
  return wrapCallExists(
    nameCheck,
    `(${nodeParamName} = ${resultExpr} or ${nodeParamName} = ${argExpr})`,
    profile,
  );
}

function buildSummaryTaintStep(info: CallableInfo, profile: CodeqlProfile, hints?: RenderingHints): string {
  const nameCheck = buildCallableNameCheck(info.callable, profile.language, info.receiverHint, profile, hints);
  const callType = profile.callNodeType ?? "DataFlow::CallNode";
  const getArg = profile.getArgumentMethod ?? "getArgument";
  const resultExpr = profile.callResultExpr ?? "call.getResult()";
  const getAnyArg = profile.getAnArgumentExpr ?? "call.getAnArgument()";

  let nodeToExpr = resultExpr;
  if (info.flowKind !== "return" && info.flowKind !== "unknown" && info.argIndex != null) {
    nodeToExpr = `call.${getArg}(${info.argIndex})`;
  }

  return [
    `exists(${callType} call |`,
    `        ${nameCheck} and`,
    `        nodeFrom = ${getAnyArg} and`,
    `        nodeTo = ${nodeToExpr}`,
    `      )`,
  ].join("\n");
}

/**
 * Generate CodeQL isAdditionalTaintStep predicates for implicit data structure
 * propagation: map lookups, struct field access, JSON unmarshaling, proto getters, etc.
 * These catch taint flows through data transformations that callable-name matching misses.
 */
function renderImplicitPropagationSteps(language: TaintAnalysisLanguage): string {
  // Each clause is a passKey-independent taint step (applies to all passes).
  // CodeQL requires every disjunction branch to bind output parameters, so we bind
  // passKey via set membership over all known pass keys instead of the reflexive
  // `passKey = passKey` (which CodeQL treats as unbound).
  const passKeyBinding = "(" + TAINT_ANALYSIS_PASSES.map((p) => `passKey = "${p.passKey}"`).join(" or ") + ")";
  const clauses: string[] = [];

  switch (language) {
    case "go":
      clauses.push(
        // Map index: m[key] propagates taint from map to value
        `    // Implicit: map index propagation
    (
      nodeTo.asExpr().(IndexExpr).getBase() = nodeFrom.asExpr() and
      ${passKeyBinding}
    )`,
        // Struct field read: s.Field propagates taint from struct to field
        `    // Implicit: struct field read propagation
    (
      nodeTo.asExpr().(SelectorExpr).getBase() = nodeFrom.asExpr() and
      ${passKeyBinding}
    )`,
        // json.Unmarshal: taints the target pointer
        `    // Implicit: json.Unmarshal propagates taint to target
    exists(DataFlow::CallNode call |
      call.getTarget().hasQualifiedName("encoding/json", "Unmarshal") and
      nodeFrom = call.getArgument(0) and
      nodeTo = call.getArgument(1) and
      ${passKeyBinding}
    )`,
        // json.NewDecoder().Decode: taints the target
        `    // Implicit: json.Decoder.Decode propagates taint
    exists(DataFlow::CallNode call |
      call.getTarget().getName() = "Decode" and
      nodeFrom = call.getReceiver() and
      nodeTo = call.getArgument(0) and
      ${passKeyBinding}
    )`,
      );
      break;

    case "python":
      clauses.push(
        // Dict access: d[key] / d.get(key)
        `    // Implicit: dict subscript propagation
    exists(DataFlow::CallNode call |
      call.getCalleeName() = "get" and
      nodeFrom = call.getObject() and
      nodeTo = call and
      ${passKeyBinding}
    )`,
        // json.loads: propagates taint from string to parsed object
        `    // Implicit: json.loads propagation
    exists(DataFlow::CallNode call |
      call.getFunction().toString().matches("%json.loads%") and
      nodeFrom = call.getArgument(0) and
      nodeTo = call and
      ${passKeyBinding}
    )`,
      );
      break;

    case "java":
      clauses.push(
        // Map.get: propagates taint from map to value
        `    // Implicit: Map.get propagation
    exists(DataFlow::CallNode call |
      call.getCallee().getName() = "get" and
      call.getCallee().getDeclaringType().getASupertype*().hasQualifiedName("java.util", "Map") and
      nodeFrom = call.getReceiver() and
      nodeTo = call and
      ${passKeyBinding}
    )`,
        // ObjectMapper.readValue: propagates taint from JSON string to deserialized object
        `    // Implicit: ObjectMapper.readValue propagation
    exists(DataFlow::CallNode call |
      call.getCallee().getName() = "readValue" and
      nodeFrom = call.getArgument(0) and
      nodeTo = call and
      ${passKeyBinding}
    )`,
      );
      break;

    case "javascript":
      clauses.push(
        // JSON.parse: propagates taint from string to parsed object
        `    // Implicit: JSON.parse propagation
    exists(DataFlow::CallNode call |
      call.getCalleeName() = "parse" and
      nodeFrom = call.getArgument(0) and
      nodeTo = call and
      ${passKeyBinding}
    )`,
        // Property access: obj.prop / obj[key]
        `    // Implicit: property read propagation
    exists(DataFlow::PropRead read |
      nodeFrom = read.getBase() and
      nodeTo = read and
      ${passKeyBinding}
    )`,
      );
      break;

    case "csharp":
      clauses.push(
        // JsonSerializer.Deserialize
        `    // Implicit: JsonSerializer.Deserialize propagation
    exists(DataFlow::CallNode call |
      call.getCallee().getName() = "Deserialize" and
      nodeFrom = call.getArgument(0) and
      nodeTo = call and
      ${passKeyBinding}
    )`,
      );
      break;
  }

  if (clauses.length === 0) {
    return "";
  }

  return clauses.join("\n    or\n");
}

function renderSummaryLibrary(
  byPass: Map<string, CallableInfo[]>,
  languageImports: string,
  profile: CodeqlProfile,
  hints?: RenderingHints,
): string {
  const hasAnySummary = [...byPass.values()].some((callables) => callables.length > 0);

  if (!hasAnySummary) {
    const implicitSteps = renderImplicitPropagationSteps(profile.language);
    const body = implicitSteps || "    none()";
    return [
      "/**",
      " * Generated by Kuzushi Taint Analysis integration.",
      " */",
      "",
      languageImports,
      "",
      "module MySummaries {",
      "  predicate isAdditionalTaintStep(DataFlow::Node nodeFrom, DataFlow::Node nodeTo, string passKey) {",
      body,
      "  }",
      "}",
      "",
    ].join("\n");
  }

  const passClauses = TAINT_ANALYSIS_PASSES.map((passDef) => {
    const callables = byPass.get(passDef.passKey) ?? [];
    if (callables.length === 0) {
      return `    passKey = "${passDef.passKey}" and nodeFrom.toString().regexpMatch("a^")`;
    }

    const callableChecks = callables
      .map((info) => buildSummaryTaintStep(info, profile, hints))
      .join("\n      or ");

    return [
      `    passKey = "${passDef.passKey}" and`,
      "    (",
      `      ${callableChecks}`,
      "    )",
    ].join("\n");
  }).join("\n    or\n");

  const implicitSteps = renderImplicitPropagationSteps(profile.language);

  return [
    "/**",
    " * Generated by Kuzushi Taint Analysis integration.",
    " */",
    "",
    languageImports,
    "",
    "module MySummaries {",
    "  predicate isAdditionalTaintStep(DataFlow::Node nodeFrom, DataFlow::Node nodeTo, string passKey) {",
    passClauses,
    implicitSteps ? `    or\n${implicitSteps}` : "",
    "  }",
    "}",
    "",
  ].join("\n");
}

function escapeQllString(value: string): string {
  return value
    .replaceAll("\\", "\\\\")
    .replaceAll('"', '\\"')
    .replaceAll("\n", "\\n")
    .replaceAll("\r", "\\r")
    .replaceAll("\t", "\\t")
    .replaceAll("\0", "\\0");
}

function hasUsableRoleForPasses(
  labels: TaintAnalysisLabelsDocument,
  enabledPasses: TaintAnalysisPassDefinition[],
  role: "source" | "sink" | "sanitizer",
): boolean {
  const enabledPassIds = new Set(enabledPasses.map((pass) => pass.passId));
  for (const pass of labels.passes) {
    if (!enabledPassIds.has(pass.pass_id)) {
      continue;
    }
    if (pass.entries.some((entry) => entry.role === role && entry.classification !== "fp")) {
      return true;
    }
  }
  return false;
}

function asLabelOutput(value: unknown): TaintAnalysisLabelOutput | null {
  if (!isRecord(value)) {
    return null;
  }

  const labelsPath = typeof value["labelsPath"] === "string"
    ? value["labelsPath"]
    : "";

  const workspaceDir = typeof value["workspaceDir"] === "string"
    ? value["workspaceDir"]
    : "";

  const codeqlBinary = typeof value["codeqlBinary"] === "string"
    ? value["codeqlBinary"]
    : "";

  const dbPath = typeof value["dbPath"] === "string"
    ? value["dbPath"]
    : "";

  const codeqlVersion = typeof value["codeqlVersion"] === "string"
    ? value["codeqlVersion"]
    : "";

  const codeqlApiProfileId = typeof value["codeqlApiProfileId"] === "string"
    ? value["codeqlApiProfileId"]
    : "";

  if (!labelsPath || !workspaceDir || !codeqlBinary || !dbPath || !codeqlVersion || !codeqlApiProfileId) {
    return null;
  }

  const record = value as Record<string, unknown>;
  if (!record["extractionDegradation"] || typeof record["extractionDegradation"] !== "object") {
    record["extractionDegradation"] = { status: "ok", reasons: [] } satisfies ExtractionDegradation;
  }

  return value as unknown as TaintAnalysisLabelOutput;
}

function resolveBaselineCacheRepoRoot(context: { repoRoot: string; scanPath?: string }): string {
  return context.repoRoot;
}

export const __taintAnalysisRunInternals = {
  renderTaintAnalysisLibraries,
  renderTaintQuery,
  selectProfileWithCompileGate,
  firstErrorExcerpt,
  augmentFinding,
  buildCallableNameCheck,
  wrapCallExists,
  hasUsableRoleForPasses,
  buildSummaryTaintStep,
  renderSummaryLibrary,
  groupCallables,
  escapeQllString,
  defaultRenderingHints,
  narrowDiffScope,
  resolveBaselineCacheRepoRoot,
  mergeBaselineTaintFindings,
  extractPassId,
};
