import { execFile, type ExecFileException } from "node:child_process";
import { existsSync } from "node:fs";
import { readdir, readFile, writeFile } from "node:fs/promises";
import path from "node:path";
import { promisify } from "node:util";
import { scoreFindingMetadata } from "../../../scanners/scoring.js";
import { selectFindings, type CodeQLSarifOutput } from "../../../scanners/run-codeql.js";
import type { Finding, TriageAgentConfig } from "../../../scanners/types.js";
import type { ScanOpts } from "../../../types.js";
import { isRecord, toErrorMessage } from "../../../utils.js";
import type { AgentTask } from "../../types.js";
import {
  candidateProfiles,
  formatProfileDiagnostics,
  libraryImportsForProfile,
  profileById,
  queryImportsForProfile,
  type CodeqlProfile,
} from "./codeql-compat.js";
import {
  NEWAZA_PASSES,
  resolveNewazaConfig,
  type NewazaLabelOutput,
  type NewazaLabelsDocument,
  type NewazaLanguage,
  type NewazaPassEntry,
  type NewazaPassDefinition,
  type NewazaPreflightOutput,
} from "./types.js";

const execFileAsync = promisify(execFile);

interface CallableInfo {
  callable: string;
  flowKind: "param" | "argument" | "return" | "receiver" | "field" | "unknown";
  receiverHint: string | null;
  argIndex: number | null;
}

/**
 * Newaza Step 4-6 task: deterministic library/query generation + analysis + report filtering.
 */
export const newazaAnalyzeTask: AgentTask<ScanOpts, Finding[]> = {
  id: "newaza-analyze",
  displayName: "Newaza Analyze",
  outputKind: "findings",
  dependsOn: ["newaza-label"],
  async run(_input, context): Promise<Finding[]> {
    const cfg = resolveNewazaConfig(context.config);
    const labelOutput = asLabelOutput(context.upstreamOutputs.get("newaza-label"));
    if (!labelOutput) {
      throw new Error("newaza-analyze requires upstream output from newaza-label");
    }

    const labels = labelOutput.labels ?? await loadLabelsFromDisk(labelOutput.labelsPath);

    const taintTemplatePath = path.join(labelOutput.newazaPath, "assets", "taint_query.ql.tmpl");
    const taintTemplate = await readFile(taintTemplatePath, "utf-8");

    const resultsDir = path.join(labelOutput.workspaceDir, "results");
    const compatRecordPath = path.join(labelOutput.workspaceDir, "exploration", "codeql_compat.json");

    const enabledPasses = NEWAZA_PASSES.filter((passDef) => labelOutput.passes.includes(passDef.passId));
    if (enabledPasses.length === 0) {
      return [];
    }

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

    for (const passQuery of passQueries) {
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
    }

    const scriptPath = path.join(labelOutput.newazaPath, "scripts", "filter_and_report.py");
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

    const findings = await convertSarifToNewazaFindings(resultsDir, context.repoName, labels);
    const capped = cfg.maxFindings ? findings.slice(0, cfg.maxFindings) : findings;
    return capped;
  },
  triageAgentConfig(finding, repoName): TriageAgentConfig {
    return {
      prompt: [
        "You are an Newaza-focused security triage agent.",
        "The finding came from a neurosymbolic pipeline: deterministic extraction + LLM API labeling + CodeQL taint analysis.",
        "Use the evidence and code path to confirm exploitability rather than trusting the label blindly.",
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
        "## Investigation instructions",
        "1. Validate that source and sink semantics match the reported CWE pass.",
        "2. Confirm attacker control, inter-procedural reachability, and realistic exploitability.",
        "3. Check framework sanitization/validation guards and barriers along the path.",
        "4. If uncertain, return needs_review with conservative confidence and concrete missing evidence.",
        "",
        "## Output requirements",
        "Return ONLY a JSON object with:",
        "fingerprint, verdict(tp|fp|needs_review), confidence(0..1), rationale, verification_steps(array), fix_patch(string|null)",
      ].join("\n"),
    };
  },
};

function withResources(args: string[], cfg: ReturnType<typeof resolveNewazaConfig>): string[] {
  const out = [...args];
  if (cfg.threads && cfg.threads > 0) {
    out.push(`--threads=${cfg.threads}`);
  }
  if (cfg.ram && cfg.ram > 0) {
    out.push(`--ram=${cfg.ram}`);
  }
  return out;
}

async function loadLabelsFromDisk(labelsPath: string): Promise<NewazaLabelsDocument> {
  const raw = await readFile(labelsPath, "utf-8");
  const parsed = JSON.parse(raw);
  if (!isRecord(parsed) || !Array.isArray(parsed["passes"])) {
    throw new Error(`Invalid labels.json at ${labelsPath}`);
  }

  return parsed as unknown as NewazaLabelsDocument;
}

function renderNewazaLibraries(labels: NewazaLabelsDocument, profile: CodeqlProfile): {
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
    profile.language,
    "source",
  );

  const sinks = renderMatcherLibrary(
    "MySinks",
    "isSink",
    "node",
    sinkByPass,
    languageImports,
    profile.language,
    "sink",
  );

  const sanitizers = renderMatcherLibrary(
    "MySanitizers",
    "isBarrier",
    "node",
    sanitizerByPass,
    languageImports,
    profile.language,
    "sanitizer",
  );

  const summaries = [
    "/**",
    " * Generated by Kuzushi Newaza integration.",
    " */",
    "",
    languageImports,
    "",
    "module MySummaries {",
    "  predicate isAdditionalTaintStep(DataFlow::Node nodeFrom, DataFlow::Node nodeTo, string passKey) {",
    "    none()",
    "  }",
    "}",
    "",
  ].join("\n");

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
  language: NewazaLanguage,
  role: "source" | "sink" | "sanitizer",
): string {
  const passClauses = NEWAZA_PASSES.map((passDef) => {
    const callables = byPass.get(passDef.passKey) ?? [];
    if (callables.length === 0) {
      return `    passKey = \"${passDef.passKey}\" and ${nodeParamName}.toString().regexpMatch(\"a^\")`;
    }

    const callableChecks = callables
      .map((info) => buildNodeCallableCheck(nodeParamName, info, language, role))
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
    " * Generated by Kuzushi Newaza integration.",
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

function groupCallables(labels: NewazaLabelsDocument, role: NewazaPassEntry["role"]): Map<string, CallableInfo[]> {
  const out = new Map<string, CallableInfo[]>();

  for (const pass of labels.passes) {
    const passDef = NEWAZA_PASSES.find((candidate) => candidate.passId === pass.pass_id);
    if (!passDef) {
      continue;
    }

    const seen = new Set<string>();
    const infos: CallableInfo[] = [];

    for (const entry of pass.entries) {
      if (entry.role !== role || entry.classification === "fp") {
        continue;
      }

      const callable = entry.signature.callable.trim();
      if (!callable || seen.has(callable)) {
        continue;
      }

      seen.add(callable);
      infos.push({
        callable,
        flowKind: entry.signature.flow_kind,
        receiverHint: entry.signature.type ?? entry.signature.module ?? null,
        argIndex: entry.signature.arg_index ?? null,
      });
    }

    infos.sort((a, b) => a.callable.localeCompare(b.callable));
    out.set(passDef.passKey, infos);
  }

  return out;
}

function renderTaintQuery(
  template: string,
  passDef: NewazaPassDefinition,
  profile: CodeqlProfile,
): string {
  const queryIdPrefix = languageQueryIdPrefix(profile.language);
  const extraTags = passDef.cwes
    .slice(1)
    .map((cwe) => ` *       external/cwe/cwe-${cwe}`)
    .join("\n");

  const rendered = template
    .replaceAll("import {{SOURCE_MODULE}}", "import libraries.MySources")
    .replaceAll("import {{SINK_MODULE}}", "import libraries.MySinks")
    .replaceAll("import {{SANITIZER_MODULE}}", "import libraries.MySanitizers")
    .replaceAll("import {{SUMMARY_MODULE}}", "import libraries.MySummaries")
    .replaceAll("{{QUERY_NAME}}", `Newaza Pass ${passDef.passId} - ${passDef.focus}`)
    .replaceAll("{{QUERY_DESCRIPTION}}", `Detect tainted dataflow for ${passDef.focus}.`)
    .replaceAll("{{QUERY_ID}}", `${queryIdPrefix}/newaza/pass${passDef.passId}-${passDef.passKey.replaceAll("_", "-")}`)
    .replaceAll("{{PRECISION}}", "medium")
    .replaceAll("{{CWE_PRIMARY}}", passDef.cwes[0] ?? "000")
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
      `Newaza taint query template render failed for pass ${passDef.passId}: unresolved placeholders`,
    );
  }

  return rendered;
}

interface PassQueryArtifact {
  passId: 1 | 2 | 3 | 4 | 5 | 6;
  queryPath: string;
  resultPath: string;
}

interface ProfileCompileAttempt {
  id: string;
  ok: boolean;
  error?: string;
}

async function renderArtifactsForProfile(args: {
  labels: NewazaLabelsDocument;
  profile: CodeqlProfile;
  taintTemplate: string;
  workspaceDir: string;
  enabledPasses: NewazaPassDefinition[];
}): Promise<PassQueryArtifact[]> {
  const libraries = renderNewazaLibraries(args.labels, args.profile);
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
  language: NewazaPreflightOutput["language"];
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

async function convertSarifToNewazaFindings(
  resultsDir: string,
  repoName: string,
  labels: NewazaLabelsDocument,
): Promise<Finding[]> {
  const files = (await readdir(resultsDir))
    .filter((name) => name.toLowerCase().endsWith(".sarif"))
    .sort();

  const deduped = new Map<string, Finding>();

  for (const fileName of files) {
    const passId = parsePassIdFromName(fileName);
    const passDef = passId
      ? NEWAZA_PASSES.find((pass) => pass.passId === passId)
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

function augmentFinding(
  finding: Finding,
  passDef: NewazaPassDefinition | undefined,
  labels: NewazaLabelsDocument,
): Finding {
  const labelPass = passDef
    ? labels.passes.find((pass) => pass.pass_id === passDef.passId)
    : undefined;

  const sourceCount = labelPass?.entries.filter((entry) => entry.role === "source").length ?? 0;
  const sinkCount = labelPass?.entries.filter((entry) => entry.role === "sink").length ?? 0;

  const passEvidence = passDef
    ? `Newaza pass ${passDef.passId} (${passDef.focus}) | labeled sources=${sourceCount} sinks=${sinkCount}`
    : "Newaza pass metadata unavailable";

  const augmented: Finding = {
    ...finding,
    scanner: "newaza-analyze",
    ruleId: passDef
      ? `newaza/pass${passDef.passId}/${finding.ruleId}`
      : `newaza/${finding.ruleId}`,
    message: passDef
      ? `[Newaza ${passDef.focus}] ${finding.message}`
      : `[Newaza] ${finding.message}`,
    evidence: finding.evidence
      ? `${finding.evidence} | ${passEvidence}`
      : passEvidence,
    cwe: passDef ? passDef.cwes.map((cwe) => `CWE-${cwe}`) : finding.cwe,
    score: scoreFindingMetadata({
      severity: finding.severity,
      likelihood: finding.likelihood,
      impact: finding.impact,
      subcategory: finding.subcategory,
    }),
  };

  return augmented;
}

function parsePassIdFromName(fileName: string): 1 | 2 | 3 | 4 | 5 | 6 | undefined {
  const match = fileName.toLowerCase().match(/pass\s*([1-6])/);
  if (!match) {
    return undefined;
  }

  return Number.parseInt(match[1], 10) as 1 | 2 | 3 | 4 | 5 | 6;
}

function languageQueryIdPrefix(language: NewazaPreflightOutput["language"]): string {
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

function buildNodeCallableCheck(
  nodeParamName: string,
  info: CallableInfo,
  language: NewazaLanguage,
  role: "source" | "sink" | "sanitizer",
): string {
  if (language === "go") {
    return buildNodeCallableCheckGo(nodeParamName, info, role);
  }

  const regexPattern = buildCallableRegexPattern(info.callable);
  return `${nodeParamName}.toString().regexpMatch("${escapeQllString(regexPattern)}")`;
}

function buildNodeCallableCheckGo(
  nodeParamName: string,
  info: CallableInfo,
  role: "source" | "sink" | "sanitizer",
): string {
  const escapedName = escapeQllString(info.callable);

  if (role === "source") {
    return [
      `exists(DataFlow::CallNode call |`,
      `        call.getTarget().getName() = "${escapedName}" and`,
      `        ${nodeParamName} = call.getResult()`,
      `      )`,
    ].join("\n");
  }

  if (role === "sink") {
    const argExpr = info.argIndex != null
      ? `call.getArgument(${info.argIndex})`
      : "call.getAnArgument()";

    return [
      `exists(DataFlow::CallNode call |`,
      `        call.getTarget().getName() = "${escapedName}" and`,
      `        ${nodeParamName} = ${argExpr}`,
      `      )`,
    ].join("\n");
  }

  // sanitizer: match either direction (return value or argument)
  const argExpr = info.argIndex != null
    ? `call.getArgument(${info.argIndex})`
    : "call.getAnArgument()";

  return [
    `exists(DataFlow::CallNode call |`,
    `        call.getTarget().getName() = "${escapedName}" and`,
    `        (${nodeParamName} = call.getResult() or ${nodeParamName} = ${argExpr})`,
    `      )`,
  ].join("\n");
}

function buildCallableRegexPattern(callable: string): string {
  const escapedCallable = escapeRegexLiteral(callable);
  return `.*\\b${escapedCallable}\\b.*`;
}

function escapeRegexLiteral(value: string): string {
  return value.replace(/[\\^$.*+?()[\]{}|]/g, "\\$&");
}

function escapeQllString(value: string): string {
  return value.replaceAll("\\", "\\\\").replaceAll('"', '\\"');
}

function asLabelOutput(value: unknown): NewazaLabelOutput | null {
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

  return value as unknown as NewazaLabelOutput;
}

export const __newazaAnalyzeInternals = {
  renderNewazaLibraries,
  renderTaintQuery,
  selectProfileWithCompileGate,
  firstErrorExcerpt,
  augmentFinding,
  buildNodeCallableCheckGo,
};
