import { execFile, type ExecFileException } from "node:child_process";
import { existsSync } from "node:fs";
import { readdir, readFile, writeFile } from "node:fs/promises";
import path from "node:path";
import { promisify } from "node:util";
import { scoreFindingMetadata } from "../../scanners/scoring.js";
import { selectFindings, type CodeQLSarifOutput } from "../../scanners/run-codeql.js";
import type { Finding, TriageAgentConfig } from "../../scanners/types.js";
import type { ScanOpts } from "../../types.js";
import { isRecord, toErrorMessage } from "../../utils.js";
import type { AgentTask } from "../types.js";
import {
  AUGUR_PASSES,
  resolveAugurConfig,
  type AugurLabelOutput,
  type AugurLabelsDocument,
  type AugurPassEntry,
  type AugurPassDefinition,
  type AugurPreflightOutput,
} from "./augur-types.js";

const execFileAsync = promisify(execFile);

/**
 * Augur Step 4-6 task: deterministic library/query generation + analysis + report filtering.
 */
export const augurAnalyzeTask: AgentTask<ScanOpts, Finding[]> = {
  id: "augur-analyze",
  displayName: "Augur Analyze",
  outputKind: "findings",
  dependsOn: ["augur-label"],
  async run(_input, context): Promise<Finding[]> {
    const cfg = resolveAugurConfig(context.config);
    const labelOutput = asLabelOutput(context.upstreamOutputs.get("augur-label"));
    if (!labelOutput) {
      throw new Error("augur-analyze requires upstream output from augur-label");
    }

    const labels = labelOutput.labels ?? await loadLabelsFromDisk(labelOutput.labelsPath);

    const libraries = renderAugurLibraries(labels, labelOutput.language);
    const librariesDir = path.join(labelOutput.workspaceDir, "libraries");
    await writeFile(path.join(librariesDir, "MySources.qll"), libraries.sources, "utf-8");
    await writeFile(path.join(librariesDir, "MySinks.qll"), libraries.sinks, "utf-8");
    await writeFile(path.join(librariesDir, "MySanitizers.qll"), libraries.sanitizers, "utf-8");
    await writeFile(path.join(librariesDir, "MySummaries.qll"), libraries.summaries, "utf-8");

    const taintTemplatePath = path.join(labelOutput.augurPath, "assets", "taint_query.ql.tmpl");
    const taintTemplate = await readFile(taintTemplatePath, "utf-8");

    const queriesDir = path.join(labelOutput.workspaceDir, "queries");
    const resultsDir = path.join(labelOutput.workspaceDir, "results");

    const enabledPasses = AUGUR_PASSES.filter((passDef) => labelOutput.passes.includes(passDef.passId));

    for (const passDef of enabledPasses) {
      const queryPath = path.join(queriesDir, queryFilename(passDef.passId, passDef.focus));
      const query = renderTaintQuery(
        taintTemplate,
        passDef,
        labelOutput.language,
      );
      await writeFile(queryPath, query, "utf-8");

      const resultPath = path.join(resultsDir, `pass${passDef.passId}.sarif`);
      await runCommand(
        labelOutput.codeqlBinary,
        withResources([
          "database",
          "analyze",
          labelOutput.dbPath,
          queryPath,
          "--format=sarifv2.1.0",
          `--output=${resultPath}`,
        ], cfg),
        labelOutput.workspaceDir,
      );
    }

    const scriptPath = path.join(labelOutput.augurPath, "scripts", "filter_and_report.py");
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

    const findings = await convertSarifToAugurFindings(resultsDir, context.repoName, labels);
    const capped = cfg.maxFindings ? findings.slice(0, cfg.maxFindings) : findings;
    return capped;
  },
  triageAgentConfig(finding, repoName): TriageAgentConfig {
    return {
      prompt: [
        "You are an Augur-focused security triage agent.",
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

function withResources(args: string[], cfg: ReturnType<typeof resolveAugurConfig>): string[] {
  const out = [...args];
  if (cfg.threads && cfg.threads > 0) {
    out.push(`--threads=${cfg.threads}`);
  }
  if (cfg.ram && cfg.ram > 0) {
    out.push(`--ram=${cfg.ram}`);
  }
  return out;
}

async function loadLabelsFromDisk(labelsPath: string): Promise<AugurLabelsDocument> {
  const raw = await readFile(labelsPath, "utf-8");
  const parsed = JSON.parse(raw);
  if (!isRecord(parsed) || !Array.isArray(parsed["passes"])) {
    throw new Error(`Invalid labels.json at ${labelsPath}`);
  }

  return parsed as unknown as AugurLabelsDocument;
}

function renderAugurLibraries(labels: AugurLabelsDocument, language: AugurPreflightOutput["language"]): {
  sources: string;
  sinks: string;
  sanitizers: string;
  summaries: string;
} {
  const languageImports = libraryLanguageImports(language);

  const sourceByPass = groupCallables(labels, "source");
  const sinkByPass = groupCallables(labels, "sink");
  const sanitizerByPass = groupCallables(labels, "sanitizer");

  const sources = renderMatcherLibrary(
    "MySources",
    "isSource",
    "node",
    sourceByPass,
    languageImports,
  );

  const sinks = renderMatcherLibrary(
    "MySinks",
    "isSink",
    "node",
    sinkByPass,
    languageImports,
  );

  const sanitizers = renderMatcherLibrary(
    "MySanitizers",
    "isBarrier",
    "node",
    sanitizerByPass,
    languageImports,
  );

  const summaries = [
    "/**",
    " * Generated by Kuzushi Augur integration.",
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
  byPass: Map<string, string[]>,
  languageImports: string,
): string {
  const passClauses = AUGUR_PASSES.map((passDef) => {
    const callables = byPass.get(passDef.passKey) ?? [];
    if (callables.length === 0) {
      return `    passKey = \"${passDef.passKey}\" and none()`;
    }

    const callableChecks = callables
      .map((callable) => `nodeHasCallable(${nodeParamName}, \"${escapeQllString(callable)}\")`)
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
    " * Generated by Kuzushi Augur integration.",
    " */",
    "",
    languageImports,
    "",
    `module ${moduleName} {`,
    "  private predicate nodeHasCallable(DataFlow::Node node, string callable) {",
    "    node.toString().regexpMatch(\".*\\\\b\" + callable + \"\\\\b.*\")",
    "  }",
    "",
    `  predicate ${predicateName}(DataFlow::Node ${nodeParamName}, string passKey) {`,
    passClauses,
    "  }",
    "}",
    "",
  ].join("\n");
}

function groupCallables(labels: AugurLabelsDocument, role: AugurPassEntry["role"]): Map<string, string[]> {
  const out = new Map<string, string[]>();

  for (const pass of labels.passes) {
    const passDef = AUGUR_PASSES.find((candidate) => candidate.passId === pass.pass_id);
    if (!passDef) {
      continue;
    }

    const names = pass.entries
      .filter((entry) => entry.role === role && entry.classification !== "fp")
      .map((entry) => entry.signature.callable.trim())
      .filter(Boolean);

    const unique = [...new Set(names)].sort((a, b) => a.localeCompare(b));
    out.set(passDef.passKey, unique);
  }

  return out;
}

function renderTaintQuery(
  template: string,
  passDef: AugurPassDefinition,
  language: AugurPreflightOutput["language"],
): string {
  const queryIdPrefix = languageQueryIdPrefix(language);
  const extraTags = passDef.cwes
    .slice(1)
    .map((cwe) => ` *       external/cwe/cwe-${cwe}`)
    .join("\n");

  const rendered = template
    .replaceAll("{{QUERY_NAME}}", `Augur Pass ${passDef.passId} - ${passDef.focus}`)
    .replaceAll("{{QUERY_DESCRIPTION}}", `Detect tainted dataflow for ${passDef.focus}.`)
    .replaceAll("{{QUERY_ID}}", `${queryIdPrefix}/augur/pass${passDef.passId}-${passDef.passKey.replaceAll("_", "-")}`)
    .replaceAll("{{PRECISION}}", "medium")
    .replaceAll("{{CWE_PRIMARY}}", passDef.cwes[0] ?? "000")
    .replaceAll("{{EXTRA_TAGS}}", extraTags)
    .replaceAll("{{SOURCE_MODULE}}", "libraries.MySources")
    .replaceAll("{{SINK_MODULE}}", "libraries.MySinks")
    .replaceAll("{{SANITIZER_MODULE}}", "libraries.MySanitizers")
    .replaceAll("{{SUMMARY_MODULE}}", "libraries.MySummaries")
    .replaceAll("{{CONFIG_NAME}}", `Pass${passDef.passId}Config`)
    .replaceAll("{{FLOW_MODULE}}", `Pass${passDef.passId}Flow`)
    .replaceAll("{{PASS_KEY}}", passDef.passKey)
    .replaceAll("{{RESULT_MESSAGE}}", `Potential ${passDef.focus} flow from $@ to $@.`)
    .replaceAll("{{LANGUAGE_IMPORTS}}", queryLanguageImports(language));

  if (rendered.includes("{{")) {
    throw new Error(
      `Augur taint query template render failed for pass ${passDef.passId}: unresolved placeholders`,
    );
  }

  return rendered;
}

function queryLanguageImports(language: AugurPreflightOutput["language"]): string {
  if (language === "python") {
    return [
      "import python",
      "import semmle.python.dataflow.new.DataFlow",
      "import semmle.python.dataflow.new.TaintTracking",
    ].join("\n");
  }

  if (language === "go") {
    return [
      "import go",
      "import semmle.go.dataflow.new.DataFlow",
      "import semmle.go.dataflow.new.TaintTracking",
    ].join("\n");
  }

  if (language === "java") {
    return [
      "import java",
      "import semmle.code.java.dataflow.DataFlow",
      "import semmle.code.java.dataflow.TaintTracking",
    ].join("\n");
  }

  if (language === "csharp") {
    return [
      "import csharp",
      "import semmle.code.csharp.dataflow.DataFlow",
      "import semmle.code.csharp.dataflow.TaintTracking",
    ].join("\n");
  }

  return [
    "import javascript",
    "import semmle.javascript.dataflow.DataFlow",
    "import semmle.javascript.dataflow.TaintTracking",
  ].join("\n");
}

function libraryLanguageImports(language: AugurPreflightOutput["language"]): string {
  if (language === "python") {
    return [
      "import python",
      "import semmle.python.dataflow.new.DataFlow",
    ].join("\n");
  }

  if (language === "go") {
    return [
      "import go",
      "import semmle.go.dataflow.new.DataFlow",
    ].join("\n");
  }

  if (language === "java") {
    return [
      "import java",
      "import semmle.code.java.dataflow.DataFlow",
    ].join("\n");
  }

  if (language === "csharp") {
    return [
      "import csharp",
      "import semmle.code.csharp.dataflow.DataFlow",
    ].join("\n");
  }

  return [
    "import javascript",
    "import semmle.javascript.dataflow.DataFlow",
  ].join("\n");
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

async function convertSarifToAugurFindings(
  resultsDir: string,
  repoName: string,
  labels: AugurLabelsDocument,
): Promise<Finding[]> {
  const files = (await readdir(resultsDir))
    .filter((name) => name.toLowerCase().endsWith(".sarif"))
    .sort();

  const deduped = new Map<string, Finding>();

  for (const fileName of files) {
    const passId = parsePassIdFromName(fileName);
    const passDef = passId
      ? AUGUR_PASSES.find((pass) => pass.passId === passId)
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
  passDef: AugurPassDefinition | undefined,
  labels: AugurLabelsDocument,
): Finding {
  const labelPass = passDef
    ? labels.passes.find((pass) => pass.pass_id === passDef.passId)
    : undefined;

  const sourceCount = labelPass?.entries.filter((entry) => entry.role === "source").length ?? 0;
  const sinkCount = labelPass?.entries.filter((entry) => entry.role === "sink").length ?? 0;

  const passEvidence = passDef
    ? `Augur pass ${passDef.passId} (${passDef.focus}) | labeled sources=${sourceCount} sinks=${sinkCount}`
    : "Augur pass metadata unavailable";

  const augmented: Finding = {
    ...finding,
    scanner: "augur-analyze",
    ruleId: passDef
      ? `augur/pass${passDef.passId}/${finding.ruleId}`
      : `augur/${finding.ruleId}`,
    message: passDef
      ? `[Augur ${passDef.focus}] ${finding.message}`
      : `[Augur] ${finding.message}`,
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

function languageQueryIdPrefix(language: AugurPreflightOutput["language"]): string {
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

function escapeQllString(value: string): string {
  return value.replaceAll("\\", "\\\\").replaceAll('"', '\\"');
}

function asLabelOutput(value: unknown): AugurLabelOutput | null {
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

  if (!labelsPath || !workspaceDir || !codeqlBinary || !dbPath) {
    return null;
  }

  return value as unknown as AugurLabelOutput;
}

export const __augurAnalyzeInternals = {
  renderAugurLibraries,
  renderTaintQuery,
  augmentFinding,
};
