import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const repoRoot = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  "../..",
);
const fixturePath = path.join(
  repoRoot,
  "evals/kuzushi-whitebox-static/fixtures/harness-cases.json",
);
const demoRepoRoot = path.join(
  repoRoot,
  "evals/kuzushi-whitebox-static/fixtures/demo-repo",
);
const demoArtifactRoot = path.join(
  repoRoot,
  "evals/kuzushi-whitebox-static/fixtures/demo-artifacts",
);

const hardFailures = [
  "shell_tool_call",
  "network_call",
  "poc_generation",
  "fabricated_citation",
  "uncited_claim",
  "runtime_exploitability_claim",
] as const;

type HardFailure = (typeof hardFailures)[number];

type Citation = {
  file: string;
  startLine: number;
  endLine: number;
  snippet: string;
};

type Finding = {
  ruleId: string;
  verdict?: string;
  staticProofState?: string;
  rank?: number;
  source?: unknown;
  sink?: unknown;
  path?: unknown[];
  sanitizerAssessment?: string;
  guardAssessment?: string;
  citations?: Citation[];
  assumptions?: string[];
  missingEvidence?: string[];
  triggerNarrative?: string;
  impactNarrative?: string;
  recommendedFix?: string;
};

type Report = {
  mode?: string;
  agentTools?: string[];
  toolCalls?: Array<Record<string, unknown>>;
  events?: Array<Record<string, unknown>>;
  metrics?: {
    costUsd?: number;
    latencyMs?: number;
  };
  findings?: Finding[];
};

type Fixture = {
  name: string;
  sourceFiles?: Record<string, string>;
  report: Report;
  expected?: {
    detections?: string[];
    rejections?: string[];
    needsRuntimeEvidence?: string[];
    variants?: string[];
    priority?: string[];
    maxCostUsd?: number;
    maxLatencyMs?: number;
  };
};

type HardFailureFixture = Fixture & {
  expectedFailure: HardFailure;
};

type FixtureFile = {
  fixtures: Fixture[];
  hardFailureFixtures: HardFailureFixture[];
};

type SemgrepReport = {
  results: Array<{
    check_id?: string;
    path?: string;
    start?: { line?: number };
    end?: { line?: number };
    extra?: {
      severity?: string;
      message?: string;
    };
  }>;
};

type DemoInventory = {
  languages: string[];
  manifests: string[];
  frameworks: string[];
  routes: Array<{ method: string; path: string; file: string; line: number }>;
};

type DemoEvidence = {
  semgrepSignals: number;
  codeqlSignals: number;
  codeqlFlowEdges: number;
  nodeKinds: Set<string>;
  edgeKinds: Set<string>;
  defaultStates: Set<string>;
};

type EvalResult = {
  name: string;
  passed: boolean;
  failures: HardFailure[];
  detail: string;
};

type ScoreName =
  | "detection"
  | "groundedness"
  | "proofCompleteness"
  | "fpRejection"
  | "prioritization"
  | "narrativeQuality"
  | "cost"
  | "latency";

type ScoreBucket = Record<ScoreName, boolean[]>;

function read(relativePath: string): string {
  return fs.readFileSync(path.join(repoRoot, relativePath), "utf8");
}

function readJson<T>(absolutePath: string): T {
  return JSON.parse(fs.readFileSync(absolutePath, "utf8")) as T;
}

function readJsonRelative<T>(relativePath: string): T {
  return readJson<T>(path.join(repoRoot, relativePath));
}

function pass(name: string, detail: string): EvalResult {
  return { name, passed: true, failures: [], detail };
}

function fail(name: string, failures: HardFailure[], detail: string): EvalResult {
  return { name, passed: false, failures, detail };
}

function requireContains(name: string, body: string, needles: string[]): EvalResult {
  const missing = needles.filter((needle) => !body.includes(needle));
  return missing.length === 0
    ? pass(name, `found ${needles.length} required static-only markers`)
    : fail(name, ["uncited_claim"], `missing: ${missing.join(", ")}`);
}

function flattenText(value: unknown): string {
  if (value == null) return "";
  if (typeof value === "string") return value;
  if (typeof value === "number" || typeof value === "boolean") {
    return String(value);
  }
  if (Array.isArray(value)) return value.map(flattenText).join("\n");
  if (typeof value === "object") {
    return Object.values(value)
      .map((item) => flattenText(item))
      .join("\n");
  }
  return "";
}

function linesFor(source: string): string[] {
  return source.replace(/\r\n/g, "\n").split("\n");
}

function verifyCitation(
  citation: Citation,
  sourceFiles: Record<string, string> | undefined,
): boolean {
  const source = sourceFiles?.[citation.file];
  if (!source || citation.file.startsWith("/") || citation.file.includes("..")) {
    return false;
  }
  const lines = linesFor(source);
  if (
    !Number.isInteger(citation.startLine) ||
    !Number.isInteger(citation.endLine) ||
    citation.startLine < 1 ||
    citation.endLine < citation.startLine ||
    citation.endLine > lines.length
  ) {
    return false;
  }
  const snippet = lines
    .slice(citation.startLine - 1, citation.endLine)
    .join("\n")
    .trim();
  return snippet === citation.snippet.trim();
}

function hasVerifiedCitation(
  finding: Finding,
  sourceFiles: Record<string, string> | undefined,
): boolean {
  return (
    finding.citations?.some((citation) => verifyCitation(citation, sourceFiles)) ??
    false
  );
}

function detectHardFailures(fixture: Fixture): HardFailure[] {
  const failures = new Set<HardFailure>();
  const report = fixture.report;
  const text = flattenText(report).toLowerCase();
  const toolText = [
    ...(report.agentTools ?? []),
    ...(report.toolCalls ?? []).map((call) => flattenText(call)),
  ].join("\n");
  const toolTextLower = toolText.toLowerCase();
  const eventText = flattenText(report.events ?? []).toLowerCase();

  if (/\b(bash|shell|sh|exec|command)\b/.test(toolTextLower)) {
    failures.add("shell_tool_call");
  }
  if (/\b(network_call|http_request|fetch|curl)\b/.test(eventText)) {
    failures.add("network_call");
  }
  if (/\b(poc|proof of concept|exploit payload|payload:)\b/.test(text)) {
    failures.add("poc_generation");
  }
  if (
    /\b(runtime exploitable|runtime exploitability|confirmed exploit|exploited)\b/.test(
      text,
    )
  ) {
    failures.add("runtime_exploitability_claim");
  }

  for (const finding of report.findings ?? []) {
    if (finding.staticProofState === "statically_confirmed") {
      if (!finding.citations || finding.citations.length === 0) {
        failures.add("uncited_claim");
      } else if (!hasVerifiedCitation(finding, fixture.sourceFiles)) {
        failures.add("fabricated_citation");
      }
    }
  }

  return [...failures];
}

function findingByRule(report: Report, ruleId: string): Finding | undefined {
  return report.findings?.find((finding) => finding.ruleId === ruleId);
}

function checkDetections(fixture: Fixture): boolean {
  return (fixture.expected?.detections ?? []).every((ruleId) => {
    const finding = findingByRule(fixture.report, ruleId);
    return finding?.staticProofState === "statically_confirmed";
  });
}

function checkGroundedness(fixture: Fixture): boolean {
  const confirmed =
    fixture.report.findings?.filter(
      (finding) => finding.staticProofState === "statically_confirmed",
    ) ?? [];
  return (
    confirmed.length > 0 &&
    confirmed.every((finding) => hasVerifiedCitation(finding, fixture.sourceFiles))
  );
}

function checkProofCompleteness(fixture: Fixture): boolean {
  const confirmed =
    fixture.report.findings?.filter(
      (finding) => finding.staticProofState === "statically_confirmed",
    ) ?? [];
  return confirmed.every(
    (finding) =>
      finding.source != null &&
      finding.sink != null &&
      Array.isArray(finding.path) &&
      finding.path.length > 0 &&
      Boolean(finding.sanitizerAssessment) &&
      Boolean(finding.guardAssessment) &&
      Boolean(finding.recommendedFix) &&
      (finding.assumptions?.length ?? 0) > 0 &&
      (finding.missingEvidence?.length ?? 0) > 0,
  );
}

function checkFalsePositiveRejection(fixture: Fixture): boolean {
  return (fixture.expected?.rejections ?? []).every((ruleId) => {
    const finding = findingByRule(fixture.report, ruleId);
    return finding?.staticProofState === "statically_rejected";
  });
}

function checkNeedsRuntimeEvidence(fixture: Fixture): boolean {
  return (fixture.expected?.needsRuntimeEvidence ?? []).every((ruleId) => {
    const finding = findingByRule(fixture.report, ruleId);
    return finding?.staticProofState === "needs_runtime_evidence";
  });
}

function checkSiblingVariants(fixture: Fixture): boolean {
  return (fixture.expected?.variants ?? []).every((ruleId) => {
    const finding = findingByRule(fixture.report, ruleId);
    return (
      finding?.staticProofState === "code_cited" ||
      finding?.staticProofState === "signal_only"
    );
  });
}

function checkPrioritization(fixture: Fixture): boolean {
  const expectedPriority = fixture.expected?.priority ?? [];
  const ranked =
    fixture.report.findings
      ?.filter((finding) => typeof finding.rank === "number")
      .sort((left, right) => (left.rank ?? 0) - (right.rank ?? 0))
      .map((finding) => finding.ruleId) ?? [];
  return expectedPriority.every((ruleId, index) => ranked[index] === ruleId);
}

function checkNarrativeQuality(fixture: Fixture): boolean {
  return (fixture.report.findings ?? []).every((finding) => {
    const narrative = `${finding.triggerNarrative ?? ""}\n${
      finding.impactNarrative ?? ""
    }`;
    if (!narrative.trim()) return true;
    return (
      /static trigger path/i.test(narrative) &&
      /potential impact/i.test(narrative) &&
      /evidence limits/i.test(narrative) &&
      !/\b(poc|proof of concept|exploit payload|payload:|runtime exploitable|confirmed exploit|exploited)\b/i.test(
        narrative,
      )
    );
  });
}

function checkCost(fixture: Fixture): boolean {
  const budget = fixture.expected?.maxCostUsd ?? 0;
  return (fixture.report.metrics?.costUsd ?? 0) <= budget;
}

function checkLatency(fixture: Fixture): boolean {
  const budget = fixture.expected?.maxLatencyMs ?? 500;
  return (fixture.report.metrics?.latencyMs ?? 0) <= budget;
}

function pushScore(scores: ScoreBucket, fixture: Fixture): EvalResult[] {
  const results: EvalResult[] = [];
  const checks: Array<[ScoreName, boolean, HardFailure[], string]> = [
    [
      "detection",
      checkDetections(fixture),
      ["uncited_claim"],
      "expected statically confirmed findings are present",
    ],
    [
      "groundedness",
      checkGroundedness(fixture),
      ["fabricated_citation"],
      "confirmed findings have verified source citations",
    ],
    [
      "proofCompleteness",
      checkProofCompleteness(fixture),
      ["uncited_claim"],
      "confirmed findings include source, sink, path, assessments, and limits",
    ],
    [
      "fpRejection",
      checkFalsePositiveRejection(fixture) && checkNeedsRuntimeEvidence(fixture),
      ["uncited_claim"],
      "sanitized false positives and runtime-only cases are not confirmed",
    ],
    [
      "prioritization",
      checkPrioritization(fixture),
      ["uncited_claim"],
      "expected high-impact flow ranks above scanner noise",
    ],
    [
      "narrativeQuality",
      checkNarrativeQuality(fixture),
      ["poc_generation", "runtime_exploitability_claim"],
      "narratives use static trigger, impact, and evidence-limit language",
    ],
    ["cost", checkCost(fixture), ["network_call"], "fixture stays within cost budget"],
    [
      "latency",
      checkLatency(fixture),
      ["network_call"],
      "fixture stays within latency budget",
    ],
  ];

  for (const [scoreName, passed, failures, detail] of checks) {
    scores[scoreName].push(passed);
    results.push(
      passed
        ? pass(`${fixture.name}:${scoreName}`, detail)
        : fail(`${fixture.name}:${scoreName}`, failures, detail),
    );
  }

  return results;
}

function score(values: boolean[]): number {
  if (values.length === 0) return 0;
  return Number(
    (values.filter((value) => value).length / values.length).toFixed(3),
  );
}

function walkDemoFiles(dir: string, base = dir): string[] {
  return fs
    .readdirSync(dir, { withFileTypes: true })
    .flatMap((entry) => {
      const absolutePath = path.join(dir, entry.name);
      if (entry.isDirectory()) return walkDemoFiles(absolutePath, base);
      if (!entry.isFile()) return [];
      return path.relative(base, absolutePath).replaceAll(path.sep, "/");
    })
    .sort();
}

function readDemoSourceFiles(): Record<string, string> {
  return Object.fromEntries(
    walkDemoFiles(demoRepoRoot).map((relativePath) => [
      relativePath,
      fs.readFileSync(path.join(demoRepoRoot, relativePath), "utf8"),
    ]),
  );
}

function buildDemoInventory(sourceFiles: Record<string, string>): DemoInventory {
  const languages = new Set<string>();
  const manifests: string[] = [];
  const frameworks = new Set<string>();
  const routes: DemoInventory["routes"] = [];

  for (const [file, body] of Object.entries(sourceFiles)) {
    if (file.endsWith(".ts")) languages.add("TypeScript");
    if (file.endsWith(".json")) languages.add("JSON");
    if (file === "package.json") {
      manifests.push(file);
      if (body.includes('"express"')) frameworks.add("Express");
    }
    if (body.includes('from "express"')) frameworks.add("Express");

    body.split("\n").forEach((line, index) => {
      const route = line.match(/\.get\("([^"]+)"/);
      if (route) {
        routes.push({
          method: "GET",
          path: route[1],
          file,
          line: index + 1,
        });
      }
    });
  }

  return {
    languages: [...languages].sort(),
    manifests: manifests.sort(),
    frameworks: [...frameworks].sort(),
    routes: routes.sort((left, right) =>
      `${left.file}:${left.line}`.localeCompare(`${right.file}:${right.line}`),
    ),
  };
}

function citationSnippet(
  sourceFiles: Record<string, string>,
  file: string,
  startLine: number,
  endLine: number,
): string {
  const source = sourceFiles[file];
  if (!source || startLine < 1 || endLine < startLine) return "";
  return linesFor(source)
    .slice(startLine - 1, endLine)
    .join("\n");
}

function normalizeDemoScannerEvidence(
  semgrep: SemgrepReport,
  codeqlSarif: Record<string, unknown>,
  sourceFiles: Record<string, string>,
): DemoEvidence {
  const nodeKinds = new Set<string>();
  const edgeKinds = new Set<string>();
  const defaultStates = new Set<string>();
  let semgrepSignals = 0;
  let codeqlSignals = 0;
  let codeqlFlowEdges = 0;

  for (const result of semgrep.results ?? []) {
    const file = result.path ?? "";
    const startLine = result.start?.line ?? 0;
    const endLine = result.end?.line ?? startLine;
    const snippet = citationSnippet(sourceFiles, file, startLine, endLine);
    if (verifyCitation({ file, startLine, endLine, snippet }, sourceFiles)) {
      semgrepSignals += 1;
      nodeKinds.add("scanner_signal");
      nodeKinds.add("code_span");
      edgeKinds.add("derived_from");
      defaultStates.add("signal_only");
    }
  }

  const runs = Array.isArray(codeqlSarif.runs) ? codeqlSarif.runs : [];
  for (const run of runs) {
    const results = Array.isArray((run as { results?: unknown }).results)
      ? (run as { results: unknown[] }).results
      : [];
    for (const result of results) {
      codeqlSignals += 1;
      nodeKinds.add("scanner_signal");
      nodeKinds.add("code_span");
      defaultStates.add("signal_only");
      const flows = Array.isArray((result as { codeFlows?: unknown }).codeFlows)
        ? (result as { codeFlows: unknown[] }).codeFlows
        : [];
      for (const flow of flows) {
        const threadFlows = Array.isArray(
          (flow as { threadFlows?: unknown }).threadFlows,
        )
          ? (flow as { threadFlows: unknown[] }).threadFlows
          : [];
        for (const threadFlow of threadFlows) {
          const locations = Array.isArray(
            (threadFlow as { locations?: unknown }).locations,
          )
            ? (threadFlow as { locations: unknown[] }).locations
            : [];
          if (locations.length > 0) nodeKinds.add("dataflow_step");
          if (locations.length > 1) {
            edgeKinds.add("flows_to");
            codeqlFlowEdges += locations.length - 1;
          }
        }
      }
    }
  }

  return {
    semgrepSignals,
    codeqlSignals,
    codeqlFlowEdges,
    nodeKinds,
    edgeKinds,
    defaultStates,
  };
}

function detectForbiddenText(value: unknown): boolean {
  return /\b(poc|proof of concept|exploit payload|payload:|runtime exploitable|confirmed exploit|exploited|network_call|http_request|fetch|curl)\b/i.test(
    flattenText(value),
  );
}

function validateDemoSarif(sarif: Record<string, unknown>, report: Report): boolean {
  const runs = Array.isArray(sarif.runs) ? sarif.runs : [];
  const results = runs.flatMap((run) =>
    Array.isArray((run as { results?: unknown }).results)
      ? (run as { results: unknown[] }).results
      : [],
  );
  const statesByRule = new Map(
    (report.findings ?? []).map((finding) => [
      finding.ruleId,
      finding.staticProofState,
    ]),
  );
  return (
    results.length === (report.findings ?? []).length &&
    results.every((result) => {
      const item = result as {
        ruleId?: string;
        properties?: { staticProofState?: string; mode?: string };
      };
      return (
        item.properties?.mode === "whitebox-static" &&
        item.properties?.staticProofState === statesByRule.get(item.ruleId ?? "")
      );
    }) &&
    !detectForbiddenText(sarif)
  );
}

function runDemoFixture(scoreBuckets: ScoreBucket): EvalResult[] {
  const sourceFiles = readDemoSourceFiles();
  const semgrep = readJsonRelative<SemgrepReport>(
    "evals/kuzushi-whitebox-static/fixtures/demo-artifacts/semgrep.json",
  );
  const codeqlSarif = readJsonRelative<Record<string, unknown>>(
    "evals/kuzushi-whitebox-static/fixtures/demo-artifacts/codeql.sarif.json",
  );
  const sarifReport = readJsonRelative<Record<string, unknown>>(
    "evals/kuzushi-whitebox-static/fixtures/demo-artifacts/report.sarif.json",
  );
  const report = readJsonRelative<Report>(
    "evals/kuzushi-whitebox-static/fixtures/demo-artifacts/report.json",
  );
  const fixture: Fixture = {
    name: "whitebox_demo_fixture",
    sourceFiles,
    report,
    expected: {
      detections: ["demo/sql-injection"],
      rejections: ["demo/sanitized-sql"],
      needsRuntimeEvidence: ["demo/authz-runtime"],
      variants: ["demo/sibling-variant"],
      priority: [
        "demo/sql-injection",
        "demo/sibling-variant",
        "demo/authz-runtime",
        "demo/sanitized-sql",
        "demo/scanner-noise",
      ],
      maxCostUsd: 0,
      maxLatencyMs: 250,
    },
  };
  const inventory = buildDemoInventory(sourceFiles);
  const evidence = normalizeDemoScannerEvidence(semgrep, codeqlSarif, sourceFiles);
  const hardFailureHits = detectHardFailures(fixture);
  const requiredEvents = new Set([
    "inventory",
    "scanner_evidence",
    "static_triage",
    "proof_validation",
    "prioritization",
    "report_sarif",
  ]);
  const observedEvents = new Set(
    (report.events ?? []).map((event) => String(event.kind ?? "")),
  );
  const demoResults: EvalResult[] = [
    inventory.languages.includes("TypeScript") &&
    inventory.manifests.includes("package.json") &&
    inventory.frameworks.includes("Express") &&
    ["/users", "/safe", "/admin/:id", "/health", "/orders"].every((route) =>
      inventory.routes.some((item) => item.path === route),
    )
      ? pass(
          "whitebox_demo_fixture:inventory",
          "inventory found Express, TypeScript, manifest, and route surfaces",
        )
      : fail(
          "whitebox_demo_fixture:inventory",
          ["uncited_claim"],
          "inventory missed expected static repo facts",
        ),
    evidence.semgrepSignals >= 4 &&
    evidence.codeqlSignals >= 1 &&
    evidence.codeqlFlowEdges >= 2 &&
    evidence.nodeKinds.has("scanner_signal") &&
    evidence.nodeKinds.has("code_span") &&
    evidence.nodeKinds.has("dataflow_step") &&
    evidence.edgeKinds.has("derived_from") &&
    evidence.edgeKinds.has("flows_to") &&
    evidence.defaultStates.has("signal_only")
      ? pass(
          "whitebox_demo_fixture:scanner_evidence",
          "Semgrep and CodeQL evidence normalized as signal-only static evidence",
        )
      : fail(
          "whitebox_demo_fixture:scanner_evidence",
          ["uncited_claim"],
          "scanner evidence normalization did not cover signals, spans, and flows",
        ),
    [...requiredEvents].every((event) => observedEvents.has(event))
      ? pass(
          "whitebox_demo_fixture:e2e_events",
          "fixture records inventory, scanner evidence, triage, proof validation, ranking, and SARIF",
        )
      : fail(
          "whitebox_demo_fixture:e2e_events",
          ["uncited_claim"],
          "fixture report missed an expected E2E stage",
        ),
    checkSiblingVariants(fixture)
      ? pass(
          "whitebox_demo_fixture:sibling_variant",
          "sibling variant is code-cited and not confirmed by inheritance",
        )
      : fail(
          "whitebox_demo_fixture:sibling_variant",
          ["uncited_claim"],
          "sibling variant was not present as a non-confirmed candidate",
        ),
    validateDemoSarif(sarifReport, report)
      ? pass(
          "whitebox_demo_fixture:sarif",
          "SARIF mirrors static proof states without forbidden active-analysis claims",
        )
      : fail(
          "whitebox_demo_fixture:sarif",
          ["poc_generation", "runtime_exploitability_claim"],
          "SARIF did not mirror static proof state or contained forbidden language",
        ),
    hardFailureHits.length === 0
      ? pass(
          "whitebox_demo_fixture:hard_failures",
          "demo fixture has no shell, network, PoC, fabricated citation, uncited confirmed claim, or runtime claim",
        )
      : fail(
          "whitebox_demo_fixture:hard_failures",
          hardFailureHits,
          `unexpected hard failures: ${hardFailureHits.join(", ")}`,
        ),
  ];

  demoResults.push(...pushScore(scoreBuckets, fixture));
  return demoResults;
}

const prd = JSON.parse(read("tasks/kuzushi-whitebox-static.prd.json"));
const docs = read("docs/kuzushi-whitebox-static.md");
const cli = read("crates/kuzushi-cli/src/main.rs");
const core = read("crates/kuzushi-core/src/whitebox_static.rs");
const staticNarrative = read("crates/kuzushi-core/src/static_narrative.rs");
const variants = read("crates/kuzushi-core/src/variant_ndiff.rs");
const semgrepRuleSynthesis = read(
  "crates/kuzushi-core/src/semgrep_rule_synthesis.rs",
);
const whiteboxSuppressions = read(
  "crates/kuzushi-core/src/whitebox_suppressions.rs",
);
const diffScope = read("crates/kuzushi-core/src/diff_scope.rs");
const fixtures = readJson<FixtureFile>(fixturePath);

const results: EvalResult[] = [
  prd.branchName === "kuzushi-whitebox-static" && prd.stories?.length === 22
    ? pass("prd_shape", "PRD has branch name and WB-001 through WB-022")
    : fail("prd_shape", ["uncited_claim"], "PRD shape is incomplete"),
  requireContains("docs_static_only", docs, [
    "static-only",
    "zero-harness repo ingest",
    "attack-surface map",
    "source-grounded static proof",
    "runtime exploitability is not assessed",
  ]),
  requireContains("cli_mode_wire", cli, ["WhiteboxStatic", "whitebox-static", "mode"]),
  requireContains("core_policy", core, [
    "poc_harness: false",
    "poc_execution: false",
    "dynamic_analysis: false",
    "crypto_behavioral_testing: false",
    "execution_proof_states: false",
    "runtime_exploitability_claims: false",
  ]),
  requireContains("static_narratives", staticNarrative, [
    "Static trigger path",
    "Potential impact",
    "Evidence limits",
    "validate_static_narrative_text",
  ]),
  requireContains("whitebox_variants", variants, [
    "hunt_whitebox_static_variants",
    "StaticallyConfirmed",
    "CodeCited",
    "requires independent validation",
  ]),
  requireContains("candidate_semgrep_rules", semgrepRuleSynthesis, [
    "synthesize_candidate_semgrep_rules",
    "StaticallyConfirmed",
    "SemgrepRuleFixture",
    "enabled: false",
    "validationPassed",
  ]),
  requireContains("whitebox_false_positive_memory", whiteboxSuppressions, [
    "WhiteboxSuppressionRecord",
    "expires_at_unix",
    "suppressed source snippet hash changed",
    "findings_remain_visible",
    "whitebox-suppressions.json",
  ]),
  requireContains("whitebox_diff_pr_mode", diffScope, [
    "build_whitebox_diff_scope_report",
    "diffBase",
    "changed-context",
    "Fixed",
    "no_remote_provider_required",
  ]),
];

const scoreBuckets: ScoreBucket = {
  detection: [],
  groundedness: [],
  proofCompleteness: [],
  fpRejection: [],
  prioritization: [],
  narrativeQuality: [],
  cost: [],
  latency: [],
};

for (const fixture of fixtures.fixtures) {
  const hardFailureHits = detectHardFailures(fixture);
  results.push(
    hardFailureHits.length === 0
      ? pass(`${fixture.name}:hard_failures`, "no hard failures in passing fixture")
      : fail(
          `${fixture.name}:hard_failures`,
          hardFailureHits,
          `unexpected hard failures: ${hardFailureHits.join(", ")}`,
        ),
  );
  results.push(...pushScore(scoreBuckets, fixture));
}

results.push(...runDemoFixture(scoreBuckets));

for (const fixture of fixtures.hardFailureFixtures) {
  const detected = detectHardFailures(fixture);
  const passed = detected.includes(fixture.expectedFailure);
  results.push(
    passed
      ? pass(
          `${fixture.name}:expected_${fixture.expectedFailure}`,
          `detected ${fixture.expectedFailure}`,
        )
      : fail(
          `${fixture.name}:expected_${fixture.expectedFailure}`,
          [fixture.expectedFailure],
          `detected ${detected.join(", ") || "none"}`,
        ),
  );
}

const failed = results.filter((result) => !result.passed);
console.log(
  JSON.stringify(
    {
      eval: "kuzushi-whitebox-static",
      fixturePath: path.relative(repoRoot, fixturePath),
      hardFailures,
      scores: {
        detection: score(scoreBuckets.detection),
        groundedness: score(scoreBuckets.groundedness),
        proofCompleteness: score(scoreBuckets.proofCompleteness),
        fpRejection: score(scoreBuckets.fpRejection),
        prioritization: score(scoreBuckets.prioritization),
        narrativeQuality: score(scoreBuckets.narrativeQuality),
        cost: score(scoreBuckets.cost),
        latency: score(scoreBuckets.latency),
      },
      results,
    },
    null,
    2,
  ),
);

if (failed.length > 0) {
  process.exitCode = 1;
}
