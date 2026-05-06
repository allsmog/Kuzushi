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
