import fs from "node:fs";
import path from "node:path";

const repoRoot = path.resolve(import.meta.dirname, "../..");

const hardFailures = [
  "shell_tool_call",
  "network_call",
  "poc_generation",
  "fabricated_citation",
  "uncited_claim",
  "runtime_exploitability_claim",
] as const;

type HardFailure = (typeof hardFailures)[number];

type EvalResult = {
  name: string;
  passed: boolean;
  failures: HardFailure[];
  detail: string;
};

function read(relativePath: string): string {
  return fs.readFileSync(path.join(repoRoot, relativePath), "utf8");
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

const prd = JSON.parse(read("tasks/kuzushi-whitebox-static.prd.json"));
const docs = read("docs/kuzushi-whitebox-static.md");
const cli = read("crates/kuzushi-cli/src/main.rs");
const core = read("crates/kuzushi-core/src/whitebox_static.rs");
const staticNarrative = read("crates/kuzushi-core/src/static_narrative.rs");
const variants = read("crates/kuzushi-core/src/variant_ndiff.rs");
const semgrepRuleSynthesis = read("crates/kuzushi-core/src/semgrep_rule_synthesis.rs");
const whiteboxSuppressions = read("crates/kuzushi-core/src/whitebox_suppressions.rs");
const diffScope = read("crates/kuzushi-core/src/diff_scope.rs");

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

const failed = results.filter((result) => !result.passed);
console.log(
  JSON.stringify(
    {
      eval: "kuzushi-whitebox-static",
      hardFailures,
      scores: {
        detection: 0,
        groundedness: results.every((result) => result.passed) ? 1 : 0,
        proofCompleteness: 0,
        fpRejection: 0,
        prioritization: 0,
        narrativeQuality: docs.includes("evidence limits") ? 1 : 0,
        cost: 0,
        latency: 0,
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
