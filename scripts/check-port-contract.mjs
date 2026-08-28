#!/usr/bin/env node
// Port contract: Kuzushi ports ideas from OpenAI Codex without vendoring it.
// This gate checks the surfaces that keep the port honest:
//   1. attribution documents stay present and truthful,
//   2. no wholesale Codex subtree is ever committed,
//   3. CI and release workflows stay wired to the quality gates, and
//   4. a few cross-language artifact-spec spot checks on Rust sources.
//
// Everything asserted here is committed repository content. The upstream-codex
// diffing remote is contributor environment, so `pnpm setup` provisions it via
// scripts/ensure-upstream-remote.mjs instead of a gate demanding it.
//
// It deliberately does NOT re-assert the contents of other gate scripts or of
// verify-pack.mjs: those gates run directly in CI, and their own behavior is
// the check. Package.json packaging policy lives in scripts/verify-pack.mjs.
import { execFileSync } from "node:child_process";
import { existsSync, readFileSync } from "node:fs";
import path from "node:path";

const repo = process.cwd();

const requiredDocs = [
  {
    file: "docs/PORT_PLAN.md",
    needles: ["upstream-codex", "docs/architecture/kuzushi-boundaries.md", "Phase Ledger"],
  },
  {
    file: "UPSTREAM_CODEX.md",
    needles: [
      "https://github.com/openai/codex",
      "upstream-codex",
      "Kuzushi ships as Kuzushi",
      "LICENSES/Apache-2.0.txt",
      "NOTICE",
    ],
  },
  {
    file: "NOTICE",
    needles: ["OpenAI Codex", "https://github.com/openai/codex", "LICENSES/Apache-2.0.txt"],
  },
  {
    file: "LICENSES/Apache-2.0.txt",
    needles: ["Apache License", "Version 2.0, January 2004"],
  },
  {
    file: "docs/architecture/kuzushi-boundaries.md",
    needles: ["Required Contexts", "pnpm quality:architecture", "pnpm quality:model-safety"],
  },
  {
    file: "docs/architecture/kuzushi-artifacts.md",
    needles: [".kuzushi/v3/runs/<runId>/", "run.json", "failures.json", "report.md"],
  },
  {
    file: "docs/quality/crap-gate.md",
    needles: [
      "pnpm quality:crap-risk",
      "scripts/crap-gate.sh",
      "default threshold is also 7",
      "CRAP-risk",
      "greater than or equal to 7",
    ],
  },
];

// Cross-language spot checks: these Rust sources must keep flowing through the
// shared artifact-spec helpers instead of re-deriving artifact paths locally.
const rustArtifactSpecChecks = [
  {
    file: "crates/kuzushi-core/src/modules/sast_run/all.rs",
    needles: [
      "SAST_SCAN_INPUT_FILE",
      "SAST_TRIAGE_JSONL_FILE",
      "SAST_VERIFY_JSONL_FILE",
      "scan_input: PathBuf",
      "run_dir(workspace.root(), run_id)",
      "dir.join(SAST_SCAN_INPUT_FILE)",
      "dir.join(SAST_TRIAGE_JSONL_FILE)",
      "dir.join(SAST_VERIFY_JSONL_FILE)",
    ],
  },
  {
    file: "crates/kuzushi-core/src/modules/sast_run/findings_for_sast_runs.rs",
    needles: ["write_sast_scan_input", "artifacts.scan_input"],
  },
  {
    file: "crates/kuzushi-core/src/modules/application/sast_scan/run_sast_scan.rs",
    needles: ['"input": artifacts.scan_input.display().to_string()'],
  },
  {
    file: "crates/kuzushi-core/src/modules/tests.rs",
    needles: ["/data/artifacts/input", "scan_input_path.ends_with(SAST_SCAN_INPUT_FILE)"],
  },
  {
    file: "crates/kuzushi-tui/src/ui_view_models/run_trace.rs",
    needles: [
      'canonical_run_artifact_spec("run.json")',
      "run_metadata_artifact_leaf()",
      'canonical_run_artifact_spec("items.jsonl")',
      "run_items_artifact_leaf()",
      "RUN_TRIAGE_FILE",
      "RUN_VERIFY_FILE",
      'run_artifact_detail(app, run_id, "lifecycle", run_items_artifact_leaf())',
      'run_artifact_detail(app, run_id, "triage", RUN_TRIAGE_FILE)',
      'run_artifact_detail(app, run_id, "verify", RUN_VERIFY_FILE)',
    ],
  },
  {
    file: "crates/kuzushi-core/src/run_artifacts/run_events.rs",
    needles: ['canonical_run_artifact_spec("events.jsonl")', "run_events_spec().leaf"],
  },
  {
    file: "crates/kuzushi-core/src/run_artifacts/llm_audit.rs",
    needles: ["read_run_items(", "load_run_lifecycle_audit"],
  },
  {
    file: "crates/kuzushi-core/src/run_artifacts/artifact_manifest.rs",
    needles: ['canonical_run_artifact_spec("artifacts.json")', "manifest_artifact_spec().leaf"],
  },
];

// CI must stay wired to the gate entry points; the gates themselves are the
// behavior check, so only the wiring is asserted here.
const quickCiRequirements = [
  "pnpm verify:quick:summary",
  "rhysd/actionlint:1.7.12",
  "quality-gauntlet:",
  "types: [opened, reopened, ready_for_review, synchronize]",
  "github.event.pull_request.draft == false",
  "workflow_call:",
  "KUZUSHI_CRAP_RISK_BASE_REF",
  "fetch-depth: 0",
];

const fullCiRequirements = [
  "name: Full CI",
  "schedule:",
  "workflow_dispatch:",
  "workflow_call:",
  "pnpm verify:quick:summary",
  "pnpm test:coverage",
  "pnpm test:mutations",
  "rhysd/actionlint:1.7.12",
  "cargo test --workspace --locked",
  "quality-gauntlet:",
  "verify-pack:",
  "pnpm verify:pack",
  "node scripts/build-native-runtime.mjs",
  "moonrepo/setup-rust@abb2d32350334249b178c401e5ec5836e0cd88d3",
  "native-linux-x64",
  "KUZUSHI_CRAP_RISK_BASE_REF",
  "fetch-depth: 0",
];

const releaseRequirements = [
  "uses: ./.github/workflows/release-candidate.yml",
  "release tag must point at current origin/${DEFAULT_BRANCH}",
  "name: release-candidate-artifacts",
  "node scripts/verify-release-artifacts.mjs",
  "node scripts/publish-platform-packages.mjs",
  "Publish verified npm packages with the thin launcher last",
  "uses: ./.github/workflows/published-release-smoke.yml",
];

const releaseCandidateRequirements = [
  "workflow_dispatch:",
  "workflow_call:",
  "expected_sha must equal the caller commit",
  "uses: ./.github/workflows/ci-full.yml",
  "pattern: release-candidate-native-*",
  "merge-multiple: true",
  "pnpm verify:pack",
  "KUZUSHI_VERIFY_PACK_RELEASE_ASSEMBLY",
  "pnpm pack:native-platforms",
  "node scripts/build-release-artifacts.mjs",
  "node scripts/check-release-source.mjs",
  "node scripts/smoke-release-tarballs.mjs",
  "node scripts/build-native-runtime.mjs",
  "moonrepo/setup-rust@abb2d32350334249b178c401e5ec5836e0cd88d3",
];

const heavyCiJobs = [
  "rust-core",
  "windows-compile",
  "cargo-deny",
  "rust-cli",
  "coverage",
  "mutation",
  "node22-compat",
  "verify-pack",
  "e2e",
];

// Quick CI may skip a prose-only pull request, because GitHub skips a run only
// when EVERY changed file matches `paths-ignore`. It must never skip one that
// touches executable, packaging, or workflow content, and it must never adopt
// the `paths:` allow-list form, which inverts the default from run to skip.
const quickCiUnskippablePaths = [
  ".github/**",
  "scripts/**",
  "crates/**",
  "Cargo.lock",
  "pnpm-lock.yaml",
  "package.json",
];

const retiredStandaloneCiWorkflows = [
  ".github/workflows/actionlint.yml",
  ".github/workflows/secret-scan.yml",
];

const failures = [
  ...requiredDocs.flatMap(checkFileNeedles),
  ...rustArtifactSpecChecks.flatMap(checkFileNeedles),
  ...checkNeedles(".github/workflows/ci.yml", quickCiRequirements),
  ...checkNeedles(".github/workflows/ci-full.yml", fullCiRequirements),
  ...checkNeedles(".github/workflows/release.yml", releaseRequirements),
  ...checkNeedles(".github/workflows/release-candidate.yml", releaseCandidateRequirements),
  ...checkForbiddenNeedles(".github/workflows/ci.yml", [
    "schedule:",
    ...heavyCiJobs.map((job) => `  ${job}:\n`),
  ]),
  ...checkQuickCiPathFilter(),
  ...checkForbiddenNeedles(".github/workflows/ci-full.yml", ["pull_request:", "push:"]),
  ...heavyCiJobs.flatMap((job) =>
    checkWorkflowJobNeedles(".github/workflows/ci-full.yml", job, []),
  ),
  ...retiredStandaloneCiWorkflows.flatMap(checkFileAbsent),
  ...checkNoWholesaleCodexSubtree(),
];

if (failures.length > 0) {
  console.error("Kuzushi port contract check failed:");
  for (const failure of failures) console.error(`- ${failure}`);
  process.exit(1);
}

console.log("port contract check passed");

function checkFileNeedles({ file, needles }) {
  return checkNeedles(file, needles);
}

function checkNeedles(file, needles) {
  const source = readFileSync(path.join(repo, file), "utf8");
  return needles
    .filter((needle) => !source.includes(needle))
    .map((needle) => `${file} does not mention ${needle}`);
}

function checkForbiddenNeedles(file, needles) {
  const source = readFileSync(path.join(repo, file), "utf8");
  return needles
    .filter((needle) => source.includes(needle))
    .map((needle) => `${file} must not mention forbidden token ${needle}`);
}

function checkWorkflowJobNeedles(file, job, needles) {
  const source = readFileSync(path.join(repo, file), "utf8");
  const marker = `  ${job}:\n`;
  const start = source.indexOf(marker);
  if (start < 0) return [`${file} does not define job ${job}`];
  const tail = source.slice(start + marker.length);
  const nextJob = tail.search(/^ {2}[a-zA-Z0-9_-]+:\n/m);
  const jobSource = nextJob < 0 ? tail : tail.slice(0, nextJob);
  return needles
    .filter((needle) => !jobSource.includes(needle))
    .map((needle) => `${file} job ${job} does not mention ${needle}`);
}

function checkQuickCiPathFilter() {
  const file = ".github/workflows/ci.yml";
  const source = readFileSync(path.join(repo, file), "utf8");
  if (/^\s*paths:\s*$/m.test(source)) {
    return [`${file} must not use a paths allow-list; it would skip CI by default`];
  }
  const ignored = pathsIgnoreEntries(source);
  return quickCiUnskippablePaths
    .filter((needle) => ignored.includes(needle))
    .map((needle) => `${file} must not add ${needle} to paths-ignore; CI would skip real changes`);
}

function pathsIgnoreEntries(source) {
  const start = source.search(/^\s*paths-ignore:\s*$/m);
  if (start < 0) return [];
  const lines = source.slice(start).split("\n").slice(1);
  const listEnd = lines.findIndex((line) => !/^\s+-\s+/.test(line));
  return (listEnd < 0 ? lines : lines.slice(0, listEnd))
    .map((line) => line.match(/^\s+-\s+"?([^"\s]+)"?\s*$/))
    .filter((entry) => entry !== null)
    .map((entry) => entry[1]);
}

function checkFileAbsent(file) {
  return existsSync(path.join(repo, file)) ? [`${file} duplicates the default CI runner`] : [];
}

function checkNoWholesaleCodexSubtree() {
  const forbiddenRoots = [
    "codex",
    "openai-codex",
    "upstream-codex",
    "vendor/codex",
    "vendor/openai-codex",
    "third_party/codex",
    "third_party/openai-codex",
    "reference/codex",
    "reference/openai-codex",
  ];
  return repoFiles()
    .filter((file) => forbiddenRoots.some((root) => file === root || file.startsWith(`${root}/`)))
    .map(
      (file) =>
        `${file} looks like a wholesale Codex subtree; port small substrate changes instead`,
    );
}

function repoFiles() {
  return [
    ...new Set([
      ...gitLines(["ls-files"]),
      ...gitLines(["ls-files", "--others", "--exclude-standard"]),
    ]),
  ]
    .map((file) => file.replaceAll("\\", "/"))
    .filter((file) => !ignoredRepoFile(file))
    .sort();
}

function ignoredRepoFile(file) {
  return (
    file.startsWith("node_modules/") ||
    file.startsWith("target/") ||
    file.startsWith("dist/") ||
    file.startsWith("coverage/")
  );
}

function gitLines(args) {
  return execFileSync("git", args, { cwd: repo, encoding: "utf8" })
    .split(/\r?\n/)
    .map((file) => file.trim())
    .filter(Boolean);
}
