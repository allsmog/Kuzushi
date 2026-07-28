#!/usr/bin/env node
// Port contract: Kuzushi ports ideas from OpenAI Codex without vendoring it.
// This gate checks the surfaces that keep the port honest:
//   1. attribution documents stay present and truthful,
//   2. no wholesale Codex subtree is ever committed,
//   3. the upstream-codex remote exists for substrate diffing,
//   4. CI and release workflows stay wired to the quality gates, and
//   5. a few cross-language artifact-spec spot checks on Rust sources.
//
// It deliberately does NOT re-assert the contents of other gate scripts or of
// verify-pack.mjs: those gates run directly in CI, and their own behavior is
// the check. Package.json packaging policy lives in scripts/verify-pack.mjs.
import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
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
const ciRequirements = [
  "pnpm quality:crap-risk",
  "pnpm quality:identity",
  "pnpm quality:architecture",
  "pnpm quality:model-safety",
  "pnpm check:docs",
  "pnpm test:coverage",
  "pnpm test:mutations",
  "rhysd/actionlint:1.7.12",
  "OXIDIZED_JOERN_TOKEN",
  "quality-gauntlet:",
  "verify-pack:",
  "pnpm verify:pack",
  "node scripts/build-native-runtime.mjs",
  "moonrepo/setup-rust@v1",
  "native-linux-x64",
  "KUZUSHI_CRAP_RISK_BASE_REF",
  "fetch-depth: 0",
];

const releaseRequirements = [
  // Release jobs stage every green matrix build into native/<slug>/ so the
  // npm tarball and the release .tgz are multi-platform.
  "pattern: release-native-*",
  "merge-multiple: true",
  "Stage native binaries for every built platform",
  "pnpm verify:pack",
  "KUZUSHI_VERIFY_PACK_RELEASE_ASSEMBLY",
  "npm publish --access public --provenance --ignore-scripts",
  "npm publish --access public --ignore-scripts",
  "npm pack --ignore-scripts",
  "node scripts/build-native-runtime.mjs",
  "moonrepo/setup-rust@v1",
];

const failures = [
  ...checkUpstreamCodexRemote(),
  ...requiredDocs.flatMap(checkFileNeedles),
  ...rustArtifactSpecChecks.flatMap(checkFileNeedles),
  ...checkNeedles(".github/workflows/ci.yml", ciRequirements),
  ...checkNeedles(".github/workflows/release.yml", releaseRequirements),
  ...checkForbiddenNeedles(".github/workflows/ci.yml", ["**/*.md", "docs/**"]),
  ...checkNoWholesaleCodexSubtree(),
];

if (failures.length > 0) {
  console.error("Kuzushi port contract check failed:");
  for (const failure of failures) console.error(`- ${failure}`);
  process.exit(1);
}

console.log("port contract check passed");

function checkUpstreamCodexRemote() {
  const expected = "https://github.com/openai/codex.git";
  try {
    const actual = execFileSync("git", ["remote", "get-url", "upstream-codex"], {
      cwd: repo,
      encoding: "utf8",
    }).trim();
    return actual === expected
      ? []
      : [`git remote upstream-codex must point at ${expected}; found ${actual}`];
  } catch {
    return [`git remote upstream-codex is missing; add ${expected}`];
  }
}

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
