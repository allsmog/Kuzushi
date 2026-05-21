#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'USAGE'
Usage:
  scripts/crap-gate.sh [--create-baseline] [--baseline PATH] [--out-dir DIR] [--threshold N] [--] [cargo-llvm-cov args...]

Runs Kuzushi's Rust CRAP gate with real coverage:
  1. cargo llvm-cov --workspace --lcov
  2. cargo crap --workspace --lcov ... --baseline ... --fail-regression

Reports are written under target/crap/ by default.

Environment:
  KUZUSHI_CRAP_BASELINE       Default baseline path.
  KUZUSHI_CRAP_DIR            Default output directory.
  KUZUSHI_CRAP_THRESHOLD      Default CRAP threshold, 7.
  KUZUSHI_CRAP_FAIL_NEW=0     Report but do not fail new changed functions over threshold.
USAGE
}

repo_root="$(git rev-parse --show-toplevel 2>/dev/null || pwd)"
out_dir="${KUZUSHI_CRAP_DIR:-"$repo_root/target/crap"}"
threshold="${KUZUSHI_CRAP_THRESHOLD:-7}"
baseline="${KUZUSHI_CRAP_BASELINE:-"$out_dir/baseline.json"}"
create_baseline=0
llvm_cov_args=()

while [[ $# -gt 0 ]]; do
  case "$1" in
    --create-baseline)
      create_baseline=1
      shift
      ;;
    --baseline)
      baseline="${2:?--baseline requires a path}"
      shift 2
      ;;
    --out-dir)
      out_dir="${2:?--out-dir requires a directory}"
      shift 2
      ;;
    --threshold)
      threshold="${2:?--threshold requires a value}"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    --)
      shift
      llvm_cov_args+=("$@")
      break
      ;;
    *)
      echo "Unknown argument: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

require_tool() {
  local label="$1"
  shift
  if ! "$@" >/dev/null 2>&1; then
    echo "Required CRAP gate tool is unavailable: $label" >&2
    echo "Install it or document the environment blocker before claiming the gate passed." >&2
    exit 2
  fi
}

require_tool "cargo llvm-cov" cargo llvm-cov --version
require_tool "cargo crap" cargo crap --version
require_tool "node" node --version

if [[ -z "${LLVM_COV:-}" || -z "${LLVM_PROFDATA:-}" ]]; then
  if command -v brew >/dev/null 2>&1; then
    llvm_prefix="$(brew --prefix llvm 2>/dev/null || true)"
    if [[ -n "$llvm_prefix" ]]; then
      [[ -z "${LLVM_COV:-}" && -x "$llvm_prefix/bin/llvm-cov" ]] && export LLVM_COV="$llvm_prefix/bin/llvm-cov"
      [[ -z "${LLVM_PROFDATA:-}" && -x "$llvm_prefix/bin/llvm-profdata" ]] && export LLVM_PROFDATA="$llvm_prefix/bin/llvm-profdata"
    fi
  fi
fi

if [[ -n "${LLVM_COV:-}" ]]; then
  require_tool "LLVM_COV=$LLVM_COV" "$LLVM_COV" --version
fi
if [[ -n "${LLVM_PROFDATA:-}" ]]; then
  require_tool "LLVM_PROFDATA=$LLVM_PROFDATA" "$LLVM_PROFDATA" --version
fi

mkdir -p "$out_dir"
lcov="$out_dir/lcov.info"
json_report="$out_dir/report.json"
markdown_report="$out_dir/report.md"
summary_report="$out_dir/summary.txt"

echo "[crap-gate] writing coverage to $lcov"
(
  cd "$repo_root"
  cargo llvm-cov --workspace --lcov --output-path "$lcov" "${llvm_cov_args[@]}"
)

if [[ "$create_baseline" -eq 1 ]]; then
  echo "[crap-gate] writing baseline to $baseline"
  (
    cd "$repo_root"
    cargo crap --workspace --lcov "$lcov" --threshold "$threshold" --format json --output "$baseline"
    cargo crap --workspace --lcov "$lcov" --threshold "$threshold" --summary | tee "$summary_report"
  )
  exit 0
fi

if [[ ! -f "$baseline" ]]; then
  echo "Missing CRAP baseline: $baseline" >&2
  echo "Create one at the start of a refactor phase with: scripts/crap-gate.sh --create-baseline" >&2
  exit 2
fi

(
  cd "$repo_root"
  cargo crap --workspace --lcov "$lcov" --threshold "$threshold" --baseline "$baseline" --format json --output "$json_report"
  cargo crap --workspace --lcov "$lcov" --threshold "$threshold" --baseline "$baseline" --format markdown --output "$markdown_report"
  cargo crap --workspace --lcov "$lcov" --threshold "$threshold" --baseline "$baseline" --fail-regression --summary | tee "$summary_report"
)

node - "$repo_root" "$json_report" "$threshold" <<'NODE'
const { execFileSync } = require("node:child_process");
const fs = require("node:fs");
const path = require("node:path");

const [root, reportPath, thresholdText] = process.argv.slice(2);
const threshold = Number(thresholdText);
const failNew = process.env.KUZUSHI_CRAP_FAIL_NEW !== "0";
const report = JSON.parse(fs.readFileSync(reportPath, "utf8"));

function changedFiles(args) {
  try {
    const output = execFileSync("git", args, { cwd: root, encoding: "utf8" });
    return output.split(/\r?\n/).filter(Boolean);
  } catch {
    return [];
  }
}

const changed = new Set([
  ...changedFiles(["diff", "--name-only", "--diff-filter=ACMR"]),
  ...changedFiles(["diff", "--cached", "--name-only", "--diff-filter=ACMR"]),
  ...changedFiles(["ls-files", "--others", "--exclude-standard"]),
].map((file) => path.resolve(root, file)));

function isProductionRust(file) {
  return file.endsWith(".rs") &&
    !file.includes(`${path.sep}target${path.sep}`) &&
    !file.endsWith(`${path.sep}tests.rs`) &&
    !file.includes(`${path.sep}tests${path.sep}`);
}

const newOffenders = (report.entries || []).filter((entry) => {
  const file = path.resolve(entry.file);
  return entry.status === "new" &&
    Number(entry.crap) >= threshold &&
    changed.has(file) &&
    isProductionRust(file);
});

if (newOffenders.length === 0) {
  process.exit(0);
}

const lines = newOffenders
  .slice(0, 20)
  .map((entry) => `  CRAP ${entry.crap}: ${path.relative(root, entry.file)}:${entry.line} ${entry.function}`);

console.error(`New changed production functions at or above CRAP ${threshold}:`);
console.error(lines.join("\n"));
if (newOffenders.length > lines.length) {
  console.error(`  ... and ${newOffenders.length - lines.length} more`);
}
console.error("Set KUZUSHI_CRAP_FAIL_NEW=0 only for a documented transitional baseline reset.");
if (failNew) {
  process.exit(1);
}
NODE
