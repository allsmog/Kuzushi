#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd "$(dirname "$0")/.." && pwd)
cd "$repo_root"

required_version="0.8.7"
if ! version_output="$(cargo llvm-cov --version 2>/dev/null)"; then
  echo "cargo-llvm-cov ${required_version} is required; install it with: cargo install cargo-llvm-cov --version ${required_version} --locked" >&2
  exit 2
fi
read -r _ actual_version _ <<<"${version_output}"
if [[ "${actual_version:-}" != "${required_version}" ]]; then
  echo "cargo-llvm-cov ${required_version} is required, found: ${version_output}" >&2
  exit 2
fi

mkdir -p target/llvm-cov

# Keep instrumented coverage objects in one disposable tree. cargo-llvm-cov
# otherwise retains a second workspace build under target/llvm-cov-target,
# which can be several GiB for Kuzushi. Preserve the lcov report, but remove
# the instrumented build on normal exit. Set KUZUSHI_KEEP_COVERAGE_BUILD=1 only
# when debugging the coverage toolchain itself.
coverage_build_dir="$repo_root/target/llvm-cov-target"
cleanup_coverage_build() {
  if [[ "${KUZUSHI_KEEP_COVERAGE_BUILD:-0}" != "1" ]]; then
    rm -rf "$coverage_build_dir"
  fi
}
trap cleanup_coverage_build EXIT
rm -rf "$coverage_build_dir"
export CARGO_LLVM_COV_TARGET_DIR="target/llvm-cov-target"
export CARGO_LLVM_COV_BUILD_DIR="target/llvm-cov-target"

# Instrumented bridge tests spawn and terminate guarded process groups. Run
# coverage serially so overlapping guard lifecycles cannot turn host process
# pressure into unrelated SIGKILL or setpgid failures. Operators may override
# this after proving a higher safe limit on their runner.
export RUST_TEST_THREADS="${RUST_TEST_THREADS:-1}"

cargo llvm-cov \
  --workspace \
  --exclude kuzushi-bdd-tui \
  --locked \
  --lcov \
  --output-path target/llvm-cov/lcov.info

node scripts/check-diff-coverage.mjs target/llvm-cov/lcov.info
