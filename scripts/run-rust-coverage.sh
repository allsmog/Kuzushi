#!/usr/bin/env bash
set -euo pipefail

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
