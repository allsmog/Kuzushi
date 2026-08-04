#!/usr/bin/env bash
set -euo pipefail

# Cargo resolves optional Git dependency manifests before feature selection.
# Build the credential-free contract in a detached temporary worktree whose
# root manifest replaces only the four private source declarations with local
# resolver stubs. The canonical checkout and Cargo.lock remain untouched.
repo_root="$(git rev-parse --show-toplevel)"
if [[ -n "$(git -C "${repo_root}" status --porcelain --untracked-files=normal)" ]]; then
  echo "public-core validation requires a clean worktree so it can validate the exact HEAD" >&2
  exit 1
fi

scratch_root="$(mktemp -d "${TMPDIR:-/tmp}/kuzushi-public-core.XXXXXX")"
worktree="${scratch_root}/worktree"
stubs="${scratch_root}/resolver-stubs"
metadata="${scratch_root}/metadata.json"

cleanup() {
  git -C "${repo_root}" worktree remove --force "${worktree}" >/dev/null 2>&1 || true
  rm -rf "${scratch_root}"
}
trap cleanup EXIT INT TERM

# The shared setup-rust cache contains the complete private/full workspace and
# can expand to nearly the entire hosted-runner disk. This lane deliberately
# proves a clean public boundary, so discard that target cache in CI and keep
# all new artifacts inside the disposable scratch directory. Local callers keep
# their ordinary target directory untouched unless they explicitly override it.
if [[ "${GITHUB_ACTIONS:-}" == "true" ]]; then
  rm -rf "${repo_root}/target"
fi
export CARGO_TARGET_DIR="${KUZUSHI_PUBLIC_CORE_TARGET_DIR:-${scratch_root}/target}"
# Debug symbols are irrelevant to check/Clippy/contract tests and more than
# double the disk required by the large core graph on hosted runners.
export CARGO_PROFILE_DEV_DEBUG=0
export CARGO_PROFILE_TEST_DEBUG=0

git -C "${repo_root}" worktree add --detach "${worktree}" HEAD
node "${repo_root}/scripts/public-core-workspace.mjs" "${worktree}" "${stubs}"
node --test \
  "${repo_root}/scripts/public-core-cargo-lock.test.mjs" \
  "${repo_root}/scripts/public-core-workspace.test.mjs"

cd "${worktree}"

# The first metadata resolution is intentionally unlocked: it replaces only
# the now-local resolver packages in the copied lockfile. Validate the result
# before any compiler or test claim is accepted.
cargo metadata --format-version 1 --no-default-features >"${metadata}"
node "${repo_root}/scripts/public-core-cargo-lock.mjs" \
  "${repo_root}/Cargo.lock" \
  "${worktree}/Cargo.lock"
if grep -Fq "github.com/allsmog/oxidized-joern.git" "${metadata}"; then
  echo "public-core metadata still references the private oxidized-joern source" >&2
  exit 1
fi

cargo check \
  --package kuzushi-core \
  --no-default-features \
  --all-targets \
  --locked

cargo clippy \
  --package kuzushi-core \
  --no-default-features \
  --all-targets \
  --locked \
  -- \
  -D warnings

cargo test \
  --package kuzushi-cpg \
  --no-default-features \
  --locked

cargo test \
  --package kuzushi-core \
  --no-default-features \
  --test public_core_validation \
  --locked

cargo fmt --all --check
