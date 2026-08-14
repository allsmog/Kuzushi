#!/usr/bin/env bash
set -euo pipefail

# Keep the feature-disabled adapter honest even though the public default
# product includes oxidized-joern. Cargo resolves the pinned public source
# directly; no resolver overlay or cross-repository credential is needed.
repo_root="$(git rev-parse --show-toplevel)"
cd "${repo_root}"

cargo metadata --format-version 1 --locked >/dev/null

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

cargo test \
  --package kuzushi-core \
  --no-default-features \
  builtin_dispatch_policy_inventory_is_reviewed_as_one_contract \
  --locked \
  -- \
  --nocapture

cargo fmt --all --check
