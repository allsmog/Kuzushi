#!/usr/bin/env bash
set -euo pipefail

# This is the credential-free Rust contract. It deliberately validates the
# public/core library boundary, not the private CPG implementation or the full
# native package. Release CI runs the separate full workspace lane.
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
