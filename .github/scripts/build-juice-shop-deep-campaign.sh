#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

: "${KUZUSHI_REPO:?KUZUSHI_REPO is required}"
: "${AFE_DIR:?AFE_DIR is required}"
: "${AFE_SHA:?AFE_SHA is required}"
: "${OXIDIZED_DIR:?OXIDIZED_DIR is required}"
: "${OXIDIZED_SHA:?OXIDIZED_SHA is required}"
: "${TARGET_DIR:?TARGET_DIR is required}"
: "${TARGET_SHA:?TARGET_SHA is required}"
: "${VENV_DIR:?VENV_DIR is required}"
: "${REPORT_DIR:?REPORT_DIR is required}"
: "${CROSS_REPO_TOKEN:?CROSS_REPO_TOKEN is required}"

mkdir -p "$REPORT_DIR/logs" "$REPORT_DIR/provenance" "$VENV_DIR"

verify_sha() {
  local repo="$1"
  local expected="$2"
  local actual
  actual=$(git -C "$repo" rev-parse HEAD)
  if [[ "$actual" != "$expected" ]]; then
    echo "Expected $repo at $expected, got $actual" >&2
    return 1
  fi
}

verify_sha "$AFE_DIR" "$AFE_SHA"
verify_sha "$OXIDIZED_DIR" "$OXIDIZED_SHA"
verify_sha "$TARGET_DIR" "$TARGET_SHA"

python3 -m venv "$VENV_DIR"
"$VENV_DIR/bin/python" -m pip install --upgrade pip wheel setuptools \
  >"$REPORT_DIR/logs/python-bootstrap.log" 2>&1
"$VENV_DIR/bin/python" -m pip install -e "$AFE_DIR[runtime]" semgrep \
  >"$REPORT_DIR/logs/python-toolchain.log" 2>&1
"$VENV_DIR/bin/agentic-fuzz-engine" --help \
  >"$REPORT_DIR/provenance/afe-help.txt"
"$VENV_DIR/bin/semgrep" --version \
  >"$REPORT_DIR/provenance/semgrep-version.txt"

cd "$KUZUSHI_REPO"
pnpm install --frozen-lockfile >"$REPORT_DIR/logs/pnpm-install.log" 2>&1

cp Cargo.toml "$REPORT_DIR/provenance/Cargo.toml.original"
cp Cargo.lock "$REPORT_DIR/provenance/Cargo.lock.original"
ORIGINAL_CARGO_TOML=$(mktemp)
ORIGINAL_CARGO_LOCK=$(mktemp)
cp Cargo.toml "$ORIGINAL_CARGO_TOML"
cp Cargo.lock "$ORIGINAL_CARGO_LOCK"

cat >>Cargo.toml <<EOF

# Ephemeral deep-campaign override: compile against the exact checked-out
# Oxidized Joern commit first. This change exists only in the Actions worktree.
[patch."https://github.com/allsmog/oxidized-joern.git"]
cpg-analysis = { path = "$OXIDIZED_DIR/cpg-rs/cpg-analysis" }
cpg-cli = { path = "$OXIDIZED_DIR/cpg-rs/cpg-cli" }
cpg-core = { path = "$OXIDIZED_DIR/cpg-rs/cpg-core" }
cpg-incremental = { path = "$OXIDIZED_DIR/cpg-rs/cpg-incremental" }
EOF

git diff -- Cargo.toml >"$REPORT_DIR/provenance/oxidized-local-override.diff"

set +e
cargo build --release --workspace \
  >"$REPORT_DIR/logs/cargo-build-latest-oxidized.log" 2>&1
LATEST_BUILD_CODE=$?
set -e

if [[ $LATEST_BUILD_CODE -eq 0 ]]; then
  CPG_MODE="latest-local-override"
  CPG_BUILD_SHA="$OXIDIZED_SHA"
  CPG_BUILD_LOG="cargo-build-latest-oxidized.log"
else
  echo "Latest Oxidized Joern integration did not compile; recording the failure and rebuilding with Kuzushi's pinned dependency." >&2
  cp "$ORIGINAL_CARGO_TOML" Cargo.toml
  cp "$ORIGINAL_CARGO_LOCK" Cargo.lock
  git config --global \
    url."https://x-access-token:${CROSS_REPO_TOKEN}@github.com/".insteadOf \
    "https://github.com/"
  set +e
  cargo build --release --workspace --locked \
    >"$REPORT_DIR/logs/cargo-build-pinned-oxidized.log" 2>&1
  PINNED_BUILD_CODE=$?
  set -e
  git config --global --unset-all \
    url."https://x-access-token:${CROSS_REPO_TOKEN}@github.com/".insteadOf || true
  if [[ $PINNED_BUILD_CODE -ne 0 ]]; then
    echo "Both latest-local and pinned-compatible Kuzushi builds failed." >&2
    cat "$REPORT_DIR/logs/cargo-build-latest-oxidized.log" >&2
    cat "$REPORT_DIR/logs/cargo-build-pinned-oxidized.log" >&2
    exit "$PINNED_BUILD_CODE"
  fi
  CPG_MODE="pinned-compatible-fallback"
  CPG_BUILD_SHA="9ab43859f0c3342c734ff38ea6366711d216c8fd"
  CPG_BUILD_LOG="cargo-build-pinned-oxidized.log"
fi

cargo metadata --format-version 1 >"$REPORT_DIR/provenance/cargo-metadata.json"
cp Cargo.toml "$REPORT_DIR/provenance/Cargo.toml.effective"
cp Cargo.lock "$REPORT_DIR/provenance/Cargo.lock.effective"

KUZUSHI_BIN="$KUZUSHI_REPO/target/release/kuzushi"
test -x "$KUZUSHI_BIN"
"$KUZUSHI_BIN" --version >"$REPORT_DIR/provenance/kuzushi-version.txt"
"$KUZUSHI_BIN" tools --json >"$REPORT_DIR/provenance/kuzushi-tools.json"

python3 - "$REPORT_DIR/provenance/cpg-integration.json" <<PY
import hashlib
import json
import pathlib
import sys

result = {
    "requestedCheckout": "$OXIDIZED_SHA",
    "effectiveMode": "$CPG_MODE",
    "effectiveCommit": "$CPG_BUILD_SHA",
    "buildLog": "$CPG_BUILD_LOG",
    "latestCheckoutCompiled": "$LATEST_BUILD_CODE" == "0",
    "kuzushiBinary": "$KUZUSHI_BIN",
    "cargoLockSha256": hashlib.sha256(pathlib.Path("$KUZUSHI_REPO/Cargo.lock").read_bytes()).hexdigest(),
}
with open(sys.argv[1], "w", encoding="utf-8") as handle:
    json.dump(result, handle, indent=2, sort_keys=True)
    handle.write("\n")
PY

chmod +x \
  "$KUZUSHI_REPO/.github/scripts/deep-campaign-oauth-relay.mjs" \
  "$KUZUSHI_REPO/.github/scripts/juice-shop-deep-campaign.sh"

# Pull scanner images while the job still has ordinary network access. They are
# later run on an --internal Docker network that only contains the local target.
docker pull ghcr.io/schemathesis/schemathesis:stable \
  >"$REPORT_DIR/logs/docker-pull-schemathesis.log" 2>&1
docker pull ghcr.io/zaproxy/zaproxy:stable \
  >"$REPORT_DIR/logs/docker-pull-zap.log" 2>&1

sha256sum "$KUZUSHI_BIN" >"$REPORT_DIR/provenance/kuzushi-binary.sha256"
sha256sum "$VENV_DIR/bin/agentic-fuzz-engine" >"$REPORT_DIR/provenance/afe-entrypoint.sha256"

echo "KUZUSHI_BIN=$KUZUSHI_BIN" >>"${GITHUB_ENV:?GITHUB_ENV is required}"
echo "AFE_BIN=$VENV_DIR/bin/agentic-fuzz-engine" >>"$GITHUB_ENV"
echo "CPG_INTEGRATION_MODE=$CPG_MODE" >>"$GITHUB_ENV"
