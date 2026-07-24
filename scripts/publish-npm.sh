#!/usr/bin/env bash
#
# Build and inspect a platform-local npm package without publishing it.
#
# Preflight:
#   - Working tree must be clean
#   - Current HEAD must be on main
#   - The tag v<version> must exist and point at HEAD
#   - tests + native build + package verification must pass
#
# Public publishing is intentionally GitHub-Actions-only because a local build
# contains only the host platform's native payload.
#
# Env:
#   SKIP_TESTS=1          skip the test suite (NOT recommended)
#
# Usage:
#   scripts/publish-npm.sh                # dry-run
#   scripts/publish-npm.sh --publish      # fails closed with CI instructions
#

set -euo pipefail

RED=$'\033[0;31m'
GREEN=$'\033[0;32m'
YELLOW=$'\033[1;33m'
BLUE=$'\033[0;34m'
RESET=$'\033[0m'

log()   { printf '%s==>%s %s\n' "$BLUE" "$RESET" "$*"; }
ok()    { printf '%s✓%s   %s\n'  "$GREEN" "$RESET" "$*"; }
warn()  { printf '%s!%s   %s\n'  "$YELLOW" "$RESET" "$*"; }
fail()  { printf '%s✗%s   %s\n'  "$RED" "$RESET" "$*" >&2; exit 1; }

# Anchor to repo root.
SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &>/dev/null && pwd)
REPO_ROOT=$(cd -- "$SCRIPT_DIR/.." &>/dev/null && pwd)
cd "$REPO_ROOT"

for arg in "$@"; do
  case "$arg" in
    --publish)
      fail "Local publishing is disabled: push a v<version> tag so the GitHub release workflow assembles and verifies every required native platform."
      ;;
    --help|-h)
      awk 'NR > 1 { if ($0 !~ /^#/) exit; sub(/^# ?/, ""); print }' "$0"
      exit 0
      ;;
    *) fail "unknown arg: $arg" ;;
  esac
done

# ── Preflight ────────────────────────────────────────────────────────────────

log "Reading package version"
VERSION=$(node -e "console.log(require('./package.json').version)")
TAG="v${VERSION}"
ok "package: $(node -e "console.log(require('./package.json').name)")@${VERSION}"

log "Checking working tree is clean"
if ! git diff --quiet || ! git diff --cached --quiet; then
  git status --short
  fail "working tree has uncommitted changes — commit or stash first"
fi
ok "clean"

log "Checking current branch is main"
BRANCH=$(git rev-parse --abbrev-ref HEAD)
if [ "$BRANCH" != "main" ]; then
  warn "on branch '$BRANCH', not main — proceed only if you know what you're doing"
fi

log "Checking tag $TAG exists and points at HEAD"
if ! git rev-parse -q --verify "refs/tags/${TAG}" >/dev/null; then
  fail "tag $TAG does not exist locally — run: git tag -a $TAG -m \"$VERSION\""
fi
TAG_SHA=$(git rev-list -n 1 "$TAG")
HEAD_SHA=$(git rev-parse HEAD)
if [ "$TAG_SHA" != "$HEAD_SHA" ]; then
  fail "tag $TAG points at $TAG_SHA but HEAD is $HEAD_SHA — re-tag or check out the tag"
fi
ok "$TAG → $HEAD_SHA"

log "Checking tag is pushed to origin"
if ! git ls-remote --tags origin "refs/tags/${TAG}" | grep -q "$TAG"; then
  warn "tag $TAG is not on origin — the GitHub release workflow won't fire"
  warn "run: git push origin $TAG"
fi

if ! command -v npm >/dev/null 2>&1; then
  fail "npm not found on PATH"
fi

# ── Build + verify ───────────────────────────────────────────────────────────

if [ "${SKIP_TESTS:-0}" != "1" ]; then
  log "Running node contract tests"
  pnpm run test
  log "Running Rust test suite"
  pnpm run test:rust
  ok "tests green"
else
  warn "SKIP_TESTS=1 — skipping tests"
fi

log "Building native Rust package binaries"
pnpm run build:native
ok "platform-local native binaries staged"

log "Verifying package artifact"
pnpm run verify:pack
ok "package artifact ready"

log "Dry-running npm pack to see what ships"
# `npm pack --dry-run` prints file list + total size.
npm pack --dry-run --ignore-scripts 2>&1 | tail -n 60

log "Platform-local dry-run complete; no registry mutation was attempted"
log "Release assembly is authoritative: push $TAG to run the multi-platform GitHub workflow"
