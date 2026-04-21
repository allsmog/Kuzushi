#!/usr/bin/env bash
#
# Publish the current package.json version to npm.
#
# Preflight:
#   - Working tree must be clean
#   - Current HEAD must be on main
#   - The tag v<version> must exist and point at HEAD
#   - typecheck + tests + clean build must pass
#
# Dry-run by default. Pass --publish to actually publish.
#
# Env:
#   NPM_PROVENANCE=true   enable `npm publish --provenance` (requires
#                         public repo, npm ≥9.5, and an OIDC token —
#                         only useful inside GitHub Actions; ignored
#                         locally unless NODE_AUTH_TOKEN is set)
#   OTP=<code>            pass through as `--otp=<code>` for 2FA
#   SKIP_TESTS=1          skip the test suite (NOT recommended)
#
# Usage:
#   scripts/publish-npm.sh                # dry-run
#   scripts/publish-npm.sh --publish      # actually publish
#   OTP=123456 scripts/publish-npm.sh --publish
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

PUBLISH=0
for arg in "$@"; do
  case "$arg" in
    --publish) PUBLISH=1 ;;
    --help|-h)
      sed -n '2,29p' "$0" | sed 's/^#//; s/^ //'
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

log "Checking npm whoami"
if command -v npm >/dev/null 2>&1; then
  if npm whoami >/dev/null 2>&1; then
    ok "npm user: $(npm whoami)"
  else
    warn "not logged in to npm — run \`npm login\` before --publish"
  fi
else
  fail "npm not found on PATH"
fi

log "Checking this version isn't already published"
PUB_NAME=$(node -e "console.log(require('./package.json').name)")
PUB_VIEW=$(npm view "${PUB_NAME}@${VERSION}" version 2>/dev/null || true)
if [ -n "$PUB_VIEW" ]; then
  fail "$PUB_NAME@$VERSION is already on npm — bump the version"
fi
ok "version is unpublished"

# ── Build + verify ───────────────────────────────────────────────────────────

log "Typechecking"
pnpm exec tsc --noEmit
ok "types clean"

if [ "${SKIP_TESTS:-0}" != "1" ]; then
  log "Running full test suite"
  pnpm exec vitest run
  ok "tests green"
else
  warn "SKIP_TESTS=1 — skipping tests"
fi

log "Clean build"
pnpm run build:clean
ok "dist/ rebuilt"

log "Dry-running npm pack to see what ships"
# `npm pack --dry-run` prints file list + total size.
npm pack --dry-run 2>&1 | tail -n 60

# ── Publish ──────────────────────────────────────────────────────────────────

PUBLISH_ARGS=(publish --access public)
if [ "${NPM_PROVENANCE:-}" = "true" ]; then
  PUBLISH_ARGS+=(--provenance)
fi
if [ -n "${OTP:-}" ]; then
  PUBLISH_ARGS+=(--otp="$OTP")
fi

if [ "$PUBLISH" -eq 1 ]; then
  log "Publishing $PUB_NAME@$VERSION"
  printf '%sWARNING:%s this will publish to the public npm registry.\n' "$YELLOW" "$RESET"
  printf 'Proceed? [y/N] '
  read -r reply
  case "$reply" in
    y|Y|yes|YES)
      npm "${PUBLISH_ARGS[@]}"
      ok "published $PUB_NAME@$VERSION 🎉"
      log "Next: create a GitHub release — gh release create $TAG --generate-notes"
      ;;
    *)
      warn "aborted — nothing published"
      exit 0
      ;;
  esac
else
  log "Dry-run complete (would run: npm ${PUBLISH_ARGS[*]})"
  log "Pass --publish to actually publish"
fi
