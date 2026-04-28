#!/usr/bin/env bash
# Update a GitHub PR's description from the commit log of the current
# branch. Useful when a PR has accumulated many commits since opening
# and the original description has gone stale.  Field-test issue #57.
#
# Usage:
#   scripts/sync-pr-description.sh <PR_NUMBER>
#   scripts/sync-pr-description.sh <PR_NUMBER> --base main
#
# Requires: gh, git. Writes a markdown body listing every commit on
# the branch (`git log <base>..HEAD`) under a "## Commits" section.
# Preserves any existing `## Summary` / `## Test plan` sections by
# inserting commits ABOVE them.

set -euo pipefail

PR=${1:-}
BASE=${BASE:-main}

if [ -z "$PR" ] || [ "$PR" = "--help" ]; then
  echo "Usage: $0 <PR_NUMBER> [--base <branch>]" >&2
  exit 1
fi

if [ "${2:-}" = "--base" ]; then
  BASE="${3:-main}"
fi

if ! command -v gh >/dev/null 2>&1; then
  echo "error: gh CLI not found on PATH" >&2
  exit 2
fi

# Build the commits section from `git log <base>..HEAD`.
COMMITS=$(git log "${BASE}..HEAD" --no-merges --reverse --pretty=format:"- \`%h\` %s" 2>/dev/null || true)
if [ -z "$COMMITS" ]; then
  echo "error: no commits between ${BASE} and HEAD" >&2
  exit 3
fi

# Pull existing body so we can preserve manually-edited sections.
EXISTING_BODY=$(gh pr view "$PR" --json body --jq '.body' 2>/dev/null || echo "")

# Strip any prior "## Commits" block so we don't append on every run.
EXISTING_BODY_CLEAN=$(printf "%s" "$EXISTING_BODY" | awk '
  BEGIN { skip = 0 }
  /^## Commits/ { skip = 1; next }
  skip == 1 && /^## / { skip = 0 }
  skip == 0 { print }
')

NEW_BODY=$(cat <<EOF
$EXISTING_BODY_CLEAN

## Commits

$COMMITS
EOF
)

echo "$NEW_BODY" | gh pr edit "$PR" --body-file -
echo "Updated PR #${PR} description with $(printf "%s" "$COMMITS" | wc -l) commit lines."
