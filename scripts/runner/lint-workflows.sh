#!/usr/bin/env bash
# Lint every GitHub Actions workflow with the native actionlint binary.
#
# The GitHub-hosted ubuntu image ships a running Docker daemon, so CI used to
# lint through `rhysd/actionlint:<version>`. The self-hosted macOS runner has
# no daemon. This script is the daemon-free path: it requires the exact pinned
# version to be on PATH, so the lint surface cannot drift just because a
# machine happens to carry a different build.
set -euo pipefail

version="${ACTIONLINT_VERSION:?ACTIONLINT_VERSION must name the pinned actionlint version}"

if ! command -v actionlint >/dev/null 2>&1; then
  echo "actionlint ${version} is not on PATH." >&2
  echo "Install it with: brew install actionlint" >&2
  echo "See docs/quality/self-hosted-runner.md for the full runner prerequisites." >&2
  exit 1
fi

installed="$(actionlint --version | head -n 1)"
case "${installed}" in
  "${version}" | "${version}"[!0-9]*) ;;
  *)
    echo "actionlint ${version} is required, but PATH has ${installed}." >&2
    echo "Install the pinned version with: brew install actionlint" >&2
    exit 1
    ;;
esac

echo "actionlint ${installed}"
exec actionlint
