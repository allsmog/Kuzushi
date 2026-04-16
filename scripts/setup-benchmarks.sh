#!/usr/bin/env bash
# setup-benchmarks.sh — Unified entry point for benchmark corpus setup.
#
# Usage:
#   scripts/setup-benchmarks.sh list
#   scripts/setup-benchmarks.sh <corpus> [<corpus> ...]
#   scripts/setup-benchmarks.sh all
#
# Examples:
#   scripts/setup-benchmarks.sh govwa
#   scripts/setup-benchmarks.sh juice-shop owasp-benchmark
#   scripts/setup-benchmarks.sh all
#
# Corpuses live under benchmarks/<name>/setup.sh. Each script is idempotent
# and skips already-cloned repos.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
BENCHMARKS_DIR="${REPO_DIR}/benchmarks"

if [[ -t 1 ]]; then
  GREEN=$'\033[32m'; YELLOW=$'\033[33m'; BOLD=$'\033[1m'; RESET=$'\033[0m'
else
  GREEN=""; YELLOW=""; BOLD=""; RESET=""
fi

usage() {
  cat <<EOF
Usage: scripts/setup-benchmarks.sh <corpus|all|list> [<corpus> ...]

Available corpuses:
EOF
  list_corpuses | sed 's/^/  /'
}

list_corpuses() {
  find "$BENCHMARKS_DIR" -maxdepth 2 -name setup.sh -type f \
    -exec dirname {} \; \
    | xargs -n1 basename 2>/dev/null \
    | sort
}

require_tool() {
  local tool="$1" hint="$2"
  if ! command -v "$tool" >/dev/null 2>&1; then
    printf "scripts/setup-benchmarks.sh: required tool '%s' is not installed.\n  %s\n" \
      "$tool" "$hint" >&2
    exit 1
  fi
}

run_corpus() {
  local corpus="$1"
  local script="${BENCHMARKS_DIR}/${corpus}/setup.sh"

  if [[ ! -f "$script" ]]; then
    printf "%sunknown corpus:%s %s\n\nAvailable:\n" "$YELLOW" "$RESET" "$corpus" >&2
    list_corpuses | sed 's/^/  /' >&2
    exit 1
  fi

  printf "\n%s━━━ %s ━━━%s\n" "$BOLD" "$corpus" "$RESET"

  # Per-corpus prerequisite checks.
  case "$corpus" in
    cve-corpus)
      require_tool jq "Install: apt-get install jq / brew install jq."
      ;;
    owasp-benchmark)
      require_tool npx "Install Node 22+ (bundled with npm)."
      ;;
  esac

  bash "$script"
  printf "%s✓%s %s done.\n" "$GREEN" "$RESET" "$corpus"
}

if [[ $# -eq 0 ]]; then
  usage >&2
  exit 1
fi

case "$1" in
  -h|--help)
    usage; exit 0 ;;
  list)
    list_corpuses; exit 0 ;;
  all)
    while IFS= read -r c; do
      run_corpus "$c"
    done < <(list_corpuses)
    ;;
  *)
    for corpus in "$@"; do
      run_corpus "$corpus"
    done
    ;;
esac

printf "\n%sAll requested corpuses ready.%s\n" "$GREEN" "$RESET"
