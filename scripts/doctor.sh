#!/usr/bin/env bash
# doctor.sh — Read-only diagnostics for a Kuzushi dev environment.
#
# Unlike bootstrap.sh, this script never modifies anything (no corepack
# activation, no pnpm install). It prints a concise status of every tool
# Kuzushi cares about and exits 0 even when optional tools are missing
# (use --strict to make warnings fatal).

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

STRICT=0
while (( $# )); do
  case "$1" in
    --strict) STRICT=1 ;;
    -h|--help)
      cat <<EOF
doctor.sh — read-only Kuzushi environment diagnostics

Usage: scripts/doctor.sh [--strict]

  --strict    Exit non-zero if any warnings are present.
EOF
      exit 0
      ;;
    *) echo "doctor: unknown flag: $1" >&2; exit 1 ;;
  esac
  shift
done

if [[ -t 1 ]]; then
  GREEN=$'\033[32m'; YELLOW=$'\033[33m'; RED=$'\033[31m'
  BOLD=$'\033[1m'; RESET=$'\033[0m'
else
  GREEN=""; YELLOW=""; RED=""; BOLD=""; RESET=""
fi

ok()   { printf "  %s✓%s %-22s %s\n" "$GREEN" "$RESET" "$1" "$2"; }
warn() { printf "  %s!%s %-22s %s\n" "$YELLOW" "$RESET" "$1" "$2"; WARNINGS=$((WARNINGS + 1)); }
miss() { printf "  %s✗%s %-22s %s\n" "$RED" "$RESET" "$1" "$2"; ERRORS=$((ERRORS + 1)); }

WARNINGS=0
ERRORS=0

printf "%sKuzushi doctor%s  (repo: %s)\n\n" "$BOLD" "$RESET" "$REPO_DIR"

# ─── Node ───────────────────────────────────────────────────────────
if command -v node >/dev/null 2>&1; then
  NODE_RAW="$(node --version)"
  NODE_MAJOR="${NODE_RAW#v}"; NODE_MAJOR="${NODE_MAJOR%%.*}"
  if (( NODE_MAJOR >= 22 )); then
    ok "node" "$NODE_RAW"
  else
    miss "node" "$NODE_RAW (need >= 22)"
  fi
else
  miss "node" "not installed"
fi

# ─── pnpm ───────────────────────────────────────────────────────────
PM_FIELD="$(node -e 'try { process.stdout.write(require("./package.json").packageManager || "") } catch {}' 2>/dev/null || echo "")"
PM_WANTED="${PM_FIELD%%+*}"
PM_WANTED_VER="${PM_WANTED#pnpm@}"

if command -v pnpm >/dev/null 2>&1; then
  PNPM_VER="$(pnpm --version 2>/dev/null || echo '?')"
  if [[ "$PNPM_VER" == "$PM_WANTED_VER" ]]; then
    ok "pnpm" "$PNPM_VER (matches packageManager)"
  elif [[ -n "$PM_WANTED_VER" ]]; then
    warn "pnpm" "$PNPM_VER (packageManager pins $PM_WANTED_VER; run 'corepack prepare $PM_WANTED --activate')"
  else
    ok "pnpm" "$PNPM_VER"
  fi
else
  miss "pnpm" "not installed (run scripts/bootstrap.sh)"
fi

# ─── corepack ──────────────────────────────────────────────────────
if command -v corepack >/dev/null 2>&1; then
  ok "corepack" "$(corepack --version 2>/dev/null || echo '?')"
else
  warn "corepack" "not on PATH (bundled with Node 22; 'npm i -g corepack')"
fi

# ─── git ────────────────────────────────────────────────────────────
if command -v git >/dev/null 2>&1; then
  ok "git" "$(git --version 2>/dev/null | awk '{print $3}')"
else
  miss "git" "not installed"
fi

# ─── Required build-adjacent tools ─────────────────────────────────
if command -v curl >/dev/null 2>&1; then
  ok "curl" "$(curl --version 2>/dev/null | head -1 | awk '{print $2}')"
else
  miss "curl" "not installed"
fi

# ─── Optional scanners ─────────────────────────────────────────────
if command -v semgrep >/dev/null 2>&1; then
  ok "semgrep" "$(semgrep --version 2>/dev/null | head -1)"
else
  warn "semgrep" "not installed (needed for e2e + default scan; 'pip install semgrep')"
fi

if command -v codeql >/dev/null 2>&1; then
  ok "codeql" "$(codeql version --format=terse 2>/dev/null || echo 'installed')"
else
  warn "codeql" "not installed (optional; only for --tasks codeql)"
fi

# ─── Supporting tools ──────────────────────────────────────────────
if command -v python3 >/dev/null 2>&1; then
  ok "python3" "$(python3 --version 2>/dev/null | awk '{print $2}')"
else
  warn "python3" "not installed (needed by some e2e tests)"
fi

if command -v jq >/dev/null 2>&1; then
  ok "jq" "$(jq --version 2>/dev/null)"
else
  warn "jq" "not installed (needed by benchmarks/cve-corpus/setup.sh)"
fi

if command -v sqlite3 >/dev/null 2>&1; then
  ok "sqlite3" "$(sqlite3 --version 2>/dev/null | awk '{print $1}')"
else
  warn "sqlite3" "not installed (optional — better-sqlite3 bundles its own)"
fi

# ─── node_modules presence ─────────────────────────────────────────
if [[ -d "$REPO_DIR/node_modules" ]]; then
  ok "node_modules" "present"
else
  warn "node_modules" "missing (run 'pnpm install' or 'pnpm setup')"
fi

# ─── Summary ────────────────────────────────────────────────────────
printf "\n%s%d error(s), %d warning(s).%s\n" "$BOLD" "$ERRORS" "$WARNINGS" "$RESET"

if (( ERRORS > 0 )); then
  exit 1
fi
if (( STRICT == 1 && WARNINGS > 0 )); then
  exit 1
fi
exit 0
