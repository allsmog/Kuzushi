#!/usr/bin/env bash
#
# TypeScript budget ratchet (Phase 0 of the TypeScript-removal plan).
#
# Counts tracked `*.ts` / `*.tsx` source files that are NOT in the permanent
# allowlist, and fails if that count exceeds the committed budget in
# `.ts-budget`. The budget is a ratchet: it may only ever go DOWN. Every PR
# that removes TypeScript should lower `.ts-budget` to the new true count so
# the gate can never silently regress.
#
# The allowlist is TypeScript that is *data*, not runtime, and is expected to
# live in the repo forever:
#   - evals/**/fixtures/**        SAST scan-target corpora (a security tool
#                                 needs polyglot targets to scan)
#   - examples/**                 shipped example projects
#   - .design-sync/**             Claude Design preview sources (web-by-nature)
#   - packages/kuzushi-tui-kit/** Ratatui-theme design kit (web-by-nature)
#
# This check coexists with scripts/check-retired-ts-runtime.mjs until the
# removal is complete; at zero, this ratchet replaces it.
set -euo pipefail

cd "$(git rev-parse --show-toplevel)"

ALLOWLIST='evals/.*/fixtures/|examples/|\.design-sync/|packages/kuzushi-tui-kit/'

if [[ ! -f .ts-budget ]]; then
  echo "ts-budget: missing .ts-budget file at repo root" >&2
  exit 1
fi

BUDGET="$(tr -d '[:space:]' < .ts-budget)"
if ! [[ "$BUDGET" =~ ^[0-9]+$ ]]; then
  echo "ts-budget: .ts-budget must contain a single non-negative integer, got '${BUDGET}'" >&2
  exit 1
fi

OFFENDERS="$(git ls-files '*.ts' '*.tsx' | grep -vE "$ALLOWLIST" || true)"
COUNT="$(printf '%s\n' "$OFFENDERS" | grep -c . || true)"

echo "ts-budget: ${COUNT} non-allowlisted TypeScript file(s) (budget: ${BUDGET})"

if [[ "$COUNT" -gt "$BUDGET" ]]; then
  echo "ts-budget: FAIL — over budget by $((COUNT - BUDGET)) file(s)." >&2
  echo "ts-budget: remove TypeScript or (only if legitimately data) extend the allowlist." >&2
  echo "ts-budget: offenders:" >&2
  printf '  %s\n' $OFFENDERS >&2
  exit 1
fi

if [[ "$COUNT" -lt "$BUDGET" ]]; then
  echo "ts-budget: RATCHET — count (${COUNT}) is below budget (${BUDGET})." >&2
  echo "ts-budget: lower .ts-budget to ${COUNT} in this PR so the gate cannot regress." >&2
  exit 1
fi

echo "ts-budget: OK — at budget."
