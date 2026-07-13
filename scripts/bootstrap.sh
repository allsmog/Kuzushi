#!/usr/bin/env bash
# bootstrap.sh — Deterministic one-command setup for Kuzushi contributors.
#
# Verifies pinned Rust and Node >= 22, aligns pnpm to the `packageManager` pin in package.json
# via corepack, optionally probes external tools (semgrep, codeql, python3),
# and runs `pnpm install --frozen-lockfile`.
#
# Exit codes:
#   0  success
#   1  required tool missing or version mismatch
#   2  pnpm install failed
#
# Flags:
#   --strict            treat warnings (missing optional externals) as errors
#   --skip-install      do not run `pnpm install`
#   --skip-corepack     do not try to activate pnpm via corepack
#   -h, --help          show help

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
RUST_TOOLCHAIN_FILE="${REPO_DIR}/rust-toolchain.toml"
PINNED_RUST_VERSION="$(sed -nE 's/^[[:space:]]*channel[[:space:]]*=[[:space:]]*"([^"]+)".*$/\1/p' "${RUST_TOOLCHAIN_FILE}" | head -1)"

if [[ -z "${PINNED_RUST_VERSION}" ]]; then
  echo "bootstrap: unable to read the pinned Rust channel from ${RUST_TOOLCHAIN_FILE}" >&2
  exit 1
fi

# ─── Flags ────────────────────────────────────────────────────────────
STRICT=0
SKIP_INSTALL=0
SKIP_COREPACK=0

usage() {
  cat <<EOF
bootstrap.sh — Kuzushi contributor environment setup

Usage: scripts/bootstrap.sh [flags]

Flags:
  --strict          Treat warnings (missing optional externals) as errors.
  --skip-install    Skip "pnpm install --frozen-lockfile".
  --skip-corepack   Skip corepack activation (use whatever pnpm is on PATH).
  -h, --help        Show this help and exit.
EOF
}

while (( $# )); do
  case "$1" in
    --strict) STRICT=1 ;;
    --skip-install) SKIP_INSTALL=1 ;;
    --skip-corepack) SKIP_COREPACK=1 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "bootstrap: unknown flag: $1" >&2; usage >&2; exit 1 ;;
  esac
  shift
done

# ─── Output helpers ──────────────────────────────────────────────────
if [[ -t 1 ]]; then
  GREEN=$'\033[32m'; YELLOW=$'\033[33m'; RED=$'\033[31m'
  BOLD=$'\033[1m'; RESET=$'\033[0m'
else
  GREEN=""; YELLOW=""; RED=""; BOLD=""; RESET=""
fi

ok()   { printf "  %s✓%s %s\n" "$GREEN" "$RESET" "$1"; }
warn() { printf "  %s!%s %s\n" "$YELLOW" "$RESET" "$1"; WARNINGS=$((WARNINGS + 1)); }
err()  { printf "  %s✗%s %s\n" "$RED" "$RESET" "$1" >&2; ERRORS=$((ERRORS + 1)); }
hint() { printf "    %s→%s %s\n" "$YELLOW" "$RESET" "$1"; }
section() { printf "\n%s%s%s\n" "$BOLD" "$1" "$RESET"; }

WARNINGS=0
ERRORS=0

# ─── Check Node >= 22 ────────────────────────────────────────────────
section "Verifying Node.js"

if ! command -v node >/dev/null 2>&1; then
  err "node is not on PATH."
  hint "Install Node 22 LTS: https://nodejs.org/ or run 'nvm use' (respects .nvmrc)."
  hint "With asdf/mise: 'asdf install nodejs 22.11.0 && asdf local nodejs 22.11.0'"
  exit 1
fi

NODE_RAW="$(node --version)"              # e.g. v22.11.0
NODE_MAJOR="${NODE_RAW#v}"                # 22.11.0
NODE_MAJOR="${NODE_MAJOR%%.*}"            # 22
if ! [[ "$NODE_MAJOR" =~ ^[0-9]+$ ]]; then
  err "Unable to parse Node major version from '$NODE_RAW'."
  exit 1
fi
if (( NODE_MAJOR < 22 )); then
  err "Node $NODE_RAW is too old. Kuzushi requires >= 22."
  hint "nvm: 'nvm install 22 && nvm use 22'  (repo has .nvmrc pinned to 22)"
  hint "mise/asdf: repo has .tool-versions pinned to nodejs 22.11.0"
  exit 1
fi
ok "node $NODE_RAW (>= 22 required)"

# ─── Align pnpm with packageManager via corepack ─────────────────────
section "Verifying pnpm"

PACKAGE_MANAGER="$(node -e 'const p = require("./package.json"); process.stdout.write(p.packageManager || "");' 2>/dev/null || echo "")"
if [[ -z "$PACKAGE_MANAGER" ]]; then
  err "package.json has no 'packageManager' field."
  exit 1
fi
# Strip sha suffix: "pnpm@10.30.0+sha512..." -> "pnpm@10.30.0"
PNPM_SPEC="${PACKAGE_MANAGER%%+*}"
PNPM_WANTED_VERSION="${PNPM_SPEC#pnpm@}"

if (( SKIP_COREPACK == 0 )); then
  if command -v corepack >/dev/null 2>&1; then
    corepack enable >/dev/null 2>&1 || warn "corepack enable failed (may need sudo on some systems)."
    # Activate the exact spec so pnpm matches package.json.
    if ! corepack prepare "$PNPM_SPEC" --activate >/dev/null 2>&1; then
      warn "corepack prepare '$PNPM_SPEC' failed; will fall back to whatever pnpm is on PATH."
    fi
  else
    warn "corepack not found; cannot pin pnpm via corepack."
    hint "Install Node 22 LTS which bundles corepack, or 'npm i -g corepack'."
  fi
fi

if ! command -v pnpm >/dev/null 2>&1; then
  err "pnpm is not on PATH even after corepack activation."
  hint "'corepack enable' then reopen your shell, or 'npm i -g pnpm@$PNPM_WANTED_VERSION'"
  exit 1
fi

PNPM_ACTUAL_VERSION="$(pnpm --version)"
if [[ "$PNPM_ACTUAL_VERSION" != "$PNPM_WANTED_VERSION" ]]; then
  warn "pnpm $PNPM_ACTUAL_VERSION is on PATH but package.json pins $PNPM_WANTED_VERSION."
  hint "Run 'corepack prepare $PNPM_SPEC --activate' to match exactly."
else
  ok "pnpm $PNPM_ACTUAL_VERSION matches packageManager pin"
fi

# ─── Required tools ─────────────────────────────────────────────────
section "Verifying required tools"

for tool in git curl; do
  if command -v "$tool" >/dev/null 2>&1; then
    ok "$tool ($("$tool" --version 2>/dev/null | head -1))"
  else
    err "$tool is required but not installed."
    hint "Install via your system package manager (apt/brew/dnf)."
  fi
done

for tool in cargo rustfmt; do
  if command -v "$tool" >/dev/null 2>&1; then
    ok "$tool ($("$tool" --version 2>/dev/null | head -1))"
  else
    err "$tool is required by rust-toolchain.toml but is not installed."
    hint "Install Rust with rustup; the repo will select Rust ${PINNED_RUST_VERSION} automatically."
  fi
done

if command -v rustc >/dev/null 2>&1; then
  RUSTC_VERSION_LINE="$(rustc --version 2>/dev/null | head -1)"
  RUSTC_ACTUAL_VERSION="$(printf '%s\n' "${RUSTC_VERSION_LINE}" | awk '{print $2}')"
  if [[ "${RUSTC_ACTUAL_VERSION}" == "${PINNED_RUST_VERSION}" ]]; then
    ok "rustc ${RUSTC_ACTUAL_VERSION} matches rust-toolchain.toml"
  else
    err "rustc ${RUSTC_ACTUAL_VERSION:-unknown} does not match pinned ${PINNED_RUST_VERSION}."
    hint "Run 'rustup toolchain install ${PINNED_RUST_VERSION} --component rustfmt --component clippy'."
  fi
else
  err "rustc is required by rust-toolchain.toml but is not installed."
  hint "Install Rust ${PINNED_RUST_VERSION} with rustup."
fi

if command -v cargo >/dev/null 2>&1 && cargo clippy --version >/dev/null 2>&1; then
  ok "clippy ($(cargo clippy --version 2>/dev/null | head -1))"
else
  err "Clippy is required but unavailable for the pinned Rust toolchain."
  hint "Run 'rustup component add clippy --toolchain ${PINNED_RUST_VERSION}'."
fi

# ─── Optional externals ─────────────────────────────────────────────
section "Probing optional externals"

if command -v semgrep >/dev/null 2>&1; then
  ok "semgrep ($(semgrep --version 2>/dev/null | head -1))"
else
  warn "semgrep not installed — required for 'pnpm test:e2e' and the default scan pipeline."
  hint "Install: 'pip install semgrep' (pypi) or 'brew install semgrep' (macOS)."
  hint "The Rust scanner fails with an actionable missing-binary error if semgrep is absent."
fi

if command -v codeql >/dev/null 2>&1; then
  ok "codeql ($(codeql version --format=terse 2>/dev/null || echo 'installed'))"
else
  warn "codeql not installed — optional. Required only for --tasks codeql."
  hint "gh extension install github/gh-codeql && gh codeql install-stub"
  hint "Or download: https://github.com/github/codeql-cli-binaries/releases"
fi

if command -v python3 >/dev/null 2>&1; then
  ok "python3 ($(python3 --version 2>/dev/null))"
else
  warn "python3 not installed — required for some e2e tests."
  hint "Install via your system package manager."
fi

if command -v jq >/dev/null 2>&1; then
  ok "jq ($(jq --version 2>/dev/null))"
else
  warn "jq not installed — required for benchmark corpus setup (cve-corpus)."
  hint "Install: 'apt-get install jq' / 'brew install jq'."
fi

if command -v sqlite3 >/dev/null 2>&1; then
  ok "sqlite3 ($(sqlite3 --version 2>/dev/null | awk '{print $1}'))"
else
  warn "sqlite3 CLI not installed — optional. Used by some e2e helpers."
  hint "Install: 'apt-get install sqlite3' / 'brew install sqlite'."
fi

# ─── Summary gate ───────────────────────────────────────────────────
section "Summary"

if (( ERRORS > 0 )); then
  printf "%s%d error(s), %d warning(s).%s\n" "$RED" "$ERRORS" "$WARNINGS" "$RESET" >&2
  exit 1
fi

if (( STRICT == 1 && WARNINGS > 0 )); then
  printf "%s%d warning(s) in --strict mode.%s\n" "$RED" "$WARNINGS" "$RESET" >&2
  exit 1
fi

if (( WARNINGS > 0 )); then
  printf "%s%d warning(s) — see hints above.%s\n" "$YELLOW" "$WARNINGS" "$RESET"
else
  printf "%sAll checks passed.%s\n" "$GREEN" "$RESET"
fi

# ─── Install dependencies ───────────────────────────────────────────
if (( SKIP_INSTALL == 1 )); then
  section "Skipping 'pnpm install' (--skip-install)"
  exit 0
fi

section "Running 'pnpm install --frozen-lockfile'"
cd "$REPO_DIR"
if ! pnpm install --frozen-lockfile; then
  err "pnpm install failed."
  hint "If you're updating dependencies intentionally, run 'pnpm install' without --frozen-lockfile."
  exit 2
fi

section "Configuring local git"
if [[ -f "$REPO_DIR/.gitmessage" ]]; then
  git -C "$REPO_DIR" config --local commit.template .gitmessage
  printf "  ✓ commit.template = .gitmessage (conventional commits)\n"
fi

section "Bootstrap complete"
printf "%sNext:%s  pnpm doctor     # re-verify env\n" "$BOLD" "$RESET"
printf "       pnpm typecheck:all   # type-check all TypeScript projects\n"
printf "       pnpm test            # run TypeScript unit tests\n"
printf "       cargo test --workspace  # run native Rust tests\n"
printf "       pnpm dev -- --help  # run the native CLI in dev mode\n"
