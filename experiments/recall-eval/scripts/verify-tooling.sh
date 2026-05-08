#!/usr/bin/env bash
# Pre-flight checks for the recall eval harness.
# Exit non-zero if anything required is missing.

set -uo pipefail

EVAL_DIR="$(cd "$(dirname "$0")/.." && pwd)"
REPO_ROOT="$(git rev-parse --show-toplevel)"
fail=0

ok()  { printf "  \033[32m✓\033[0m %s\n" "$*"; }
bad() { printf "  \033[31m✗\033[0m %s\n" "$*"; fail=1; }
note(){ printf "  • %s\n" "$*"; }

echo "[binaries]"
for bin in git tmux jq cargo; do
  if command -v "$bin" >/dev/null 2>&1; then ok "$bin: $(command -v "$bin")"
  else bad "$bin not on PATH"
  fi
done

# Optional but expected
for bin in semgrep codeql ctags rg; do
  if command -v "$bin" >/dev/null 2>&1; then ok "$bin: $(command -v "$bin")"
  else note "$bin not on PATH (optional; some scan engines/tools degrade)"
  fi
done

echo
echo "[kuzushi binary]"
KUZ="$REPO_ROOT/target/release/kuzushi"
if [[ -x "$KUZ" ]]; then
  ok "release binary at $KUZ"
  ok "version: $("$KUZ" --version 2>/dev/null || echo unknown)"
else
  note "release binary not built. Run: cargo build --release -p kuzushi-cli"
fi

echo
echo "[oauth credentials]"
OAUTH_FILE="${KUZUSHI_OAUTH_CREDENTIALS:-$HOME/.kuzushi/oauth-credentials.json}"
if [[ -f "$OAUTH_FILE" ]]; then
  ok "credentials present at $OAUTH_FILE"
  if jq -e .access_token "$OAUTH_FILE" >/dev/null 2>&1; then
    ok "access_token field readable"
  else
    bad "access_token field missing or unreadable"
  fi
  if jq -e .expires_at "$OAUTH_FILE" >/dev/null 2>&1; then
    expires=$(jq -r .expires_at "$OAUTH_FILE")
    ok "expires_at: $expires"
  else
    note "expires_at field missing (refresh might trip)"
  fi
elif [[ -n "${KUZUSHI_ANTHROPIC_OAUTH_TOKEN:-}" ]]; then
  ok "raw token via KUZUSHI_ANTHROPIC_OAUTH_TOKEN env"
elif [[ -n "${ANTHROPIC_API_KEY:-}" ]]; then
  note "no OAuth file; falling back to ANTHROPIC_API_KEY"
else
  bad "no OAuth credentials and no ANTHROPIC_API_KEY"
fi

echo
echo "[slices]"
for name in linux postgres redis mariadb; do
  toml="$EVAL_DIR/slices/$name/.kuzushi-slice.toml"
  if [[ -f "$toml" ]]; then
    sha=$(grep '^commit ' "$toml" | head -1 | cut -d'"' -f2)
    if [[ -n "$sha" ]]; then ok "$name pinned at $sha"
    else bad "$name has empty commit field — re-run fetch-slices.sh with KUZUSHI_SLICE_SHA_${name^^}=<sha>"
    fi
  else
    note "$name slice not populated. Run: experiments/recall-eval/scripts/fetch-slices.sh"
  fi
done

echo
echo "[kuzushi doctor]"
if [[ -x "$KUZ" ]]; then
  if "$KUZ" doctor --target "$REPO_ROOT" --json >/dev/null 2>&1; then
    ok "kuzushi doctor --json"
  else
    note "kuzushi doctor reported issues (run \`$KUZ doctor --target $REPO_ROOT\` for details)"
  fi
else
  note "skipping kuzushi doctor; release binary not built"
fi

echo
if [[ $fail -eq 0 ]]; then
  echo "verify-tooling: OK"
else
  echo "verify-tooling: $fail required check(s) failed"
fi
exit $fail
