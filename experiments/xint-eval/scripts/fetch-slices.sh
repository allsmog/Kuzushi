#!/usr/bin/env bash
# Populate experiments/xint-eval/slices/<name> as git submodules pinned to
# pre-patch SHAs, with sparse-checkout limited to scope/<name>.txt.
#
# Pre-patch SHAs default to environment variables so operators can pin without
# editing this script. If a SHA is unset, the script fetches the upstream tip
# and prints a warning — recall numbers from a tip-of-tree run are not
# comparable across days.

set -euo pipefail

EVAL_DIR="$(cd "$(dirname "$0")/.." && pwd)"
SLICES_DIR="$EVAL_DIR/slices"
SCOPE_DIR="$EVAL_DIR/scope"

declare -A REPOS=(
  [linux]="https://github.com/torvalds/linux.git"
  [postgres]="https://github.com/postgres/postgres.git"
  [redis]="https://github.com/redis/redis.git"
  [mariadb]="https://github.com/MariaDB/server.git"
)

# Pre-patch SHAs. Override via env, e.g. KUZUSHI_SLICE_SHA_LINUX=abcdef...
declare -A SHAS=(
  [linux]="${KUZUSHI_SLICE_SHA_LINUX:-}"
  [postgres]="${KUZUSHI_SLICE_SHA_POSTGRES:-}"
  [redis]="${KUZUSHI_SLICE_SHA_REDIS:-}"
  [mariadb]="${KUZUSHI_SLICE_SHA_MARIADB:-}"
)

cd "$(git rev-parse --show-toplevel)"

for name in "${!REPOS[@]}"; do
  url="${REPOS[$name]}"
  sha="${SHAS[$name]}"
  rel="experiments/xint-eval/slices/$name"
  scope_file="$SCOPE_DIR/$name.txt"

  if [[ ! -f "$scope_file" ]]; then
    echo "fetch-slices: missing scope file $scope_file" >&2
    exit 1
  fi

  if [[ -d "$rel/.git" || -f "$rel/.git" ]]; then
    echo "[$name] submodule already present, skipping add"
  else
    echo "[$name] adding submodule from $url"
    # Use --force in case the slices/<name> directory exists but is empty.
    git submodule add --force --depth 1 "$url" "$rel"
  fi

  # Configure sparse-checkout BEFORE fetching content.
  pushd "$rel" >/dev/null
  git config core.sparseCheckout true
  git sparse-checkout init --cone || true
  # shellcheck disable=SC2046
  git sparse-checkout set $(grep -v '^[[:space:]]*$' "$scope_file" | tr '\n' ' ')

  if [[ -n "$sha" ]]; then
    echo "[$name] fetching $sha"
    git fetch --depth=1 origin "$sha"
    git checkout --detach "$sha"
  else
    echo "[$name] WARN: no SHA pinned (set KUZUSHI_SLICE_SHA_${name^^}); using current HEAD"
  fi

  resolved="$(git rev-parse HEAD)"
  tree="$(git rev-parse 'HEAD^{tree}')"
  cat > .kuzushi-slice.toml <<EOF
[slice]
name = "$name"
commit = "$resolved"
tree = "$tree"
fetched_at = "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
sparse_checkout_source = "experiments/xint-eval/scope/$name.txt"
EOF

  popd >/dev/null
done

echo
echo "Slices populated. Resolved commits:"
for name in "${!REPOS[@]}"; do
  toml="$SLICES_DIR/$name/.kuzushi-slice.toml"
  if [[ -f "$toml" ]]; then
    sha=$(grep '^commit ' "$toml" | head -1 | cut -d'"' -f2)
    printf "  %-9s %s\n" "$name" "$sha"
  fi
done
