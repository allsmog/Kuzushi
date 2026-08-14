#!/usr/bin/env bash
set -euo pipefail

required_version="27.1.0"
if ! version_output="$(cargo mutants --version 2>/dev/null)"; then
  echo "cargo-mutants ${required_version} is required; install it with: cargo install cargo-mutants --version ${required_version} --locked" >&2
  exit 2
fi
read -r _ actual_version _ <<<"${version_output}"
if [[ "${actual_version:-}" != "${required_version}" ]]; then
  echo "cargo-mutants ${required_version} is required, found: ${version_output}" >&2
  exit 2
fi

base="${KUZUSHI_QUALITY_BASE_REF:-}"
if [[ -z "${base}" ]] && git rev-parse --verify --quiet 'origin/main^{commit}' >/dev/null; then
  if [[ "$(git rev-parse origin/main)" != "$(git rev-parse HEAD)" ]]; then
    base="$(git merge-base origin/main HEAD)"
  fi
fi
base="${base:-HEAD^}"
if ! git rev-parse --verify --quiet "${base}^{commit}" >/dev/null; then
  echo "mutation gate cannot resolve base commit ${base}" >&2
  exit 2
fi

# cargo-mutants runs tests from a source copy without `.git`. Preserve the
# build identity that normal Cargo builds obtain through kuzushi-core/build.rs
# so checkpoint and lifecycle tests exercise the same product contract.
export KUZUSHI_GIT_SHA="$(git rev-parse --short=12 HEAD)"
export KUZUSHI_GIT_BRANCH="$(git rev-parse --abbrev-ref HEAD)"

mkdir -p target/mutation
diff_input="$(mktemp "${TMPDIR:-/tmp}/kuzushi-mutation-diff.XXXXXX")"
mutant_list="$(mktemp "${TMPDIR:-/tmp}/kuzushi-mutation-list.XXXXXX")"
trap 'rm -f "${diff_input}" "${mutant_list}"' EXIT

write_change_diff() {
  local output="$1"
  git diff --no-color "${base}" -- '*.rs' > "${output}"
  while IFS= read -r -d '' file; do
    if git diff --no-color --no-index -- /dev/null "${file}" >> "${output}"; then
      continue
    fi
    status=$?
    if [[ "${status}" -ne 1 ]]; then
      return "${status}"
    fi
  done < <(git ls-files --others --exclude-standard -z -- '*.rs')
}

write_change_diff "${diff_input}"
if [[ ! -s "${diff_input}" ]]; then
  echo "mutation gate: no Rust changes"
  exit 0
fi

max_mutants=12
platform_args=()
case "$(uname -s)" in
  Darwin) platform_args+=(--exclude-re '(linux|windows)_|trusted_bwrap') ;;
  Linux) platform_args+=(--exclude-re '(macos|windows)_|sandbox_exec') ;;
  *) platform_args+=(--exclude-re '(linux|macos)_|trusted_bwrap|sandbox_exec') ;;
esac
filter_args=(
  # A whole-function no-op here leaves modal tests waiting forever; retain its branch mutants.
  --exclude-re 'replace ShellApp::handle_primary_modal_key -> Option<InputUpdate> with Some\(Default::default\(\)\)'
)
cargo mutants \
  --no-shuffle \
  --in-diff "${diff_input}" \
  --test-workspace false \
  --line-col false \
  "${platform_args[@]}" \
  "${filter_args[@]}" \
  --list > "${mutant_list}"
mutant_count="$(wc -l < "${mutant_list}" | tr -d '[:space:]')"
if [[ "${mutant_count}" -eq 0 ]]; then
  echo "mutation gate: no eligible Rust mutants"
  exit 0
fi

mutation_args=(
  --no-shuffle
  --in-diff "${diff_input}"
  --output target/mutation
  --test-workspace false
  --copy-target false
  --jobs 1
  --timeout 1200
  --build-timeout 600
  --cargo-arg=--locked
)
mutation_args+=("${platform_args[@]}")
mutation_args+=("${filter_args[@]}")

selection_hash="$(git hash-object "${mutant_list}")"
shard_selection="$(
  node scripts/rust-mutation-shard.mjs "${mutant_count}" "${max_mutants}" "${selection_hash}"
)"
read -r shard_index shard_count selected_count <<<"${shard_selection}"
if [[ "${shard_count}" -gt 1 ]]; then
  mutation_args+=(--sharding round-robin --shard "${shard_index}/${shard_count}")
fi

echo "mutation gate: testing ${selected_count}/${mutant_count} changed-code mutants (round-robin shard ${shard_index}/${shard_count})"

set +e
cargo mutants "${mutation_args[@]}"
status=$?
set -e

mkdir -p target/mutation
cp "${diff_input}" target/mutation/change.diff
{
  printf 'eligible_mutants=%s\n' "${mutant_count}"
  printf 'selected_mutants=%s\n' "${selected_count}"
  printf 'shard=%s/%s\n' "${shard_index}" "${shard_count}"
  printf 'selection_hash=%s\n' "${selection_hash}"
  printf 'diff_hash=%s\n' "$(git hash-object "${diff_input}")"
} > target/mutation/sample.txt

exit "${status}"
