#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'USAGE'
Usage: bash scripts/build-disk.sh [MODE] [--apply]

Modes:
  --report             Show Cargo build roots and their largest top-level entries (default).
  --prune-aux          Remove legacy target-dev trees and disposable coverage/scratch output.
  --prune-incremental  Remove rustc incremental caches while preserving compiled dependencies.
  --prune-all          Remove every discovered target and target-dev tree.

Prune modes are dry-runs unless --apply is also supplied.
USAGE
}

mode=report
apply=0
while [ "$#" -gt 0 ]; do
  case "$1" in
    --report) mode=report ;;
    --prune-aux) mode=prune-aux ;;
    --prune-incremental) mode=prune-incremental ;;
    --prune-all) mode=prune-all ;;
    --apply) apply=1 ;;
    -h|--help) usage; exit 0 ;;
    *) printf 'unknown option: %s\n' "$1" >&2; usage >&2; exit 2 ;;
  esac
  shift
done

if [ "$mode" = report ] && [ "$apply" -eq 1 ]; then
  printf '%s\n' '--apply requires a prune mode' >&2
  exit 2
fi

repo_root=$(git rev-parse --show-toplevel 2>/dev/null) || {
  printf '%s\n' 'build-disk must run inside a Git worktree' >&2
  exit 2
}

worktrees_file=$(mktemp "${TMPDIR:-/tmp}/kuzushi-worktrees.XXXXXX")
targets_file=$(mktemp "${TMPDIR:-/tmp}/kuzushi-targets.XXXXXX")
scratch_file=$(mktemp "${TMPDIR:-/tmp}/kuzushi-disk-scratch.XXXXXX")
prune_file=$(mktemp "${TMPDIR:-/tmp}/kuzushi-prune.XXXXXX")
cleanup_temp() {
  rm -f "$worktrees_file" "$targets_file" "$scratch_file" "$prune_file"
}
trap cleanup_temp EXIT

collect_worktrees() {
  git -C "$repo_root" worktree list --porcelain 2>/dev/null \
    | while IFS= read -r line; do
        case "$line" in
          'worktree '*) printf '%s\n' "${line#worktree }" ;;
        esac
      done

  # Include abandoned agent worktree directories that Git may no longer list.
  for parent in \
    "$repo_root/.claude/worktrees" \
    "$repo_root/.codex/worktrees" \
    "$repo_root/.worktrees"; do
    [ -d "$parent" ] || continue
    for candidate in "$parent"/*; do
      [ -d "$candidate" ] || continue
      printf '%s\n' "$candidate"
    done
  done
}

collect_worktrees > "$worktrees_file"
printf '%s\n' "$repo_root" >> "$worktrees_file"
sort -u -o "$worktrees_file" "$worktrees_file"

collect_configured_target() {
  local configured_target=$1
  [ -n "$configured_target" ] || return 0
  case "$configured_target" in
    /*) ;;
    *) configured_target="$repo_root/$configured_target" ;;
  esac
  [ -d "$configured_target" ] || return 0
  (cd "$configured_target" && pwd -P)
}

: > "$targets_file"
while IFS= read -r worktree; do
  [ -n "$worktree" ] || continue
  for candidate in "$worktree/target" "$worktree/target-dev"; do
    [ -d "$candidate" ] && printf '%s\n' "$candidate" >> "$targets_file"
  done
done < "$worktrees_file"
collect_configured_target "${CARGO_TARGET_DIR:-}" >> "$targets_file"
collect_configured_target "${KUZUSHI_EVIDENCE_LOOP_TARGET_DIR:-}" >> "$targets_file"
sort -u -o "$targets_file" "$targets_file"

size_kib() {
  du -sk "$1" 2>/dev/null | awk 'NR == 1 { print $1 }'
}

human_kib() {
  awk -v kib="$1" 'BEGIN {
    if (kib >= 1048576) printf "%.1f GiB", kib / 1048576;
    else if (kib >= 1024) printf "%.1f MiB", kib / 1024;
    else printf "%d KiB", kib;
  }'
}

report_targets() {
  total_kib=0
  count=0
  printf 'Kuzushi Cargo build roots\n'
  if [ ! -s "$targets_file" ]; then
    printf '  none found\n'
  fi

  while IFS= read -r target; do
    [ -n "$target" ] || continue
    target_kib=$(size_kib "$target")
    target_kib=${target_kib:-0}
    total_kib=$((total_kib + target_kib))
    count=$((count + 1))
    printf '  %9s  %s\n' "$(human_kib "$target_kib")" "$target"

    : > "$scratch_file"
    for child in "$target"/* "$target"/.[!.]* "$target"/..?*; do
      [ -d "$child" ] || continue
      child_kib=$(size_kib "$child")
      child_kib=${child_kib:-0}
      printf '%s\t%s\n' "$child_kib" "$child" >> "$scratch_file"
    done
    if [ -s "$scratch_file" ]; then
      sort -nr "$scratch_file" | awk 'NR <= 5' \
        | while IFS=$'\t' read -r child_kib child; do
            printf '      %9s  %s\n' "$(human_kib "$child_kib")" "${child#"$target"/}"
          done
    fi
  done < "$targets_file"

  printf '  ---------\n'
  printf '  %9s  total across %d build root(s)\n' "$(human_kib "$total_kib")" "$count"
  printf '\nOther large generated/cache roots (reported only; never pruned here)\n'
  found_other=0
  for other in \
    "$repo_root/native" \
    "$repo_root/npm/platform-packages" \
    "${CARGO_HOME:-$HOME/.cargo}/registry" \
    "${CARGO_HOME:-$HOME/.cargo}/git" \
    "${RUSTUP_HOME:-$HOME/.rustup}/toolchains"; do
    [ -d "$other" ] || continue
    other_kib=$(size_kib "$other")
    other_kib=${other_kib:-0}
    printf '  %9s  %s\n' "$(human_kib "$other_kib")" "$other"
    found_other=1
  done
  [ "$found_other" -eq 1 ] || printf '  none found\n'
}

validate_prune_path() {
  local path=$1
  case "$path" in
    ''|/|"$HOME"|"$repo_root")
      printf 'refusing unsafe prune path: %s\n' "$path" >&2
      exit 2
      ;;
  esac
}

queue_prune_path() {
  local path=$1
  [ -e "$path" ] || return 0
  validate_prune_path "$path"
  printf '%s\n' "$path" >> "$prune_file"
}

case "$mode" in
  report)
    report_targets
    exit 0
    ;;
  prune-aux)
    while IFS= read -r target; do
      [ -n "$target" ] || continue
      validate_prune_path "$target"
      if [ "$(basename "$target")" = target-dev ]; then
        queue_prune_path "$target"
        continue
      fi
      queue_prune_path "$target/llvm-cov-target"
      queue_prune_path "$target/.ephemeral"
      queue_prune_path "$target/mutation.old"
    done < "$targets_file"
    ;;
  prune-incremental)
    while IFS= read -r target; do
      [ -n "$target" ] || continue
      validate_prune_path "$target"
      find "$target" -type d -name incremental -prune -print 2>/dev/null \
        >> "$prune_file" || true
    done < "$targets_file"
    ;;
  prune-all)
    while IFS= read -r target; do
      [ -n "$target" ] || continue
      queue_prune_path "$target"
    done < "$targets_file"
    ;;
esac

sort -u -o "$prune_file" "$prune_file"
if [ ! -s "$prune_file" ]; then
  printf 'No matching build artifacts found.\n'
  exit 0
fi

candidate_kib=0
while IFS= read -r path; do
  [ -n "$path" ] || continue
  path_kib=$(size_kib "$path")
  path_kib=${path_kib:-0}
  candidate_kib=$((candidate_kib + path_kib))
  if [ "$apply" -eq 1 ]; then
    printf 'remove %9s  %s\n' "$(human_kib "$path_kib")" "$path"
    rm -rf "$path"
  else
    printf 'would remove %9s  %s\n' "$(human_kib "$path_kib")" "$path"
  fi
done < "$prune_file"

if [ "$apply" -eq 1 ]; then
  printf 'Reclaimed up to %s.\n' "$(human_kib "$candidate_kib")"
else
  printf 'Dry run: up to %s is eligible. Re-run with --apply to delete it.\n' \
    "$(human_kib "$candidate_kib")"
fi
