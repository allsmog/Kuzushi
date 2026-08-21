#!/usr/bin/env bash
set -euo pipefail

default_budget_gib=40

usage() {
  cat <<'USAGE'
Usage: bash scripts/build-disk.sh [MODE] [--apply] [--budget-gib N]

Modes:
  --report             Show Cargo build roots with per-category usage (default).
  --check-budget       Exit 1 when aggregate build-root usage exceeds the budget.
  --prune-aux          Remove legacy target-dev trees and disposable coverage/scratch output.
  --prune-incremental  Remove rustc incremental caches while preserving compiled dependencies.
  --prune-all          Remove every discovered target and target-dev tree.

Options:
  --apply          Actually delete (prune modes are dry-runs without it).
  --budget-gib N   Budget for --check-budget in GiB (decimals allowed).
                   Default: 40, or KUZUSHI_BUILD_DISK_BUDGET_GIB.

Prune modes are dry-runs unless --apply is also supplied. Applying refuses any
build root that a running Cargo/rustc process or a live executable is using,
and fails closed when process liveness cannot be determined.
USAGE
}

mode=report
apply=0
budget_gib="${KUZUSHI_BUILD_DISK_BUDGET_GIB:-$default_budget_gib}"
while [ "$#" -gt 0 ]; do
  case "$1" in
    --report) mode=report ;;
    --check-budget) mode=check-budget ;;
    --prune-aux) mode=prune-aux ;;
    --prune-incremental) mode=prune-incremental ;;
    --prune-all) mode=prune-all ;;
    --apply) apply=1 ;;
    --budget-gib)
      shift
      [ "$#" -gt 0 ] || { printf '%s\n' '--budget-gib requires a value' >&2; exit 2; }
      budget_gib=$1
      ;;
    -h|--help) usage; exit 0 ;;
    *) printf 'unknown option: %s\n' "$1" >&2; usage >&2; exit 2 ;;
  esac
  shift
done

case "$mode" in
  report|check-budget)
    if [ "$apply" -eq 1 ]; then
      printf '%s\n' '--apply requires a prune mode' >&2
      exit 2
    fi
    ;;
esac
if ! printf '%s' "$budget_gib" | grep -Eq '^[0-9]+([.][0-9]+)?$' || \
   [ "$(awk -v g="$budget_gib" 'BEGIN { print (g > 0) ? 1 : 0 }')" -ne 1 ]; then
  printf 'budget must be a positive number of GiB, got: %s\n' "$budget_gib" >&2
  exit 2
fi

repo_root=$(git rev-parse --show-toplevel 2>/dev/null) || {
  printf '%s\n' 'build-disk must run inside a Git worktree' >&2
  exit 2
}
repo_root=$(cd "$repo_root" && pwd -P)
home_root=${HOME:-}
if [ ! -d "$home_root" ]; then
  printf '%s\n' 'build-disk requires HOME to name an existing directory' >&2
  exit 2
fi
home_root=$(cd "$home_root" && pwd -P)

worktrees_file=$(mktemp "${TMPDIR:-/tmp}/kuzushi-worktrees.XXXXXX")
targets_file=$(mktemp "${TMPDIR:-/tmp}/kuzushi-targets.XXXXXX")
scratch_file=$(mktemp "${TMPDIR:-/tmp}/kuzushi-disk-scratch.XXXXXX")
prune_file=$(mktemp "${TMPDIR:-/tmp}/kuzushi-prune.XXXXXX")
process_file=$(mktemp "${TMPDIR:-/tmp}/kuzushi-processes.XXXXXX")
cleanup_temp() {
  rm -f "$worktrees_file" "$targets_file" "$scratch_file" "$prune_file" "$process_file"
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
  { du -sk "$1" 2>/dev/null || true; } \
    | awk 'NR == 1 { print $1; found = 1 } END { if (!found) print 0 }'
}

sum_dir_list_kib() {
  local total=0 entry entry_kib
  while IFS= read -r entry; do
    [ -n "$entry" ] || continue
    entry_kib=$(size_kib "$entry")
    total=$((total + ${entry_kib:-0}))
  done
  printf '%s\n' "$total"
}

human_kib() {
  awk -v kib="$1" 'BEGIN {
    if (kib >= 1048576) printf "%.1f GiB", kib / 1048576;
    else if (kib >= 1024) printf "%.1f MiB", kib / 1024;
    else printf "%d KiB", kib;
  }'
}

path_within() {
  case "$1" in
    "$2"|"$2"/*) return 0 ;;
  esac
  return 1
}

# Resolve symlinked parents (e.g. macOS /var -> /private/var) so process paths
# compare against the physically-resolved target roots.
canon_path() {
  local raw=$1 parent
  case "$raw" in
    /*/*) ;;
    *) printf '%s\n' "$raw"; return ;;
  esac
  parent=$(cd "${raw%/*}" 2>/dev/null && pwd -P) || { printf '%s\n' "$raw"; return; }
  printf '%s/%s\n' "$parent" "${raw##*/}"
}

# --- Process liveness -------------------------------------------------------
# KUZUSHI_BUILD_DISK_PROCESS_TABLE is a test hook: a file of
# "pid<TAB>cwd<TAB>exe" rows substituted for live enumeration ("?" = unknown
# cwd). Normal runs enumerate real processes and fail closed on any error.

list_processes() {
  if [ -n "${KUZUSHI_BUILD_DISK_PROCESS_TABLE:-}" ]; then
    cat "$KUZUSHI_BUILD_DISK_PROCESS_TABLE"
    return
  fi
  if [ -d /proc/self ]; then
    # Linux: /proc gives real executable paths; ps comm= is a truncated name.
    for proc_dir in /proc/[0-9]*; do
      row_pid=${proc_dir#/proc/}
      row_exe=$(readlink "$proc_dir/exe" 2>/dev/null) || row_exe=''
      if [ -z "$row_exe" ]; then
        row_exe=$(cat "$proc_dir/comm" 2>/dev/null) || row_exe='?'
      fi
      printf '%s\t%s\t%s\n' "$row_pid" "$(live_process_cwd "$row_pid" "$row_exe")" "$row_exe"
    done
    return
  fi
  # macOS: comm carries the executable path as invoked.
  ps -axo pid=,comm= \
    | sed -E 's/^[[:space:]]*([0-9]+)[[:space:]]+/\1\t/' \
    | while IFS=$'\t' read -r row_pid row_exe; do
        printf '%s\t%s\t%s\n' "$row_pid" "$(live_process_cwd "$row_pid" "$row_exe")" "$row_exe"
      done
}

is_toolchain_exe() {
  case "${1##*/}" in
    cargo|cargo-*|rustc|rustdoc) return 0 ;;
  esac
  return 1
}

live_process_cwd() {
  local pid=$1 exe=$2 cwd=''
  # Only toolchain processes need cwd attribution; skip the expensive lookup
  # (and its transient failures) for everything else.
  if ! is_toolchain_exe "$exe"; then
    printf '%s\n' '-'
    return
  fi
  if [ -d /proc ] && [ -e "/proc/$pid/cwd" ]; then
    cwd=$(readlink "/proc/$pid/cwd" 2>/dev/null) || cwd=''
  elif command -v lsof >/dev/null 2>&1; then
    cwd=$(lsof -a -p "$pid" -d cwd -Fn 2>/dev/null | sed -n 's/^n//p' | head -1) || cwd=''
  fi
  printf '%s\n' "${cwd:-?}"
}

worktree_owning_target() {
  local target=$1 worktree
  while IFS= read -r worktree; do
    [ -n "$worktree" ] || continue
    if path_within "$target" "$worktree"; then
      printf '%s\n' "$worktree"
      return 0
    fi
  done < "$worktrees_file"
  return 1
}

# Prints a refusal reason when the target root is (or may be) in use; prints
# nothing when it is provably idle. Fails closed: an unattributable Cargo/rustc
# process counts as in use.
target_in_use_reason() {
  local target=$1 owner pid cwd exe
  owner=$(worktree_owning_target "$target") || owner=''
  while IFS=$'\t' read -r pid cwd exe; do
    [ -n "$exe" ] || continue
    [ "$pid" = "$$" ] && continue
    exe=$(canon_path "$exe")
    case "$cwd" in
      /*) cwd=$(canon_path "$cwd") ;;
    esac
    if path_within "$exe" "$target"; then
      printf 'executable %s (pid %s) is running from it\n' "$exe" "$pid"
      return 0
    fi
    is_toolchain_exe "$exe" || continue
    if [ "$cwd" = '?' ] || [ -z "$cwd" ]; then
      printf '%s (pid %s) is running and its working directory is unknown\n' "$exe" "$pid"
      return 0
    fi
    if [ -n "$owner" ] && path_within "$cwd" "$owner"; then
      printf '%s (pid %s) is running inside %s\n' "$exe" "$pid" "$owner"
      return 0
    fi
    if [ -z "$owner" ]; then
      printf '%s (pid %s) is running and %s is not owned by a known worktree\n' "$exe" "$pid" "$target"
      return 0
    fi
    if path_within "$target" "$cwd"; then
      printf '%s (pid %s) is running above it\n' "$exe" "$pid"
      return 0
    fi
  done < "$process_file"
  return 1
}

owning_target_of() {
  local path=$1 target
  while IFS= read -r target; do
    [ -n "$target" ] || continue
    if path_within "$path" "$target"; then
      printf '%s\n' "$target"
      return 0
    fi
  done < "$targets_file"
  printf '%s\n' "$path"
}

refuse_active_targets() {
  local path target reason refused=0
  list_processes > "$process_file" || {
    printf '%s\n' 'refusing to prune: process enumeration failed' >&2
    exit 3
  }
  while IFS= read -r path; do
    [ -n "$path" ] || continue
    target=$(owning_target_of "$path")
    if reason=$(target_in_use_reason "$target"); then
      printf 'refusing %s: %s\n' "$path" "$reason" >&2
      refused=1
    fi
  done < "$prune_file"
  if [ "$refused" -eq 1 ]; then
    printf '%s\n' 'nothing was deleted; stop the processes above and re-run' >&2
    exit 3
  fi
}

# --- Reporting --------------------------------------------------------------

category_kib() {
  local target=$1 name=$2
  find "$target" \
    \( -name llvm-cov-target -o -name llvm-cov -o -name release \
       -o -name .ephemeral -o -name mutation -o -name mutation.old \) -prune \
    -o -type d -name "$name" -print 2>/dev/null | sum_dir_list_kib
}

print_target_categories() {
  local target=$1 target_kib=$2
  local incremental_kib deps_kib release_kib coverage_kib scratch_kib other_kib
  if [ "$(basename "$target")" = target-dev ]; then
    printf '      %9s  scratch (legacy target-dev tree)\n' "$(human_kib "$target_kib")"
    return
  fi
  incremental_kib=$(category_kib "$target" incremental)
  deps_kib=$(category_kib "$target" deps)
  release_kib=$(size_kib "$target/release")
  coverage_kib=$(( $(size_kib "$target/llvm-cov-target") + $(size_kib "$target/llvm-cov") ))
  scratch_kib=$(( $(size_kib "$target/.ephemeral") + $(size_kib "$target/mutation") + $(size_kib "$target/mutation.old") ))
  other_kib=$((target_kib - incremental_kib - deps_kib - release_kib - coverage_kib - scratch_kib))
  if [ "$other_kib" -lt 0 ]; then
    other_kib=0
    printf '      (category sizes overlap: rustc hardlinks incremental workproducts into deps)\n'
  fi
  printf '      %9s  incremental\n' "$(human_kib "$incremental_kib")"
  printf '      %9s  deps (compiled dependencies + test executables)\n' "$(human_kib "$deps_kib")"
  printf '      %9s  release artifacts\n' "$(human_kib "$release_kib")"
  printf '      %9s  coverage\n' "$(human_kib "$coverage_kib")"
  printf '      %9s  scratch (.ephemeral, mutation)\n' "$(human_kib "$scratch_kib")"
  printf '      %9s  other (fingerprints, build scripts, final binaries)\n' "$(human_kib "$other_kib")"
}

total_targets_kib() {
  local total=0 target target_kib
  while IFS= read -r target; do
    [ -n "$target" ] || continue
    target_kib=$(size_kib "$target")
    total=$((total + ${target_kib:-0}))
  done < "$targets_file"
  printf '%s\n' "$total"
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
    print_target_categories "$target" "$target_kib"
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

check_budget() {
  local total_kib budget_kib
  total_kib=$(total_targets_kib)
  budget_kib=$(awk -v g="$budget_gib" 'BEGIN { printf "%d", g * 1048576 }')
  printf 'Build roots use %s of a %s GiB budget.\n' \
    "$(human_kib "$total_kib")" "$budget_gib"
  if [ "$total_kib" -gt "$budget_kib" ]; then
    printf 'over budget: run `bash scripts/build-disk.sh --report` to see where,\n'
    printf 'then `--prune-incremental --apply` and/or `--prune-aux --apply` to reclaim.\n'
    return 1
  fi
  return 0
}

validate_prune_path() {
  local path=$1 worktree
  case "$path" in
    ''|/|"$home_root"|"$repo_root")
      printf 'refusing unsafe prune path: %s\n' "$path" >&2
      exit 2
      ;;
  esac
  if path_within "$repo_root" "$path"; then
    printf 'refusing unsafe prune path (contains the repository): %s\n' "$path" >&2
    exit 2
  fi
  while IFS= read -r worktree; do
    [ -n "$worktree" ] || continue
    if [ "$path" = "$worktree" ]; then
      printf 'refusing unsafe prune path (is a worktree root): %s\n' "$path" >&2
      exit 2
    fi
  done < "$worktrees_file"
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
  check-budget)
    check_budget
    exit $?
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

if [ "$apply" -eq 1 ]; then
  refuse_active_targets
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
