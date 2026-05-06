#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PRD="$ROOT/tasks/kuzushi-rust-tui-ux-audit.prd.json"
PROGRESS="$ROOT/progress/kuzushi-rust-tui-ux-audit.progress.md"
CURRENT_PROMPT="$ROOT/.ralph/current-kuzushi-rust-tui-ux-audit-prompt.md"

mode="${1:---once}"
if [[ "$mode" != "--once" && "$mode" != "--loop" ]]; then
  echo "usage: $0 [--once|--loop]" >&2
  exit 2
fi

if [[ ! -f "$PRD" ]]; then
  echo "missing PRD: $PRD" >&2
  exit 1
fi
if [[ ! -f "$PROGRESS" ]]; then
  echo "missing progress file: $PROGRESS" >&2
  exit 1
fi

next_story_json() {
  node --input-type=module - "$PRD" <<'NODE'
import fs from "node:fs";
const prd = JSON.parse(fs.readFileSync(process.argv[2], "utf8"));
const story = [...prd.stories]
  .filter((item) => item.passes !== true)
  .sort((a, b) => a.priority - b.priority)[0];
if (!story) process.exit(2);
process.stdout.write(JSON.stringify(story));
NODE
}

mark_story_complete() {
  local story_id="$1"
  node --input-type=module - "$PRD" "$story_id" <<'NODE'
import fs from "node:fs";
const [prdPath, storyId] = process.argv.slice(2);
const prd = JSON.parse(fs.readFileSync(prdPath, "utf8"));
const story = prd.stories.find((item) => item.id === storyId);
if (!story) throw new Error(`unknown story ${storyId}`);
story.passes = true;
fs.writeFileSync(prdPath, `${JSON.stringify(prd, null, 2)}\n`);
NODE
}

fast_checks() {
  node --input-type=module - "$PRD" <<'NODE'
import fs from "node:fs";
const prd = JSON.parse(fs.readFileSync(process.argv[2], "utf8"));
process.stdout.write((prd.fastGlobalChecks ?? []).join("\n"));
NODE
}

story_targets() {
  local story_json="$1"
  node --input-type=module - "$story_json" <<'NODE'
const story = JSON.parse(process.argv[2]);
process.stdout.write((story.targets ?? []).join("\n"));
NODE
}

run_one_story() {
  local story_json status story_id story_title story_finding story_gate
  story_json="$(next_story_json)" || {
    status=$?
    if [[ "$status" == "2" ]]; then
      echo "all Rust TUI UX audit stories are already marked complete"
      return 2
    fi
    return "$status"
  }

  story_id="$(node --input-type=module -e 'const s=JSON.parse(process.argv[1]); console.log(s.id)' "$story_json")"
  story_title="$(node --input-type=module -e 'const s=JSON.parse(process.argv[1]); console.log(s.title)' "$story_json")"
  story_finding="$(node --input-type=module -e 'const s=JSON.parse(process.argv[1]); console.log(s.finding)' "$story_json")"
  story_gate="$(node --input-type=module -e 'const s=JSON.parse(process.argv[1]); console.log(s.storyGate ?? "")' "$story_json")"

  mkdir -p "$(dirname "$CURRENT_PROMPT")"
  cat >"$CURRENT_PROMPT" <<PROMPT
# Ralph Rust TUI UX audit story

Work on ${story_id}: ${story_title} (${story_finding}).

Read first:
- docs/assessments/rust-tui-ux-audit.md
- tasks/kuzushi-rust-tui-ux-audit.prd.json
- progress/kuzushi-rust-tui-ux-audit.progress.md
- crates/kuzushi-tui/src/app.rs
- crates/kuzushi-tui/src/renderer.rs
- crates/kuzushi-tui/src/commands.rs
- crates/kuzushi-cli/tests/cutover_cli.rs

Story JSON:

\`\`\`json
${story_json}
\`\`\`

Implement one coherent slice for this story only. Preserve unrelated user or
in-flight changes. Keep the implementation on the Rust Ratatui shell path; do
not resurrect TypeScript/Ink UI behavior.

Required after implementation:
- Run the story gate: ${story_gate}
- Run the PRD fast global checks.
- Update progress/kuzushi-rust-tui-ux-audit.progress.md with files changed,
  checks run, result, remaining work, and blockers.
- Mark this story passes=true in tasks/kuzushi-rust-tui-ux-audit.prd.json only
  after gates pass.
- Commit and push with: ralph:rust-tui-ux complete ${story_id} - ${story_title}
PROMPT

  if [[ -z "${AI_CMD_BIN:-}" ]]; then
    echo "AI_CMD_BIN is not set; wrote $CURRENT_PROMPT and stopped before implementation" >&2
    return 3
  fi

  local ai_args=()
  if [[ -n "${AI_CMD_ARGS:-}" ]]; then
    read -r -a ai_args <<<"${AI_CMD_ARGS}"
  fi
  "$AI_CMD_BIN" "${ai_args[@]}" <"$CURRENT_PROMPT"

  if [[ -n "$story_gate" && "$story_gate" != "null" ]]; then
    (cd "$ROOT" && bash -lc "$story_gate")
  fi

  while IFS= read -r check; do
    [[ -z "$check" ]] && continue
    (cd "$ROOT" && bash -lc "$check")
  done < <(fast_checks)

  mark_story_complete "$story_id"

  {
    echo
    echo "### ${story_id} automation gate"
    echo
    echo "- Task attempted: ran the Rust TUI UX audit automation gate for ${story_title}."
    echo "- Files changed: see git diff for this story."
    echo "- Tests/checks run: ${story_gate}; PRD fast global checks."
    echo "- Result: gates passed and PRD story marked passes=true."
    echo "- Remaining work: next incomplete PRD story by priority."
    echo "- Blockers or repo facts that contradicted this prompt: none recorded by automation."
  } >>"$PROGRESS"

  cd "$ROOT"
  git add "$PRD" "$PROGRESS" "$CURRENT_PROMPT"
  while IFS= read -r target; do
    [[ -z "$target" ]] && continue
    if [[ -e "$ROOT/$target" ]]; then
      git add "$ROOT/$target"
    fi
  done < <(story_targets "$story_json")
  git commit -m "ralph:rust-tui-ux complete ${story_id} - ${story_title}"
  git push
}

if [[ "$mode" == "--once" ]]; then
  run_one_story
else
  while run_one_story; do
    :
  done
  status=$?
  if [[ "$status" == "2" ]]; then
    exit 0
  fi
  exit "$status"
fi
