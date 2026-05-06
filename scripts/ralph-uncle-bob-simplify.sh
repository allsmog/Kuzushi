#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PRD="${RALPH_PRD:-$ROOT/tasks/kuzushi-uncle-bob-simplify.prd.json}"
PROGRESS="${RALPH_PROGRESS:-$ROOT/progress/kuzushi-uncle-bob-simplify.progress.md}"
CURRENT_PROMPT="${RALPH_CURRENT_PROMPT:-$ROOT/.ralph/current-kuzushi-uncle-bob-simplify-prompt.md}"

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

json_field() {
  local story_json="$1"
  local field="$2"
  node --input-type=module -e 'const story=JSON.parse(process.argv[1]); const value=story[process.argv[2]]; if (Array.isArray(value)) console.log(value.join("\n")); else if (value === undefined || value === null) console.log(""); else console.log(String(value));' "$story_json" "$field"
}

fast_checks() {
  node --input-type=module - "$PRD" <<'NODE'
import fs from "node:fs";

const prd = JSON.parse(fs.readFileSync(process.argv[2], "utf8"));
process.stdout.write((prd.fastGlobalChecks ?? []).join("\n"));
NODE
}

ensure_clean_worktree() {
  local dirty
  dirty="$(cd "$ROOT" && git status --porcelain --untracked-files=all)"
  if [[ -n "$dirty" ]]; then
    echo "working tree must be clean before starting a Ralph simplification story" >&2
    echo "$dirty" >&2
    return 1
  fi
}

validate_changed_paths() {
  local story_json="$1"
  node --input-type=module - "$ROOT" "$PRD" "$PROGRESS" "$story_json" <<'NODE'
import { execFileSync } from "node:child_process";
import path from "node:path";

const [root, prdPath, progressPath, storyJson] = process.argv.slice(2);
const story = JSON.parse(storyJson);
const output = execFileSync(
  "git",
  ["-C", root, "status", "--porcelain=v1", "-z", "--untracked-files=all"],
  { encoding: "utf8" },
);

const entries = output.split("\0").filter(Boolean);
const changed = [];
for (let index = 0; index < entries.length; index += 1) {
  const entry = entries[index];
  const status = entry.slice(0, 2);
  let filePath = entry.slice(3);
  if (status.includes("R") || status.includes("C")) {
    const renamedPath = entries[index + 1];
    if (renamedPath) {
      filePath = renamedPath;
      index += 1;
    }
  }
  changed.push(filePath);
}

const exact = new Set([
  ...((story.targets ?? []).map(String)),
  path.relative(root, prdPath),
  path.relative(root, progressPath),
]);
const prefixes = [
  ...((story.targets ?? []).map(String)),
  ...((story.allowedNewFileDirs ?? []).map(String)),
].filter((value) => value.length > 0);

const allowed = (filePath) => {
  if (exact.has(filePath)) return true;
  return prefixes.some((prefix) => filePath.startsWith(`${prefix}/`));
};

const disallowed = changed.filter((filePath) => !allowed(filePath));
if (disallowed.length > 0) {
  console.error("Ralph story changed paths outside its allowed target set:");
  for (const filePath of disallowed) console.error(`- ${filePath}`);
  console.error("Allowed targets:");
  for (const filePath of exact) console.error(`- ${filePath}`);
  for (const prefix of story.allowedNewFileDirs ?? []) console.error(`- ${prefix}/`);
  process.exit(1);
}
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

stage_story_changes() {
  local story_json="$1"
  git -C "$ROOT" add "$PRD" "$PROGRESS"
  node --input-type=module - "$story_json" <<'NODE' | while IFS= read -r target; do
const story = JSON.parse(process.argv[2]);
const paths = [...(story.targets ?? []), ...(story.allowedNewFileDirs ?? [])];
process.stdout.write(paths.map(String).join("\n"));
NODE
    [[ -z "$target" ]] && continue
    if [[ -e "$ROOT/$target" ]]; then
      git -C "$ROOT" add -- "$target"
    fi
  done
}

append_progress() {
  local story_id="$1"
  local story_title="$2"
  local story_gate="$3"
  {
    echo
    echo "### ${story_id} automation gate"
    echo
    echo "- Task attempted: ran the Uncle Bob simplification loop for ${story_title}."
    echo "- Files changed: see git diff for this story commit."
    echo "- Tests/checks run: ${story_gate}; PRD fast global checks."
    echo "- Result: gates passed and PRD story marked passes=true."
    echo "- Remaining work: next incomplete PRD story by priority."
    echo "- Blockers or repo facts that contradicted this prompt: none recorded by automation."
  } >>"$PROGRESS"
}

write_prompt() {
  local story_json="$1"
  local story_id="$2"
  local story_title="$3"
  local story_gate="$4"

  mkdir -p "$(dirname "$CURRENT_PROMPT")"
  cat >"$CURRENT_PROMPT" <<PROMPT
# Ralph Uncle Bob simplification story

Work on ${story_id}: ${story_title}.

Read first:
- docs/assessments/codebase-simplification-hotspots.md
- tasks/kuzushi-uncle-bob-simplify.prd.json
- progress/kuzushi-uncle-bob-simplify.progress.md
- AGENTS.md or CLAUDE.md instructions if present in this checkout

Story JSON:

\`\`\`json
${story_json}
\`\`\`

Implement exactly one coherent refactor slice for this story.

Hard rules:
- Start by inspecting git status and the target files.
- Preserve unrelated user or in-flight changes.
- Keep behavior, CLI output, persisted .kuzushi formats, scan/shell/run parity,
  module contracts, and model/runtime enforcement unchanged.
- Do not resurrect TypeScript/Ink UI code.
- Prefer extraction, naming, smaller functions, clearer boundaries, and deletion
  of dead duplication.
- Do not make broad style-only churn.
- Keep comments only when they explain non-obvious why.
- Do not edit PRD/progress files; this harness updates them after gates pass.
- Do not commit or push; this harness commits and pushes after validation.

Required before returning:
- Run the story gate: ${story_gate}
- Run any focused tests needed for files you touched.
- Leave only story-allowed files changed.
PROMPT
}

run_one_story() {
  local story_json status story_id story_title story_gate commit_message requires_ai_changes
  ensure_clean_worktree

  story_json="$(next_story_json)" || {
    status=$?
    if [[ "$status" == "2" ]]; then
      echo "all Uncle Bob simplification stories are already marked complete"
      return 2
    fi
    return "$status"
  }

  story_id="$(json_field "$story_json" id)"
  story_title="$(json_field "$story_json" title)"
  story_gate="$(json_field "$story_json" storyGate)"
  commit_message="$(json_field "$story_json" commitMessage)"
  requires_ai_changes="$(json_field "$story_json" requiresAiChanges)"
  if [[ -z "$commit_message" ]]; then
    commit_message="refactor: simplify ${story_title}"
  fi

  write_prompt "$story_json" "$story_id" "$story_title" "$story_gate"

  if [[ -z "${AI_CMD_BIN:-}" ]]; then
    echo "AI_CMD_BIN is not set; wrote $CURRENT_PROMPT and stopped before implementation" >&2
    return 3
  fi

  local ai_args=()
  if [[ -n "${AI_CMD_ARGS:-}" ]]; then
    read -r -a ai_args <<<"${AI_CMD_ARGS}"
  fi
  "$AI_CMD_BIN" "${ai_args[@]}" <"$CURRENT_PROMPT"

  if [[ "$requires_ai_changes" != "false" && -z "$(cd "$ROOT" && git status --porcelain --untracked-files=all)" ]]; then
    echo "AI command completed without changing any tracked or untracked story files" >&2
    return 4
  fi
  if [[ -n "$(cd "$ROOT" && git status --porcelain --untracked-files=all)" ]]; then
    validate_changed_paths "$story_json"
  fi

  if [[ -n "$story_gate" && "$story_gate" != "null" ]]; then
    (cd "$ROOT" && bash -lc "$story_gate")
  fi

  while IFS= read -r check; do
    [[ -z "$check" ]] && continue
    (cd "$ROOT" && bash -lc "$check")
  done < <(fast_checks)

  mark_story_complete "$story_id"
  append_progress "$story_id" "$story_title" "$story_gate"
  validate_changed_paths "$story_json"
  stage_story_changes "$story_json"

  if git -C "$ROOT" diff --cached --quiet; then
    echo "no staged changes after story validation" >&2
    return 5
  fi
  git -C "$ROOT" commit -m "$commit_message"
  git -C "$ROOT" push
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
