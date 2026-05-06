#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PRD="$ROOT/tasks/kuzushi-whitebox-static.prd.json"
PROGRESS="$ROOT/progress/kuzushi-whitebox-static.progress.md"
CURRENT_PROMPT="$ROOT/.ralph/current-kuzushi-whitebox-static-prompt.md"

if [[ ! -f "$PRD" ]]; then
  echo "missing PRD: $PRD" >&2
  exit 1
fi
if [[ ! -f "$PROGRESS" ]]; then
  echo "missing progress file: $PROGRESS" >&2
  exit 1
fi

story_json="$(
  node --input-type=module - "$PRD" <<'NODE'
import fs from "node:fs";
const prd = JSON.parse(fs.readFileSync(process.argv[2], "utf8"));
const story = [...prd.stories]
  .filter((item) => item.passes !== true)
  .sort((a, b) => a.priority - b.priority)[0];
if (!story) process.exit(2);
process.stdout.write(JSON.stringify(story));
NODE
)" || {
  status=$?
  if [[ "$status" == "2" ]]; then
    echo "all whitebox-static stories are already marked complete"
    exit 0
  fi
  exit "$status"
}

story_id="$(node --input-type=module -e 'const s=JSON.parse(process.argv[1]); console.log(s.id)' "$story_json")"
story_title="$(node --input-type=module -e 'const s=JSON.parse(process.argv[1]); console.log(s.title)' "$story_json")"
story_gate="$(node --input-type=module -e 'const s=JSON.parse(process.argv[1]); console.log(s.storyGate)' "$story_json")"

mkdir -p "$(dirname "$CURRENT_PROMPT")"
cat >"$CURRENT_PROMPT" <<PROMPT
# Ralph whitebox-static story

Work on ${story_id}: ${story_title}.

Read:
- tasks/kuzushi-whitebox-static.prd.json
- progress/kuzushi-whitebox-static.progress.md

Implement one coherent slice, run the story gate, update progress, commit, and push.
Do not add shell execution, network calls, PoC generation, fabricated citations,
uncited claims, or runtime exploitability claims.
PROMPT

if [[ -n "${AI_CMD_BIN:-}" ]]; then
  read -r -a ai_args <<<"${AI_CMD_ARGS:-}"
  "$AI_CMD_BIN" "${ai_args[@]}" <"$CURRENT_PROMPT"
else
  echo "AI_CMD_BIN is not set; wrote $CURRENT_PROMPT and will only run gates" >&2
fi

if [[ -n "$story_gate" && "$story_gate" != "null" ]]; then
  (cd "$ROOT" && bash -lc "$story_gate")
fi

fast_checks="$(
  node --input-type=module - "$PRD" <<'NODE'
import fs from "node:fs";
const prd = JSON.parse(fs.readFileSync(process.argv[2], "utf8"));
process.stdout.write((prd.fastGlobalChecks ?? []).join("\n"));
NODE
)"
while IFS= read -r check; do
  [[ -z "$check" ]] && continue
  (cd "$ROOT" && bash -lc "$check")
done <<<"$fast_checks"

if node --input-type=module - "$ROOT/package.json" <<'NODE'
import fs from "node:fs";
const pkg = JSON.parse(fs.readFileSync(process.argv[2], "utf8"));
process.exit(pkg.scripts?.["eval:kuzushi-whitebox-static"] ? 0 : 1);
NODE
then
  (cd "$ROOT" && pnpm eval:kuzushi-whitebox-static)
fi

node --input-type=module - "$PRD" "$story_id" <<'NODE'
import fs from "node:fs";
const [prdPath, storyId] = process.argv.slice(2);
const prd = JSON.parse(fs.readFileSync(prdPath, "utf8"));
const story = prd.stories.find((item) => item.id === storyId);
if (!story) throw new Error(`unknown story ${storyId}`);
story.passes = true;
fs.writeFileSync(prdPath, `${JSON.stringify(prd, null, 2)}\n`);
NODE

{
  echo
  echo "### ${story_id} automation gate"
  echo
  echo "- Task attempted: ran the whitebox-static automation gate for ${story_title}."
  echo "- Files changed: see git diff for this story."
  echo "- Tests/checks run: ${story_gate}; fast global checks; pnpm eval:kuzushi-whitebox-static when present."
  echo "- Result: gates passed and PRD story marked passes=true."
  echo "- Remaining work: next incomplete PRD story by priority."
  echo "- Blockers or repo facts that contradicted this prompt: none recorded by automation."
} >>"$PROGRESS"

cd "$ROOT"
git add "$PRD" "$PROGRESS" "$CURRENT_PROMPT" .
git commit -m "ralph:whitebox-static complete ${story_id} - ${story_title}"
git push
