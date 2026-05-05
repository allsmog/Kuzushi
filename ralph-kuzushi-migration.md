# Archived Ralph Prompt

The Rust/pi-agent-core migration prompt has been retired because the migration
is committed and pushed.

Use the consolidated finish prompt instead. Do not pass `--tasks`; that mode
reads `.ralph/ralph-tasks.md`, which may still contain completed migration
tasks and can false-complete the loop.

```sh
ralph \
  --prompt-file ./ralph-kuzushi-finish-from-bridge.md \
  --agent codex \
  --model gpt-5.5 \
  --completion-promise KUZUSHI_FINISH_FROM_BRIDGE_COMPLETE \
  --max-iterations 80
```
