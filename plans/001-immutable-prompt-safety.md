# Plan 001: Keep repository prompt customization below immutable safety policy

> Executor: implement this plan in the existing dirty tree. Preserve unrelated
> changes. Do not commit or push. If the descriptor or prompt-boundary APIs no
> longer match the current-state symbols below, stop and report the drift.

## Status

- **Priority**: P1
- **Effort**: M
- **Risk**: MED
- **Category**: security
- **Planned at**: commit `775a4134f2cb`, 2026-07-12

## Why this matters

Kuzushi treats a scanned target as adversarial, yet dispatch auto-loads
`<target>/.kuzushi/prompts/**` and some agentic tools use that text as the
entire system prompt. A checked-out repository can therefore erase the static,
no-network/no-write, untrusted-content safety spine without an operator trust
decision.

## Current state and contract

- `crates/kuzushi-core/src/modules/builtins/with_v2_builtins/execution.rs`:
  `apply_declared_prompt_file_default` hydrates descriptor prompt defaults from
  the active target.
- `crates/kuzushi-core/src/options/prompt_paths.rs`: prompt paths live below the
  target's `.kuzushi/prompts` directory.
- `crates/kuzushi-core/src/capabilities/agentic_sast/application/run_agentic_sast_report.rs`:
  `agentic_sast_prompt_from_input` currently replaces the builtin system prompt;
  its test explicitly asserts replacement.
- `crates/kuzushi-core/src/prompts/{spine,boundaries}.rs` contain the canonical
  safety vocabulary and untrusted-derived-data renderer.
- `docs/agentic-prompt-hardening-design.md` states that repository content is
  untrusted. Preserve scan/shell/run dispatch parity and no-silent-fallback.

## Scope

In scope: prompt hydration/composition, descriptor prompt metadata if needed,
workspace stored-option validation, SAST triage/verify forwarding, focused
tests, and prompt-control documentation. Out of scope: model selection,
provider routing, or changing the public tool names.

## Steps

1. Distinguish target-derived prompt text from explicit operator-supplied inline
   text at the canonical preparation boundary. Target-derived text must be data,
   never replacement authority. Reject descriptor prompt keys in target-local
   stored options, while retaining session/global and explicit-call behavior.
2. Compose every auto-loaded target prompt under the tool's builtin safety and
   output-contract instructions, using the shared untrusted-content boundary.
   Apply the same rule to the SAST umbrella's triage and verify prompt files.
3. Preserve explicit one-shot operator inline replacement only when provenance
   is explicit in the prepared input; do not infer trust from a path inside the
   target. Keep prompt customization useful as focus/context text.
4. Add tests proving a malicious target prompt cannot remove the safety spine,
   target-local option stores cannot inject prompt replacements, explicit inline
   operator input still follows its documented semantics, and all three modes
   prepare identical canonical input.
5. Update `docs/modules.md`, `docs/operator-control-surfaces.md`, and the prompt
   hardening design to describe the provenance split truthfully.

## Verification

```text
cargo test -p kuzushi-core prompt --offline
cargo test -p kuzushi-core modules:: --offline
pnpm quality:model-safety
pnpm quality:architecture
```

All commands must exit 0. New tests must assert the immutable spine text remains
present after target prompt hydration.

## Done criteria

- No target-owned file or workspace option can replace the safety spine.
- Explicit operator prompt behavior is tested and documented.
- Scan, shell, and run still converge on shared preparation/dispatch.
- Only in-scope files are changed beyond pre-existing dirty edits.

## STOP conditions

Stop if the safe fix requires silent model/runtime substitution, disables
project prompt customization entirely, or requires a new interactive approval
surface for headless execution that cannot be represented at preparation time.
