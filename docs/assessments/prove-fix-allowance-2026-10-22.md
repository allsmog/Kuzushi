# Prove and Fix model work cannot be allowed, October 22, 2026

Main's Rust library suites are red, and the largest cause is not test drift.
`verify:finding` — and, by the same omission, `patch:finding` — cannot reach a
provider standalone in any of the three modes. The shared allowance boundary
neither offers these tools an `allowanceRef` nor binds one, and the LangGraph
runtime refuses every unbound model request. This records the reproduction, the
root cause, and the decision the fix needs. No code changes with this document.

## What was observed

`cargo test -p kuzushi-tui --lib --locked` on `ee1e2acb` reports 4904 passed /
6 failed; `cargo test -p kuzushi-core --lib --locked --no-fail-fast` reports
7018 passed / 10 failed. Six of those sixteen are this host's missing
dependencies and would pass on CI's image: four need an isolating
patch-validation sandbox (`bwrap`, which `.github/actions/install-patch-validation-sandbox`
installs) and two need Node 25 or newer for the KWP worker's `--allow-net`
permission boundary. Nine fail on any host, and one more cannot be classified
here because `bwrap` masks it:

| Crate | Test | Cause |
| --- | --- | --- |
| tui | `run_command_dispatches_verify_through_langgraph_runtime_bridge` | Prove/Fix allowance gap, below |
| core | `exploit_chain_scan_honors_input_model_override` | `exploit-chain:scan` needs an approved allowance the fixture never approves |
| core | `sast_scan_can_continue_into_langgraph_runtime_triage` | `triage:run` "cannot borrow a parent Discovery allowance" |
| core | `sast_empirical_verification_uses_proof_tool_and_gates_patch_on_exploitability` | `sast:scan` needs an approved allowance the fixture never approves |
| tui | `missing_model_catalog_cannot_borrow_the_final_hunt_allowance` | the hunt completes where the test requires a refusal |
| tui | `run_command_dispatches_legacy_taint_iris_next_hunt_through_langgraph_runtime_bridge_and_persists` | undiagnosed |
| tui | `line_scene_pages_own_the_scroll_keys_while_the_prompt_is_empty` | asserts the pre-`LinePageRows` unclamped `default_scroll` |
| tui | `selecting_model_proof_materializes_non_runtime_reality_without_opening_fix` | its fixture's derived journey phase is now `Map`, not absent |
| core | `systems_hunt_descriptor_prompt_defaults_are_real_prompts` | `invariant_draft_system_prompt` is one 1120-byte line; the heuristic wants 1200 bytes and a newline |
| tui | `run_command_dispatches_patch_through_langgraph_runtime_bridge_and_persists` | unclassified: its bridge dispatch should hit the gap below before validation, but this host's missing `bwrap` would also fail it |

Every one of these is reachable by `cargo test --workspace --locked`, which is
what `ci.yml`'s `rust-tests` job runs, so no head can pass that job today.
`verify:quick` deliberately runs no Rust tests, so a contributor's local gate
stays green while the suite rots. Separately, no PR CI run since 2026-10-08
(run 37785083392, the last success) has started a runner: every later run's
`quality-gauntlet` job completes within a few seconds and its dependants are
skipped, and the most recent one (job 118646931638) has no uploadable log and
an empty check-run output. The cause is outside the repository and is not
diagnosed here, but it means no head has carried a CI receipt for two weeks,
which is how nine host-independent failures accumulated without anyone having
to decide about them.

## The Prove and Fix allowance gap

Reproduced on this head by dispatching `verify:finding` through the shell with
an owned local bridge, exactly as
`run_command_dispatches_verify_through_langgraph_runtime_bridge` does:

```
error: structured output failed: Investigation allowance refused this request;
finish and report or review the remaining work. (allowance_refused): Model work
requires an approved investigation allowance. Prepare and approve a finite plan
first; no provider request started.
```

That advice cannot be followed. Approving a plan and passing its reference back
is refused by the same dispatch:

```
error: verify:finding received unknown option "allowanceRef". Next: use one of:
fingerprint, mode, VERIFY_PROMPT, VERIFY_PASSES, passes, model, gateModel, ...
```

Both answers come from one omission. `phase_work`
(`crates/kuzushi-core/src/modules/allowance_dispatch.rs:33`) maps `ToolPhase`
to `InvestigationWork` for `Map`, `Scan`, `Review` and `Report` and returns
`None` for everything else, so `Prove` and `Fix` have no investigation work.
`descriptor_work` falls back to `phase_work` whenever a descriptor carries no
`allowance_category`, and no Prove or Fix tool carries one. `supports_allowance`
is therefore false for `verify:finding`
(`verify_module.rs:23`, `workspace_policy(ToolPhase::Prove, InputAware, …)`)
and for `patch:finding` (`patch_module.rs:65`,
`repository_execute_policy(ToolPhase::Fix, Always, …)`), with three consequences:

1. `declare_allowance_option` adds no `allowanceRef` option, so descriptor-backed
   option validation rejects the reference an operator would supply.
2. `bind_runtime` finds no reference, and `require_inherited_runtime_allowance`
   returns early for a tool that does not support an allowance, so the runtime
   is passed through with no `AllowanceBinding`.
3. `require_model_allowance`
   (`crates/kuzushi-openai/src/langgraph_runtime/bridge_observation.rs:73`)
   refuses every unbound model request, with no tool-specific wording to say
   that this particular refusal has no remedy.

So Prove's and Fix's model work is possible only as a child of an umbrella that
is itself bound — `sast:scan` dispatches both through
`run_sast_phase_subtool`, carrying its own runtime. Standalone dispatch fails in
all three modes: the shell's `use verify` + `run`, `kuzushi run verify:finding`,
and any planner that schedules the tool directly. Because point 2 also skips
`require_inherited_runtime_allowance`, the umbrella's children borrow its
Discovery allowance with none of the Review accounting that `triage:run` is
held to — which is the same boundary `sast_scan_can_continue_into_langgraph_runtime_triage`
fails at today, from the other side.

`patch:finding`'s standalone refusal was not reproduced separately. This host
has no `bwrap`, so its validation stage fails closed too, and
`run_command_dispatches_patch_through_langgraph_runtime_bridge_and_persists`
fails without naming which came first. The claim above rests on
`ToolPhase::Fix` reaching the same `_ => None` arm, not on an observed run.
Core's own `dispatches_patch_finding_through_runtime_and_persists_result` does
reach validation and fails on `bwrap`, but it drives a mock runtime, and
`require_model_allowance` lives only in the LangGraph runtime, so it never
exercises this gap.

## What is still open — owner decision

Both candidate fixes are one or two lines, and both change live accounting, so
neither should land without the owner deciding how `sast:scan` approves its
children's work.

1. **Map Prove and Fix onto `InvestigationWork::Review` in `phase_work`.** The
   two tools gain `allowanceRef`, get bound, and are accounted as Review work,
   which is what `protectedReviewCalls` already exists to protect. But it also
   switches on `require_inherited_runtime_allowance` for them, and that path is
   what refuses `triage:run`'s borrow of a parent Discovery allowance. Expect
   `sast:scan`'s verify and patch continuation to start failing the way its
   triage continuation already does, unless the umbrella approves Review work
   for its children in the same change.
2. **Give the two descriptors an explicit `allowance_category`.** Narrower, and
   it leaves `phase_work` honest about phases that genuinely have no
   investigation work, but it has the same effect on the umbrella path and
   leaves the next Prove or Fix model tool to rediscover this by hand.

Either way the refusal in point 3 above deserves to name its own cause: a tool
that cannot accept an allowance should not be told to approve a plan.

`InvestigationWork` has no Prove or Fix variant, and
`visible_tool_names` (`registry/dispatch_catalog_tool.rs:36`) hides both phases
from the planner's catalog, so the exclusion looks deliberate rather than
accidental. If it is, the product statement that `verify:finding` and
`patch:finding` are headless descriptor-backed tools needs revisiting too:
today they are reachable only through `sast:scan`.

## Verification and limits

| Verification | Result |
| --- | --- |
| `cargo check --workspace --all-targets --locked` | Exit 0 |
| `cargo test -p kuzushi-tui --lib --locked` | 4904 passed / 6 failed |
| `cargo test -p kuzushi-core --lib --locked --no-fail-fast` | 7018 passed / 10 failed |
| `pnpm test` | 404 passed / 0 failed, 7 skipped |
| `node scripts/verify-pack.mjs` | Exit 0 |
| `pnpm verify:quick:summary` | All ten steps status 0 |

The two refusal messages above were captured by instrumenting
`run_command_dispatches_verify_through_langgraph_runtime_bridge` to print its
log lines; the instrumentation was reverted and is not part of this change.
No `cargo deny`, clippy, coverage, mutation, e2e, Windows or macOS result is
claimed: this host runs none of them. No failing test was fixed.
