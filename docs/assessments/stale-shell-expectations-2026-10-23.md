# Two stale shell expectations in the red Rust suites, October 23, 2026

`prove-fix-allowance-2026-10-22.md` recorded nine host-independent failures in
`cargo test --workspace --locked`, which is what `ci.yml`'s `rust-tests` job
runs, so no head can carry a CI receipt today. Six of the nine wait on the
owner's allowance-accounting decision and one asks whether a prompt or a
prompt-length heuristic is wrong. The remaining two are stale expectations about
shell behavior that has since changed on purpose. This records their
reproduction and what the expectations now assert.

## What was observed

On `b891f86c`, `cargo test -p kuzushi-tui --lib --locked --no-fail-fast` for the
two names:

| Test | Observed | Expected by the test |
| --- | --- | --- |
| `line_scene_pages_own_the_scroll_keys_while_the_prompt_is_empty` | `j` leaves `default_scroll` at 0 | 1 |
| `selecting_model_proof_materializes_non_runtime_reality_without_opening_fix` | `journey_phase` is `Some(Map)` | `None` |

## Why each expectation was stale

**Scroll keys.** A line page's scroll is clamped to the rows it really draws:
`gallery_line_offset` normalizes through `LinePageRows`, and
`window_capacity` returns `None` when the drawn rows fit the canvas, so every
scroll of a page that fits resolves to 0. The test opened `VizPage::AttackPath`
with no taint flow at the default 160x40 viewport, where the page draws only its
guidance lines — fewer rows than the canvas has. `j` was therefore correctly
clamped to 0, and the old assertion described the unclamped offset that
preceded the row model. The clamp is the behavior worth keeping: an operator
cannot scroll past the end of a short page.

The fixture now gives the page a two-stage flow to draw and an 80x14 canvas
shorter than those rows, so `j`, `G` and `g` move real distances again and the
test still proves what its name claims — the keys reach the page instead of the
composer.

**Journey phase.** `journey_reality_projection` derives a destination for any
app with a target, and the proof fixture accepts no Map, so the guided journey
rests at `Map`. `journey_phase` reports `None` only when the destination is
`Report`, which is what this fixture used to derive. Resting at `Map` with no
Map artifacts is the correct derivation under
`WorkflowPhase::INVESTIGATION_ORDER`; offering `Report` there was not. The
invariant the test protects is unchanged and now stated directly: selecting a
model proof records Prove reality without moving the journey, before and after a
restart.

## What is still open

Seven of the nine remain, all as `prove-fix-allowance-2026-10-22.md` describes
them: six behind the `verify:finding` / `patch:finding` allowance decision and
`systems_hunt_descriptor_prompt_defaults_are_real_prompts`, where
`invariant_draft_system_prompt` is a deliberately compact 1120-byte single line
and the contract wants 1200 bytes and a newline. Padding a live prompt to pass a
length proxy, and relaxing the proxy, are both owner calls; neither is made
here.

## Verification and limits

| Verification | Result |
| --- | --- |
| `cargo test -p kuzushi-tui --lib --locked --no-fail-fast` | 4906 passed / 4 failed / 8 ignored; both names pass |
| the same, filtered to `state_transitions::key_dispatch` | 78 passed / 0 failed |
| the same, filtered to `scene` | 159 passed / 0 failed |
| `cargo clippy -p kuzushi-tui --all-targets --locked -- -D warnings` | Exit 0 |
| `pnpm verify:quick:summary` | All ten steps status 0 |
| `cargo fmt --all --check`, `git diff --check` | Clean |

The four that remain are the bridge and allowance failures the October 22
assessment already names: `run_command_dispatches_verify_through_langgraph_runtime_bridge`,
`run_command_dispatches_patch_through_langgraph_runtime_bridge_and_persists`,
`missing_model_catalog_cannot_borrow_the_final_hunt_allowance`, and
`run_command_dispatches_legacy_taint_iris_next_hunt_through_langgraph_runtime_bridge_and_persists`.

No production file changes, so no CLI, TUI, artifact or dispatch behavior
changes. No `cargo deny`, clippy-on-workspace, coverage, mutation, e2e, Windows
or macOS result is claimed.
