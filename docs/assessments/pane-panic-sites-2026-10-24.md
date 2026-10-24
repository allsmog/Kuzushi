# Four unaudited panic sites in the saved-context comparison, October 24, 2026

`boundary_lints::tests::pane_facing_code_stays_free_of_unaudited_panic_sites`
fails on `55e4fa7b`. The four sites it names all live in
`ui_view_models/study_context/comparison`, which `55e4fa7b` added, so this is a
failure neither [the October 22 allowance
assessment](prove-fix-allowance-2026-10-22.md) nor [the October 23 stale
expectations](stale-shell-expectations-2026-10-23.md) could have seen. The
October 23 run recorded `cargo test -p kuzushi-tui --lib` as 4906 passed / 4
failed, the ratchet green, on the head it merged as `f744320d`; the same suite
on `55e4fa7b` reports 4984 passed / 5 failed, and the fifth is this one.

## What was observed

```
new panic site in pane-facing code — a panic there corrupts the raw-mode
terminal; return a degraded view instead, or audit it into AUDITED_PANIC_SITES:
ui_view_models/study_context/comparison/content.rs: let claims = &context.structure.as_ref().unwrap().source_claims;
ui_view_models/study_context/comparison/content.rs: .expect("JSON values serialize")
ui_view_models/study_context/comparison.rs: .unwrap()
ui_view_models/study_context/comparison.rs: structure_entries(context.structure.as_ref().unwrap(), view)
```

The three `unwrap`s read `StudyContextComparison::differences` and `structure`,
both `Option`, behind an earlier `ready()` call that happens to prove they are
`Some`. Nothing in the types says so. `ready()` lives in
`app/batch_scan/context_comparison.rs`, three modules away from the projections
that depend on it, and it already carries a third condition — `error.is_none()`
— that neither projection needs. A comparison that stores an error beside a
partial read, or any later change that relaxes `ready()`, turns an operator's
`Tab` between comparison views into a panic inside the Ratatui draw path, which
is what the ratchet exists to prevent.

## What changed

`ComparisonEntry::Source` now carries `&ContextSourceClaims` instead of being a
bare variant. `structure_entries` already holds the `ContextDocumentDiff` it
pushes that variant from, so the claims travel with the entry and
`content::source_lines` receives them as an argument. The entry can no longer
be built without the structure it describes, so the site is gone rather than
guarded.

`entries` reads the two options through `iter().flatten()` and `map_or_else`.
With `ready()` true both are `Some` and every caller sees the same rows as
before; with either absent the view is empty and the existing `status` lines
report the pending or failed read, which is what the page already drew for a
comparison that is not ready.

`value_lines`'s `expect` is audited rather than rewritten. It serializes a
`serde_json::Value`, which can hold neither a non-finite number nor a
non-string map key, so neither error `to_string_pretty` reports is reachable
from one. `ui_view_models/scope_review/paths.rs` carries the same writer over a
`&str` and was audited on October 18 for the same reason. A `match` arm here
would add a branch no test can reach.

No stored comparison, artifact, export or dispatch behavior changes, and no
rendered line changes for a ready comparison.

## Verification

| Verification | Result |
| --- | --- |
| `cargo test -p kuzushi-tui --lib --locked boundary_lints` | 10 passed / 0 failed |
| `cargo test -p kuzushi-tui --lib --locked study_context` | 46 passed / 0 failed |
| `cargo clippy -p kuzushi-tui --all-targets --locked -- -D warnings` | Exit 0 |
| `cargo fmt --all -- --check`, `git diff --check` | Clean |

Two retained regressions cover the change: every view of a comparison with no
stored result reads as pending instead of panicking, and the source entry
carries the claims of the structure it came from.

`cargo test -p kuzushi-tui --lib --locked --no-fail-fast` on this head reports
4986 passed / 5 failed. Four are the bridge and allowance failures the October
22 assessment names. The fifth,
`target_command_resumes_onboarding_after_deferred_picker`, derived `Workbench`
where it expects `Setup`; it passes on its own under the same toolchain and
this change touches nothing on that path, so it is recorded here as an
order-dependent failure to diagnose separately, not as a result of this work.
The four host-independent `kuzushi-core` failures are unchanged. Nothing here addresses the allowance decision those
record, and no `cargo deny`, coverage, mutation, e2e, Windows or macOS result
is claimed: this host runs none of them, and no PR CI run has started a runner
since October 8.
