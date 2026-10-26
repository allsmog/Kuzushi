# An unloadable `scope.toml` read as no scope at all, October 25, 2026

`load_program_scope` is deliberately strict: a `.kuzushi/scope.toml` that is
malformed, oversized, unreadable or a symlink out of the workspace surfaces as
`Err`, and its own doc comment says callers "must refuse to run rather than
silently ignore a malformed scope". The scope-gated dispatchers honor that —
recon dispatch, the HAR/Burp importers, the recon importers and the suppression
sweep all propagate the error with `?`. The interactive shell did not. It
collapsed every failure into `set_program_scope(None)`, and the footer chip
renders nothing for `None`, so a broken authorization boundary looked exactly
like an absent one.

## What was observed

`refresh_program_scope` in
`app/session/handle_context_command/navigation_target_story.rs` had three ways
to reach `None` and no way to distinguish them:

```rust
let Some(target) = self.target_path_buf() else {
    self.domain_mut().set_program_scope(None);   // no target
    return;
};
let workspace = match kuzushi_core::WorkspaceTarget::new(target) {
    Ok(workspace) => workspace,
    Err(_) => {
        self.domain_mut().set_program_scope(None); // unresolved target, no log
        return;
    }
};
match kuzushi_core::load_program_scope(&workspace) {
    Ok(scope) => self.domain_mut().set_program_scope(scope),
    Err(error) => {
        self.domain_mut().set_program_scope(None); // unloadable file
        self.log("error", format!("scope.toml load failed: {error}"));
    }
}
```

`scope_footer_segment` in `ui_view_models/status_footer.rs` then read that one
`Option` and returned `None` for an unloadable file, an empty file and an absent
file alike. Three consequences:

- The footer — the only always-visible signifier of the bug-bounty boundary, and
  the one PR #64 documents as showing `scope: on` "when the file is loaded" —
  presented a broken allow/deny list as "no scope configured". The one
  transcript line scrolls out of the two-row strip.
- The footer therefore disagreed with dispatch, which refuses the same target
  with `Could not parse .../scope.toml`.
- `refresh_program_scope`'s doc comment already claimed "operators see
  `scope: load failed`". No code produced that string.
- The `WorkspaceTarget::new` failure was swallowed with no transcript line at
  all.

This is the silent fallback `AGENTS.md` rules out for approval gates, on the one
state a bug-bounty operator is accountable for.

## What changed

`DomainCache` stores a three-state `ProgramScopeState` —
`Unconfigured` / `Loaded(ProgramScope)` / `Unavailable` — instead of
`Option<ProgramScope>`. The reason stays in the transcript; the state carries
only which of the three holds, so no error text reaches the frame.

`refresh_program_scope` delegates to `resolve_program_scope_state`, which maps
each outcome to one state and logs both failure causes. `Ok(None)` (no file) and
`Ok(Some(_))` are now distinct from `Err`, and an unresolvable target reports
`Unavailable` with a `scope.toml target unresolved` line rather than nothing:
if Kuzushi cannot establish the boundary, it says so.

`scope_footer_segment` returns `scope: load failed` for `Unavailable`, keeps
`scope: on` for a non-empty loaded scope, and stays chipless for an absent or
empty one — an empty scope's lists are a documented no-op. Both footer surfaces
(`optional_idle_chips` and the investigation footer's `operational_segments`)
share that one function, so neither is left behind. The status footer is frame
chrome and plain output does not render it; headless callers already see the
dispatchers' refusal, which is what this change brings the footer into line
with.

`DomainCache::program_scope` still returns the loaded list and is still the
accessor for the list itself; only the projection reads the state. No stored
artifact, export, dispatch decision or scope verdict changes, and no rendered
line changes for a scope that loads.

## Verification

| Verification | Result |
| --- | --- |
| `cargo test -p kuzushi-tui --lib --locked program_scope` | 5 passed / 0 failed |
| `cargo test -p kuzushi-tui --lib --locked status_footer` | 31 passed / 0 failed |
| `cargo test -p kuzushi-tui --lib --locked scope` | 226 passed / 0 failed |
| `cargo test -p kuzushi-tui --lib --locked --no-fail-fast` | 5022 passed / 0 failed / 8 ignored |
| `cargo clippy -p kuzushi-tui --all-targets --locked -- -D warnings` | Exit 0 |
| `pnpm verify:quick:summary` | ten steps, `ok: true` |
| `cargo fmt --all -- --check`, `git diff --check` | Clean |

Four retained regressions cover the change: an unloadable `scope.toml` is
`Unavailable` and logs its parse reason, a target that no longer resolves is
`Unavailable` and logs that, a parsed file loads while an absent one stays
`Unconfigured`, and the footer separates `scope: load failed` from both the
absent and the empty case.

## The red-suite picture on this head

Three assessments recorded nine host-independent Rust failures
([October 22](prove-fix-allowance-2026-10-22.md),
[October 23](stale-shell-expectations-2026-10-23.md),
[October 24](pane-panic-sites-2026-10-24.md)). None of the nine reproduces on
`b8a76ac6`:

| Suite | Result on `b8a76ac6` |
| --- | --- |
| `cargo test -p kuzushi-tui --lib --locked --no-fail-fast` | 5018 passed / 0 failed / 8 ignored |
| `cargo test -p kuzushi-core --lib --locked --no-fail-fast` | 7184 passed / 5 failed / 14 ignored |

The five remaining core failures are this host's missing dependencies, as the
October 22 assessment classifies them: three patch-validation tests need an
isolating `bwrap` sandbox (absent here) and two KWP worker tests need Node 25 or
newer for `--allow-net` (this host runs Node 22.22.0). The allowance failures
that assessment attributes to the `verify:finding` / `patch:finding` gap, and
`systems_hunt_descriptor_prompt_defaults_are_real_prompts`, pass here;
`b8a76ac6` ("restore allowance-backed release qualification") touched exactly
those fixtures. `target_command_resumes_onboarding_after_deferred_picker`, which
the October 24 assessment recorded as an order-dependent failure to diagnose
separately, passed in the full parallel suite on this head. Those three
documents now overstate the red, and the owner's allowance decision is no longer
blocking a green `rust-tests` job.

## Limits

No `cargo deny`, coverage, mutation, e2e, Windows or macOS result is claimed:
this host runs none of them, `cargo-deny` is not installed here, and no hosted
CI run has produced a usable result since October 8. The only `main` run since
then — the Release Candidate dispatch on `b8a76ac6`, run 40159650830 — failed
three seconds into its `candidate-identity` job and its log is no longer
retrievable, which matches the account-level billing/spending restriction PR
#344 and the October 24 commits record rather than anything in this tree.
Nothing here changes the scope verdicts
themselves, the dispatchers' refusals, or `scope.toml` parsing; it changes only
how the shell projects a boundary it could not establish.
