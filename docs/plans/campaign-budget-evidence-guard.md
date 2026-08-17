# Campaign live-budget evidence guard

Implementation contract for #179.

## Problem

A budgeted campaign child is currently authorized to continue from a scalar
`LiveSpendPoller::poll()` result. Missing/unreadable lifecycle data, complete
malformed records, and stream truncation all collapse to the last known spend
(often `$0`). That turns unavailable accounting evidence into authorization to
continue spending.

## Required invariant

A newline-less torn append is temporary and may be deferred. Every complete
record must be valid, target the expected run, preserve contiguous sequence and
hash-chain state, and pass envelope hash verification. Once the canonical
stream has been observed, persistent I/O failure, truncation/replacement, or a
complete invalid record is not `$0`; it is `budget-evidence-unavailable` and
must stop/reap the child, park without retry, retain observed spend as a lower
bound, and mark provider spend unresolved.

Before first observation, a bounded startup grace is allowed because the child
may not yet have created `items.jsonl`. A short bounded streak is also allowed
for transient open/seek/read failures. Both thresholds must be tested through a
pure state machine without sleeping.

## Scope

Production changes belong only in the existing campaign runner files:

- `crates/kuzushi-cli/src/application/campaign_run/budget.rs`
- `crates/kuzushi-cli/src/application/campaign_run/child.rs`
- `crates/kuzushi-cli/src/application/campaign_run/policy.rs`
- the minimal settlement/accounting changes in
  `crates/kuzushi-cli/src/application/campaign_run/mod.rs`

Do not edit findings, release, TUI, provider pricing, or other open-PR branches.

## Acceptance

- typed `Available`, `Pending`, and `Unavailable` poll states;
- byte-oriented complete-prefix parsing so incomplete UTF-8 in a torn final
  line remains deferred;
- strict run-id, sequence, previous-hash, and envelope-hash validation;
- truncation detection without resetting/double-counting;
- bounded startup and transient-I/O tolerances;
- distinct non-retryable `BudgetEvidenceUnavailable` outcome;
- last observed spend carried into settlement as a lower bound;
- process-group kill/reap remains mandatory;
- existing over-budget, under-cap, unbudgeted, torn-tail, and incremental
  performance behavior remains covered.

Exact-head validation:

```bash
cargo fmt --all -- --check
cargo test -p kuzushi-cli application::campaign_run --locked
cargo clippy -p kuzushi-cli --all-targets --locked -- -D warnings
node scripts/crap-risk-gate.mjs
```
