# Inventory input and completion timing

The native shell remains usable during a controlled Git inventory wait on an
owned fixture with 16,000 inert files. Typing, resize, cancellation, explicit
rebuild and receipt recovery are observed separately. This is local evidence
for the Logs composer during runtime-free context preparation; broader product
acceptance remains open.

## Corrected task identity

The first settled completion capture exposed a misleading `finished in 0s`
notice beside a receipt that recorded several seconds. An ad hoc launch left
its lifecycle task under a generated identity. Completion created another row
under the tool name, with start and finish both assigned at completion.

Background launch now binds the lifecycle task and tool to the same activity
row. A unique existing planned row remains usable; ambiguous rows remain
separate, and an explicitly selected planning task retains its exact identity.
Completion timing resolves that binding before reading the task interval.
Missing activity still produces no duration, and a known subsecond interval
can still render as zero seconds. The correction changes shell presentation
identity without changing dispatch, scheduling, artifact formats or model policy.

## Observed input

J232 uses `context:build` with enrichment disabled and a fixed sample of 200
files. Its owned Git proxy delegates to the real Git executable and holds only
`ls-files` while explicitly armed. Each probe confirms both a live Git child
and a running context receipt before sending input, then verifies the child
remains live after observing the echo. The fixture reads only its own tmux pane.

Timing uses a monotonic clock immediately before `send-keys` and after the pane
capture returns. It includes tmux IPC and capture overhead. Six single samples
meet the fixture's 300 ms bound:

| Terminal | Observed echo |
| --- | ---: |
| 120x36 | 26.90 ms |
| 160x48 | 24.49 ms |
| 96x89 | 26.35 ms |
| 80x24 | 7.81 ms |
| 60x20 | 7.14 ms |
| 40x12 | 7.57 ms |

These are local send-to-observed-echo samples, not a percentile, worst-case
bound, physical keyboard/display measurement or reference-product comparison.
The controlled Git wait does not establish responsiveness under sustained CPU
pressure, giant-repository throughput or every interactive view.

Cancellation stops the held child, keeps the typed draft and leaves the prior
context snapshot byte-identical. The explicit rebuild uses another controlled
wait, then reaches the idle Logs prompt with `rebuild-draft` intact. Its task
notice records six seconds and its separate run receipt records seven seconds.
No-color restart retains the canceled receipt and completed rebuild without
repeating work. Source hashes remain unchanged across all three context runs.

## Verification and retained limits

Sixty-six distinct focused Rust tests pass across background launch, completion
events and activity projection, including eight new binding/timing tests. The
locked workspace build passes. The DevEx harness and required-snapshot contracts
pass. The first harness attempt could not create its isolated tmux socket in the
sandbox; the permitted isolated-socket run passes. The full Rust suite was not
run for this increment.

All ten exact quick-plan commands pass, including 391 Node tests, workspace
checking and the CRAP-risk proxy over 499 changed code files. The initial
module-declaration ordering failure remains retained; only formatting was rerun
after its local correction. The other nine passing commands were preserved.
Package commands ran directly because of the known pinned package-manager
signature issue, without disabling verification.

Final J232 records 12 machine passes, zero failures and 14 live text/ANSI capture
pairs with matching dimensions and native identity. Its raw result remains
`REVIEW_REQUIRED`, with three human judgments pending and operator approval
false. Assistant judgments are separate. At 40x12 the abort hint and draft fit,
but repeated metadata and a prior notice consume scarce log rows. Tall screens
retain unused space, and Replay remains a dense diagnostic reader. This does
not close reference UX parity.

Earlier evidence remains retained: the initial fixture's read-only SQLite
connection failed; query-only read/write access corrected the
check. A later capture preceded UI completion despite a persisted terminal
receipt. The final journey requires the idle prompt before accepting that
capture. The legacy echo directive timestamps before reading the pane, so its
initial timing numbers are excluded. The pre-fix settled run retains the
incorrect zero-second notice.

Native SHA-256:
`7da785ee95c4ab204ff77ed8bba513859b3a4bdb7dcc670e2c24c640289fd7ec`.
Final captures:
`/tmp/kuzushi-tui-integration-20261012/inventory-input-final-tui/20261013-065711/J232`.
Focused test names, build, fixture checks and assistant review:
`/tmp/kuzushi-tui-integration-20261012/inventory-input-audit`.

The fixture has a staged index without a commit. Generic target revision fields
are unavailable; its own source hashes establish unchanged bytes. Complete
enumeration of this fixture and its 200-file sample do not establish complete
context or scan coverage. There are no provider requests, investigation
reservations, findings, discovery attempts or target source execution. The live
allowance stays exhausted at six of six. No module promotion, retirement or
broader delivery milestone completion follows this test.
