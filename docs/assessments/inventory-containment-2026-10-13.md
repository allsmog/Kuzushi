# Repository inventory containment

Inventory source reads now use the existing repository-bound file reader.
The Git-index path previously checked only whether the final component was a
regular file. A symlinked ancestor could therefore be followed by the content
reader even though ordinary filesystem enumeration excluded directory symlinks.
Both inventory paths now pass the canonical repository root to the shared reader.
On supported Unix and Windows platforms, it authenticates path components and
the file handle before content inspection. Other platforms retain that reader's
documented canonical-path fallback.

An invalid path fails inventory preparation before publication. Existing context
and the previous shard proposal remain byte-identical. Refusal does not create
an accepted scope, a finding, a model request or a scanner job. The helper does
not follow a replacement location to make a failed inventory appear complete.
Public descriptors and existing inventory caps are unchanged.

Eleven inventory tests and six real shared-dispatch context tests pass. The
new cases use inert owned source and check ancestor refusal and retention of
both prior consumers. Existing cases cover deep directories, filesystem cycles,
entry and byte truncation, cancellation, tracked leaf symlinks, Git membership
and explicit sampling. The native J228 fixture exercises the refusal, prior
artifacts, explicit restoration and historical failure reading separately.

## Git acquisition boundary

The audit also found `Command::output()` running before the inventory's entry
loop. That path now uses the shared controlled subprocess adapter: 64 MiB stdout,
1 MiB stderr and a 30-second deadline. The calling thread polls the existing
cancellation probe while the adapter owns child cleanup. No `Send` or `Sync`
requirement is added to callers' cancellation closures. Parsing retains at most
100,001 paths, including one overflow witness for the existing entry cap.

Cancellation during acquisition returns an empty partial inventory, labeled
`interrupted`, with no content inspection or filesystem fallback. Capture-limit,
deadline and other Git failures fail preparation before publication. Missing Git,
non-repositories and empty indexes retain the existing filesystem path. A damaged
index now fails explicitly instead of silently including untracked files. These
bounds apply to path acquisition; source identity and manifest checks still have
separate IO and no whole-operation latency claim is made.

The initial native containment journey J228 recorded 14 machine checks, zero
failures and 17 captures. Spending recovery J227 recorded 30 checks, zero failures
and 20 captures. Both used native SHA
`aa9f0a5952871c0e7312ea2a7819e4bc03f492f302ee35ddd0f04e8f0ae6fc2f`.
They remain `REVIEW_REQUIRED`, with two and three human review questions
respectively. At 40x12 the retained error notice competes with the receipt body;
paging works, but this is not evidence of polished narrow-screen parity.

The fixture does not establish live model usefulness, arbitrary repository
coverage, every platform's filesystem guarantees or full TUI acceptance.

## Acquisition verification

The follow-up has 47 passing focused tests: nine acquisition adapter tests,
13 inventory-boundary tests, three context receipt tests, 12 shared subprocess
tests, seven actual prepared-dispatch tests and three TUI receipt tests. Combined
with the halt-input work, there are 237 distinct passing focused tests. The final
workspace build and all ten quick-plan commands pass. The CRAP-risk proxy covers
482 changed code files. Package commands were invoked directly without disabling
the pinned package-manager signature check.

J229 records 14 machine passes, zero failures and 17 live capture sets at six
sizes, including no-color restart. Native SHA:
`e67ddd5af6734bc13d5f8cbfe55bbc37963bed4bcd35f761756d8d89e1c99c15`.
Captures are at
`/tmp/kuzushi-tui-integration-20261012/git-acquisition-tui/20261013-044842/J229`.
The owned fixture changes only its Git index to provoke a read failure. It
asserts both prior artifacts remain unchanged before recovery, then asserts an
explicit second context result and unchanged historical failure receipts after
recovery and restart. Source bytes remain unchanged. No model calls, findings or
discovery jobs are created. Cancellation, deadlines and output limits are covered
by adapter tests; this native journey exercises a real Git failure and recovery.

J229 remains `REVIEW_REQUIRED`, with two human judgments pending. Dismissing the
notice restores more body space at 40x12, but diagnostic metadata and repeated
plan descriptions still precede the failure cause in Replay. That information
hierarchy is a concrete remaining TUI improvement. The assistant capture review,
test names and verification summary are in the sibling `halt-input-audit` folder.
