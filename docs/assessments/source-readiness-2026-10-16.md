# Source readiness before discovery

Historical checkpoint. The later [supplied-input reader](supplied-input-reader-2026-10-16.md)
separates historical inputs from the primary result and changes reading-page
navigation. Counts and visual observations below describe this earlier build.

Deep discovery now checks that the active findings ledger belongs to the
selected repository before source capture or inference. It authenticates the
original workspace snapshot and loads its bounded membership tree before the
model request. The prepared membership is reused when capturing the returned
candidates, rather than loading the tree a second time after paid work.

The existing reader limits remain: 64 KiB snapshot metadata, 64 MiB tree data
and 100000 tree members. The oversized-membership regression constructs an
authenticated 100001-entry object, without creating 100001 source files. A
separate shared-dispatch regression rejects a foreign active ledger with zero
requests and zero committed calls in either ledger. This avoids known futile
requests; it does not add support for larger repository trees.

Some capture eligibility still depends on which files the model cites. Full
cited files must be UTF-8 and fit the separate capture allowance. Post-request
capture refusal remains possible, paid and visible. Cancellation or a storage
failure during insertion can leave earlier rows recorded. The existing partial
insertion warning remains; this adds no all-or-nothing transaction.

Result guidance now follows the actual storage outcome. Withheld candidates
point to Replay, label historical candidate output and omit the inherited
instruction to review new ledger observations. A possible partial insertion
instead directs the operator to inspect earlier ledger rows as well. Original
output stays intact, including source text that happens to contain the same
instruction. Successful storage adds ledger guidance. An empty later pass
names scope and coverage review and leaves earlier observations and human
decisions unchanged. The repeated-pass regression includes a persisted human FP
decision. Full-source byte counts and capture limits use exact B, KiB or MiB
labels without rounding.

There are 418 distinct focused Rust passes. Two registry tests initially hit
the outer sandbox's nested network-denial probe and passed on an exact rerun
with normal local process permissions. Both logs remain retained. One unrelated
registry test stays ignored. The workspace build, ten quick gates and risk
proxy pass; the latter covers 392 changed code files. The quick receipt reports
dirty and drifted source state, so it is local draft evidence rather than
signed publication verification.

Sequential J318/J304 record 99 machine passes, zero failures, 111 capture pairs
and fourteen pending human judgments. Thirteen frozen programs, 4377 source
inputs and 772 runtime inputs match before and after both journeys. J318 keeps
its three separately invoked intercepted requests, one stored observation, one
human FP decision and protected Review capacity through no-color restart.
J304 retains its six fixed intercepted calls, context experiment, export and
lesson retirement. Native SHA256:
`a04a17c4dc0b5dbe427799386aad342027e3cf830cc4510cb8dba77d4563c9d5`.

Thirty ANSI cell replays were generated; ten were visually inspected, including
all six viewport sizes. These are terminal-cell renderings, not OS screenshots
or human acceptance. The corrected action and byte labels are visible. Primary
output remains dense, repeats its summary and includes full frozen settings and
system instructions. At 40 columns the failure action requires scrolling;
long evidence rationale still truncates. Reference parity remains unqualified.

The registry dump and visible catalog are byte-identical to the preceding
checkpoint: 189 registered actions, 118 visible, with 81 Core, 32 Labs and five
Compatibility actions visible. Eight hidden Core actions, including three with
descriptor-only evidence, remain unqualified. Other scanners' captured-source
migration, the actual SHA-change TUI flow, complete monorepo support and all
nine broad delivery milestones remain open.

Publication remains **Keep as draft** on `main`. The original seven-file index
and saved 366-file review proposal are preserved. No project commit, push or
new live request is added. Fourteen live experiment requests have been spent;
no live allowance remains. Evidence: `/tmp/kuzushi-source-readiness-20261016`.
