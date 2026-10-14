# Background Review refresh, October 6, 2026

Interactive Review reads now use the existing bounded artifact workers. One
pending request binds the target, filter, identity policy inputs, selected scan
references and previously loaded ledger watermark. Older results cannot replace
a newer request or projection. Passive external refreshes retain an operator's
pending filter and navigation action. Later typing or navigation prevents that
action from taking focus.

The same snapshot reader serves synchronous callers. Presentation continuations
can wait for the read; mutation continuations preserve synchronous ordering.
Snapshots apply rows, aliases, decisions, source qualification, counts and their
watermark together. They stay outside the per-frame artifact cache. Interactive
store-change probes schedule a read without opening SQLite on the input loop.
This changes no scan plan, module option, model, finding identity or list limit.

Loading and failed reads identify previous results. Invalid filters preserve
recorded review progress and offer a retry. An unavailable previously loaded ledger
retains rows and clears current completion claims. A fresh empty target remains
an honest empty state. A damaged selected scan receipt uses wider ledger counts
and an explicit warning rather than preserving a falsely narrow population.
The existing store service can bootstrap an absent empty database; the new reader
distinguishes that from losing a previously loaded durable projection.

Evidence lives under `/tmp/kuzushi-experiment-main-20261006/`. All 74 focused
findings checks pass, including blocked-reader typing, competing filters,
passive refresh, target changes, newer projections, delayed alias opening,
invalid filters, unavailable ledgers and retry. The CRAP-risk gate passes for
74 changed code files. The workspace build passes. Four reviewed Map snapshots
replace separator chains with a readable comma-separated context summary;
all 30 canonical references and the separator lint pass.

The broader TUI run completed with 3,783 passes, seven failures and four ignored
checks. Its raw log is retained. Six relevant failures received focused passing
reruns after the filter race repair, source-evidence and visible-control assertion
updates, Map copy repair, and a process-group check outside the sandbox that
denied `ps`. The existing patch-dispatch failure is retained outside this work's
scope. This evidence does not establish a fully green TUI suite.

The first native J101 run, `tui/20261006-184428/J101`, has 33 machine passes and
six independent screen judgments. The filter-error judgment fails: a typo sent
the operator back to reviewing 1,000 previously reviewed findings. That regression was
repaired after inspection. Raw `REVIEW_REQUIRED` and the failing judgment remain
intact. Source bytes and 2,000 observations were unchanged; exactly six bounded
synthetic decisions were added. No model or scanner request occurred, and target
source was never executed.

The final J101 run, `tui/20261006-185552/J101`, has 33 machine passes, no
machine failures and six separate passing screen judgments. The invalid-filter
screen preserves recorded review progress, names the previous results and gives an
explicit retry. Recovery clears its own error. All six viewport sizes and
no-color restart remain coherent. Text and ANSI hashes and actual capture
provenance are recorded in `manual-review.json`; raw `REVIEW_REQUIRED` remains
unchanged. Sampled echoes were 75, 74, 75, 75, 93 and 70 ms, within the 300 ms
test allowance. These samples do not certify worst-case latency or parity with
the reference products. The final workspace build and focused tests use the
code captured by this run. The live-model receipt is unchanged at seven settled
requests, with two protected review requests and no unresolved reservations.

Complete-ledger paging, durable decision-write responsiveness, larger workloads,
actual Git transitions, full platform/accessibility coverage and the complete
approved investigation remain open. All nine delivery milestones stay unchecked.
