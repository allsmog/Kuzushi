# Source baseline integrity, October 9, 2026

Historical Git baseline inspection now distinguishes unchanged tracked source,
changed source, an unreachable comparison and unverified source. A dirty working
tree, dirty historical baseline or unavailable scope cannot become `current`,
including when the commit SHA is unchanged. Missing root baselines are disclosed.

The baseline and sweep actions expose full SHAs, phase, scope and provenance.
Verdicts appear before their SHA so reasons stay readable in the transcript.
Their outputs explicitly state that these legacy records cannot establish
complete scan coverage or a finding fix. Structured sweep data adds
`sourceMeaning`, `scopeCoverageVerified: false` and `findingFixVerified: false`.
Baseline data adds the source meaning and false coverage flag. Existing row
formats, tool names, options and aliases remain available.

All coverage actions use Operate with no phase result. An operational run cannot
seed a Map baseline or replace an accepted Map. The recommendation action's
heuristics remain unqualified by this audit; its new unverified match branch
creates no staleness recommendation. No implementation is removed or promoted.

Skip writes reject dirty source, recheck the captured report against current
source/history, write in a ledger transaction and recheck source before commit.
Rejected writes do not commit their skip rows. Git and SQLite remain separate
systems; these checks do not establish an atomic source snapshot across external
edits. Exact context and complete scan scope require their own immutable receipts.

Git inspection uses NUL-separated paths, strict UTF-8 and bounded subprocesses.
Each subprocess has a ten-second timeout, two-MiB stdout limit and 64-KiB stderr
limit. External diff, text conversion and fsmonitor are disabled. These limits
do not bound total history reads or the whole sweep. `.kuzushi` state is excluded
from working-tree dirtiness in this metadata check.

Evidence root: /tmp/kuzushi-source-baselines-20261009.
Final J148: /tmp/kuzushi-source-baselines-20261009/settled-tui/20261009-154657/J148.
Native SHA-256:
072f112915081e761dba6401e4563d3be906e15356cc7bfeb9ae4f7a58f3eea9.

J148 records 22 machine passes, zero failures and 20 live text/ANSI pairs across
40x12, 60x20, 80x24, 96x89, 120x36 and 160x48, including no-color restart.
Every capture matches the same native binary, requested/actual dimensions and
plain text after ANSI removal. Four scoped assistant screen judgments are
recorded separately; raw REVIEW_REQUIRED and operator approval false remain.

The owned inert fixture has two actual Git commits and a same-SHA working-tree
edit. Its three historical rows are labeled synthetic metadata, not scan
evidence. The real Rust CLI and TUI inspect them through prepared dispatch.
Dirty writes are refused. All three rows remain unchanged through restart.
Source bytes match the explicitly staged edits and isolated configuration bytes
remain unchanged. No provider request, scanner job, source execution, finding,
decision, provider reservation or investigation work attempt is created.

Forty-six distinct focused tests cover the ledger and Git parsing (17), prepared
dispatch (4), and TUI phase/result ownership (25). The four dispatch tests were
rerun after the verdict-first presentation change. Workspace build passes for
the final source. All ten repository summary steps pass, including the CRAP-risk
proxy for 529 changed code files. The verifier records dirty source and `driftedDuringRun: true`; dirty source
alone sets that flag, so it does not establish a concurrent edit or a clean
committed snapshot. Final
documentation checks run separately after this receipt update.

Retained failures include a fixture that hid trackable `.kuzushi` configuration
and a native wait for a status phrase split after a long SHA. An initially wrong
test JSON key was also corrected. The fixture now uses the real workspace ignore
contract, the test consumes the preserved `revisionSha` field, and presentation puts verdicts
before their baseline identity. The failed tmux run is retained separately.

The screen review also identifies unfinished operator experience work:

- Setup shows cached prior revision facts after source drift until restart;
  the stale footer does not qualify the Target row itself.
- A dirty metadata write failure floods Logs with structured proof diagnostics
  and offers unrelated model/tools recovery hints.
- Journey and autonomy chrome can reappear on Logs and Quit before Start Map,
  because the hiding rule depends on the current view.

These are open TUI defects, not evidence of reference-quality acceptance.
The subsequent [Setup freshness increment](setup-source-refresh-2026-10-09.md)
refreshes cached facts on explicit reopen. Automatic invalidation remains open;
the diagnostic and premature-chrome defects are unchanged.
The later [operational reading increment](operational-failure-reading-2026-10-09.md)
corrects those two defects on the named paths while preserving full failure
payloads. Detailed-reader hierarchy and complete TUI acceptance remain open.
Cancellation, total-work limits, nested Git roots, all scope races, full option
parity, live-model usefulness, large monorepo execution and complete investigation
acceptance remain unqualified. The legacy intake still records root metadata
from completed phase summaries without validating complete selected scope.

Two additional tools have scoped outcome evidence: coverage:baselines and
coverage:sweep. The matrix now has 55 of 109 qualified, with 54 unassigned;
qualification is limited to the stated evidence. The native default catalog
remains 98 tools. All nine broad delivery milestones remain open. Work is
uncommitted on main. The separate model-test allowance remains pending; no OAuth
renewal or inference occurred in this increment.
