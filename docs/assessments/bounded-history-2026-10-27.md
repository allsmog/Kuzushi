# Bounded investigation history

Campaign status, workspace campaign spending and the TUI history browser now
share a bounded catalogue. One malformed plan or queue preserves other readable
investigations and makes the result partial. An unreadable directory is an
unavailable history, with unknown spending, rather than a successful empty list.

An explicit campaign ID is loaded first, including an ID absent from the browse
result. Refresh preserves that identity through the existing selection fold.
The catalogue sorts its loaded subset by ID. It does not claim to return the
latest 100 investigations across an arbitrarily large directory.

## Read contract

- At most 1,000 directory entries are examined, with one continuation lookahead.
- At most 100 investigations are loaded per catalogue, including the requested ID.
- Plan, queue and optional run documents share 32 MiB of metadata allowance.
  Plan and queue files are limited to 4 MiB each; run metadata to 256 KiB.
  Bounded EOF probes can read one additional byte per admitted file.
- A snapshot supports at most 1,000 jobs. Oversized or malformed snapshots stay
  unavailable; a parsed prefix never supplies partial job counts.
- Successful reads charge their actual document bytes. An uncertain failed read
  retains its reserved maximum until the query ends. Confirmed inspected bytes
  and accounted metadata bytes are separate counters.
- Browsing reads plans and queues. Optional child-run findings and correlated
  failure details are read for explicit detail under the same allowance.
- Modern run metadata uses the shared canonical decoder, including cost and
  run-ID validation. A legacy count-only document can supply its count, never a
  canonical failure reason. Malformed or mismatched summaries remain unavailable.
- Paths stay within the repository and exclude symlinks. Cancellation yields no
  partial success and starts no work. A canceled status query writes no trend.

The status result adds `historyCoverage` version 1, including completeness,
limits, omissions and byte accounting. Existing plan, queue, job and cost fields
remain readable. Partial status uses the existing partial envelope and CLI exit
4. Direct lookup of an unreadable requested plan remains an error. The plan
digest comes from the same loaded document; rendering does not read it again.

No artifact format, tool identity, input alias, model selection or approval
boundary changes. These reader limits do not approve work or change spending
allowances. The existing public campaign-ID enumerator remains for compatibility;
the supported status, spending and TUI history path uses the bounded catalogue.

## Verification and open qualification

Evidence root: `scripts/devex/artifacts/history-loading-current-20261027/`.
The retained red status test reproduces one malformed plan hiding readable
history. Its path-escape rejection check already passed before the change.
The reader checks cover shared prepared dispatch, cancellation, malformed
plans and queues, symlinks, metadata and job limits, exact lookup outside the
browse result and optional run metadata. A separate test removes the source
plan after loading and verifies that status retains its snapshot digest.

There are 475 distinct passing focused Rust checks: 312 campaign checks,
19 run-summary checks, 123 TUI campaign checks, 18 header checks and three
registry contracts. Five existing campaign tests remain ignored. The workspace
build and Core/TUI all-target Clippy pass. All ten draft repository gates pass,
including the CRAP-risk proxy. The custom receipt is
`control/final-draft-receipt.json`; its dirty/drifted state is not a clean-head
publication receipt. The earlier signed receipt remains unchanged and its
canonical-digest signature verifies. Shared canonical run-summary decoding
preserves cost, run-ID and unknown-field validation. The legacy three-field
count-only format remains readable, with matching run-ID validation when present.
Retained red runs include two metadata-integrity failures and one legacy-format
regression found and fixed before final qualification.

J393 is a history-only keyboard flow. Its fixture declares synthetic unstarted
plans and selects an investigation omitted from the real headless status result.
The flow inspects that exact plan, refreshes, reads six viewport sizes, introduces
damaged history and a blocked directory, then explicitly repairs and refreshes.
It approves and starts no study jobs. Final attempt 4 has 24 machine passes,
zero failures, 19 authenticated capture triples and six answered agent screen
questions. Twelve ANSI replays were directly inspected across six sizes.
The prepared headless query returns partial status with 100 of 111 fixture
investigations; exact lookup opens an omitted ID. Damaged history and the
unreadable directory remain visible through explicit repair and refresh.
There are zero provider requests, new work attempts or decisions. This run uses
binary `91795d00303bafca1dd608e4864b9d9a8909270f3958693c53b8318f27e6b330`
before the final canonical metadata refinement. Its six judgments and retained
earlier failed or unqualified attempts are under `native-attempt-4/` and its
sibling attempt directories.

The final rebuilt J121 end-to-end flow has 343 machine passes, zero failures,
154 authenticated capture triples and 21 answered agent screen questions.
Twenty-six ANSI replays were directly inspected, including representatives of
all six sizes. Binary
`b76ff6a37ad4fd9ba35f09c7da3ef77e0cab70fab5ee943742cefb34a0006935`
executes Context prerequisites, explicit context acceptance, three fixed Scan
passes, cancellation, allowance refusal, specific approval revisions, human
triage, export recovery and no-color restart. It retains four observations,
two identities, three decision records, five admitted call reservations
including one unsettled reservation, and two unused protected Review calls.
The original three Scan jobs have four attempts including cancellation. There
are five intercepted provider requests and zero live requests or source
execution. The owned three-file greeting fixture has dirty source and a
borrowed Git HEAD; this is not a scan of the committed Kuzushi tree.
See `end-to-end-attempt-1/agent-review.json` and
`end-to-end-attempt-1/independent-end-state.json`.

Both final journeys retain raw exit 4, `REVIEW_REQUIRED`. The agent verdict is
`PASS_WITH_FINDINGS`, separate from operator acceptance. Repeated controls,
dense identifiers, raw JSON inspection, sparse wide panels and the optional
stale severity diagnostic remain visible findings. The replays render captured
ANSI cells with Menlo 15 and a chosen dark background; they are not OS screenshots.

This increment bounds campaign metadata. The findings-decision ledger, other
compatibility readers and remote-filesystem latency remain separate scaling
qualification. The TUI refresh still performs bounded local reads synchronously.
Full module usefulness, real-model quality, operator acceptance and parity with
the reference terminal applications remain open.
