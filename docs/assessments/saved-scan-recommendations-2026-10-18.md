# Saved scan advice and explicit historical source comparison

Automatic recommendation hydration previously called a complete historical Git
sweep, without the hydration cancellation handle. The same gatherer served
`coverage:recommend` and `worklist:rank`. Inspection errors disappeared into an
absent sweep, and an empty Map recommendation list said coverage was current.
Opening a view could therefore perform historical source work while presenting
an unjustified freshness claim.

Automatic advice and default tool recommendations now use saved context, finding
paths and baseline rows only. They do not run Git diffs or discover jobs. A
present but unreadable findings store is an error, rather than apparent absence.
Hydration passes its cancellation handle through ledger and finding-path SQL.
Both use the same removable SQLite progress callback. Late canceled hydration
results are discarded before publication. Worklist execution shares this path.

Map's empty recommendation state names saved history and unchecked current
source. It offers the explicit comparison command. Tool receipts also disclose
whether a source comparison was requested. Existing recommendation rows and
artifact formats remain compatible; the library gatherer's changed default is
documented in `RELEASING.md`.

## Finite comparison work

`coverage:recommend` accepts `compareSource=true`. That action and
`coverage:sweep` declare `maxSourceComparisons` and `maxDiffBytes`, defaulting to
32 Git diff attempts and 8 MiB aggregate diff stdout. Tool option bounds are
checked at shared prepared dispatch. Initial sweep and skip revalidation consume one
allowance; revalidation cannot silently reset it. Limit failure stops before
new baseline writes. Explicit comparison failures propagate instead of becoming
empty staleness evidence. No automatic retry, follow-up job or cap increase is
added. Successful results include comparison limits, attempts and diff bytes.

The diff cache retains compact NUL-separated text rather than allocating a
string for every path. Whole-repository diff membership, source revalidation,
transaction rollback, cancellation and dirty-source refusals remain in force.
No comparison establishes complete scan coverage or a finding fix.

These limits bound diff attempts and captured diff stdout. They are not a total
RAM, wall-clock or dollar ceiling. Metadata commands retain the existing
per-command limits. SQL materialization retains the 10,000-row cap, but database
sorting, lock waits and full history size are not qualified by this increment.
Persisted context density remains advisory. Formal UX approval and complete
reference-product parity remain open.

## Verification

All 179 distinct focused Rust checks pass: 28 ledger, nine recommender, 25
worklist, fourteen dispatch/consumer, two shared SQLite control, two finding-path,
one registry policy, 81 hydration and seventeen Map renderer checks. They cover
shared revalidation limits, output exhaustion, distinct revision limits,
same-SHA dirty content, source drift, cancellation, damaged stores, callback
cleanup and the six Map widths. The locked workspace build, Core/TUI Clippy and
changed-code risk gate pass. The 189 registered policy tuples are unchanged.

The published binary's J334 before-case fails at the missing saved-only receipt.
Its exact controlled Git adapter records three diff requests during startup and
default advice, without an explicit source-comparison request. This is evidence
of implicit historical work, not a cancellation failure. Earlier test assertion
and test-import failures are retained in the evidence root and excluded from the
final passing counts.

Final J334 uses one frozen build with thirteen executables, 4,627 source inputs
and 813 runtime inputs. It records twelve machine passes, zero failures,
seventeen capture pairs and four pending human judgments. Its main executable
SHA-256 is `309faf8aa8b7a2650811ab9cedc14c5a3ea38c060040e3d1c89f4c2e8fccfbf0`.

Independent checks authenticate captures and dimensions, no-color restart,
source hashes, exact HEAD and all historical rows. There are zero automatic
comparisons and four explicitly requested diffs: one canceled attempt, one
limit-stopped attempt, and two for the separate successful retry. The controlled
child stopped in 41.148 ms after cancellation. This is one observation, not a
general latency guarantee. No observation, decision, provider reservation or
investigation job is created. Restart retains the one explicitly written skip
and original history.

Thirteen terminal-cell replays were inspected, including six widths, the limit
stop, cancellation, retry and no-color recovery. They use a chosen Menlo font
and dark background, not OS screenshots or formal operator approval. Wrapping
and paging retain the text. Duplicate receipts and long diagnostic identifiers
still dominate narrow transcript views; four formal human judgments remain
pending. Native Map completeness is not claimed by transcript verification.

Evidence root: `/tmp/kuzushi-saved-recommendations-20261018`. It retains the
before-case, focused logs, frozen manifests, catalog, independent checks and
visual inspection record. Quick repository verification is recorded separately
in `draft-receipt.json` there. No new live model request is added; the historical
total remains fourteen. This is a draft on main after `41998697db`. Four delivery
items remain locally verified and five remain open in the original plan.
