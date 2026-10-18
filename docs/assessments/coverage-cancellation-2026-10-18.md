# Cancel historical source inspection without advancing baselines

`coverage:sweep` previously dropped the active cancellation handle before Git
inspection. A long comparison could continue after the operator requested a
stop. The shared dispatch entry guard already rejected pre-canceled requests;
the missing behavior was interruption after execution started.

The executor now forwards that handle through Git commands, coverage SQL reads,
scope iteration and skip writes. SQLite reads install a progress callback only
for the query and remove it before returning, including after failure. Git uses
the existing bounded child-control adapter. Cancellation between skip inserts
rolls back the transaction; source validation and the final pre-commit check
remain in force. `coverage:baselines` uses the same SQL control. Existing public
library entry points retain their signatures and default behavior.

No tool, option, persisted schema, model choice or workflow phase changes.
Historical source inspection still cannot establish scan coverage, a finding
fix or accepted Map work. Retry remains an explicit operator action.

## Verification

All 38 distinct focused Rust checks pass: 26 ledger checks, eleven coverage
dispatch/consumer checks and the 189-tuple registry policy check. The cases
include interrupted SQL, handler removal after cancellation and read failure,
rollback after an actual first insert, successful explicit retry, source drift
and the existing entry guard. The locked workspace build, Core/TUI Clippy and
changed-code risk proxy pass. The risk proxy covers ten changed production
files, including the preceding scope preview draft.

The qualified pre-fix native case is
`before-native/20261018-013712/J334` under the evidence root. It waits for startup
recommendation reads to finish, arms only the coverage adapter's exact diff
arguments, and requires the visible active-work abort control before Ctrl+C.
The owned child remained active after the unchanged three-second limit. Its
three passing checks and one failure are retained.

| Final sequential case | Machine passes | Failures | Capture pairs | Pending human judgments |
| --- | ---: | ---: | ---: | ---: |
| J334, cancellation, explicit skip retry and restart | 10 | 0 | 15 | 3 |
| J148, dirty source, new SHA and honest historical records | 20 | 0 | 18 | 4 |
| Total | 30 | 0 | 33 | 7 |

J334 uses `native-v4`; J148 uses `native-v5`. Both authenticate the same thirteen
executables and 4,620 source inputs. Their 813-entry runtime manifests differ
only in J148's corrected idle-exit expectation. J334 and both shared fixtures
remain byte-identical. The main executable SHA-256 is
`41b38ebadf3400895005269d1727bae012e03471fea27fec42bed09dfa70c098`.

The final controlled adapter stopped in 49.822 ms after the recorded cancel
request. Historical rows stayed unchanged. A separate explicit retry then wrote
one skip row at the recorded HEAD; restart retained it and the original rows.
This is one controlled timing observation, not a general latency guarantee.
J148 preserves three historical rows while distinguishing a dirty working tree,
a dirty baseline, an unavailable scope and a changed SHA. Neither case creates
findings, decisions, investigation jobs or provider requests. Independent checks
authenticate source bytes, baseline contents, process exit, capture provenance,
no-color output and the false coverage/finding-fix flags.

Fourteen final terminal-cell reconstructions were visually inspected across all
six sizes, cancellation, retry, paging and restart. They use a chosen font and
background; they are not OS screenshots or formal operator approval. Seven human
judgments remain pending. Transcript duplication, diagnostic density and full
reference-product parity remain open.

Earlier fixture failures are retained and excluded from the final totals. The
old fixture ran work on import and assumed reads initialized its ledger. It now
seeds synthetic history explicitly, uses an isolated home and inspects WAL-mode
SQLite with a normal connection, without issuing data writes. An initially broad
Git hook intercepted startup hydration; those runs do not prove cancellation of
the requested sweep. J334's stale Setup caption and J148's obsolete idle-exit
confirmation were corrected to the current interaction contract.

## Readiness and limits

Visible descriptor facts are refreshed from the actual 118-tool catalog: 81
Core, 32 Labs and five Compatibility actions. There are 110 in-scope visible
actions and unchanged 189 registered policy tuples. Thirty rows had stale
metadata fields. Existing per-tool functional verdicts remain scoped; no tool
is promoted, retired or deleted.

The existing 10,000-row materialization cap and per-Git 2 MiB stdout/ten-second
limits remain. Aggregate retained diff memory, total history work and lock-wait
latency are not qualified by this repair. Automatic advisory hydration has its
own lifecycle and is outside the direct tool-stop timing claim.

Evidence root: `/tmp/kuzushi-coverage-cancellation-20261018`. All failed attempts,
focused logs, current catalog, independent checks and captured screens remain
there. Historical real-model requests stay at fourteen; this work adds none.
The changes remain a draft on main after `2f267dfbf6`. Four delivery items are
locally verified and five remain open in the original bounded investigation plan.
