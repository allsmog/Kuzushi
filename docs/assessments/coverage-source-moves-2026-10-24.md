# Historical source checks preserve both sides of a move

Git rename detection could hide a removed path from `coverage:sweep`. For a
committed move from `src/original.txt` to `docs/moved.txt`, `git diff --name-only`
could return only the destination. Filtering that output by the `src` boundary
then reported unchanged source. An explicit `writeSkips` inspection could advance
that boundary's baseline even though its file had been removed.

Two focused regressions reproduced both failures before the repair: the departed
scope was `Current`, and one incorrect skip row was written. Historical Git
comparison now uses `--no-renames`, so removed and added paths both participate in
scope filtering. The existing NUL framing, whole-repository comparison, output
and request limits, cancellation and transactional revalidation remain in force.
The same comparison feeds explicit source-based recommendations. Displayed
counts now say `path(s)`; the compatible JSON field remains `files`. A move can
contribute two paths to a parent scope. Larger output still stops at the existing
byte limit; the repair grants no additional allowance.

## Verification

All 47 distinct focused Rust checks pass: 30 coverage-ledger checks, eight real
prepared-dispatch contracts and nine recommendation checks. The move regressions
cover Git rename settings `true`, `copies` and `false`, both changed boundaries
and refusal to advance either baseline. The locked workspace build, Core
all-target Clippy and changed-code risk proxy pass. Final repository summary
verification is retained under the evidence root below.

| Sequential native case | Machine passes | Failures | Capture pairs | Pending human judgments |
| --- | ---: | ---: | ---: | ---: |
| J353, cross-boundary move, selective skip and restart | 12 | 0 | 32 | 3 |
| J334, active cancellation, shared comparison limit and explicit retry | 13 | 0 | 18 | 4 |
| J148, dirty source, changed SHA and historical records | 20 | 0 | 18 | 4 |
| Total | 45 | 0 | 68 | 11 |

J353's final `native-attempt-3` freezes 6,515 repository inputs and thirteen
programs. J334 and J148 use `native-attempt-2` with identical program hashes and
production inputs. Only the J353 journey and its fixture changed to add exhaustive
compact-reader paging. The main executable SHA-256 is
`5d17abb2132d282f35094452d05d5ff1590229d8d94b1709ee492185c7c706d8`.
All owned processes reached terminal results before subsequent source or document
edits. The initial attempt failed before launch because the sandbox could not
access the host tmux socket; it is retained separately.

J353 creates two actual owned Git revisions with identical moved content and
synthetic historical baselines. An independent reconciliation reads the Git
objects, working-tree bytes and SQLite rows. Both affected scopes and their
parent remain changed. All four original baseline records remain; only the
untouched scope receives the one explicitly requested skip. Headless shared
dispatch returns the same changed-scope recommendations. No finding, decision,
scan job, accepted Map or provider reservation is created. Global settings
persist without the enclosing repository's artifact-ignore policy leaking into
the isolated HOME.

The native journey captures all six viewport sizes and no-color restart. At
40×12, seventeen captures reach every one of the transcript's 84 virtual rows
through ordinary Home, End and Page Up controls. Eleven final ANSI cell replays
were visually inspected, including each size, the changed boundaries and restart.
They use Menlo and a chosen background, not OS screenshots or formal operator
approval. Full revision identifiers remain available, but timestamps, repeated
baseline identifiers and long paths make this diagnostic transcript dense at
narrow widths. This is a remaining usability concern, not reference-level parity.

## Scope and remaining work

This repair qualifies historical metadata inspection and its recommendation
consumer for the tested move. It does not establish complete scan coverage,
finding fixes, discovery precision, arbitrary adapter source bindings or the
usefulness of a model's proposed boundaries. Eleven human judgments and broader
module, history/lock, layout and product acceptance remain open. No module is
promoted or removed, and no broad delivery milestone is closed.

Evidence root:
`scripts/devex/artifacts/coverage-source-moves-20261024/`. Failed regressions,
focused logs, frozen native inputs, capture provenance and `reconciliation.json`
are retained there. No live request is made. Cumulative live experiment usage
remains sixteen with no unused allowance. Changes are a local draft on `main`
after `29e5aefa73`.
