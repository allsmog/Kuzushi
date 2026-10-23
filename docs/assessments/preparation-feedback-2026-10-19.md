# Workspace preparation feedback, 2026-10-19

Draft on main after `a2a38eedf13a8c760acfb13eaffc759a32260ba7`. This
repair is separate from the staged diagram-context checkpoint. It adds no
model work or changes to dispatch authorization, workspace policy or scope
acceptance. Four broad delivery items remain locally verified and five remain
open in the [acceptance ledger](../quality/bounded-investigation-acceptance.md).

When workspace initialization refused an ignored `.kuzushi/scope.toml`, the
shell logged the error but left the scope reader pending despite creating no
worker. The operator saw an indefinite working state. Malformed or undeclared
tool inputs could leave similar owners pending.

Preparation now returns errors through one failure path. The owning reader or
context study receives the actual cause, clears pending state and preserves its
draft. A refusal captured for an earlier target cannot clear the current
target's request. Existing worker failure and cancellation callbacks use the
same extracted notification helpers without adding new execution paths.

An empty scope-history read now has an explicit completion notice. If a saved
revision was already inspected, that revision stays available for reading. A new
proposal starts at the top of its detail document; refreshing the same proposal
preserves its scroll position. The native captures exposed this separate scroll
defect, which was reproduced in a failing Rust test before the repair.

Verification evidence is retained in the ignored local directory
`scripts/devex/artifacts/preparation-feedback-20261019/`:

| Check | Result |
| --- | --- |
| Distinct focused Rust checks | 152 passed, including 67 scope-reader tests, five preparation tests, one error-format test and existing tool-result, context-study and boundary checks |
| Workspace build | Passed with `cargo build --workspace --locked` |
| Repository summary | All ten checks passed, including format, workspace check, model policy and CRAP-risk checks; the dirty receipt is separate from the published clean receipt |
| Final native journey | J340, attempt 8: 23 machine passes, zero failures, three pending human judgments, 18 text/ANSI/provenance capture sets |
| Frozen inputs | 6,371 repository files and 13 programs stayed unchanged during the final journey |
| Native executable | SHA-256 `2c4e60b866a16d5c3b227fcc0378149bd582a8e3bff59c405aff12b70acd29d9` |
| Provider/source execution | Zero model requests; the owned source file was never executed |

The journey uses the real native executable through the installed wrapper and
tmux. It deliberately creates an owned repository whose ignore rule hides
workspace state. After the visible refusal, the fixture explicitly corrects
only its own ignore configuration. The operator retries the history read and
then builds inventory. The original source file's digest is unchanged.

The recovered revision remains an unaccepted whole-repository scope containing
two files. Enumeration is complete under inventory policy, with limited
coverage because `.git` and `.kuzushi` are omitted. No scan plan is approved or
launched. Independent ledger inspection finds zero observations and decisions,
with no allowance, reservation or work-attempt tables created. No-color restart
reads the same draft. The fixture has no commit, so it makes no SHA-transition
or vulnerability-fix claim.

Thirteen selected terminal-cell renders were reviewed across 160x48, 120x36,
96x89, 80x24, 60x20 and 40x12, narrow paging, Back, return, recovery and restart.
Ten final images are byte-identical to directly inspected attempt-7 renders;
the changed return and recovered-draft images were inspected from attempt 8.
These are ANSI cell replays with Menlo 15 and a chosen dark background, not
operating-system screenshots. The three formal human judgments remain pending.

Earlier attempts are retained. They exposed duplicated error text, an ambiguous
completion wait, incorrect fixture assumptions about omitted inventory fields,
and an unsupported read-only SQLite open. The helper now checks for a
checkpointed database, copies stable bytes and reads that immutable copy.
Attempt 6 had 19 machine passes; visual review then exposed the scroll defect.
Attempt 7 had 22 machine passes, but a palette description could satisfy its
return-title wait. Attempt 8 requires the actual bordered scope-panel title and
asserts that the palette is absent.

This closes the reproduced preparation and initial-scroll defects locally.
It does not establish reference-level UX parity or overall investigation
completion. The 40x12 error requires paging, and the scope overlay still lacks
a visible paging hint there. Wide layouts remain text-heavy with substantial
unused space. The separate diagram-context work still requires complete file
enumeration for an exact-file selection, and its prepared live test remains
unapproved and unexecuted.
