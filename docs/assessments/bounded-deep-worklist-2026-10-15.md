# Bounded deep worklist and saved-result reading

This checkpoint extends the earlier [worklist qualification](worklist-coverage-module-audit-2026-10-10.md).
The worklist remains advisory and auxiliary. It creates no accepted Map,
finding observations, model calls, graph builds or scan jobs.

## Bounded source inspection

The optional deep path previously used the systems classifier's recursive file
collector. A returned-row cap did not bound directory entries or total prefix
reads, and its separate parser rejected some advertised row limits. Deep ranking
now uses one shared repository inventory and the shared prefix adapter extracted
from the threat-lead helper. The latter keeps its original 6,000-file, 256 KiB
per-file and 16 MiB prefix limits and compatible receipt fields.

The deep worklist selects production systems-source paths from that inventory.
Its limits are 2,000 file attempts, 16 KiB per file and 16 MiB in total prefixes.
Inventory and prefixes share the existing 512 MiB read ceiling; inventory also
keeps its 100,000-entry limit. Capacity is reserved before reads. Failed reads
retain conservative reservations. Symlinks and non-production source paths are
excluded. Cancellation is checked during inventory, prefix reads and per-file
classification. Retained classifier evidence is limited to 32 signals per file.
The public 1 through 500 row limit works independently of inspection limits.

The additive systemsInspection receipt records these bounds and actual counts.
Prefix, file, byte or evidence limits make inspection partial. Its contributor
and canonical result disclose that state. Other degraded contributors now also
return partial instead of a successful complete envelope. Headless partial
results retain exit 4 and their usable data. A bounded advisory result does not
establish complete source coverage or a vulnerability verdict.

## Operator reading and recovery

The worklist presents ranked files before detailed resource facts, retains raw
contributor values and wraps inspection limits with KiB/MiB amounts. Legacy deep
results show unrecorded limits. The default path performs no deep walk.

After restart, explicit worklist reading searches at most 100 run summaries for
a completed or partial ranking. Saved JSON uses the existing bounded asynchronous
artifact reader. Target, status, row shape, row cap and count consistency are
checked before projection. Saved results identify their originating run and say
that current source and context equivalence remain unverified. Loading and
unreadable results offer receipt inspection, without fabricated empty counts.
The result is memoized by hydrated content identity; rendering performs no file
reads or repeat JSON parsing on cache hits. Opening the reader launches no work.

The Map projection keeps its current-context and live-capture behavior. Historical
lookup is confined to the explicit worklist gallery. A capture invalidated by
new context cannot be replaced with historical rows. Exact saved settings remain
in canonical run inputs. A new explicit ranking replaces the current capture.

## Limits still open

This qualifies finite deep prefix inspection and retained reading, not every
recommender dependency. SQLite grouping, sorting, identity folds and aggregate
query latency remain unbounded by returned-row limits. Legacy systems scanners
outside the read-safe worklist path were not changed or executed. General
ranking usefulness, large-history interaction, external-publication refresh,
full source equivalence and operator UX acceptance remain open. The full
investigation implementation goal remains active.

Native testing also found an absent-context hydration defect: a valid three-row
result became an empty deck when missing context/run artifacts acquired cache
stamps. Worklist context identity now distinguishes actual evidence from a
hydrated absence, so missing artifacts do not invalidate an explicit result.
A regression test preserves that capture while still retaining existing
context-regeneration and target-isolation checks. The first failed native
capture and its correct three-row canonical result are retained as evidence.

## Verification

Evidence is retained at `/tmp/kuzushi-deep-worklist-20261015`. There are 127
distinct focused Rust passes across worklist gathering, shared prefix inspection,
threat-lead regression, actual passive context consumption, TUI reading and
rendering, registry policy and primary-result ownership. The workspace build
passes. All ten quick repository gates pass, including the risk proxy over 104
changed code files with 15 support checks. The receipt is a dirty, drifted and
unsigned draft. This is not clean-commit, full-suite or release qualification.

Native journeys run sequentially on the same frozen programs:

| Journey | Machine passes | Failures | Capture pairs | Human UX judgments pending |
| --- | ---: | ---: | ---: | ---: |
| J294 bounded deep worklist | 10 | 0 | 29 | 3 |
| J160 default worklist and coverage recovery | 34 | 0 | 36 | 6 |
| J293 bounded legacy hint regression | 17 | 0 | 28 | 4 |

All 93 text/ANSI capture pairs authenticate the frozen native binary and exact
requested tmux dimensions. The six-size matrix includes 40x12, 60x20, 80x24,
96x89, 120x36 and 160x48. J294 verifies the actual three-row deep result, partial
inspection, default/deep switching and saved-result reading after no-color
restart. Its three tool attempts preserve source/configuration and create no
finding observations, primary attempts, graph, scan job or provider reservation.
The final 120-column active and restarted views and narrow resource captures
were inspected as ANSI cell replays. That review found the paging gap below. These use a chosen font/background and are
not OS screenshots or operator acceptance. All 13 human judgments stay pending.
Legacy contributor labels still expose internal phase terminology, and file
selection/detail, broader interaction timing and reference-quality UX remain
open rather than being certified by these frames.

Headless deep/default commands use the exact frozen binary in a separate owned,
unborn Git fixture. They return partial exit 4 and completed exit 0 respectively,
with model null, unchanged source and no graph. No fixture commits are made.
The first native J294 failure retains a correct three-row canonical result and
the contradictory empty deck; the final run verifies the hydration repair.
Earlier compile/test probes are preserved alongside their final passing checks.

The final native SHA-256 is
`e0ce403d73a8f0934068c30e5d4de04ee0ce3faa6deb2c99bcbe8d8bba02eba5`.
All 4,260 source and 702 runtime inputs remain unchanged during each final native
journey. No real provider request, OAuth renewal, target source execution,
exploit work or vulnerability patching occurs. Cumulative real experiment use
remains 14, with zero further requests approved. No commit or push is performed.

## Narrow-terminal defect recorded at this checkpoint

Machine-green journeys do not establish complete reading. The shared gallery
`renderer/views/scene/line_page.rs` treats scroll offsets as logical rows. Its
window takes only the viewport's display-line capacity from an oversized row,
then Page Down advances to the next logical row. The hidden continuation cannot
be reached. At 40x12, J294 capture `15-deep-page-7-40x12` shows the start of the
resource-bounds row while its remaining text is absent. Long file paths have the
same problem. Generated wrapping passes its unit check, but viewport navigation
does not expose all of those lines.

J294's later `nav-mode` convergence also sends Escape while the gallery owns
that key, leaving for Map. Its nine tail captures therefore show Map, not the
worklist. Those captures remain authenticated but do not qualify worklist tail
reading. The final standard-width result and actual no-color saved reading are
valid; complete narrow reading remains a concrete implementation gap.

The next priority is shared continuation navigation for oversized rows, with
row/fragment position, resize and input ownership preserved, plus explicit
journey checks that the worklist still owns every narrow capture. Recheck the
long-path J160 case too. Do not mark the human questions or complete TUI journey
accepted from the current machine verdicts. No full UX or reference parity claim
follows from this checkpoint.

The subsequent [gallery continuation repair](gallery-continuation-2026-10-15.md)
reproduces and fixes this reading defect and strengthens the named native
journeys. This checkpoint retains its original failures and UX limitations.
