# Gallery continuation and resize repair

The earlier deep-worklist checkpoint exposed a concrete reading defect: a
wrapped logical row taller than the viewport was clipped, and Page Down skipped
the rest of that row. A focused regression reproduced missing parts 2 through
7 of an eight-line owned row before the implementation changed.

The shared gallery now scrolls through display lines. Its logical row total
stays stable across terminal widths, and wrapped projections also state the
visible display-line range. An indexed row boundary keeps continuation windows
from scanning the whole document from the beginning. Plain output still emits
the exhaustive document.

A transient logical text anchor preserves a continuation through repeated
narrow/wide resizes. It survives a viewport that temporarily fits the document,
keeps End anchored to the tail, and rejects changed visible row content. This
is presentation state, not source authentication or a claim of SHA equivalence.
Repeating an unchanged terminal size does not rebuild the projection. Frame
readers retain their own cursors. Draft text, cursor and view remain intact.
A one-line move up after End now starts at the actual tail.

The named native journeys use owned inert fixtures and the installed wrapper
with copied frozen programs. The worklist sweeps move down and back up, check
the pinned Worklist title on every narrow capture, and authenticate every
physical line and complete source path against the saved ranking. Deep bounds
and incomplete-coverage wording are checked too. This accounts for the extra
content line exposed when a notice expires. It replaces the previous generic
Navigate/End sequence that accidentally left the gallery for Map.

The evidence directory is `/tmp/kuzushi-gallery-continuation-20261015`.
All 124 focused gallery tests and three scroll-navigation tests pass. The
workspace build passes. These are focused checks, not a full Rust suite.

| Sequential journey | Machine passes | Failures | Text/ANSI pairs | Human judgments pending |
| --- | ---: | ---: | ---: | ---: |
| J294 bounded deep worklist | 75 | 0 | 76 | 3 |
| J160 default worklist and recovery | 89 | 0 | 85 | 6 |
| J158 component inventory and recovery | 72 | 0 | 63 | 5 |

All 224 capture pairs authenticate their native binary and requested terminal
dimensions. The six-size matrix includes 40x12, 60x20, 80x24, 96x89, 120x36 and
160x48. Source and runtime inputs remain unchanged during each named run. The
same 4,263 source inputs and 13 programs are used; the SQLite/title fixture
repairs intentionally change runtime inputs between completed runs. Earlier
input manifests, native programs and failed harness assertions are retained.
The final native binary SHA-256 is
`f57822abacf7d43d30fa7fe5dfd7f713abb4369838a2d8942f0736c162efa1ca`.

The deep sweep reaches all 39 displayed lines across 17 logical rows. The
default sweep reaches all 25 displayed lines across 13 logical rows. Both retain
every complete source path and stay in the intended gallery on all 65 narrow
captures. Native component checks reach full freshness/version text and the
failure cause with its recovery command. No-color restart remains covered.
ANSI cell replays were inspected with a chosen font and background. They are
not OS screenshots or human acceptance.

The Components fixture opens its existing SQLite database with WAL coordination
permitted and immediately enables query-only SQL before reading. This avoids a
read-only WAL connection failure without granting SQL mutation to the checks.

Earlier harness probes and their failed assertions are retained. They are not
promoted to passes. All ten repository draft gates pass. The CRAP-risk proxy
covers 116 changed code files and 15 supporting checks. `quick-receipt.json`
is dirty, drifted and unsigned. It does not establish clean-commit or release
qualification.


The broader UX remains partial: 40x12 devotes most rows to chrome, the notice
and gallery disagree about Escape, the legend still exposes Phase A/B labels,
and file selection with evidence detail remains open. Very large component
documents retain the existing 16-bit scroll ceiling. Human UX questions remain
pending. This repair does not qualify reference parity or the full investigation
plan.

No new model requests, credential access, target source execution, exploit
work or vulnerability patching are included. Cumulative live experiments remain
14 provider requests with no additional allowance approved. No commit or push
has been made.

The subsequent [compact gallery checkpoint](compact-gallery-reading-2026-10-15.md)
reclaims short-terminal reading space, corrects notice/exit hints and removes
internal contributor phase labels. This earlier checkpoint retains its original
limitations and evidence.
