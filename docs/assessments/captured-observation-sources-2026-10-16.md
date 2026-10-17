# Captured observation sources

Historical checkpoint. The later [source-readiness increment](source-readiness-2026-10-16.md)
adds ownership and tree checks before inference, corrects withheld-result
guidance and formats capture bytes. Counts below describe this earlier build.

This draft adds an immutable source insertion path to the findings store and
uses it for `systems-hunt:deep-semantic-hunt`. The preceding discovery audit
identified a gap between the final source check and ledger insertion: insertion
read the working file again and could bind a historical candidate to newer bytes.

The new path authenticates the original snapshot and tree in the content store,
checks target ownership, and reads each cited file within an explicit byte limit.
The complete file hash must match the original tree. The exact prefix supplied
to discovery must match those authenticated bytes. Primary files and supporting
citations are captured together before any observation is inserted. Model claims
remain separate from source citations and do not acquire a confidence score.

Insertion uses the captured bytes for source identity, structural identity hints,
source evidence and primary grounding. It does not reopen the working source.
The observation references the original workspace snapshot, including its
recorded Git metadata, instead of a newly synthesized per-file snapshot. A later
edit cannot replace the captured observation bytes. Context-only files retain
their existing role; capturing a supporting file creates no discovery job.

`maxSnapshotBytes` is a descriptor-backed full-file retention limit, separate
from the prefix bytes supplied to the model. Its default is 16 MiB, its ceiling
is 512 MiB, and each file retains the shared 64 MiB safety ceiling. The receipt
names captured files, full bytes and the selected limit. Exhaustion or failed
source authentication withholds all candidates before insertion by this action.
The paid request, raw output and frozen input remain recorded. There is no
automatic retry, repair, cap increase or new model request.

Cancellation is checked between captures and before each insertion. Storage
failures or cancellation during an insertion batch can leave earlier observations
recorded; the existing partial-publication warning remains. This is not an
all-or-nothing multi-observation transaction or a filesystem-wide atomic snapshot.
Other adapters using ordinary insertion still capture source at insertion time.
Their migration and the complete source-revision acceptance remain open.

Shared grounding now preserves literal whitespace in filenames at its entry
point, matching the existing contained-path resolver. This avoids redirecting
` owned.c ` to `owned.c` while checking source evidence.

There are 434 distinct focused Rust passes, including an owned two-revision
Git fixture that retains both original SHAs and observation blobs. The workspace
build, ten final quick gates and the risk proxy pass. These are local dirty draft
receipts, not signed publication verification.

Final sequential J318/J304 have 96 machine passes, zero failures,
111 capture pairs and fourteen pending human judgments. Frozen source/runtime
inputs and thirteen native binaries match throughout both journeys. J318 makes
three explicit intercepted requests: malformed output, a one-byte capture refusal
with zero imports, and a successful separately invoked request. It retains three
settled reservations, one finding, one human FP decision and protected Review
capacity through no-color restart. J304 retains its six fixed intercepted calls,
context experiment, decisions, export and retirement. No live provider is used.

The reused tree reader has a 100000-member limit, and full cited files must be
UTF-8. Readiness for larger trees before billable work still needs improvement.
The source-revision TUI journey and migration of other insertion adapters remain
open; this checkpoint does not close the complete SHA or workflow requirement.
Live detection quality, human UX and reference parity remain unqualified.
Publication remains **Keep as draft** on `main`. No live allowance is available.
Evidence: `/tmp/kuzushi-captured-observations-20261016`.

Inspection of thirty ANSI cell replays confirms the repaired limit reason and
retained controls at the tested sizes. These are tmux cell renderings, not OS
screenshots or human acceptance. The withheld output still repeats a historical
ledger instruction even though no observation was inserted. That instruction
must be removed or replaced. Primary frozen-input text remains dense, long
rationale truncates, and the source allowance needs readable byte units.
These remain open UX work; the dedicated failure reader was not qualified here.
