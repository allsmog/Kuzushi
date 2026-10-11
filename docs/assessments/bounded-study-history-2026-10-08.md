# Direct bounded study history, October 8, 2026

The prior-study picker now requests its own background history read. Operators
can choose resource evidence directly from a fresh scope or context-matrix draft
without visiting Campaign first. It uses the existing hydration runtime,
target-scoped cache, cancellation and result-generation handling. Loading or
failure preserves the composer, draft, hover selection, paging and work origin.
Explicit `r` refresh retains previous choices while the new read runs. Background
completion never accepts evidence or takes focus.

The shared core reader visits at most 1,000 directory entries, plus one sentinel
entry to disclose truncation. It retains at most 100 study choices, reads at most
1 MiB per metadata file and 32 MiB overall, and never traverses source directories
or reads discovery artifacts for calibration. Cancellation, including at the
last read, withholds publication. Symlinked study directories and escaped roots
are not followed. Malformed or oversized plans are counted as unreadable;
unreadable queue status stays unknown. A missing queue describes unstarted work.
Choices are ordered by recorded creation time within the inspected set, rather
than claiming a complete globally recent history when limits were reached.

The UI discloses visited entries, retained choices, unreadable metadata, skipped
symlinks and each limiting condition. Its progress counts are recorded history;
new plan preparation still authenticates the selected study's actual calibration
conditions. A named choice outside the history window remains available. Failed
reads show refresh guidance and preserve the last choices. Plain output contains
the complete picker document. Existing persisted study and allowance formats
are unchanged.

J134 is retained at
`/tmp/kuzushi-study-history-20261008/tui/20261008-182730/J134`.
It records 24 machine passes, no failures and four human review questions, with
23 authenticated captures across six sizes and a no-color cold restart.
The fixture performs six owned discovery jobs with fully intercepted transport
to establish prior receipts. The history dataset adds 150 labeled, unstarted
plan copies and one malformed record. The picker loads directly from the scope
tree, retains 100 choices from 153 inspected entries, and discloses its choice
limit. Keyboard paging exposes the partial-history warning at 40x12.

A temporary owned history-directory failure produces an honest error while
retaining the selected study. Restoring the directory and refreshing recovers
the list. Cancel and explicit selection preserve the two-boundary draft; no
additional discovery starts, provider requests or source changes occur. The
six committed fixture requests remain unchanged. The native binary SHA-256 is
`4bc6409fc270d2641801b3d10800a58cd6f3dbf5d962f9c096e696f46751d27d`.
An earlier retained run passed 17 machine checks; the later run adds explicit
narrow limitation disclosure and no-color restart. The harness driver is unchanged.

Seven focused core history tests, eight hydration tests and five picker tests
pass. They cover bounded width and bytes, cancellation, malformed metadata,
symlinks, delayed reading, target isolation, late completion, retry and retained
selection. The complexity gate passes after extracting scanning and request
selection helpers. Raw exit 4 remains `REVIEW_REQUIRED`; separate implementation
judgments do not grant human acceptance or broad reference parity.
All ten repository summary gates pass in
`/tmp/kuzushi-study-history-20261008/verify.json`, with its recorded local
platform and CI exclusions.

There are no live model requests, source execution, exploit work, reproducer
work or vulnerability patches. Live OAuth validation, broader module usefulness,
complete context-matrix acceptance and the full investigation journey remain
open. No broad delivery milestone is closed by this increment.
