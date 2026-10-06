# Bounded source traversal and responsive scope history

This increment supports source-bound investigation planning. It does not complete
logical-scope study compilation, inherited scan context, AI proposals, the full
module audit or the complete operator journey.

Source identity and blob indexing share one iterative directory walker. The
walker excludes symlinks and generated paths, verifies canonical containment,
tracks visited directories and caps all examined entries at 1,000,000. Empty
directories and ignored entries consume that bound. Exceeding it fails without
a complete source identity. Existing identity/file hash serialization, generated
path exclusions and oversized-file membership rules remain unchanged. The
separate inventory limits remain 100,000 entries, 512 MiB inspected and 256 KiB
per inspected file. Source identity retains 1,000,000 files/16 GiB and blob
indexing retains 200,000 files/1 GiB, with a 64-MiB per-file ceiling.

A 64-KiB heap buffer permits cancellation between read chunks without consuming
a small thread stack. Remaining aggregate bytes constrain the actual read, so a
file growing during capture cannot bypass the byte allowance. Full blob capture
reserves capacity before storing the file. Hash-only registration publishes no
snapshot after a canceled traversal. Public per-file observer callbacks remain
one per successfully hashed file; internal context-backed traversal can report
progress while walking directories that contain no files.

Scope inventory, edits, acceptance, exact reads, file pages and latest-head lookup
wait on locks with cancellation checks. Existing lock opening and recovery
contracts remain in place. The additive `pack:scopes operation=latest` returns
`data.review` as a saved revision or null. Opening and refreshing the TUI use
background prepared dispatch instead of blocking the UI thread on the strategy
ledger. Cancellation and interruption settle the scope overlay's pending state,
retain the saved draft, and permit a separately requested retry.

Focused evidence under `.git/bounded-investigations/` records nine traversal tests,
46 total incremental-index tests, eight lock-matched tests (including six direct
lock tests and two existing lockfile scanner tests), 38 scope tests, three source
binding tests, 13 scope-named TUI tests and the separately added real canceled
scope-event test. The shared SAST cancellation regression also passes. The first
small-stack test exposed a stack-resident read buffer; its failed receipt remains,
and the heap-buffer repair now passes on a 300-level tree in a 64-KiB thread.

J82 at `/tmp/kuzushi-bounded-investigations-tui/20261005-151131/J82/` has eleven
machine passes and six separately judged passing captures. A real Python process
holds each exact inventory/strategy lock and is verified live. The native TUI
cancels each wait, shows stopped work, retains its draft, retries only after
operator input and exits through explicit confirmation. The fixture includes a
300-level chain and 128 empty sibling directories; discovery stays whole repo.
The journey invokes no scanners or live providers and creates no scan plans or
work/call reservations. Text, ANSI, actual dimensions and native identity are
recorded separately from the raw REVIEW_REQUIRED result.

Failed predecessors are retained. The first native cancellation settled the
backend but left Working visible and prevented retry; the aborted-event hook
fixes that defect. A later driver exit failure is retained too. J82 verifies the
120x36 and 40x12 lock/cancellation states. It does not replace J81's prior six-size
editing/restart evidence or certify every viewport for every new state.

Workspace build and the CRAP proxy pass. Quick verification passes all ten gates
at 2026-10-05T22:11:26.432Z in
`.git/bounded-investigations/source-scope-final-verification.json`. That receipt
records the dirty worktree and conservative drift flag, excludes full CI, and
precedes this documentation closeout. No commit, push, model request or scan job
is performed in this increment.

Cancellation is cooperative between filesystem operations; it cannot interrupt a
kernel-blocked filesystem call. Native lock testing is on macOS. Windows behavior,
all filesystem replacement races, million-entry/16-GiB performance, durable lock
recovery under every crash seam and completed scoped study execution remain
unproven. The hard limits are local source safety bounds, not dollar ceilings.
Every implementation milestone remains unchecked.
