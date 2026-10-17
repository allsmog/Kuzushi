# Exact source prefixes and a working bounded context handoff

The deterministic systems context producer now preserves exact UTF-8 source and
hands realistic default output to the standalone invariant context consumer.
Its Core qualification covers bounded lexical context production. Downstream
model quality, human UX, reference parity and bundled research execution remain
open. Everything stays a draft on `main`.

## Reproduced failures and repair

Three before-fix tests failed. A file ending exactly at its byte limit was
reported as truncated. A multibyte character cut at the prefix boundary became
a replacement character. Invalid UTF-8 inside source was also rewritten.

The shared reader now checks file sizes on the opened handle before and after
the bounded read. It keeps exact valid UTF-8, trims an incomplete trailing code
point only when the file prefix is truncated, and excludes invalid UTF-8 with
an explicit reason. Literal replacement characters already present in valid
source are preserved. Raw bytes read still count toward the inspection budget, including bytes
excluded from retained text. Version 1 coverage adds `includedSourceTextBytes`
and `incompleteUtf8PrefixBytes`; existing coverage fields remain.

A separate before-fix test used 64 owned files with safe checked parsing
operations. Default gathering produced 50 surfaces and 475,710 encoded bytes.
The next consumer rejected that data at its 128 KiB envelope cap before any
request. Its unused packs and repeated lexical evidence caused most of the
size. The original one-comment fixture had not exposed this default failure.

The explicit supplied-context envelope now has a 4 MiB hard bound. Only selected
surface ids, repository-relative paths and positive line anchors enter model
input, alongside freshly captured bounded source. Lexical annotations, packs
and caller coverage metadata are explicitly omitted. The 32 KiB source-text
budget, 80 KiB complete prompt cap, selected model, source limits and request
limits remain unchanged. Unsupported paths, excessive surfaces and oversized
input still fail before transport. The default-sized handoff makes exactly one
fully intercepted request, retains omissions and accepts no context or findings.

Replay Inputs displays the actual source and three anchor fields supplied to
the model, with the omitted annotation categories named. The gatherer's existing
bounded surfaces and packs retain their original shape. `RELEASING.md` records
the additive coverage fields and migration for consumers of frozen surfaces.

## Source and execution evidence

The frozen CLI inspected a copy of 18 current Kuzushi repository files without
executing target code. Seventeen surfaces contained 165 signal quotes, each
checked against its exact source line and the documented 240-character clip.
Source bytes were unchanged. Evidence and source caps produced an honest partial
result with exit code 4 and usable JSON. No observation, decision, call
reservation, work attempt, code index or CodeQL work was created.

There are 133 distinct focused Rust passes, including shared dispatch, the
producer and consumer, affected source-reader consumers and policy inventory.
The renderer extraction repeats its 15 relevant checks. The workspace build,
all ten summary gates and the CRAP-risk gate pass for 464 changed code files.
The first gate run found a 42-line renderer; a focused rerun confirmed it, then
summary rendering was extracted and verification passed. The initial copied-
source verifier incorrectly expected exit zero for partial work; it now checks
the documented partial exit code rather than treating the receipt as failure.

The registry still has 189 registered and 118 visible tools: 81 Core, 32 Labs
and five Compatibility. All 189 dispatch policy tuples and the visible catalog
are unchanged. Only the hidden invariant context option description changes.
The verification receipt is dirty draft evidence, not a clean publication
receipt. Frozen source/runtime manifests separately prove native-run stability.

## Terminal evidence and remaining work

Final sequential J314/J324 have 54 machine passes, zero failures and 102
authenticated capture pairs. They cover 120x36, 160x48, 96x89, 80x24, 60x20 and
40x12, keyboard paging, invalid options, exact-byte CLI cases and no-color
restart. J324 reaches all 53 Result and 77 Inputs rows. Its two model requests
are fully intercepted; no live provider is called. A protected Review call
remains separate from its exhausted synthetic Context capacity.

Fourteen ANSI cell replays were inspected. These are rendered terminal cells,
not OS screenshots or formal human approval. Exact source text appears in the
first color 40x12 Inputs frame. After restart, a notice reduces the viewport to
four rows: the source path is visible first and source text requires paging.
Long ids, repeated receipt metadata, operational transcript chatter and narrow
chrome density remain open. Seven human UX judgments remain `REVIEW_REQUIRED`.
Reference parity remains unqualified after these checks.

One in-scope hidden Core action still needs full qualification: `uaf-hunt:hunt`.
All nine broad milestones remain open. The producer's supported deterministic
role is demonstrated; semantic inference and model usefulness remain separate.
No exploit development, reproducer work, vulnerability patching or bundled
trigger generation was executed. No project commit, push or new live request
was made. Historical live usage stays fourteen requests with no remaining
allowance.

Evidence: `/tmp/kuzushi-source-prefix-fidelity-20261017`, including before-fix
logs, focused results, real-source quote proof, registry delta, native manifests,
journey reports and the visual review.
