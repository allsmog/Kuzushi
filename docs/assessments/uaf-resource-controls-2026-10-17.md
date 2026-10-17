# Bounded UAF resource controls

The UAF action now enforces local request deadlines, cancellation and byte
bounds, preserves partial finding history and exposes its limits before work.
It is auxiliary Labs Scan work and cannot complete Scan. Full qualification
remains open, particularly compiler-database selection and source grounding.
Everything stays a draft on `main`.

## Reproduced failures and repair

Four before-fix checks failed: canceled work still started its helper and
completed; `clangTimeoutSecs` did not stop a late reply; a 2 MiB reply was
accepted without a frame guard; and an invalid search expression appeared as
an empty successful result. These were local controlled tests with no live
provider or target-code execution.

The MCP adapter now has bounded writer and reader queues. One request deadline
covers pipe writes and skipped replies, with shared cancellation checked while
waiting. Frames are limited to 512 KiB, cumulative replies to 1 MiB and skipped
messages to 64 per request. Blank lines consume those same bounds. Fatal
transport failure stops the helper without automatic restart. Normal closure
allows 200 ms for shutdown, then reaps the process group. An undrained stderr
pipe can no longer block the helper. Mutable borrowing replaces the handler's
raw pointer and unsafe `Send` implementation.

Repository search now uses the shared controlled subprocess adapter: five
seconds, 512 KiB stdout and 16 KiB stderr. Search exit codes are checked;
non-match and failure remain distinct. Repository replies have a 512 KiB
serialization ceiling before entering model history. Local repository errors
are counted and retained. Step exhaustion, navigation errors and absent clang
navigation produce partial results. Finding-run persistence uses the same
partial status, so a failed navigation cannot become a completed empty run.

The descriptor declares actual defaults, ranges and compatibility aliases.
`maxAgentSteps` accepts 1..400 with default 120; `clangTimeoutSecs` accepts
1..300 with default 60; `maxFindings` accepts 1..500. Shared preparation rejects
out-of-range input. The selected model and reasoning configuration are retained.
Unknown dollars remain absent with unresolved-spend metadata in both envelope
and payload. Provider requests and retries keep the shared allowance boundary.

The primary result names candidates, work and limits. Technical protocol bounds
are retained in `data.localIoLimits`. New receipt fields are additive and old
reports load their defaults. Existing tool identity, JSON pair controls,
finding rows and transcript paths remain. Historical artifacts are unchanged.

## Verification

There are 51 distinct focused Rust passes, including the dispatch-policy
inventory, plus five repeated output checks after the display wording repair.
The workspace builds. Source risk checks cover 478 changed code files. The
initial risk check found a long search function; command construction was
extracted. All ten final repository gates pass. The formatter also required
canonical layout and template-string syntax in the new provider fixture; the
formatted fixture is checked in the final native pair.

Final sequential J328/J279 have 65 machine passes, zero failures and 74
authenticated capture pairs. J328 uses one fixed source-only job with two
intercepted requests, two model steps, a one-second delayed-helper deadline and
one protected Review call. The helper is reaped, the tool and finding run stay
partial, source bytes stay unchanged and restart adds no requests. J279 retains
three completed local passes, six observations and two scripted FP decisions.
Both cover 120x36, 160x48, 96x89, 80x24, 60x20 and 40x12, including no-color
restart. J328's narrow Result document is exhaustively paged.

Fourteen final ANSI cell replays were inspected. These are rendered terminal
cells, not OS screenshots or human approval. An earlier pair was archived
before replacing ambiguous unit copy with a labeled `1s` deadline. The final
pair was rebuilt and repeated. Eight human judgments remain `REVIEW_REQUIRED`.

The first broad gate also caught three older documentation phrases using a
reserved proof term. The focused architecture check confirmed them, and the
wording now names source anchors and repository-relative paths directly.

The registry remains 189 actions and 118 visible: 81 Core, 32 Labs and five
Compatibility. The visible catalog and 189 dispatch-policy tuples are
unchanged. Only UAF descriptor metadata and limits differ from the prior
checkpoint. No module implementation was deleted.

## Qualification still open

The helper still discards the accepted `compileCommandsPath`. Its actual
selection must be repaired and checked. Source/finding/graph grounding,
immutable context consumption, read/list truncation disclosures, real clangd
navigation, positive headless execution and detector usefulness remain open.
Moving the action to Labs does not close those requirements.

The narrow Replay first frame also omits the selected result's candidate count
when it removes the summary; its footer count belongs to the workspace. This
needs a shared-reader repair. Technical timeout chains, repeated scope/receipt
copy and narrow chrome density remain open. Reference parity is unqualified.

No hidden action remains in Core awaiting curation, but the functional audit
and all nine broad milestones remain open. No project commit, push or live
request was made. Historical live usage stays fourteen with no remaining
allowance. Excluded exploit, reproducer and patch work was not executed.

Evidence: `/tmp/kuzushi-uaf-resource-controls-20261017`, including before-fix
logs, final focused checks, registry delta, native manifests, journey reports,
archived first captures and the final visual review. The verification receipt
is dirty draft evidence, not a clean signed publication receipt.
