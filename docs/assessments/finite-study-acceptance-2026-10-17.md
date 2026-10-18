# Finite study plans and approval visibility

Finite study plans with three-pass defaults and restart recovery are implemented
and verified locally. An accepted plan has fixed membership, frozen conditions,
bounded attempts and an explicit allowance. Findings cannot add jobs. Stop,
allowance exhaustion and restart retain recorded work without granting new
execution authority. Broader spending, module usefulness, monorepo architecture
and operator acceptance remain separate open requirements.

## Requirements and evidence

| Required behavior | Current evidence |
| --- | --- |
| Three discovery passes, one worker and whole-repository scanning available | `capabilities/campaign/study_plan.rs` prepares the shared SAST input with three passes and one worker by default. Whole-repository discovery remains available. Current batch tests enforce the finite trial bound. |
| Freeze exact jobs; no recursive or finding-generated additions | `campaign/batch.rs`, batch validation and `approved_work.rs` authenticate job membership and plan digest. Scope and matrix compilers produce fixed jobs. The dispatcher consumes those jobs; discovery output does not extend the queue. J130 finishes the same 27 jobs across nine boundaries after an explicitly approved allowance revision. |
| Bind source, context, scope, model, prompt, configuration and workers | Batch equivalence and shared prepared dispatch reject changed inputs before execution. Current tests cover source drift, context isolation, engine bytes, tampered jobs, matrix conditions and worker expansion. Missing source or context evidence remains a refusal. |
| Finite attempts, including transport failures and cancellation | CLI approved-work tests bound quota failures and job attempts. J121 retains four attempts for three Scan jobs, including a canceled attempt; completed selection excludes that canceled run while preserving its history. |
| Limits do not authorize silent expansion | J130's four-call allowance protects two Review calls, completes two discovery jobs and parks 25 before they consume attempts. An unchanged resume is refused. A separately reviewed 29-call revision completes the original jobs, retaining the two protected Review calls. |
| Stop preserves partial work and unresolved reservations | J131 completes one job and cancels one attempted job, leaving 25 unstarted jobs. Its two committed intercepted calls include one unresolved reservation. Restart keeps the same 27-job plan, attempts and accounting, with no automatic work. |
| Real phase consumption and explicit result selection | J121 runs the context producer jobs, accepts context, executes discovery, explicitly accepts partial and completed results, records human decisions and exports Report. Dependency labels alone are not credited as execution ordering. |
| Recovery preserves history and requires new authority where needed | Current checkpoint and CLI recovery tests retain source identity, exact context, Unicode drafts, attempt identities and accounting. J121 restarts through missing-context recovery and retains four raw observations, two findings and three human decision records, with effective FP and defer decisions. |
| Approval remains understandable while reading a long plan | The repaired allowance page pins fixed jobs, authenticated workers, attempt limits, total calls, protected Review calls and the allowance model above every page. Unknown dollar consumption stays beside approval. J130 verifies these terms at End across all six viewports. |

## Approval repair

The first nine-scope native candidate exposed a concrete approval defect: at the
end of the long plan, `y approve` was visible while total calls and protected
Review capacity were off-screen. The fixed terms now remain pinned throughout
reading. They come from the parked canonical prepared request. Worker counts
come from the matching frozen receipt; a mismatch is shown as unknown.

Rendering and approval share the reduced document extent, including after
resize. Early approval stays blocked. The full document and plain output retain
all terms. Long model labels are abbreviated only in the pinned display. No
tool option, artifact schema, public module contract or spending policy changes.

## Verification

All 186 distinct focused Rust checks pass: 51 Core, 75 CLI and 60 TUI checks.
The locked workspace build, all-target TUI Clippy and the risk proxy pass. The
risk check covers eight changed production files, including the preceding
context-reader repair. Final repository verification is recorded separately in
the publication receipt.

| Final native case | Machine passes | Failures | Capture pairs | Pending human judgments |
| --- | ---: | ---: | ---: | ---: |
| J130, nine-scope allowance exhaustion and explicit revision | 55 | 0 | 39 | 5 |
| J131, Stop and restart | 20 | 0 | 12 | 4 |
| J121, context through Scan, triage, Report and recovery | 192 | 0 | 117 | 19 |
| Total | 267 | 0 | 168 | 28 |

The cases ran sequentially in tmux using 13 frozen executables and authenticated
manifests covering 4,608 source inputs and 808 runtime inputs. The main binary
SHA-256 is `3b5befbe1a8310adea7b1fafc241d1c05523c3b57b19847dbcc48b68cc2b2018`.
J130 is retained in `native-v4`; J131 and J121 are in `native-v6`. Production
binaries and source inputs are identical. Between those bundles, only J131's
Stop assertion changed after J130 completed. Each case independently verifies
its manifests before and after execution.

Independent checks authenticate actual queues, plan membership, source hashes,
context references, attempt history, allowance ledgers and capture provenance.
The three final cases make 34 intercepted requests across separate fixture
investigations. Failed candidates have additional intercepted requests. No live
provider request, target-source execution or queue-completion injection is
added. Historical real requests remain fourteen with no approved capacity left.

Twenty-two ANSI cell replays were visually inspected: eight J130 frames, five
J131 frames and nine J121 frames. They include the approval size matrix,
operator Stop, canceled versus unstarted jobs, partial counts, final selection,
40-column Report and no-color restart. They reconstruct captured live terminal
cells using Menlo and a chosen background; they are not OS screenshots or formal
operator approval. All 28 human judgments remain pending. Per-case metadata and
direct Campaign chrome remain dense; full reference parity is unqualified.

Retained failed candidates include an outdated settings-row cursor, an obsolete
caption, a fragile fixture SQLite reader and the repaired approval defect. The
SQLite observation failure did not terminate the dispatcher; its existing
process was followed to completion before retrying. Assertions now identify the
actual settings row and distinguish canceled from unstarted work. A replay
selector was also corrected to inspect the exact final Report frame rather
than an earlier frame with a matching suffix. Assertions and evidence checks
remain in place.

Evidence root: `/tmp/kuzushi-study-plan-acceptance-20261017`. It contains focused
logs, build and risk results, continuity proof, native manifests, ledgers,
captures, independent verifiers and visual-inspection records. The earlier
immutable-context qualification is documented separately. Three delivery items
are locally verified; six original delivery items remain open.
