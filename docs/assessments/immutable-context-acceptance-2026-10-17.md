# Immutable context acceptance and scanner reading

The accepted-context-reference delivery item is implemented and verified locally.
Jobs consume an exact saved revision without activating it globally. Model-backed
discovery and Review retain their scanner text separately from later rendering
or context edits. Source changes refuse new execution while preserving historical
reading. Context generation quality and the complete operator experience remain
open in their own acceptance requirements.

## Requirements and current evidence

| Required behavior | Evidence |
| --- | --- |
| Versioned immutable references and authenticated saved bytes | `scan/application/threat_model_digest.rs`, `scan/infrastructure/threat_model_digest.rs` and supporting `scan_context` storage retain bounded typed references. Current tests reject malformed versions, oversized objects, corruption, missing objects, foreign targets and mismatched text hashes. |
| Select accepted context independently of the global active context | Shared SAST dispatch consumes Alpha, Beta and explicit omission while Beta stays active. J273 selects Alpha, prepares three jobs, reads missing-object failure, restarts and inspects changed source while Beta remains active. |
| Bind every fixed job to the same accepted revision and scanner projection | J273 independently checks the three prepared job inputs against the plan's exact references. Refreezing preserves recorded bytes and explicit absence. Legacy approved work without a saved projection requires replacement approval. |
| Preserve supporting context independently of subsequent edits | Current shared-dispatch tests consume frozen supporting text after the live supplement changes. Recorded absence remains absence. Invalid live context requires an explicit choice. |
| Recheck source and lesson eligibility without rewriting accepted context | Current source-drift tests refuse execution and retain historical inspection. J273 adds an inert fixture file and verifies identical saved text and object bytes with `sourceMatchesAtInspection=false`. J304 blocks future use after lesson retirement and retains historical evidence. |
| Show the text supplied, its source status, omissions and full provenance | The repaired scanner reader shows selected context, compact source status and request text first. Limits, omissions, full source explanation, revision and hashes remain reachable by paging and in plain output. Current framed tests cover all six sizes, Home/End/PageDown, draft/cursor preservation and return. |
| Consume the selected context downstream | Current SAST runtime-capture tests and the Review prompt test verify selected-context consumption. J304 executes three baseline and three candidate jobs; all three candidate adapter requests carry the exact saved UTF-8 lesson context. Transport is intercepted. |

The storage object's identity is a domain-separated BLAKE3 hash. The scanner
text has its own SHA-256. Independent verification checks both, the retained
object backup, plan membership, active context and actual ledgers. Uninitialized
allowance tables are null facts, not zero-dollar accounting.

## Reader repair

The original current-build J273 had 27 machine passes and no failures, but its
captures put limitations and the context catalog ahead of request content.
At 80 columns the actual text began below the first frame; at 40 columns the
reader offered only a few lines beneath the catalog.

Scanner mode now uses the full document area with a pinned selected-context
label. Its renderer and paging use the same layout. The initial source label
distinguishes matching, historical, unchecked and unfrozen previews. Original
request warnings stay in the exact text. Other context modes keep their catalog.
No tool option, dispatch contract, artifact format or spending policy changes.

## Verification and limits

All 75 distinct focused Rust tests pass: 23 Core and 52 TUI. The locked workspace
build, all-target TUI Clippy and the risk proxy pass for the four production
files. Final quick repository verification is recorded with this draft.

Sequential final J273 and J304 run on one frozen build with 93 machine passes,
zero failures, 81 capture pairs and ten pending human judgments. Thirteen
binaries, 4,606 source inputs and 808 runtime inputs match before and after.
J273 records 38 passes and 27 captures. J304 records 55 passes and 54 captures,
six fixed completed jobs, six observations, one retained human decision and six
settled intercepted requests. Dollar charges remain unavailable.

Eighteen ANSI cell replays were inspected, covering the size matrix, both narrow
request pages, provenance, missing-object refusal, no-color restart, historical
source and the learning workflow. These are terminal reconstructions, not OS
screenshots, and close no formal operator judgments. Report metadata remains
dense; full reference parity and overall model usefulness are unqualified.

One failed native candidate is retained. Its assertion expected a component row
one page too early at 40 columns. The final journey preserves that assertion on
the next page and retains the same production build. An independent verifier's
initial plain-SHA object assumption was corrected to the documented BLAKE3
identity rather than discarding the integrity check.

Evidence root: `/tmp/kuzushi-context-acceptance-20261017`, including focused logs,
build/risk results, the quick receipt and `native-v3` manifests, verification,
captures and ledgers. No live provider request or target-source execution is
added. Historical live requests remain fourteen with no approved capacity left.
This increment remains a draft on main.
