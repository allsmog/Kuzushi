# Failed taint review and retained candidate truth

The bundled hidden `taint-iris-next:hunt` action now remains failed when model
output is invalid, including the explicit `allowDeterministicFallback` path.
The prior implementation reported that path as successful, recorded a completed
finding run and printed `hunt complete`. A regression test reproduced the
successful envelope before the fix. Deterministic candidates remain available
for review, with their original unverified text, error, retry count and cost.
Candidate retention supplies no model verdict or completed Scan.

The shared finding lifecycle receives the actual terminal status. Both an empty
failure and an explicitly retained candidate produce failed finding runs.
Existing decisions are not created or rewritten. The compatibility data status
`hunted-with-agent-output-invalid` stays readable; new canonical result status
is `failed`. Historical receipts are unchanged.

The bundled entry point is now Labs and cannot publish a primary phase result,
matching its experimental decomposed discovery action. Its name, input options,
default mode and exact dispatch remain. This curation prevents a deterministic
plan or an experimental candidate response from completing Scan. It is not a
claim of broader engine qualification or a proposed implementation deletion.

Replay can read one exact retained result after failed, canceled, interrupted,
blocked or skipped work, including when progress updates were coalesced or
saturated. Artifact authentication, matching producer/status, healthy event
integrity, durable writes and current delivery remain required. Missing,
compound, stale, mismatched or corrupt evidence cannot enable the reader.
The Result remains distinct from the full receipt, which retains progress
fidelity and the failed outcome. This does not make omitted progress complete.

## Action audit

| Dimension | Evidence and limits |
| --- | --- |
| Purpose | Bundled deterministic taint evidence preparation followed by optional model candidate discovery. Structural fallback is an explicit candidate-retention choice. |
| Phase | Auxiliary experimental Scan action. Neither plan nor hunt publishes a phase result. Its historical DAG membership is retained. |
| Inputs | Repository target, bounded legacy source collector, optional selected threat model, catalog pin, engine limits, explicit model and Discovery allowance. Accepted `scanScopeRef` membership is unsupported. |
| Execution | Existing shared prepared dispatch and real executor remain. Native shell checks use intercepted transport with actual model-free context preparation and explicit cached-prerequisite reuse. Headless DAG ordering is not inferred. |
| Outputs | Invalid output retains structural candidates only when requested, records failed result and finding runs, and preserves errors, retries and cost uncertainty. No automatic human decision or runtime proof. |
| Failure | Empty failure and candidate retention are covered separately. Replay keeps the complete authenticated output readable without changing failed state. Other schema, source-drift, cancellation and engine branches remain unqualified. |
| Resources | Initial and repair sessions use the shared Discovery accounting. The owned fixture admits two requests and preserves one protected Review call. It offers no new scan jobs. Whole-engine work and source-execution policy remain unqualified. |
| Interfaces | Failure construction and finding persistence are shared by shell/run/scan callers. Interactive prerequisite reuse is shell behavior. Result/receipt reading is shell presentation; plain output retains the same saved text and canonical status. |
| Value | Correct failure truth, retained observations and readable recovery are demonstrated on an inert fixture. Live detection quality, precision, scope isolation and general product value are not established. |

## Verification

All 324 distinct focused Rust checks pass, including seven authentication
checks, shared dispatch, finding lifecycle, reader eligibility and six-size
rendering. The final workspace build and all ten repository gates pass.
The CRAP-risk proxy covers 444 changed code files. One live test remains ignored.

Final sequential J326/J304 have 81 machine passes, zero failures, 77
authenticated capture pairs and nine pending human judgments. They use the same
frozen CLI and six-program runtime bundle with unchanged source/runtime inputs.
J326 retains one unverified candidate and failed result/finding runs, settles
two Discovery calls, refuses more work and protects one Review call. J304 runs
three baseline and three candidate jobs, retains the human decision, supplies
reviewed lesson text, exports the report and blocks retired guidance after
restart. All eight provider requests are intercepted; no target source executes.
The fresh full registry changes only the bundled taint descriptor. The actual
visible catalog remains 118 tools, including 81 Core, 32 Labs and five
Compatibility actions. Evidence is saved in
`/tmp/kuzushi-taint-hunt-outcomes-20261017`.

All 77 terminal-cell replays were rendered and twelve inspected, including all
six Result sizes, no-color reading, Report, retirement and restart. They are
not OS screenshots or formal human acceptance; the selected font does not
reproduce terminal font fallback. The first 40-column Result shows failed state,
unknown cost, committed calls and retained candidate uncertainty. Restart keeps
those facts, with the candidate count reachable by paging.

The initial regression and prerequisite journey failures are retained. A
documentation edit during one native attempt invalidated its runtime manifest;
that attempt is not final frozen evidence. A complete-journey attempt omitted
required MCP siblings and stopped before inference. The bundle was corrected
without changing scanner gates. The formatting gate caught the new fixture;
its focused failure was retained before formatting and a full final rerun.
Renderer expectations now name Result while retaining checks for the actual
error, full receipt, supplied inputs, paging, held drafts and plain completeness.
Artifact authentication and prerequisite consent were not bypassed.

Repeated promoted error text remains dense, and fallback's legacy
`agent selected CWEs` label can misattribute deterministic selections. This
needs a separate attribution repair. Narrow Report still spends its first frame
on general guidance. Large-history performance, complete engine cancellation,
exact scope/source isolation, schema-failure branches, live quality and reference
parity remain unqualified.

The operator's **Keep as draft** decision remains. Work stays uncommitted on
`main`, with no push or new live request. The fourteen-request live experiment
allowance is exhausted. Five hidden Core actions still need full qualification;
the descriptor-only Core action count falls to zero because this bundled action
is curated to Labs. This does not qualify the engine. All nine broad milestones,
operator UX acceptance and reference parity remain open.
