# Classifier scores and review authority

The classifier action previously treated an empty object as score 0.15,
replaced explicit zero with a guessed value, clamped out-of-range scores and
trained its percentile estimator with those values. A retained probe against
the original library reproduces all four cases. Loading history also ignored
the newly requested percentile. Finally, scoring below threshold wrote a
`needs_review` opinion into the findings ledger. None of that establishes an
evidence-based finding verdict.

Evidence is retained at `/tmp/kuzushi-classifier-review-20261016`, including
`before-probe.json`, `after-probe.json` and the complete registry comparison.

## Tool contract

`classifier-gate:score` remains exact-dispatch compatible and hidden. It is now
an auxiliary Labs Review action with explicit Review accounting. It cannot
complete Review, replace a saved human or automatic opinion, or start a deep
auditor. The existing `shouldDeepAudit` boolean remains a compatibility hint.
The public classifier types and score helpers remain available.

| Dimension | Evidence and limit |
| --- | --- |
| Purpose | Suggest whether stored finding metadata deserves further source review. Ranking and calibration remain unqualified. |
| Phase | Auxiliary Review; no primary phase result or follow-up dispatch. |
| Inputs | Explicit finding reference, finite percentile strictly between zero and one, configured compatible model and approved Review capacity. No authenticated source context is supplied. |
| Execution | Shared prepared dispatch and selected-model routing. The classifier has its own cohesive executor file rather than sharing configuration-path helpers. |
| Outputs | Exact numeric score or partial unscored result, historical threshold and sample count, declared percentile, metadata limitation, unchanged-decision and no-follow-up fields. Existing fields remain readable. |
| Failure | Missing, malformed or out-of-range scores train no samples. Structured invalid output is not replaced by contradictory raw text. Bad state is preserved with an error; failed persistence does not claim a saved sample. |
| Resources | One query with no tool/MCP use, one turn, a 64 KiB metadata prompt and a requested 512 output tokens. Adapter enforcement varies. Internal transport attempts still need approved capacity. Returned state payload is limited to 4 KiB before decoding, not total database IO. |
| Interfaces | Shell and run share dispatch, validation, output and accounting. The action is not a Scan engine. Native failure, limits, export and restart are checked separately from model quality. |
| Product value | Repairs invented low scores, unintended review writes and ignored percentile selection. Retain this optional research action without promoting it or deleting its implementation. Use the supported Review plan for source-grounded triage. |

## Score and history semantics

Every usable score must be finite and within zero to one, inclusive. Zero is a
real value. Boolean-only responses do not manufacture numeric values. An
unreadable response remains partial with no sample or review write, and offers
no automatic continuation.

Persisted histories have a key per exact `f32` percentile. Matching legacy
history remains readable; its old bytes are preserved when later samples use
the new key. Another percentile starts its own stream. Known marker invariants
and numeric precision are checked. Malformed, oversized and invalid state
cannot silently reset history. A sample is applied in memory only after durable
storage succeeds. A failure after a query still consumes its admitted request;
it does not authorize a retry or establish that a model opinion was retained.

Historical thresholds mix prior models, source revisions and potentially
unverified legacy samples. They are not calibrated probabilities or
current-source assessments. Real-model usefulness, complete cancellation and
late-result recovery remain open, so the action stays Labs.

## Verification

There are 327 distinct focused Core passes across classifier behavior, shared
registry consumers and phase ownership. Architecture and the risk gate pass.
The workspace build and all ten summary checks pass. The later warning-only
repair is verified through a new build and native reading. Receipts remain dirty
and unsigned; they are not publication receipts.

The initial J311 completed four intercepted requests, refused a fifth and
retained one observation, the human false-positive decision and two separate
single-sample histories through export and restart. Its 40-column assertion
exposed a warning whose introduction hid the word `unscored`. The warning now
starts with that fact. The original captures and frozen inputs remain retained.
Final native evidence is recorded under `readable-partial`.

Final J311 is `readable-partial/native/J311/20261016-132929/J311`: 24 machine
passes, zero failures, 35 capture pairs and three pending human judgments.
The repaired warning shows `Classifier unscored` on the initial 40-column
screen. Tab opens the full receipt, where paging reaches the explicit
metadata-only limitation. Four reservations settle, a fifth request is refused,
the two percentile streams retain one sample each and the complete human
decision and observation bytes remain unchanged through export and no-color
restart. No classifier phase attempt or follow-up queue is created.

Sequential J304 is `readable-partial/native/J304/20261016-133018/J304`: 55 machine
passes, zero failures, 54 capture pairs and seven pending human judgments.
Its six fixed local jobs and intercepted requests preserve six observations,
the recorded policy decision, exact reviewed lesson text, source-review
requirements, retirement and blocked future use through export and restart.
No model accuracy claim follows from intercepted responses.

Both final journeys use the same 13 programs, 4320 source inputs and 753 runtime
inputs, unchanged during execution. The executable SHA-256 is
`5494dd03cc99cd143f5ffcb5c361df46346438c11f29e8fec51c956967293913`.
`readable-partial/native-evidence.json` authenticates the 89 capture pairs,
viewport dimensions and no-color checks. The total is 79 machine passes and
ten pending human judgments. Selected frames were visually inspected as ANSI
cell replays; these are not OS screenshots or human acceptance. Both journeys
retain `REVIEW_REQUIRED`.

The complete registry has 187 descriptors; only the classifier's purpose,
allowance, maturity and result-ownership facts change. The visible catalogs
remain 79 default and 116 optional-visible tools. The hidden Core qualification
remainder is thirteen actions, including nine descriptor-only cases. All nine
original broad delivery milestones remain open. No module is deleted or
promoted, and no commit or push is made.

The transport is fully intercepted and cannot fall back to the network.
It checks the selected GPT-5.5 model, medium reasoning, redacted metadata,
empty tools and fresh sessions. This tests delivery and spending contracts,
not inference quality. No new live request, exploit development, reproducer or
vulnerability patching is included. The fourteen earlier live experiment
requests remain the entire approved usage.
