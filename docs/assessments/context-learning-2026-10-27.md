# Context experiments, reviewed lessons and recorded source revisions

Status: bounded local qualification with remaining interface findings. Operator acceptance, live-model usefulness and full reference-interface parity remain open.

## Behavior changed

The discovery-pass overview now names each context case, its baseline or candidate role and its own repetition count before explanatory prose. It shows the total fixed workload. Changing the default for new cases does not rewrite existing repetitions. A missing baseline is disclosed without presenting every case as a candidate.

The projection is pure TUI presentation over the existing matrix. It changes no plan, approval, accounting, context, model, dispatch policy or artifact format. The complete case editor and source readers remain available. The separate [scope overview changes](scope-overview-2026-10-27.md) keep literal boundaries, coverage and workload readable.

Two focused tests failed against the earlier presentation: case names and individual workload were absent, and an unset baseline was not disclosed on this overview. Both pass after the change. The focused tests also cover different per-case counts, wrapping and unchanged form state.

## Current qualification

Retained local evidence root: `scripts/devex/artifacts/context-learning-current-20261027/`. Artifact directories are local qualification records, not published source files.

| Check | Result |
| --- | --- |
| Study presentation | 36 Rust passes, zero failures; `control/context-cases-green.log` |
| Scope review | 101 Rust passes, zero failures; `control/final-scope-tests.log` |
| Locked workspace build | Pass; `control/final-workspace-build.log` |
| All-target Core/TUI Clippy | Pass; `control/final-clippy.log` |
| Changed-code risk proxy | Pass; `control/final-risk.log` |
| J363 context matrix, partial work, explicit retry allowance, triage, export and restart | 79 machine passes, zero failures; eight answered agent questions |
| J357 accepted lesson, inactive context copy, separate follow-up approval and retirement | 70 machine passes, zero failures; seven answered agent questions |
| J367 native observations across two actual Git SHAs and five export formats | 38 machine passes, zero failures; four answered agent questions |

Final runs are `J363-attempt-3/native/20261027-080138/J363`, `J357-attempt-1/native/20261027-072637/J357` and `J367-attempt-2/native/20261027-075624/J367`. Together they retain 150 authenticated text/ANSI/source-receipt capture triples. Twenty-nine replays were directly inspected for the final selections. All 19 questions have State, Intent, Honesty and Craft answers in their `agent-review.json`. Raw exit 4 remains `REVIEW_REQUIRED`; agent judgment is `PASS_WITH_FINDINGS`; operator acceptance remains false.

J363 uses native SHA256 `0ef11a9d90cdf12d3a092595e1c6bd4b60e0d12634c2e5a90b8786d53f268816`. J357 and J367 use `fd8c0cf4c2d1a0ca7b585bb20df2699915b65583b4a13ee9cae9e90ebcd575fd`, before the case-overview-only change. Both flows use a single context rather than that changed matrix branch. Each run freezes the 13-program native bundle and authenticates repository/runtime inputs before and after execution; the input and empty-index guards pass. J367 additionally freezes its freshly built relationship-fixture test program. No production tool is replaced by that fixture program.

The earlier J363 run retains the absent-name finding. The first J367 attempt stopped at sandbox access to the local tmux socket before product launch. A J363 controller attempt also stopped before product launch because it still expected the earlier native hash after a Python-version-specific hashing helper failed. Separate corrected attempts retain the original failures. No product assertion or driver was weakened.

## Independent state checks

Post-run reads use stable immutable ledger copies only after verifying that the live WAL is absent or empty. The live databases remain unchanged. Each final run retains `independent-end-state.json` and `capture-hashes.json`.

- **Context matrix:** two exact inactive context revisions, three jobs per case and one worker. The first allowance permits seven requests with two protected for Review. An intercepted transport rejection leaves four jobs completed, one failed and one parked. An explicit revision raises the total to nine and changes attempts per job to two while preserving all six work ids and the protected Review allocation. Resume reaches six completed jobs with seven retained attempts, including the failure. Alpha recurrence is 3/3 and Beta is 1/3. Four observations and two scripted operator decision records remain. Seven intercepted requests are settled, two Review calls remain unused, and restart makes no new request. The globally active Gamma context and source bytes stay unchanged.
- **Reviewed lesson:** a manually authored lesson is reviewed, accepted and copied into a separate inactive context. Three baseline jobs and three separately approved candidate jobs share the same six-call accounting. The frozen lesson, including Unicode text and its limitations, reaches the three candidate agentic requests; installed Semgrep uses its own literal policy rule. Six raw observations and the original scripted operator decision remain. Later unversioned source applicability requires reassessment. Retirement preserves lesson text and history while blocking new use of the copied context. No-color restart retains six settled intercepted requests and creates no further work.
- **Source revisions:** an offline owned bundle provides actual commits `7cac9e253984e19ccc6aaeee3eb157de049ba667` and `c557cdbf94b931ecc250b33d33d793f79036a908`. Two runtime-free scans retain four observations with exact snapshot/blob/tree bindings. Finding files are dirty, untracked fixture text, not committed versions of those files. Each retained blob matches its saved preimage. The older observation remains readable after its live file is removed. Comparison exposes both full SHAs and dirty state. JSON, JSONL, CSV, SARIF and Markdown-bundle exports retain the later observation source and the earlier relationship endpoint sources. Two scripted operator decisions survive restart; no absence is classified as a fix.

All fixtures contain inert owned greeting or public-example policy text. Source programs are never executed. J363 and J357 intercept every provider fetch with no network fallback; J367 denies provider transport and records zero attempts. The simulated adapter requests explicitly select GPT-5.5 with medium reasoning. These runs add **zero live provider requests**. The earlier twenty-request live allowance remains exhausted. Unavailable dollar charges remain unavailable in the investigation receipts.

## Remaining limits

J363 imports manually declared context drafts whose grounding checks report failure. This tests exact selection and isolation, not successful architecture grounding or accepted Map quality. J357 qualifies manual reviewed-lesson reuse and retirement, not new live lesson generation. Its synthetic policy marker establishes neither a vulnerability nor improved scanner precision. The installed scanner's complete package closure is not authenticated by these repeats.

Recurrence is visible independently of severity. Evidence confidence is available in Review; the context-results page does not yet show that evidence-confidence axis or offer a direct finding shortcut. A model self-score, recurrence ratio and evidence confidence must keep distinct meanings. This increment adds no new confidence inference.

Long context ids, hashes, repeated controls, sparse wide panels and dense receipt prose remain interface findings. Small terminals require paging; physical-terminal font fallback remains unproven. ANSI cell replays use Menlo 15 and a disclosed dark background and are not OS screenshots. The named flows complete, but these records do not close the broader [bounded-investigation acceptance work](../quality/bounded-investigation-acceptance.md).
