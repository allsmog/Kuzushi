# Context matrix stops and retained attempts

The interrupted experiment exposed two operator problems. A failed pass hid the
allowance halt even when another fixed job was parked for exhausted capacity.
Report also called retained attempts "attempted jobs", and its detail view put
the failure history below long context receipts. Six approved jobs could appear
to become seven jobs after a retry.

The campaign notice now discloses allowance exhaustion alongside completed,
failed and parked counts. Report and allowance controls stay visible at 40
columns. Exact dispatcher-cause matching still prevents an old parked queue
from hiding a new source, approval or execution error.

Report counts attempts separately from logical jobs and places their recorded
outcomes directly below Scope. A completed retry retains the earlier failed run.
Missing, partial and skipped receipts keep their own labels. These are read-only
presentation changes over existing typed receipts; module names, export formats,
finding decisions and allowance policy are unchanged. J113's shared wording
expectation is updated; only J363 was run in this increment.

## Native result

Final J363 has **78 machine passes, zero failures, 72 live capture pairs and eight
pending operator judgments**. Its raw exit remains `4`, `REVIEW_REQUIRED`.
The agent answered all eight questions using State, Intent, Honesty and Craft,
and inspected nineteen ANSI cell replays. Replays use Menlo and a chosen default
background; they are not OS screenshots or reference-parity evidence.

The owned fixture has one inert greeting source file, two selected immutable
contexts and a third globally active context that remains unused by discovery.
Normal prepared dispatch and the OAuth bridge use fake credentials and a fully
intercepted transport, with the explicit GPT-5.5 model and medium reasoning.

| Stage | Recorded result |
| --- | --- |
| Initial approval | Six fixed jobs, three passes per case, one worker, seven total calls, two protected Review calls and one attempt per job |
| Failure and halt | One nonretryable HTTP 400; four completed, one failed and one unstarted parked job; five committed calls |
| Partial result | Alpha recurrence 2/2 completed, Beta 1/2; three raw observations, one identity and one scripted operator FP event |
| Explicit revision | Nine total calls, the same two protected calls, two attempts per job and unchanged six-job plan |
| Resume | Only the failed and unstarted jobs run; six jobs complete in seven attempts, with the original failed receipt retained |
| Final review and export | Alpha 3/3, Beta 1/3; four observations; explicit FP reaffirmation preserves the first decision and adds a second event |
| Restart | The same source, contexts, plan, observations, decisions and seven committed calls; no new request; two Review calls remain unused |

Fresh requests contain no prior observation title or FP rationale. Each case's
prompt hash stays identical across its attempts. The comparison distinguishes
changed context from matching recorded source content and does not infer a fix
from Beta's missing observations.

The existing review rule asks for reassessment when a scanner observation
reappears after an FP. The fixture explicitly reaffirms the newer observation;
it does not silently carry or erase the earlier decision. Both events remain
in the ledger. The unversioned fixture does not establish safe decision reuse
across SHAs. Imported context grounding coverage gaps remain visible in Report.

## Verification and evidence

The production cut passes 94 focused Rust checks: 32 campaign, 28 campaign-reader
and 34 Report checks. TUI all-target Clippy, workspace build and the risk proxy
pass. The ten-gate draft summary is recorded separately. Its receipt is dirty
and unsigned; publication still requires clean final-head verification.

The executable SHA-256 is
`650d2aa5d26ddab86c92da1cb5191a929c9c6f5b7998ad6e2afd499815c1a409`.
Thirteen programs and 6,599 repository inputs remain unchanged during the native
run. Later documentation changes are recorded separately.

Local evidence root: `scripts/devex/artifacts/matrix-limits-20261025/`.
The final run is under
`native-attempt-6/native/J363/20261025-041108/J363/`; its frozen inputs,
terminal result, agent assessment and independent receipt checks sit beside it.
JSON metadata equals its investigation sidecar. Independent checks validate
no-color SGRs and the full rendered receipt rows.

Earlier raw failures remain recorded: two setup waits, the missing mixed-stop
notice, a helper assumption about unstarted jobs, the buried history, and an
exit-notice timing race. The two meaningful Rust red checks are retained too.
A missing build-cache library and a corrected test-only SafeText constructor
are recorded separately from product regressions.

All provider responses and scanner findings in this increment are synthetic.
There are zero live provider requests and no target-source execution. The real
sixteen-request allowance remains exhausted. General model quality, module
usefulness, large-history behavior and full operator UX acceptance remain open;
the four locally verified delivery items and five open items are unchanged.
