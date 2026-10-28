# Recorded scan settings and readable Report details

Investigation reports preserved their source, context and attempts but dropped
the requested scanner settings from the saved plan. A later operator setting
could therefore leave the report without enough information to identify the
original rule-source request. Expanded reports also put every completed run ID
before spending and coverage.

## Change

The shared Core report reader now projects `scanSelection` from authenticated
study input or every frozen context/scope case. Its recorded subset contains
`taskMode`, `tasks`, `semgrepConfig`, `semgrepBinary`, `semgrepJobs` and
`semgrepTimeoutMs`. Literal strings, missing fields, explicit nulls and unusual
recorded values remain distinct. Prompts, context bodies, credentials and
unrelated options are excluded from this subset. It reads neither current tool
settings nor current rule files.

The TUI groups identical setting records without collapsing cases or discovery
jobs. Overview shows their count and requested tasks. Details show every case
ID and complete escaped parameter value, with an accurate `p overview` hint.
Spending, coverage, source and model precede those settings. A compact context
summary stays near the top; case detail and completed run IDs remain later in
the full receipt. Failed, canceled and otherwise unresolved attempts stay
prominent. Reading and paging start no work.

This is an additive report field. Plans, equivalence formats, approvals,
execution and public tool names are unchanged. See
[the migration](../../RELEASING.md#recorded-scan-settings-in-investigation-reports)
and [the module contract](../modules.md).

## Functional and terminal evidence

- Thirty-one Core checks cover authenticated report consumers, every context
  case, shared dispatch/export, literal strings, omissions and excluded input.
  The four targeted selection checks overlap that suite and are not added.
  One existing native-fixture producer remains explicitly opt-in.
- Eighty-nine distinct TUI checks cover the report view models, export,
  keyboard routes and renderer. The narrower selection/history checks overlap
  these groups and are not added. The locked workspace build, workspace
  all-target Clippy and current CRAP-risk proxy pass.
- Final J399 uses an owned 602-file source fixture, one saved response replay
  under intercepted transport, seven accepted boundaries and twenty-one fixed
  local Semgrep jobs with one campaign worker. Every source member is submitted
  three times. It retains twenty-four observations and eight explicit human
  deferrals. These are harmless policy markers, not demonstrated vulnerabilities.
- After all jobs finish, the journey changes the current `semgrepConfig` to
  `p/unrelated-current`. Report and JSON export retain all seven frozen case
  selections. Strict capture checks find the original rule source at 40x12,
  60x20, 80x24, 96x89, 120x36 and 160x48. No-color restart retains the same work.
- Final J399 records 84 machine passes, zero failures, seven answered agent
  screen questions and eight inspected terminal-cell replays. All 6,925
  authenticated source/runtime inputs remain unchanged. Raw exit 4 remains
  REVIEW_REQUIRED; the agent verdict is PASS_WITH_FINDINGS and operator
  acceptance remains open. Replays are not operating-system screenshots.
- Independent reconciliation checks the twenty-one discovery jobs plus the
  separate proposal job, one replay call, two allowance revisions and all
  source hashes. A fresh headless export after restart independently matches
  the frozen selections, with observations, decisions and spending unchanged.
  All 624 protected original experiment files still match their saved hashes.

Evidence is retained under
`scripts/devex/artifacts/report-discovery-selection-current-20261028/`:
`control/core-report.log`, `control/qualification.json`,
`control/report-interface-checks.json`, `J399-attempt-6/terminal.json`,
`J399-attempt-6/agent-screen-review.json` and
`control/reconciliation-6/result.json`. Earlier attempts remain available:
one stopped on missing auxiliary metadata, one exposed an unrepaired fixture
reference, one found the detail-ordering defect, and two failed strict capture
checks on transition/repaint frames. The final journey waits for live content
and settles before detail captures. No failure was converted into a pass.

## Limits and remaining work

The selected request paths do not pin historical rule-source bytes or establish
the full enabled-rule policy. Actual engine outcomes remain separate. This
increment does not change engine equivalence or test mutation of a referenced
rule file between passes. Equal recorded parameters alone do not prove equal
effective engine policy.

Compact terminals still require several pages for long absolute paths. Lower
receipt metadata remains dense, some controls repeat, and scope names clip in
list columns. Physical input latency, full reference-interface parity, broader
engine/model usefulness and operator acceptance remain open. This fixture adds
no live provider requests, executes no target application source and promotes
no module. Cumulative approved live experiment use remains twenty, with no
remaining live allowance. Exploit development, reproducers and vulnerability
patching remain outside scope.
