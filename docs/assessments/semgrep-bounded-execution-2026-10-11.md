# Semgrep execution, spending disclosure and input recovery

October 11, 2026. Local changes on main at `f8649511f746`.

The audit found an unbounded wait in the Semgrep adapter. Output capture already
had limits, but a stalled process could hold an approved job indefinitely. Shared
dispatch now declares a positive time allowance: standalone `timeoutMs`, or
`semgrepTimeoutMs` for the selected SAST task. The default is 30 minutes and the
ceiling is 24 hours. A prepared engine shares the allowance across roots and
64-file batches. Existing controlled subprocess code handles cancellation,
bounded output, process-tree termination and reaping. Returned earlier batches
remain partial when later work fails. Source authentication, post-process parsing
and scheduling/cleanup remain separately qualified.

The public `SemgrepScanner` shape remains unchanged. Direct legacy invocations
use the default deadline. Frozen descriptor bindings require re-preparation and
explicit approval. Time receipts add configured allowance, elapsed time and
source-authentication scope; approval names the frozen limit. Positive remaining
durations below one millisecond no longer display a zero deadline.

Native reading exposed two additional input defects. Setting-value completion
offered another option key, making `set tasks semgrep` display a misleading
`Config` suffix. Completion now uses the selected descriptor's choices and
boolean values. Free-form text and its cursor remain intact. Shell list input
now accepts JSON arrays of strings and quoted single entries through the shared
Core coercion helper. Malformed arrays refuse before storage. Existing
comma-separated input and structured JSON coercion remain compatible.

206 distinct focused checks pass: 70 Core checks across Semgrep, subprocess
control, partial/stopped native work and operator text; 136 TUI completion and
allowance checks. The locked workspace build and 296-file risk proxy pass.
Native claims remain limited to the tested options and consumers.
All ten repository summary gates pass in
`/tmp/kuzushi-bounded-semgrep-20261011/precommit-verify-receipt.json`.
The dirty/drifted receipt remains unsigned. Final documentation receives a
focused contract check.

Sequential J203 is
`/tmp/kuzushi-bounded-semgrep-20261011/final-native/20261011-113614/J203`.
It records 48 machine passes, zero failures and 44 text/ANSI captures at all six
viewport sizes, including no-color restart. Native SHA-256 is
`eb3c50de7e3a8698657c264cf79923a2c6e06b016abc34384acbeb018b9f80e4`.

The installed scanner reads two harmless Python text fixtures with one explicit
local policy rule. Target source is never executed. The first 1 ms job fails
and produces no observation; its failed phase result remains unselected. The
operator then prepares and approves three jobs at 60000 ms each, with one worker
and one provider call protected for Review. Three actual jobs produce three raw
observations consolidated into one signal-only finding. Scripted owner deferral,
JSON export, context references, recurrence and resource history survive restart.
No provider request or remote rule selector is used. Context is bound provenance;
local rules drive this inspection. The retained live fixture still has four
reservations, six attempts, three observations and one decision.

Four unsuccessful attempts remain under `native`, `context-complete`,
`settled-input` and `canonical-input`. They preserve the single-node Map gate,
the misleading completion, the literal stored array and a wrapping-sensitive
assertion. The final Map describes both actual files and adds no invented flow.
Resize captures now wait for their real reader. No live journey/helper was edited.

Status remains `REVIEW_REQUIRED`, with operator approval false. Assistant screen
judgments are separate. Failure causes and controls are readable at 40×12, while
paths and full Report provenance still require substantial paging. Native request
estimate wording remains generic. Default-rule usefulness, installed exact-scope
coverage, large repositories, all configurations/interfaces and model-backed
Review remain open. The matrix records scoped evidence for 74 of 112 tools;
38 remain unassigned, including eight excluded actions. No module promotion,
retirement, broad milestone or full reference-parity claim follows.
