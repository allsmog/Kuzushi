# Attempt consumption and completed-pass recurrence

The investigation view now separates lifetime attempt consumption from the
current retry counter. Resume can reset `attempts`; the recorded `dispatches`
counter stays cumulative. `campaign:status` exposes both values. Missing or
contradictory lifetime counters remain unknown. The TUI names current counts
and discloses that older records lack a lifetime total. Job details retain both
numbers, while compact rows keep the pass identity and total visible together.

Recurrence now counts observations from the final run of each completed logical
pass. A candidate observed only during a canceled, failed or superseded attempt
stays in the findings ledger and consolidated batch rows with zero completed-pass
recurrence. Its run references name only the runs where it was observed. A
later miss does not change its severity, confidence or human decision. A focused
severity-gate regression keeps a retained high-severity candidate blocking even
when the final retry misses it. The raw observation/export membership remains
separate from the recurrence denominator.

Opening campaign history does not implicitly change Review scope. The visible
`o observations` action opens the existing batch reader and explicitly scopes
Review to retained batch observations. Its notice names `batch clear` for
returning to workspace history. The selected job and composer draft survive;
unsupported campaign kinds keep the existing Review scope. Reading starts no
jobs, creates no allowance and accepts no phase result.

Keyboard checks also exposed a Review backlog collision. Ordinary Review keeps
`t` for Trace. In backlog mode, `t` owns the producing-tool filter and `T` opens
Trace. The composed keymap and visible hints use the same definitions. Report
copy now asks operators to inspect incomplete records, which includes canceled
attempts without relabeling them as unexpected interruptions.
The compact Review list also names its active backlog state. Full reducer tests
showed that the toggle worked while the former title hid the change. The detail
header now follows the active `t` or `T` trace binding.

An additional regression found that correlated legacy Scan results could name
engine runs without a phase-stage receipt. The occurrence reader now combines
that established membership with canonical stage membership and validates run
identifiers. Both historical evidence and final-pass recurrence retain those
child observations, with each source run attached only to its own findings.

## Verification

J275 reads explicitly labeled synthetic history created by the frozen native
fixture test. Its canonical records contain three completed logical passes,
five attempt records, six raw observations and four candidates. Canceled-only
and superseded-only observations recur in zero completed passes; the latest-only
candidate occurs once and the repeated candidate twice. This is a reader and
interaction test. No discovery executor or model provider is invoked, and target
source is never executed.

The first setup attempt is retained because it assumed row ordering by title.
The corrected fixture verifies candidates by identity. The next attempt showed
that reopening campaign jobs did not automatically load the batch observation
panel. J275 now uses the explicit visible observations action. All failed
captures remain in `/tmp/kuzushi-recurrence-20261015`.

The final source snapshot passes 146 focused Rust tests and the locked workspace
build. One native fixture test is intentionally ignored in the ordinary test
invocation and is invoked explicitly by J275. All 4,176 Rust/build inputs match
before tests and after build. The staged risk check passes all 22 changed
production files. The native SHA-256 is
`cbf298802ae518b4cea3bc5637fc827f097132410ef94f88c5382c9e2d69e75d`;
fourteen executables, including the reader fixture, are frozen in the evidence
directory. The runtime snapshot records 224 inputs.

Final J275 is `tui-v6/20261015-030544/J275`: 32 machine passes, zero failures,
22 live text/ANSI capture pairs and five pending human judgments. It covers
all six detail sizes, forty-column paging, explicit observation scope, retained
zero recurrence, legacy totals, backlog/tool-filter ownership and no-color
restart. The assistant inspected those captures. It retains six raw observations
and zero decisions, provider reservations or work attempts. Source and plan
hashes remain unchanged. The earlier v4c run stopped because its expected
backlog-off footer label was outside the compact footer; the final screen makes
backlog state and trace ownership visible in the body too.

Sequential J121 on the same frozen bundle is
`integration-v6/20261015-030635/J121`: 123 machine passes, zero failures,
96 live text/ANSI capture pairs and 17 pending human judgments. It executes the
real owned-fixture producer flow with every provider fetch intercepted. It
retains cancellation and consumption, explicit retry and allowance revisions,
partial reporting, final acceptance, source reassessment and no-color recovery.
Unlike J275's historical reader seed, it does not inject queue completions or
finding decisions for the canceled request. The assistant inspected cancellation,
limits, partial/final reports, source reassessment and compact recovery captures.

Across both journeys, 155 machine checks pass and 22 human judgments remain
pending. Both exit with `REVIEW_REQUIRED`, not operator acceptance. Human UX
judgments remain separate from machine assertions. This
increment does not establish reference-product parity, live-model quality,
complete module readiness or full product acceptance. The existing live-call
allowance remains exhausted; the separate Scan approval remains unanswered.
