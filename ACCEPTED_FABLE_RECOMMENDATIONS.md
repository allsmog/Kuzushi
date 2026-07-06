# ACCEPTED_FABLE_RECOMMENDATIONS.md

This review maps the Fable UX/data recommendations back to Kuzushi, a defensive
AI security scanner. "Finding", "target", "evidence", "scope", "severity",
"confidence", "priority", "status", and "decision" are the real product terms.
Neutral Fable terms such as "project", "generated item", "certainty", "mute",
and "fixed" are not accepted as public scanner terminology unless explicitly
mapped below.

## Recommendation Decisions

### 1. Separate the Five Finding Signals

- Decision: modify
- Reason: Fable correctly identified the core UX/data issue, but its neutral
  mapping used "priority" for real severity and "certainty" for real
  confidence. Kuzushi must preserve the real domain split:
  `severity`, `confidence`, derived `priority`, lifecycle `status`, and human
  `decision`.
- Domain impact: prevents high-impact/low-confidence findings from being
  misread as confirmed, and prevents human decisions from being treated as
  scanner state.
- Implementation notes: update `FindingListRow`, `FindingDetailModel`, plain
  renderers, report projections, and CLI output so each finding exposes all
  five fields with labels. Do not collapse proof state, triage verdict,
  suppression, and runtime verification into one "confirmation" label.

### 2. Use Rank as List Order, Not a Sixth Peer Signal

- Decision: accept
- Reason: rank is an ordering result, not a finding fact. Kuzushi already sorts
  visible findings by severity/proof rank in the Workbench; this should become
  an explicit priority sort.
- Domain impact: reviewers can understand "why first" without confusing
  priority with severity or confidence.
- Implementation notes: define `priority` as a pure selector over severity,
  confidence, proof/status, decision state, scope, and recency as approved.
  Show rank as row position only. Keep severity and confidence visible.

### 3. Rename Confidence to "Certainty"

- Decision: reject
- Reason: "confidence" is already used in scanner data, triage results,
  reports, and run diffs. Renaming it would churn public contracts and obscure
  existing persisted data.
- Domain impact: avoids breaking JSON, report, and CLI consumers.
- Implementation notes: keep `confidence`. Improve copy by labeling it as
  "confidence that this finding is real" in help/detail views.

### 4. Rename Target/Scope to Project/Eligibility

- Decision: reject
- Reason: Kuzushi's real domain is target-scoped defensive review. "Project" is
  too weak, and "eligibility" is not equivalent to security scope.
- Domain impact: prevents scope-gated operations from being presented as a
  generic readiness check.
- Implementation notes: public UI/CLI must continue using `target`,
  `scope.toml`, `InScope`, `OutOfScope`, and `Unknown`. It may separately show
  dependency readiness or "not analyzable" for missing tools/config.

### 5. Honest Empty, Loading, Failed, Cancelled, Partial, and Filtered States

- Decision: accept
- Reason: This is directly aligned with the scanner's non-negotiables.
- Domain impact: prevents a failed or cancelled scan from being read as "0
  findings" or "clean".
- Implementation notes: every Workbench findings list, Activity output,
  CLI list command, and report preview needs a state model that distinguishes
  not-run, running, completed with zero findings, failed, cancelled/partial,
  and filtered-out.

### 6. Make Decision Durability Visible

- Decision: modify
- Reason: Kuzushi has a current guard that prevents auto triage from
  overwriting human-authored triage, but the `triage` table is still a
  single-row upsert, not an append-only decision log.
- Domain impact: strengthens reviewer trust and prevents decision loss across
  reruns.
- Implementation notes: add an append-only `finding_decisions` table keyed by
  durable finding identity. Keep current `triage` reads compatible as a latest
  projection during migration. UI confirmation should say a decision was saved
  only after the transaction is durable.

### 7. Distinguish Reject, Suppress, Defer, Accepted Risk, and Resolved/Absent

- Decision: modify
- Reason: Fable's "dismiss/hide/defer/resolved" model is directionally right,
  but real scanner meanings are more precise.
- Domain impact: prevents false positives, accepted risk, scheduled review, and
  disappearance from being merged into a misleading "closed" state.
- Implementation notes: use real decision terms:
  `confirmed`, `rejected_false_positive`, `suppressed`, `deferred`,
  `accepted_risk`. Treat `resolved_absent` as scanner-observed status, not a
  user decision. Keep existing `true_positive`, `false_positive`,
  `needs_review`, and `by_design` as compatibility aliases during migration.

### 8. Pin Reappeared Previously Rejected Findings

- Decision: accept
- Reason: A re-detected finding with a prior rejection is a conflict requiring
  human attention; it must not silently reopen or silently hide.
- Domain impact: preserves human authority while still showing that the scanner
  saw the candidate again.
- Implementation notes: add a projection flag such as `decision_conflict` or
  `reappeared_after_rejection`, feed it into Workbench rows, `runs diff`, and
  complete reports.

### 9. Merge Home and Cockpit

- Decision: modify
- Reason: The current product already has Workbench as the default command
  center with a phase rail and derived `next` guidance. Removing Workbench or
  replacing it with Fable's generic Home would regress the real shell design.
- Domain impact: keeps the security review cockpit intact while reducing
  duplicated orientation surfaces.
- Implementation notes: keep `ShellView::Workbench`. Treat "Home" as the
  Workbench orientation state or target-picker landing, not a new primary
  screen. Keep the phase rail derived from workspace reality.

### 10. Demote the Diagram/Context Pane

- Decision: modify
- Reason: Fable correctly notes that the review queue is the center of gravity,
  but Kuzushi's DFD, code, risk, flow, and chain center tabs carry real
  defensive review context.
- Domain impact: prevents diagrams from overshadowing finding review while
  preserving useful evidence/context.
- Implementation notes: keep Workbench center tabs, but default review focus to
  findings/details when findings exist. Empty center tabs must show honest
  guidance only, never dummy findings or dummy flows.

### 11. Add Clear Focus Model and Responsive Layout

- Decision: accept
- Reason: This matches current Workbench focus and narrow terminal goals.
- Domain impact: reduces operator errors in keyboard-driven review.
- Implementation notes: ensure active pane is visible in Ratatui and plain
  renderings; footer must name focused pane; narrow layouts must preserve
  finding fields rather than truncating them.

### 12. Make Activity Progress Honest

- Decision: accept
- Reason: Current Activity is trace-backed; Fable's stall/outcome guidance
  reinforces existing semantics.
- Domain impact: avoids confusing stale animation with actual work.
- Implementation notes: Activity rows should derive from real `RunTraceStep`
  events and run terminal status. Add elapsed/last-event age where feasible.
  Completion should produce a persistent outcome banner; zero-result runs must
  not auto-open empty artifact views.

### 13. Use One Report Projection for Preview and Export

- Decision: accept
- Reason: Report preview and exported bytes must be the same truth.
- Domain impact: prevents users from approving one report and shipping another.
- Implementation notes: create a canonical `WorkspaceFindingExportRecord`
  projection used by JSON, JSONL, SARIF, CSV, markdown bundle, and preview.
  Record omitted fields per format.

### 14. Add Report Completeness Modes

- Decision: accept
- Reason: Reviewers need both "actionable/open" and "complete including
  suppressed/rejected" exports.
- Domain impact: prevents suppressed or rejected findings from disappearing
  without explanation.
- Implementation notes: add `completeness=open|complete` to export inputs,
  report metadata, and preview. Default may be `open`, but must be labeled.

### 15. Replace `kuzushi` CLI With Fable's `tool ui/run/step` Model

- Decision: reject
- Reason: Kuzushi already has public mode semantics: `kuzushi scan`,
  `kuzushi`, `kuzushi run`, `kuzushi findings`, `kuzushi finding`,
  `kuzushi runs`, `kuzushi export`, and shell verbs. Replacing these would
  break the module/mode contract.
- Domain impact: preserves scan/shell/run parity and existing operator muscle
  memory.
- Implementation notes: implement improvements as non-breaking flags,
  aliases, subcommands, and output fields on existing commands.

### 16. Add Global `--json` Everywhere and Remove Scan-Only Automation Flag

- Decision: reject
- Reason: Kuzushi's non-negotiable mode parity says `--ci` is scan-only and
  `kuzushi run` always emits machine-readable JSON. Adding a generic
  `--json/--ci` contract everywhere would conflict with current semantics.
- Domain impact: avoids machine-output ambiguity.
- Implementation notes: keep command-specific JSON where it already exists or
  is needed. Do not add `--ci` or `--json` to `kuzushi run`.

### 17. Rename `--target` to `--project`

- Decision: reject
- Reason: `--target` is the correct scanner term and is part of the explicit
  target/scoping contract.
- Domain impact: preserves scope discipline.
- Implementation notes: fix commands that still default to cwd, especially
  suppression paths, rather than renaming the flag.

### 18. Adopt Fable Exit Code Table

- Decision: reject
- Reason: Current Kuzushi already uses command-specific semantics, including
  `scan --fail-on` behavior. Repurposing exit codes globally would be a
  breaking automation change.
- Domain impact: avoids CI regressions.
- Implementation notes: document current exit codes and add tests for honest
  failed/cancelled/zero-finding outcomes. Any exit-code redesign needs a
  migration plan.

### 19. Split Durable Identity From Per-Run Finding Occurrence

- Decision: accept
- Reason: This is the strongest data recommendation. Current `findings` rows
  are per scan/run and current fingerprints include line numbers; decisions
  need a durable cross-run owner.
- Domain impact: preserves human verdicts across line shifts, tool wording
  drift, and repeated runs.
- Implementation notes: add a durable `finding_identities` table and a
  per-run `finding_occurrences`/existing `findings` linkage. Migrate
  existing `fingerprint` and aliases without orphaning triage, verification,
  suppression, patch, or evidence records.

### 20. Remove Absolute Line Number From Stable Identity

- Decision: accept
- Reason: Current `fingerprint_parts(rule_id, file_path, start_line)` is too
  brittle. Fable's warning is correct.
- Domain impact: prevents harmless line shifts from resurrecting known findings
  as brand-new and losing decisions.
- Implementation notes: define identity from weakness kind, normalized path,
  structural anchor, and stable evidence signature. Keep line numbers as
  location/evidence, not as the sole identity anchor.

### 21. Default Uncertain Matches to New

- Decision: accept
- Reason: A duplicate is recoverable; a wrong merge can attach a human decision
  to the wrong security claim.
- Domain impact: protects review integrity.
- Implementation notes: store match tier and expose uncertain/duplicate
  remediation in compare views.

### 22. Use Content-Addressed Blobs for Large Evidence

- Decision: modify
- Reason: Useful for HAR/Burp/capture blobs and large excerpts, but security
  artifacts may be sensitive.
- Domain impact: improves durability while requiring retention/redaction
  policy.
- Implementation notes: add blob refs only with explicit purge/tombstone
  semantics. Reports must not claim evidence that was purged.

### 23. Treat Reports as Pure Projections

- Decision: accept
- Reason: Report generation must not mutate finding truth.
- Domain impact: prevents report side effects from changing review state.
- Implementation notes: report generator should use read-only store access
  except for optional export metadata, never write findings, decisions, or
  assessments.

### 24. Add Help From the Runtime Keymap

- Decision: modify
- Reason: Good direction, but must fit the existing shell command specs and
  keybinding modules.
- Domain impact: reduces drift between visible help and real behavior.
- Implementation notes: use `SHELL_COMMAND_SPECS` and existing keybinding
  view-models as the source of truth. Do not invent a second router.

### 25. Make "Fixed" Become "Resolved/Absent" Unless Coverage Proves Fix

- Decision: accept
- Reason: Current run diff labels findings missing from the comparison run as
  "Fixed". That overstates scanner evidence.
- Domain impact: avoids falsely reporting remediation when a detector missed a
  finding, scope changed, a run was partial, or identity matching failed.
- Implementation notes: rename CLI/TUI/report diff class to `resolved_absent`
  or `not_seen`. Only call something fixed when a human or integration records
  remediation evidence.
