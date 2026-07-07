# DOMAIN_RISK_REVIEW.md

This review identifies where generic Fable recommendations could distort the
real meaning of Kuzushi, a defensive AI security scanner.

## 1. Recommendations That Could Distort Scanner Meaning

1. `project` / `eligibility` replacing `target` / `scope`.
   - Risk: scope gating becomes a generic readiness affordance.
   - Required change: keep target and scope terminology. Use readiness only
     for tool/config/dependency availability.

2. `priority` replacing real severity.
   - Risk: impact and action ordering collapse into one field.
   - Required change: preserve `severity` and introduce/display derived
     `priority` separately.

3. `certainty` replacing confidence.
   - Risk: public data contracts and existing triage fields churn.
   - Required change: keep `confidence`; explain it as tool confidence that
     the finding is real.

4. `dismiss/hide/mute` replacing real review decisions without mapping.
   - Risk: false positive, suppression, accepted risk, and defer become
     ambiguous.
   - Required change: use scanner decisions: confirmed, rejected false
     positive, suppressed, deferred, accepted risk.

5. `fixed` for run-diff absence.
   - Risk: a missing finding is reported as remediated when it may be missed,
     moved, filtered, partial, or unmatched.
   - Required change: use `resolved_absent` or `not_seen`; require coverage or
     human remediation evidence before saying "fixed".

6. "Verified" or "confirmation" as a catch-all proof label.
   - Risk: static proof, model triage, runtime artifact checks, and human
     confirmation collapse.
   - Required change: label static proof state, verification result,
     confidence, and human decision as separate fields.

7. Fable's global CLI model.
   - Risk: breaks scan/shell/run parity and public command contracts.
   - Required change: keep Kuzushi commands and add non-breaking flags/output
     fields.

## 2. Wording That Could Mislead Users

- "0 findings" without terminal run status.
  - Must say whether the run completed, failed, was cancelled, was partial, or
    has not run.

- "Clean" after anything except a completed run with zero findings.
  - Failed/cancelled/partial runs must never render as clean.

- "Confirmed" for unverified or auto-triaged findings.
  - Use "candidate", "statically supported", "triaged true positive", or
    "human confirmed" as applicable.

- "Exploit", "exploited", "proof of exploitation", or "attack succeeded".
  - Do not use for normal validation UI/report copy. Kuzushi is defensive and
    must not imply live exploitation.

- "Resolved" for suppressed or deferred findings.
  - Suppression and defer are human attention decisions; resolved/absent is a
    scanner-observed or remediation-backed status.

- "Hidden" for suppression.
  - Suppressed findings remain auditable and recoverable. Use "suppressed"
    with reason/scope and report inclusion rules.

- "Priority" alone in row badges.
  - Must be accompanied by severity and confidence or users will infer
    unsupported certainty.

## 3. Status, Priority, and Confidence Model Issues

- Current Workbench row ordering uses severity plus proof tier. It does not
  expose a formal derived priority formula.
- Current `FindingProjection` has severity, verdict label, confidence label,
  proof state, and runtime validation, but not an explicit lifecycle status or
  human decision history.
- Current `triage` is a single current row per finding. Human overwrite is
  guarded, but history is not append-only.
- Current `suppressed` and `snoozed_until` fields live on findings, while
  whitebox suppressions also live in `whitebox-suppressions.json`. The relation
  between suppression, triage verdict, and decision state is not unified.
- Current `runs diff` compares fingerprints and labels absent findings
  "fixed"; it does not account for partial run coverage or uncertain identity
  matching.
- Current fingerprint identity includes `start_line`, making confidence in
  cross-run carry-forward weaker than the UI may imply.

Required changes:
- Define canonical scales for severity and confidence.
- Define lifecycle status separately from human decision.
- Define derived priority as a pure, inspectable selector.
- Add decision history and conflict projection.
- Replace line-number identity with structural/evidence identity.

## 4. Report Structure Issues

- CSV currently omits confidence, decision/verdict details, evidence summary,
  proof/static-vs-runtime labels, completeness mode, and report provenance.
- SARIF carries severity level and fingerprint but not full Kuzushi confidence,
  decision, proof status, suppression, or omitted-field metadata.
- Markdown bundle per-finding files carry severity/tool/rule/location/message
  and evidence, but not confidence, decision history, run provenance, model
  provenance, completeness mode, or explicit model-vs-observed labels.
- JSON/JSONL expose raw `Finding` but do not provide a canonical
  cross-format projection with omitted-field metadata.
- Report export has no open-vs-complete completeness mode.
- There is no preview path that proves preview bytes and exported bytes share
  a serializer.

Required changes:
- Build one canonical export projection.
- Add completeness metadata and deterministic ordering.
- Add omitted-field metadata where formats cannot carry full fidelity.
- Include stable identity/alias, location, severity, confidence, status,
  decision, evidence/provenance, tool/rule, run id, tool version, and model
  provenance where available.

## 5. Data Loss Risks

- The current triage table overwrites the prior row unless protected by
  `triaged_by=human`. That preserves human rows from auto triage but does not
  preserve all decision history.
- Legacy fingerprint migration deletes duplicate finding rows after collision.
  Future identity migrations must not delete rows before migrating evidence,
  decisions, aliases, patch results, verification records, and suppression
  references.
- `replace_finding_evidence` deletes evidence rows before inserting
  replacements. It is transaction-wrapped during normal finding insert, but
  future evidence migrations must preserve run-immutable evidence.
- Suppression CLI code currently defaults missing target to cwd. That violates
  explicit target discipline and can record a suppression in the wrong
  workspace.
- Evidence blobs in request/response imports may be sensitive. Purge/redaction
  must leave tombstones and must not leave findings claiming missing evidence.
- Current identity uses `start_line`; line shifts can orphan decisions and
  suppressions by producing a new fingerprint.

Required changes:
- Add append-only decision table.
- Add identity migration with alias/decision preservation.
- Make suppression target handling explicit.
- Add evidence purge/tombstone semantics.
- Add migration tests for alias, decision, evidence, and count preservation.

## 6. Review Workflow Risks

- A row can disappear after a decision if the filter changes, making users
  think data was deleted unless the UI acknowledges the saved decision and
  filter effect.
- Current row fields emphasize severity/proof but do not clearly expose
  separate status and decision.
- Evidence detail currently mixes scanner message, proof, triage, and evidence
  without a strong observed-vs-derived structure.
- Reappeared rejected findings have no first-class conflict lane.
- Filtered-empty and completed-clean can look similar unless every list view
  reserves a clear empty-state reason.
- Comparison against a partial/failed run can imply resolution if absent
  findings are not labeled as coverage gaps.

Required changes:
- Add review queue reconciliation header: visible count, total count,
  filters, completeness/open mode.
- Add conflict section for reappeared prior decisions.
- Add explicit saved-decision feedback.
- Disable confirm/reject if required evidence failed to load; allow defer.
- Add coverage-aware compare labels.

## 7. Required Changes Before Implementation

1. Approve the real public vocabulary:
   - target, scope, finding, evidence, severity, confidence, priority, status,
     decision, verification, report.

2. Approve decision vocabulary and compatibility mapping:
   - `true_positive` -> confirmed
   - `false_positive` -> rejected false positive
   - `needs_review` -> undecided/review needed
   - `by_design` -> accepted risk or suppressed by policy, pending final call

3. Define identity v3:
   - weakness kind/rule/CWE
   - normalized repo-relative path
   - structural anchor when available
   - stable evidence signature
   - no absolute line number as a required identity input

4. Define status model:
   - candidate/new, seen, statically_supported, statically_rejected,
     verified_static, needs_runtime_evidence, resolved_absent, stale,
     partial_coverage, failed_run.

5. Define priority formula:
   - inputs, ordering, tie breakers, and whether suppressions/deferred findings
     are excluded from open mode.

6. Define report projection schema:
   - canonical fields, completeness modes, omitted-field behavior, SARIF
     property mapping, CSV columns, markdown bundle manifest.

7. Define migration safety:
   - transaction plan, backup plan, old reader compatibility, alias/decision
     preservation, and test fixtures.

8. Confirm safety copy:
   - no exploit/payload/live-attack wording; validation is static or
     already-captured artifact analysis unless an explicitly authorized
     defensive harness is documented as such.
