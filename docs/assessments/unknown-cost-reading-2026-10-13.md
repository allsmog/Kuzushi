# Unknown spending in ordinary investigation views

Fresh unmetered model work previously appeared as a zero-dollar lower bound in
the Workbench header and session rail. The qualifier was technically a lower
bound, but it gave an operator a misleading number while the total and remaining
dollar capacity were unknown. The header also discarded the typed receipt's
estimate state by reducing it to a scalar and completeness flag.

The header now retains RuntimeCostReport and uses the shared cost formatter.
Incomplete zero becomes **unknown (metering incomplete)**. A missing legacy
receipt remains distinct from an unmetered call, an accounting error remains an
error, exact zero remains an exact zero, and fully priced estimates retain their
qualifier. Small positive observed amounts retain a nonzero representation rather
than rounding to a zero-dollar label.

The same incomplete formatter now reaches Run Focus headers, completion receipt
labels and task metadata. Workbench, rail, Cost, contextual strips and the halt
card agree on unknown spending. An unmetered budget share stays unknown rather
than claiming a percentage from a zero or partial subtotal. Positive observed
subtotals remain visible as lower bounds; fully priced estimates and complete
costs retain their budget shares. Accounting errors are disclosed on the budgeted
rail too.

Unknown and invalid spend take priority over optional target/idle atoms in the
narrow Workbench identity row. At 40 columns in the tested Review state, the
operator sees both the current page and cost unknown. Reality-derived phase
warnings keep their higher priority. No new rows, dialogs or approval flows are
added, and spending guards, reservations, job counts, model selection and
configured caps are unchanged. Internal presentation DTOs change, while persisted
artifacts, public tool options and raw cost receipts retain their formats.

Seventy distinct focused Rust checks pass. They cover known zero, missing and
unmetered receipts, observed subtotals, estimates, invalid accounting, header
projection, compact identity, rail, Cost paging/resize and typed semantic
equivalence across views. Initial compilation found an old scalar-header test;
its assertion now reads the typed report. A rail assertion still expected the
old label and was updated to the new contract. An empty test selector was not
credited as passing evidence; the actual module's six tests were run by their
listed names. The locked workspace build and all ten exact quick-plan
commands pass, including 391 Node tests and the CRAP-risk proxy over
558 changed code files. Package commands ran directly without disabling
signature verification. The full Rust suite was not run.

The immutable native bundle has SHA-256:
`be00c8a25871e007f1cfc661ce6963e12603706cf44bbd0d52b7ffaa3954e41f`.
Sequential native journeys use owned inert source, isolated homes and completely
intercepted provider responses. No source execution or standalone security
scanner runs. Human questions remain pending and operatorApproved remains false. Final J227
records 31 machine passes, no failures and 20 captures with three human
questions. J241 records 18 machine passes, no failures and 15 captures with
four human questions. J121 records 109 machine passes, no failures and
87 captures with 15 human questions. All remain REVIEW_REQUIRED. Captures:
`/tmp/kuzushi-tui-integration-20261012/unknown-cost-tui/20261013-202217`.

J227 checks a real context executor returning an answer without billing metadata.
Its halt card and Cost page say unknown, no invented budget percentage appears,
inspection and exit remain available, and another runtime launch stays blocked.
Paging retains the whole label through six terminal sizes. No cap is raised, the
single reservation persists, protected Review stays protected, and the same
receipt remains inspectable after no-color restart.

J241 checks a separately approved related-source search. The actual Review
header says cost unknown at 120 and 40 columns while the related observation
requires independent review. Its original source, confirmation, active context,
partial receipt and allowance history persist through restart.

J121 checks the complete owned investigation: context acceptance, three fixed
passes, deliberate allowance approval, halt, partial/final reports, specific
remaining-work revision, original-job resume, source reassessment and restart.
These journeys establish workflow and presentation behavior, not real model
usefulness or parity with the terminal references. Existing historical
free-form cost labels are not rewritten. Dense states with additional reality
warnings and broader output shapes remain part of the final UX review. The
transient notice still crowds the tested 40x12 Review body until dismissed;
clearer cost text does not establish complete layout quality.

The registry census is unchanged: 113 visible actions, 90 Core, 18 Labs and five
Compatibility. Thirteen in-scope actions still need audit. Source/scope
qualification, dirty-observation authentication, useful detection and complete
UX acceptance remain open. No broad milestone closes. The live allowance stays
exhausted at six of six; this increment makes zero live provider requests.
Evidence, failures, focused checks and immutable manifest:
`/tmp/kuzushi-tui-integration-20261012/unknown-cost-audit`.
