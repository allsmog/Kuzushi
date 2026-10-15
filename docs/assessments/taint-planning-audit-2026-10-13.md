# Deterministic planning, inventory bounds and action choice

`taint-iris-next:dataflow-plan` is auxiliary Scan preparation and now appears
as Labs. `taint-iris-next:source-sink-trace` is Compatibility. Both exact names
call the same planner with the same options and output; the alias has no
distinct executor contribution. Neither can own a selectable Scan result.
Existing dispatch names, artifact shapes and runtime-free behavior remain.
Detection, candidate linking and ranking algorithms are unchanged.

The source collector recursively called itself for each directory. It now
uses a heap-backed stack of directory iterators, preserving sorted depth-first
order and loose parent files. The existing 20,000-file full-inventory limit,
100,000-entry walk limit and 512 MiB aggregate read limit remain. A complete
walk fails explicitly at a limit; sampled reads remain a bounded prefix.
Steady-state symlink cycles and external files stay excluded.

Partition advice also performed a separate directory walk with only a C-file
count cap. A tree with few C files could make that statistics walk inspect
arbitrarily many directories. The count now uses captured inventory membership
and saturates at 2,000 without filesystem reads. The failing count regression
exposed `.cxx` being declared as C++ but omitted from collection. This specialist
collector now includes it, without widening the shared agent inventory policy.
Advice asks the operator to review scopes and workload before more work.

The shell module shorthand bypassed tool maturity by selecting the first
non-hidden tool in a Core module. It now checks the shared discovery predicate
for that registered primary. An experimental primary requires an exact action;
the shell does not select a different remaining action or global SAST. Supported
primary shorthands remain unchanged. The new error names the operator's move.
Missing-context receipts now lead with **Missing context or source inventory**,
retaining the full target and recovery details in their payload.

| Audit dimension | Evidence and limits |
| --- | --- |
| Purpose | Prepare supporting analysis; the trace alias has the same executor. Useful candidate/engine results remain unqualified. |
| Phase | Scan authorization retained, auxiliary output only. Registry and shell tests prevent phase-result ownership. |
| Inputs | Explicit workspace, declared planning options and existing prerequisite checks. Empty inventory/context produces an honest failed result without a model. |
| Execution | Prepared dispatch, JSON/plain CLI and shell workers exercise missing prerequisites on owned directory metadata. No scanner query or model runs. |
| Consumers | Durable prerequisite failures and full payload survive Replay and restart. Finding-review consumption of nonempty plans remains unqualified. |
| Failure | File, entry and byte limits fail honestly; malformed/partial source reads and cancellation across the complete pipeline still need qualification. |
| Resources | Iterative collection, a 160-level walk on a 128 KiB stack, stable prefixes and pure statistics count are verified. Engine work, repeated source reads and cancellation remain unqualified. |
| Scope | Selected-root inventory and symlink exclusion have tests. Discovery receives repository inventory; this does not establish scoped candidate isolation or backend graph containment. |
| Interfaces | Shared dispatch and no-model failure behavior agree across CLI/shell. Six sizes and normal no-color restart are exercised. Useful engine output and all options remain open. |

## Verification

Twenty-six distinct focused Rust tests pass, including the explicitly selected
isolated small-stack test. They cover inventory order, root files, symlinks,
limits, `.cxx`, captured statistics, descriptor policy, module shorthand,
activity classification, phase ownership and module rendering. The existing
184-tool dispatch policy fingerprint remains unchanged. The locked workspace
build and all ten exact quick-plan commands pass, including 391 Node tests and
the CRAP-risk proxy over 526 changed code files. The full Rust suite was not run.
Package commands ran directly without disabling signature verification.

The initial descriptor test failed before curation. An intermediate partition
test failed because the source inventory omitted `.cxx`; that product defect
was fixed rather than weakening the expected count. The earlier native outcome
placed a long absolute path before its missing-prerequisite explanation. The
cause-first summary is verified separately. A final narrow assertion required
correction for ordinary line wrapping, with its failed capture retained.

Both headless exact interfaces return canonical failed status and exit 3 in
JSON and plain modes when context and usable inventory are missing. Source
bytes stay unchanged. Core/all catalogs omit/include the curated tools and
retain 113 visible actions: 94 Core, 14 Labs and five Compatibility.

Native J237 covers explicit action choice, both failed exact interfaces,
recorded evidence, six sizes, exit confirmation and no-color restart into Setup.
The final run records 15 machine passes, zero failures and 15 capture pairs.
Four human judgments and operator approval remain pending; its raw result is
`REVIEW_REQUIRED`. At 40x12, the cause fits at the top in two lines. The full
recorded error and recovery guidance remain reachable by paging, although the
generic Replay body is still dense and complete narrow evidence access is open.
The full target remains in structured receipt data.
No finding observations, decisions, phase attempts, provider reservations,
model-call events or additional analysis jobs are created. Absent accounting
tables are recorded as absent. Source is never executed and its bytes remain
unchanged. This fixture establishes failure and resource-control behavior,
not scanner usefulness, source feasibility or calibrated precision.

Final native SHA-256:
`6eb05938c76e3c780a46a2895f11f50a17f2666daeebc0fae299b70bc3fc7095`.
Captures:
`/tmp/kuzushi-tui-integration-20261012/taint-planning-final-tui/20261013-165852/J237`.
Tests, native CLI, retained failures and immutable manifests:
`/tmp/kuzushi-tui-integration-20261012/taint-planning-audit`.

The complete J121 workflow was also revalidated after the generic shorthand
change, with 109 machine passes, zero failures and 87 capture pairs. It retains
accepted context, three fixed passes, protected Review capacity, partial and
final exports, explicit allowance revision, original-job-only resume, source
reassessment and restart. Four fully intercepted requests add no live spending.
Fifteen human judgments remain open. That run used native SHA-256
`9449d9a035f0e9d502d898e3fba53c2c92875d9e82b5132e47196d10a245ef0b`,
before the missing-context summary refinement. No broader equivalence claim is
made for actual model quality or engine coverage. Captures:
`/tmp/kuzushi-tui-integration-20261012/taint-planning-complete-tui/20261013-165329/J121`.

The candidate retirement is documented separately in
[module retirement candidates](module-retirement-candidates.md). No deletion
is authorized or applied. Seventeen in-scope actions remain without assigned
functional verdicts; existing scoped verdicts retain their individual limits.
The live test allowance stays exhausted at six of six. All broad delivery
milestones and complete reference UX parity remain open. Work stays staged on
main without a commit or push.
