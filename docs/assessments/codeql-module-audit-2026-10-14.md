# CodeQL needs source-bound inputs and honest preparation/query outcomes

Explicit dbPath scanning bypassed the managed database's source and content
authentication. It accepted a directory with CodeQL-like metadata, selected a
language and analyzed it directly. A stale or unrelated database could therefore
produce observations associated with the current checkout. Database preparation
also used a recursive unbounded language walk, and numeric scan options silently
clamped overflow. Language-resolution subprocesses reset the selected timeout to
an adapter default. A database artifact could own a Map result.

Both CodeQL modules are now Labs and auxiliary. Creation retains its explicit
repository-execution authorization, isolated checkout and existing promotion
flow. Its receipt includes sourceCommit and targetScope, with a readable source
line. Creation does not complete Map. Query observations are partial, retain
SARIF/findings and cannot complete Scan. Source-byte authentication does not
establish query completeness, finding validity or a fix at another revision.

The internal analysis handle now requires an authenticated managed database. Default
and explicit paths share source/provenance checks, content identity, operator
promotion receipt and lifetime lock. Explicit paths must remain below the
target's .kuzushi directory. Raw/unpromoted paths are refused; matching managed
custom destinations can be created with outputPath. Dirty source, language
mismatch and changed database content fail before ledger publication where
tested. Existing post-analysis content authentication remains. This does not
prove immutable source/query execution or cancelable authentication across all
large cases.

Creation language selection uses the existing inventory: 100,000 entries,
512 MiB inspected overall, 256 KiB per inspected file, symlink exclusion and
iterative filesystem fallback. It preserves loose root files and refuses a
partial/canceled inventory instead of guessing one language from a prefix.
Explicit language remains available. Existing inventory omissions and generation
limits do not become complete repository coverage.

Shared input validation constrains timeoutMs from one to 86,400,000 for both tools, with
the existing 30-minute defaults and per-command/attempt semantics. A fixed
action can run several commands. Language resolution now uses the selected
scanner's timeout; transport/deadline failures stop that path, while unsuccessful
legacy-format commands may try the existing second format. threads defaults to
one in shared descriptors and direct construction. threads and ram reject values
outside one to u32::MAX rather than clamping. RAM is only requested through the
selected executable; no OS memory ceiling is claimed. Authentication traversal,
locks, total elapsed work, cache/query costs and live engine bounds remain open.

Unused private raw-database language/shape helpers and their output DTO are
removed after their callers moved to the authenticated handle. No public tool
name or module is deleted. The retained DAG dependency is display metadata;
it does not execute context:build or approve repository execution.

| Audit dimension | Evidence and limits |
| --- | --- |
| Purpose | Optional database preparation and query observations. Useful real engine coverage remains unqualified. |
| Phase | Labs auxiliary Map/Scan. Preparation and observations never own phase completion. |
| Inputs | Explicit clean source, build/suite/language inputs, selected executable and bounded numeric options. Creation requires repository-execution consent; no model is needed. |
| Execution | Shared prepared dispatch and real source/database authentication, with owned launchers and synthetic SARIF where recorded. |
| Outputs | Source-bound database receipts, partial query observations, retained finding/SARIF history and errors. |
| Failure | Raw DB, stale source, language mismatch, database mutation, missing dependency, cancellation and malformed limits have scoped evidence. |
| Resources | Bounded inventory, selected process timeout and one requested thread. Total work, memory and authentication cancellation remain unqualified. |
| Scope | Whole source-bound database; exact repository discovery membership and multiple managed language databases remain unqualified. |
| Interfaces | Canonical options and internal handles serve scan/shell/run; native evidence is recorded below. |
| Product value | Closes raw-DB provenance bypass and recursive discovery, removes hidden timeout reset and numeric clamping. Real precision and complete UX remain open. |

Evidence is retained under
`/tmp/kuzushi-tui-integration-20261012/codeql-module-audit`.
Initial failures are retained. Three older assertions relied on integer clamping,
an unmanaged cancellation fixture and completed query status. Updated checks
protect rejection, managed cancellation and the intended partial contract.
CRAP-risk failures identify an overlong function and branchy language helper;
small named helpers resolve those local issues.

Final focused verification records 123 CodeQL Rust checks, 27 TUI phase-result
checks, 12 paste/input checks, 39 journey-truth checks and one shared registry
policy check. All 202 pass.
The locked workspace build passes. The CRAP-risk proxy passes across 639 changed
code files. This is focused verification, not a full Rust-suite result.
All ten quick-plan gates pass through their checked-in commands, including 391
Node tests. Affected gates were rerun after the phase-truth correction; unchanged
Node test evidence is retained. Package signature verification was not bypassed.

Six headless input/dependency cases and eleven native preparation/query scenarios
pass. The latter cover default and custom managed destinations, partial nonempty
SARIF consumption, raw DB rejection, language mismatch, database-content change,
query deadline, preparation deadline and dirty source. Four additional CLI receipt
checks pass before the final TUI-only phase correction; headless executors are
unchanged by that correction. The native preparation deadline stopped during
Git source acquisition before invoking the owned launcher; it does not prove a
whole-action deadline or a real CodeQL build deadline. That early failure also
retains legacy source-helper wording naming a patch tool and suggesting Git
installation. Its cause records the deadline; this presentation gap remains open.
Earlier observations and the managed database survive the tested refusals.

The TUI investigation exposed two input/reading defects. Help and Keymap accepted
paste into a visible draft while retaining modal ownership of Enter and Home.
Paste now restores the exact origin before routing to its existing input owner,
preserves the draft/cursor and waits for explicit submission. The regression
checks include multiline paste and both overlays. Raw-database refusal originally
put a long path before its cause, clipping the useful reason from notices.
The cause and rebuild action now precede the path.

Reviewing the restart captures exposed a separate phase-authority defect that
the existing no-phase-result assertions missed. A finding with any nonempty
local scan ID could infer completed Map and Scan through the ledger fallback,
even when its run was partial and auxiliary. Finding counts now contribute
review progress only. Legacy phase inference requires a compatible completed
run receipt; selected modern attempts retain their explicit acceptance rules.
Raw/imported IDs, partial primary scans and auxiliary CodeQL results cannot
manufacture checkpoints. Historical findings remain available through Review.
The final restart journey also checks the rendered rail, rather than only the
absence of a phase field in run metadata.

Retained journey failures also include invalid fixture expectations: a long-command
prefix outside the composer viewport, an external fake bundle directory containing
the source root, missing initial exit confirmation for unsaved planning choices,
and requiring another confirmation after those choices were gone on restart. The fixture now
uses a dedicated sibling bundle and explicit input/exit states. These failures
are retained and are not counted as passes.

The final immutable bundle is
`/tmp/kuzushi-tui-integration-20261012/codeql-module-truth-final-native`.
Its product SHA-256 is
`9bdde126a68730e147d25c665e630fb39d2e4003436798d66bc3102a8e54bb17`.
The current registry contains 113 visible tools: 77 Core, 31 Labs and five
Compatibility. This audit assigns the two remaining in-scope visible tool rows;
hidden tools, real engine usefulness and full phase qualification remain open.

Final J250 records 22 machine passes, no failures and 20 authenticated capture
pairs at six terminal sizes plus no-color restart. It retains the exact partial
query digest, source SHA and observations after raw/dirty refusals, and its
restart rail no longer claims completed Map or Scan. Four human judgments remain
pending. Captures:
`/tmp/kuzushi-tui-integration-20261012/codeql-module-truth-final-tui/20261014-055211/J250`.

Sequential J121 on the same immutable bundle records 109 machine passes,
no failures and 87 authenticated capture pairs. Accepted context, finite passes,
protected Review, explicit allowance revision, source reassessment, partial report
and restart retain their receipts. Four provider responses are fully intercepted;
there are no live provider calls. Fifteen human judgments remain pending. Captures:
`/tmp/kuzushi-tui-integration-20261012/codeql-module-truth-complete-tui/20261014-055421/J121`.
Both raw results remain REVIEW_REQUIRED, with operator approval unset.

Text review confirms visible execution consent, separate source/scope receipt
lines, explicit query limitations, useful raw-DB refusal and accessible historical
results. It also retains UX gaps: the 40x12 default Replay frame is mostly outcome,
path and notice chrome; two page-down presses still do not reach the detailed
query limitation. Long paths and artifact/event rows crowd broader receipts.
No human approval or reference-product parity follows from machine checks.

The live allowance remains exhausted at six of six. Validation uses owned
inert source/tool fixtures, never real CodeQL query/build execution or provider
spend. Source-binding helpers live under a historical remediation namespace;
no patch, exploit or reproducer operation is invoked. No broad milestone closes.
