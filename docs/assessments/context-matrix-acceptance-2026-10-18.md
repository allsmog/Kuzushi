# Context matrix discovery and recovery checkpoint

Prepared on main from `41998697dbc114bab95763ebdfb2edaead0026ee`.
Evidence: `/tmp/kuzushi-context-matrix-acceptance-20261018`.
This checkpoint includes the saved scan advice and compact completion receipt
increments documented separately. Four delivery items remain locally verified;
five remain open.

## Discovery behavior

The standard agentic scanner previously instructed discovery to query prior
findings before reporting and omit duplicates. A repeated study could therefore
miss a rediscovery because it was already recorded. The initial intercepted
matrix test did not detect that instruction because it returned fixed findings.

The scanner now instructs each pass to report its source-supported observations,
including rediscoveries. It removes the findings MCP attachment before building
prompt enrichment and runtime policy. Source and selected threat-model tools
remain available. Removing the only attachment also disables the empty-list
legacy MCP fallback. The ledger still consolidates observations; Review and
other history consumers keep their existing tools. There is no new option,
model fallback, public schema change or engine promotion.

An existing-ledger regression proves the generic policy would attach findings
and the actual agentic scanner removes it. Prompt and policy tests also cover
preserved source/context settings and the empty-attachment case. This protects
the standard agentic path. It does not establish hard history-file isolation for
every custom runtime or qualify other engines as independent discovery.

The descriptor description changes recorded scan conditions. A fixed plan that
fails descriptor authentication must be prepared and explicitly approved again;
prior attempts and spending remain historical evidence. See RELEASING.md.

## Keyboard behavior

Home and End select the first and last study form fields. They never approve a
plan or start work. Numeric editors retain caret ownership and expanded readers
retain their own navigation. Visible hints disclose the form shortcuts. The
native journey uses those shortcuts to avoid dependence on a restored cursor.

## Verification

There are 356 distinct focused Rust passes: 41 agentic scanner, ten matrix,
272 batch study and 33 study view-model checks. The three discovery-policy
checks are included in the 41. The 189-tuple registry policy contract passes
separately without a fingerprint change. Locked workspace build, Core/TUI
Clippy, the CRAP-risk gate and fixture formatting pass. Repository publication
also requires the clean ten-step verification receipt and its signature.

Final sequential native journey: **J109**, under
`native-v4/native/J109/20261018-032218/J109` in the evidence directory.

- 48 machine passes, zero failures, eight pending human UX judgments.
- 49 live text/ANSI capture pairs across 120x36, 160x48, 96x89, 80x24,
  60x20 and 40x12, including no-color restart and accounting failure/recovery.
- Sixteen selected ANSI cell replays inspected. These are terminal-cell
  renderings, not OS screenshots or human approval of the pending judgments.
- Thirteen frozen executables, 4,629 source inputs and 813 runtime inputs.
- Main executable SHA-256:
  `5ef378825a34d277450a98feaa4158500e45f801a7187ee30120f951bfe22f6c`.

Three accepted immutable contexts each receive three fresh passes, one worker
and nine fixed jobs. The local fixture intercepts every provider request. It
asserts the selected model/reasoning, fresh sessions, absent prior-history
guidance and tools, and no earlier synthetic observation in the prompt. Each
case has identical prompt hashes across its repetitions; the three cases have
different prompt hashes. The globally active Gamma context is never substituted
for Alpha or Beta.

The independent verifier authenticates the canonical plan and all nine prepared
input hashes against the single allowance revision. There are nine completed
single-attempt jobs, nine work attempts and nine settled Discovery reservations.
Eleven calls were approved with two protected Review calls left unused. Dollar
consumption is unknown, with incomplete cost evidence; zero-valued compatibility
totals do not establish free execution. Hiding and restoring the owned allowance
table preserves exactly the same approval rows. Restart and result readers add
no work or requests.

Six labeled synthetic observations consolidate under one finding identity.
Recurrence is Alpha 3/3, Beta 2/3 and Gamma 1/3. The comparison labels the missed
observation as not observed and discloses changed threat-model conditions. The
canonical finding remains present, unsuppressed, untriaged and unverified. No
human verdict or resolution follows from a later miss. The owned source file
and active-context mirror hashes remain unchanged.

Earlier native-v1/v2 navigation failures are retained and made no intercepted
requests. Native-v3 passed mechanically before inspection exposed the history
instruction defect. It does not qualify discovery independence. Native-v4 is
the final evidence with the repaired scanner and stricter provider assertions.

## Limits and remaining work

All observations are labeled synthetic over inert owned source. No target
source is executed. This test establishes neither model precision nor complete
repository coverage, statistical confidence or parity with reference TUIs.
Narrow screens preserve navigation but abbreviate long labels and require
selection/scrolling to reach the last case. Broad TUI acceptance and eight
human judgments remain open, along with reviewed lessons and the remaining
delivery ledger work.

No live provider request is added. The cumulative live experiment use remains
fourteen, with its existing allowance exhausted. Exploit development,
reproducer execution and vulnerability patching remain outside this work.
