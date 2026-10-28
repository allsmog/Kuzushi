# Background investigation history

Terminal history refresh now uses the existing bounded view-reader pool instead
of reading campaign metadata and trend files on the input thread. The pool has
two reader slots, separate from discovery-worker concurrency. Each refresh owns
one request identity; a newer request cancels the earlier read and keeps only
the latest unscheduled request. Target and request checks discard stale results.

The bounded catalogue keeps its existing entry, file, job and aggregate metadata
limits. CLI and nonterminal readers retain synchronous behavior. This changes
presentation scheduling, not scan authority, provider selection, artifact formats
or resource allowances. No new discovery worker or model request is created.

## Interaction and recovery

History remains readable while loading. The terminal shows a loading state
instead of claiming that an unread catalogue is empty. Launch, worker changes,
exclusions and Review planning wait for the refreshed records. Reading, typing,
navigation and the owned dispatcher's Stop action remain available.

Selection follows the recorded investigation and job IDs. Leaving detail or
choosing another row cancels the deferred selection. Completion keeps the current
view, composer and newer operator notice. The transient wait notice clears after
success. Batch-result scope is bound only after its exact selected plan loads;
its findings projection uses the existing background ledger reader.

An explicit request for a different plan gets its own loading card with the
requested identity. Previous job counts and launch guidance do not stand in for
that plan's readiness. A same-plan refresh keeps its existing reader available.
Saved Review totals are captured again when the history read is admitted,
after the preceding findings refresh has accepted its projection.

The paged job reader pins the selected job label, including its pass, above the
parent workload. Both identity and total jobs stay visible at 40 columns.
Paged job lists also pin the selected study identity. Returning to a saved
scroll position must not hide which approved plan owns the displayed jobs.
The shared view, model, repository-index and session status header stays outside
the paged document. Its original document rows are omitted from the paged body,
so retaining orientation does not duplicate the header or reset reading position.
The existing compact-header rules still apply. A separate fixed study cost line
uses the shared campaign cost label, so session dollars cannot stand in for
unavailable study charges.
A cold loading view says `Investigation history`; active study forms still own
their heading.

Findings refresh precedes metadata loading because replacing the findings cache
invalidates outstanding view reads. A pending work receipt does not prevent
history inspection. Canceled singleton reads release their claimed keys when
their worker ends, without clearing claims belonging to a newer generation.

The phase projection is also read off-thread and applied through the existing
shared application helper. A captured projection generation prevents an older
history response from overwriting a newer phase update. A failed reader retains
previous records, qualifies spending as unknown and offers an explicit refresh.

## Verification status

Evidence root: `scripts/devex/artifacts/history-background-current-20261027/`.
The retained red regression demonstrates synchronous catalogue loading. Twelve
controlled background checks now cover held input, cancellation, the two-reader
bound, latest-request coalescing, exact batch handoff, target changes, newer
notices, phase-state protection and explicit failure recovery. Serial runs have
581 distinct passing TUI checks across campaign, hydration, batch membership,
study controllers, reader and header selections. The workspace build and
all-target TUI Clippy with warnings denied pass. All ten final draft repository
gates pass; their receipt records a dirty draft. The changed-code risk gate
passes for 67 production files. The signed clean receipt for the separately
approved and pushed commit `8b2281e99f` remains unchanged.

J394 uses 21 labeled synthetic unapproved plans with 20,002 unstarted jobs.
Its metadata exceeds the catalogue's 32 MiB allowance. The real headless status
must report partial history before the terminal reads the exact small plan,
types, navigates, opens the palette, resizes and restarts without color. It never
approves or executes those jobs, source programs or provider requests. Its
screen review is distinct from machine checks and operator acceptance.

Final J394 attempt 6 has 22 machine passes, zero failures, 15 authenticated
capture triples and four answered agent screen questions. Nine ANSI replays
were directly inspected across six sizes. The actual loading frame keeps the
Unicode draft; the final narrow page pins `Job: held-2` above its workload.
The palette retains focus and no-color restart restores the untouched plan.
There are zero new queues, observations, decisions or provider requests.
Binary SHA256:
`a9e87459b9ec0db8fd0573803083a0886c1ed1cc7db2af2691609151ed92a4ae`.
Raw status remains `REVIEW_REQUIRED`, exit 4. The agent verdict is
`PASS_WITH_FINDINGS`, separate from operator acceptance. Repeated controls,
long coverage warnings, generic palette routing labels and legacy phase help remain
findings. These are captured ANSI cells rendered with Menlo 15 and a chosen
dark background, not OS screenshots.

Final J121 attempt 5 uses the same binary and has 343 machine passes, zero
failures, 154 authenticated capture triples and 21 answered agent screen
questions. Twenty-two ANSI replays were directly inspected, including all six
Report sizes. It completes Context preparation and explicit Map acceptance,
three original Scan jobs, admitted cancellation, a protected-allowance halt,
explicit retry and allowance revisions, FP/deferral decisions, export recovery,
no-color restart and missing-context inspection. The agent verdict is
`PASS_WITH_FINDINGS`; raw exit 4 remains separate from operator acceptance.

Independent read-only ledger and source checks retain four observations, two
finding identities, three decision records, five call reservations including one
unsettled, and seven work attempts. The three original Scan jobs retain four
attempt runs, including the cancellation; current queue attempt counters sum to
three after resume and do not replace that history. Two protected Review calls
remain unused. Five intercepted requests add zero live requests. The owned
three-file greeting source is unchanged and never executes. Its dirty checkout
borrows the repository HEAD; this is not a scan of the committed Kuzushi tree.
Both recorded fixture process identities are terminal after completion.

Attempt 1 retains 20 machine passes and zero failures but fails agent review:
the compact paged reader lost its selected job identity. Other retained runs
include the initial test helper's constructor error, the sandbox's denied
process-group probe, the extra read caused by cache invalidation, and two
fixtures that bypassed canonical target activation. The corrected fixtures use
the same `WorkspaceTarget` root as actual activation; the loading and handoff
assertions remain intact.

Two complete J121 repeats stopped at the same linked-study check, each with
155 machine passes and one failure. Their correct Scan jobs were loaded, but
the retained page offset hid the investigation ID. The initial stale-plan
diagnosis was too broad; the captures establish a missing fixed identity.
The separate requested-plan loading card does not resolve that paging defect.
The fixed reader now pins the study ID, and the original native identity check
is unchanged. Both owned dispatcher/bridge pairs were verified terminal before
replacement. An initial cleanup comparison expected an omitted schema field;
it failed before any stop request and was corrected to compare recorded owner
fields against the versioned control. No signal or new work was needed.

The third repeat passes the plan-identity handoff, then records 158 machine
passes and two failures after cancellation. Paging hid both the `Study jobs`
title and the ready repository-index status. The latter caused an observation
timeout even though cancellation and saved partial work were correct. The shared
header is now fixed above the paged body, with a focused cancellation regression.
The original title and index assertions remain unchanged. The journey's owned
dispatcher and intercepted bridge were verified terminal after cancellation.

The fourth repeat reaches all 21 screen questions and records 340 machine passes
with three failures: unavailable study charges had scrolled out of view after
cancellation, the allowance halt and completion. Session dollars stayed labeled
as session dollars, but did not supply the missing study cost disclosure. The
fixed study-cost line reuses the existing shared label; an all-size paging
regression protects unknown charges. The original three native cost assertions
remain unchanged. Both owned process identities were verified terminal.

This increment does not establish a hard filesystem deadline, universal remote
filesystem performance, full finding-ledger scale or reference-interface parity.
Other shell operations and compatibility readers still need their own evidence.
