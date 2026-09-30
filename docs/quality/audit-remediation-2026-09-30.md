# Audit remediation ledger — 2026-09-30

Tracks the supplied 100-item audit (reviewed `cdfb4fc6df743b14fb3bcb362b1b40923544365f`) against implementation based on main `13e6aae8db57729a5aab350a1c7348df17036150`.

**Implemented** means code and focused regressions exist; it does not imply a merged change or platform qualification. **Partial** names the remaining acceptance work. **Open** is not fixed. This ledger must not be summarized as all 100 complete.

| # | Audit item | State | Evidence / remaining work |
|---|---|---|---|
| 1 | Kill and reap the entire sandbox process tree on timeout | Partial | Unix/Windows owned process supervision and bounded cleanup added. Podman container cleanup and qualified backend fixtures remain. |
| 2 | Bound stdout and stderr while reading, not after completion | Implemented | Bounded concurrent stream readers terminate overflow; noisy-child regressions. |
| 3 | Actually remove ambient credentials from sandboxed children | Implemented | Empty child environment with explicit PATH/LANG and grants; synthetic-secret test. |
| 4 | Make resource limits real for the preferred Bubblewrap backend | Open | Implement and qualify memory/process/CPU/scratch limits for each supported backend. |
| 5 | Give Podman an explicit, digest-pinned image and consistent command semantics | Open | Separate and pin container image identity, disable implicit pull, and propagate image policy through callers. |
| 6 | Supervise stdin delivery and report broken input pipes | Implemented | Bounded supervised stdin; broken-pipe errors and blocked-reader tests. |
| 7 | Unify sandbox capability reporting across supported operating systems | Open | Unify installed versus verified backend capability reporting and doctor behavior. |
| 8 | Bind offense authorization to the final parsed URL authority | Implemented | Validate final URL authority, IPv6 and ports against typed scope before curl. |
| 9 | Recheck engagement expiration before every outbound play | Implemented | Revalidate scope and expiration for every transport send; fake-clock regression. |
| 10 | Parse HTTP response framing without treating body text as headers | Implemented | Parse only the initial HTTP header section; preserve body and reject upgrade framing. |
| 11 | Do not promote partial curl output to a completed response | Implemented | Only complete, untruncated exit-zero curl output becomes a response. |
| 12 | Run curl with an explicit configuration and proxy policy | Implemented | Disable curl config and proxy inheritance explicitly. |
| 13 | Disable curl URL globbing for model-generated paths | Implemented | Disable curl globbing and separate flags from the final URL. |
| 14 | Give the MCP server a responsive cancellation and shutdown lifecycle | Partial | Bounded concurrent requests, cancellation, shutdown and output deadline implemented. Blocking CPG work still requires a cancellable worker. |
| 15 | Enforce advertised MCP input schemas at the shared dispatch boundary | Implemented | Compile offline JSON Schema validators once and reject invalid arguments before handlers. |
| 16 | Content-pin the legacy package module trust path | Open | Authenticate installed package closure and bind describe/execute to an immutable approved snapshot. |
| 17 | Stop projection watermarks from skipping failed events | Implemented | Contiguous projection sequence; failure blocks later watermark advancement until replay. |
| 18 | Make spend admission atomic across processes and limiter instances | Implemented | SQLite immediate transaction makes cap admission and reservation atomic across connections. |
| 19 | Refresh durable budget caps at reservation time | Implemented | Read durable caps during admission; independent-connection cap-change regression. |
| 20 | Give unresolved spend reservations provenance and reconciliation | Open | Persist reservation run/model/owner provenance and expose reconciliation. |
| 21 | Include the full model execution contract in semantic cache keys | Open | Bind semantic cache identity to the full execution contract without persisting credentials. |
| 22 | Bound semantic-cache disk usage and make pruning incremental | Open | Add disk/entry quotas and incremental, correctly stamped pruning. |
| 23 | Preserve accumulated loop spend when a later model turn fails | Implemented | Typed loop failures retain transcript and known spend; unresolved reservations retain observed cost. |
| 24 | Journal tool-call intent and completion before resuming side effects | Partial | Persist tool-call intent before execution; unresolved intent refuses automatic replay. Per-tool replay-safety declarations and reconciliation UI remain. |
| 25 | Give resumable loop checkpoints cross-process ownership | Implemented | Kernel file lease covers same-request load, save and clear; lock files retain stable identity. |
| 26 | Apply byte and record bounds to checkpoint loading and serialization | Partial | Loop and stage reads bounded; loop count and serialization bounded. Stage serialization and per-tool result quotas remain. |
| 27 | Report checkpoint degradation before operators depend on resume | Partial | Checkpoint write/load/lease failures are explicit and stop unsafe continuation. Operator-facing resume health receipts remain. |
| 28 | Budget tool-loop context by tokens and tool-result size | Open | Apply token and per-tool-result budgets with a resumable evidence summary. |
| 29 | Preserve backpressure after storage messages leave bounded channels | Partial | Internal actor queue is count-bounded. Aggregate queued-byte admission remains. |
| 30 | Move blocking storage work off Tokio executor threads | Implemented | Storage actor performs blocking database and sync work on a blocking worker. |
| 31 | Make projection rebuilds recoverable without destroying the serving view | Implemented | Transactional rebuild preserves serving projection, generation and lifecycle on failure. |
| 32 | Implement space-reclaiming event-log compaction | Open | Implement real event-log compaction with crash-safe publication and reader ownership. |
| 33 | Stream event-log verification and index terminal deduplication | Open | Stream event-log verification and maintain bounded terminal-event deduplication. |
| 34 | Propagate event-log directory fsync failures | Implemented | Propagate directory synchronization failures. |
| 35 | Invalidate loop resumes when the implementation changes | Implemented | Checkpoint identity includes the executing binary digest and protocol revision. |
| 36 | Reserve lifecycle capacity for model completion and cost receipts | Open | Reserve capacity for model completion and spend receipts through overload and shutdown. |
| 37 | Make scoped CPG artifact keys collision-resistant | Implemented | Versioned collision-resistant scoped CPG keys. |
| 38 | Replace mtime-only graph freshness with source-content identity | Implemented | Source-content, configuration, implementation and graph-byte identities replace mtime freshness. |
| 39 | Keep both C and C++ in genuinely mixed repositories | Implemented | Retain C and C++ in mixed repositories. |
| 40 | Return failed-language coverage in CPG tool results | Implemented | Reject incomplete graph queries with failed-language coverage. |
| 41 | Disclose every taint-query truncation and its scope | Partial | All taint category and flow caps disclosed. Core adapter input validation and resource coverage remain. |
| 42 | Enforce or reject the advertised maxCallDepth option | Implemented | Reject maxCallDepth while the engine cannot enforce it. |
| 43 | Make regex versus literal matching an explicit contract | Implemented | Explicit regex/literal query mode; invalid regex returns a diagnostic. |
| 44 | Bound CPG work by bytes, memory, and cancellation as well as file count | Open | Bound source and graph bytes and move builds/queries to supervised cancellable workers. |
| 45 | Make CPG source census errors visible and platform-correct | Open | Make source census fallible and consistent for exclusions, generated files, symlinks and Windows paths. |
| 46 | Avoid rediscovering and reopening every language on every graph query | Open | Reuse source census and authenticated graphs under a bounded worker lifecycle. |
| 47 | Make method-position answers exact or explicitly approximate | Partial | method_at identifies nearest-preceding approximation. Exact containment and downstream reaching-definitions behavior remain. |
| 48 | Reject overflowing and ambiguous CPG query inputs | Partial | Reject overflowing line numbers. Ambiguous file/method resolution remains. |
| 49 | Put a local deadline around code-index initialization and tool requests | Implemented | Deadline covers initialization, lock wait, writes and response; cancelled clients retire and reap. |
| 50 | Bound code-index protocol frames and discard unrelated frames iteratively | Implemented | Bound protocol frames and ignored-frame counts; iterative frame filtering. |
| 51 | Ground the finding's own primary location on every insert | Implemented | Ground every primary anchor against actual source while preserving original coordinates. |
| 52 | Replace evidence-shape heuristics with typed evidence variants | Partial | Reject zero-line code and mixed code/HTTP evidence; preserve explicit non-source kinds. Typed evidence migration remains. |
| 53 | Merge corroborating and contradicting evidence independently of severity | Implemented | Union independently grounded cross-producer evidence regardless of severity; stable provenance and ordering. |
| 54 | Persist per-finding prefilter dispositions | Open | Continue existing PR #299 (supersedes #296); add durable per-input dispositions and readable output. No third prefilter implementation here. |
| 55 | Enforce citations for substantive verification verdicts | Implemented | Validate bounded exact source citations and required proof roles before accepting verdicts. |
| 56 | Preserve every panel member's reasoning and evidence | Partial | Preserve every verification pass and dissent in consensus receipts. Triage and gate panel receipts remain. |
| 57 | Calibrate confidence rather than average self-reported certainty | Partial | Label model confidence as uncalibrated and retain raw values. Held-out calibration dataset remains. |
| 58 | Separate static assessment vocabulary from runtime verdict vocabulary | Open | Migrate static verdict terminology across stored receipts, adapters, exports and TUI. |
| 59 | Do not promote arbitrary stderr text to a crash proof | Implemented | Only observed process signals qualify as crash evidence; stderr text cannot promote proof. |
| 60 | Add vulnerability-specific non-crash success oracles | Open | Define and enforce vulnerability-specific success oracles. |
| 61 | Implement a faithful Python proof adapter | Open | Implement isolated Python harness with interpreter/environment receipts. |
| 62 | Implement faithful Node/TypeScript proof adapters | Open | Implement isolated Node/TypeScript harnesses with package/config identity. |
| 63 | Capture the reproducer's build environment, not just source and argv | Open | Capture toolchain, dependencies, environment and sandbox provenance for reproduction. |
| 64 | Use one-to-one finding/oracle matching for headline precision | Implemented | Deterministic one-to-one weighted assignment with duplicate grouping and exhaustive small-graph checks. |
| 65 | Separate unjudged findings from false positives | Partial | Expose unjudged findings and yield metric. Adjudication workflow remains. |
| 66 | Bind each benchmark to one exact scan run | Implemented | Bind benchmark receipts to one exact scan and SARIF run ID. |
| 67 | Refuse success-like benchmark scores after failed execution | Implemented | Failed, incomplete and stale scan receipts cannot publish a benchmark score. |
| 68 | Verify oracle revision against the actual benchmark target | Partial | Require actual clean target HEAD matching oracle and bind run artifacts. Ignored-file provenance and complete score-artifact binding remain. |
| 69 | Publish actual repeated, costed detection baselines | Open | Run repeated pinned paid-model benchmarks and publish actual cost/detection receipts; no synthetic baseline substitutes. |
| 70 | Make expected recall thresholds enforceable | Implemented | Range-checked opt-in recall threshold enforcement changes exit status. |
| 71 | Wire runtime cost receipts into the benchmark harness | Implemented | Cost receipts preserve exact zero, known spend and unknown-cost distinctions. |
| 72 | Score complete benchmark exports rather than clamped presentation lists | Implemented | Score the complete run-bound SARIF export with explicit completeness checks. |
| 73 | Cancel superseded target inspections instead of only discarding their results | Open | Cancel superseded inspection work rather than only dropping results. |
| 74 | Disclose incomplete target inspection instead of presenting partial counts as complete | Open | Carry inspection gaps and cancellation through progress and final UI. |
| 75 | Restore the original composer draft when reverse-history search is canceled | Implemented | Restore draft, cursor and paste payloads on history-search cancellation or empty acceptance. |
| 76 | Store command history as structured records so multiline commands survive restart | Implemented | Versioned structured history preserves multiline input; compatible legacy import. |
| 77 | Apply the history byte budget on writes as well as reads | Implemented | Enforce history count and byte limits when writing and reading. |
| 78 | Make text editing operate on grapheme clusters | Open | Use grapheme boundaries consistently for movement, deletion and cursor rendering. |
| 79 | Treat collapsed paste placeholders as atomic editable objects | Open | Model paste placeholders as atomic editable objects with payload lifetime. |
| 80 | Reject shadowed keybindings and chord-prefix conflicts | Open | Reject active-context key conflicts and one-stroke/chord-prefix shadowing. |
| 81 | Provide an interactive linear mode for screen-reader users | Open | Add an interactive linear terminal mode with accessible focus and prompts. |
| 82 | Stream plain-mode progress and consume input incrementally | Open | Stream plain-mode events and consume commands incrementally. |
| 83 | Separate review disposition from proof status in finding filters | Open | Separate disposition and proof-state facets in filtering and counts. |
| 84 | Put the exact export preview on the Report route | Open | Place a source-bound exact export preview on the Report route. |
| 85 | Give interactive OAuth children exclusive ownership of terminal input | Open | Suspend terminal input ownership while interactive OAuth child runs. |
| 86 | Bound and coalesce the terminal input backlog | Open | Bound and coalesce input backlog while preserving ordered command events. |
| 87 | Require a Rust test receipt for the actual merge candidate | Partial | Rust test job runs for every ready PR update and merge queue. Required-check administration must be configured externally. |
| 88 | Pin the frequently executed PR action supply chain | Partial | Pin CI actions, actionlint image, and reference-workflow first-party actions. Verified sticky-comment action pin remains. |
| 89 | Measure the entire interval between deep-quality runs | Implemented | Select latest successful ancestral full-quality run; explicit bootstrap baseline required. |
| 90 | Fail closed on missing coverage instrumentation | Implemented | Missing changed executable-line instrumentation fails coverage. |
| 91 | Parse Git's quoted filenames correctly in coverage | Implemented | Decode Git quoted UTF-8 filenames and octal escapes. |
| 92 | Fix the mutation diff loop's lost exit status | Implemented | Preserve mutation diff command failure status. |
| 93 | Discover all Node contract tests automatically | Implemented | Recursively discover every Node contract test. |
| 94 | Keep quiet verification's failure evidence | Implemented | Bounded logs retain command, exit, digest and diagnostic tail in verification receipts. |
| 95 | Exercise platform runtime contracts before release time | Partial | Configure Windows/macOS runtime jobs for ready PRs. Actual platform receipts and path selection remain. |
| 96 | Add a real scanner integration lane beside deterministic smoke | Implemented | Real Semgrep 1.146.0 invokes the native CLI with local rules; vulnerable line 2 found, fixed fixture clean. Separate Full CI job. |
| 97 | Test the dependency tree that fresh npm users actually resolve | Implemented | Fresh npm production resolution passes bridge contracts and records its graph; public-install receipts now include the installed graph and bridge checks. |
| 98 | Promote `latest` only after the public-install smoke passes | Partial | Publish candidate dist-tag and gate latest promotion on exact-version public smoke. GitHub release visibility follows promotion. Interrupted promotion and actual public-tag qualification remain. |
| 99 | Turn the Clippy allowance list into an actual shrinking baseline | Open | Capture stable existing Clippy diagnostics and reject additions. |
| 100 | Test workflow semantics rather than token presence | Partial | Parse YAML and assert promotion/PR-test/quality-base semantics. Remaining token-only release contracts must be migrated. |

## Verification

- Full Node contract suite: 336 passed before the final runner-architecture assertion; that assertion is tested separately.
- Repository quick gate and workspace/all-target Clippy with warnings denied passed.
- History/editor-related TUI suite: 54 passed.
- Core focused suite: 889 passed, one ignored; includes findings, runtime, verification, offense, spend, storage, stage checkpoints and scoped CPG integration.
- MCP common, CPG, MCP CPG, code-index, sandbox and evaluator suites passed.
- Real pinned Semgrep and fresh npm dependency-graph smoke passed.
- Full core-suite attempts stalled in aggregate scan/lifecycle tests; the isolated scan fixture passed. Repository-execution tests also failed because this workspace cannot open the required Bubblewrap namespaces. The full core gate is not claimed green.
- macOS/Windows, actual container resource enforcement, public npm publication and paid benchmark runs require their corresponding execution environments. No such receipt is claimed here.

## Review boundaries

No merge, package publication, branch-protection change or benchmark spend is performed by this remediation branch. Prefilter work remains on its existing PR rather than being copied into a third implementation.
