# Changelog

Notable changes to Kuzushi. Release procedure lives in
[RELEASING.md](./RELEASING.md); GitHub Releases carry the per-tag commit log.

## Unreleased

**Additive:**

- Local verification now leaves a signed receipt. `pnpm verify:quick:summary`
  binds its result to the commit, tree, clean/dirty state, toolchain, host, and
  a digest of the plan that ran, and states what the run does not cover;
  `pnpm verify:receipt:sign` signs it and `pnpm verify:receipt:verify` refuses
  anything unsigned, stale, dirty, failing, from another commit, or produced by
  a weakened plan. A new `.husky/pre-push` hook asks for that receipt before a
  push reaches `main`. The gate stays trust-on-owner and advisory — `git push
  --no-verify` bypasses it — but it is now auditable. See
  [docs/quality/local-verify-receipt.md](./docs/quality/local-verify-receipt.md).
- Confirmed findings now feed later scans. `threat-model:build mode=refine`
  records a grounded `variantPatterns[]` entry on the threat each confirmed
  finding realizes. The entry holds the CWE, the location, the proven call-site
  line, and that line's distinctive identifiers. taint-iris-next seeds the
  matching CWE's structural queries from these entries, and the agentic-SAST
  threat-model digest asks the agent to look for siblings of each call site. The
  new `sast:scan` option `threatModelFeedback=refine` (default `off`) runs the
  refine after triage and reports it under `data.threatModelFeedback`. The
  scan releases its shared lease on the bound model revision before that
  refine commits, so the refine does not wait on the scan's own lock. On Juice
  Shop, one refine attached 9 of 10 new findings and wrote 9 patterns, and the
  next CWE-89 hunt plan carried the `routes/login.ts` pattern keywords.
- `threat-model:diff` compares two threat-model permutations. Its required
  `from` and `to` options each take a revision id (`tmr_…`) or a lineage id
  (`tm_…`, meaning that lineage's head revision), so two revisions of one
  lineage and two competing lineages are compared the same way. The result
  lists threats added, removed, and changed (keyed by `stableId`, else `id`,
  naming the changed fields), DFD node/flow/trust-boundary deltas, entry-point
  coverage on both sides, and whether the methodology changed. Independent
  builds mint fresh `stableId`s, so threats unmatched on both sides pair by a
  display `id` that is unique on each side and count as re-keyed. On Juice
  Shop, the single-pipeline build (11 threats) against the staged build (20)
  reads +9 added, 11 re-keyed, instead of +20 added and -11 removed. An id that does
  not resolve is an error naming what was tried, never a substitute revision.
  In the shell, `threats diff <from> <to>` runs the same tool; bare `threats
  diff` still inspects compatibility-mirror edits.

**Fixed:**

- Map's embedded visualization no longer hides rows without saying so. The
  Components/attack-path/heatmap/worklist projections drew into the canvas as a
  plain scrolled `Paragraph`, and Ratatui clips one silently: on a real 2657-row
  component tree the operator saw the tree stop mid-branch, with an unrelated
  receipt line and the NEXT ACTION drawer on the next rows and no indication
  that anything was missing. Only `z` zoom, whose full-frame path reserves a row
  for `rows X-Y/N`, disclosed the true size. The embedded canvas now reserves
  that row too and states the same window. It also clamps the window, so `G`
  (and a held `j`) land on the tree's last page instead of scrolling the canvas
  past its content into blank rows, and a projection that fits its canvas is
  never scrolled away and states no position. Reported by the 2026-09-29 KZ TUI
  operator-experience audit (#172).

- A RESULT READY card the shell presents on its own now arrives with its keys
  armed. A Map launched from Setup, or a phase run launched from the planning
  picker, finishes by restoring the launch origin's input mode and then moving
  the operator to the Workbench page holding the unresolved attempt. The origin
  mode for those launches is ordinarily Prompt, and the card's single-key
  actions (`u` select, `n` continue, `d` discard, `r` run again, …) are
  dispatched only in Navigate mode — so the card the shell had just asked the
  operator to decide arrived disarmed, and the `u` it advertised landed in the
  composer as text with no card action and no notice. The one existing
  regression test covered only the case with a prompt draft in flight, where
  preserving Prompt is correct, so the empty-composer case went unnoticed; the
  KZ TUI operator-experience audit (#172) reproduced it as an intermittent
  "key-dispatch race". Presenting a result card now enters Navigate mode when
  nothing else owns the keys: the composer is empty, no Run Focus steer draft
  is open, and neither a reverse search nor a focused Answers deck is capturing
  input. A draft in flight is still never interrupted: the mode stays as
  restored, and the card's control hint already names the `Esc` step that
  reaches the actions from there.

- The Scan page's finding delta no longer prints a total its own breakdown
  contradicts. Where the attempt has no typed receipt delta, the panel took its
  total from the runs' recorded emission count and its severity bands from the
  findings ledger — two different quantities, because corroboration folds
  same-issue producer observations into one finding. A `secret-scan` that
  emitted 27 observations over 25 distinct findings therefore rendered
  `findings 27` directly above `20 high · 5 medium`, while the rail, the footer
  and Review all said 25. Both numbers now come from one pass over the ledger
  rows attributed to the attempt's runs, and the recorded count is named for
  what it is when it is higher: `findings 25 distinct · 27 observations`, the
  same distinction `SastFindingTally` already draws in the core. Attribution is
  the shared source-aware `finding_observed_in_runs`, so a finding a later run
  re-observed still counts for the run that found it. A ledger that is clamped
  or narrowed by a Review filter supports neither claim, so the recorded count
  stands alone there and no bands are shown — a filter never moves what an
  accepted attempt found. Reported in issue #172 (2026-09-28 audit).

- `secret-scan` and `iac-scan` disclose the paths they could not read. Both
  walkers returned `Ok(())` for a directory `read_dir` refused, so an
  unreadable subtree produced no findings, no `filesScanned` and no
  `filesSkipped` — a permission-denied `config/` was indistinguishable from an
  empty one. `secret-scan` additionally dropped a file whose content failed to
  read into an outcome that incremented neither counter, so the file left the
  report entirely. Both engines now record every unread directory, entry, and
  file in a shared `coverageGaps` structure that the report text prints as
  `Unread paths: <n> (coverage is incomplete)` and the tool JSON carries
  verbatim, bounded at 50 named paths with the remainder counted. A deliberate
  exclusion is unchanged: an oversized or non-text file stays in
  `filesSkipped`. Both engines also hand their gaps to the aggregate scan
  through `ScanEngineOutput::scan_errors`, so `kuzushi scan` refuses to report
  a partially read target as complete instead of forwarding findings alone.
  Direct `secret-scan`/`iac-scan` dispatch still completes over what it could
  read, with the gap disclosed, rather than failing the whole run.

- A single-pipeline `threat-model:build` that misses grounded entry points
  now runs one bounded gap-fill call when budget remains, as the staged
  pipeline and refine already did. Before, it only labelled the gaps
  `unresolved`. After that, a build that still covers less than the new
  `minCoverage` option (default 0.5) is refused rather than saved. A
  single-pipeline Juice Shop build had been persisted at 0/40 entry points
  covered. A failed gap-fill call keeps the model and records
  `gap-fill-failed`.
- `threat-intel:discover` on a Bazel sub-module without manifests of its own
  reads the enclosing workspace root's `go.mod`, `MODULE.bazel`/`WORKSPACE`,
  and top-level `*.bzl` `go_repository` rules. It never reads above the git
  root, and reads stay confined to that root. An empty package inventory is
  now `partial` with a reason instead of a clean `completed`.
- TUI polish from the operator feedback sweep:
  - In Navigate mode, a letter hotkey that changes state (suppress, decide,
    pause, …) shows a notice naming what it did and that Esc returns to typing.
    Movement keys stay quiet.
  - The phase chip no longer flips to Scan while an ad-hoc Map tool
    (`run entry-points:extract`, an agent launch) is still writing artifacts.
  - DFD node labels cut at a whole word instead of mid-word.
  - The Findings header shows active search terms as facet chips
    (`sev:high tool:semgrep text:"sqli"`) rather than the raw query.
  - Run Focus shows an ETA for planned variant rows such as
    `threat-model:build[stride]` from that tool's history, and the context
    rail no longer repeats the cost the Run Focus header already shows.
- A tool refused before doing any work, for example because no model is
  configured, now records its run as `blocked` rather than `failed`. That
  matches the artifact contract. The refusal message is unchanged.
- KWP brokered network fetches ignore proxy environment variables and dial
  only the approved, pinned address. Before, with `HTTPS_PROXY` set, the
  request went through the proxy, which resolved the host itself and bypassed
  the pin.
- Pull-request CI now runs clippy and the full Rust test suite (`rust-tests`)
  once when a PR becomes ready for review, and again in the merge queue. The
  quick gate skips both, so a PR could previously merge without `cargo test`
  ever running in CI. Development pins Node 26.3.1, the CI version. The KWP
  dynamic-module tests skip on older Node instead of failing, and the
  cancellation-settlement test skips where directory permissions are not
  enforced (root).
- The tmux-driven TUI journeys (`kuzushi-bdd-tui`) run in `rust-tests` for the
  first time. Their scenarios now match the current screens: the Report route
  lists six formats and an `EXPORTED` receipt, Workbench pages can be viewed
  ahead of reality while the header names the phase still required, `Shift+Tab`
  cycles pages forward, and a completed Setup Map presents its result for
  acceptance. Setup scenarios select rows by label instead of counting key
  presses, so a new readiness row no longer shifts them.
- Choosing OpenAI OAuth for an OpenAI API model no longer switches the model
  on the same key press. It raises a model-switch confirmation that names the
  current and target models, and only `y` continues. Continuing either reuses
  the stored connection or starts the browser login. `n` or Esc keeps the
  model and leaves the credential picker open. The target is checked against
  the model policy before it is applied. The credential row, Setup detail, and
  picker intro now name the real target (`openai-oauth:gpt-5.6-terra`) instead
  of the stale GPT-5.4.

- `triage:run` now discloses bounded item-level receipts for findings
  excluded by the deterministic stage-1 prefilter, including finding/identity
  IDs, score, threshold, total count, and an explicit omitted count instead of
  reporting only an aggregate drop count.

- A headless or shell `threat-model:build mode=refine` now reads the findings
  ledger. Before, `kuzushi run` handed the tool no findings store, so refine
  reported `newFindings 0` no matter what triage had confirmed.
- `taint-iris-next` applies `cweFocus` before the `maxCwes`/`maxCatalogEntries`
  cap. Before, `cweFocus=CWE-89 maxCwes=1` on Juice Shop kept only the
  top-ranked CWE-79 entry and then filtered it out. That replaced the real
  CWE-89 entry (score 88, with Sequelize sinks) with a synthesised entry
  (score 50) whose sinks came from unrelated attack-surface text.
- The CPG MCP server queries every buildable language, not only languages
  with a persisted graph. On Juice Shop a persisted client-side JavaScript
  graph hid the whole TypeScript server, so `cpg.taint_paths` found no
  sources or sinks. It now reports `routes/search.ts` `req.query` →
  `sequelize.query`. A language whose implicit build fails is skipped and
  named on stderr; the call fails only when no language loads.
- `kuzushi --target <repo> mcp health|serve <backend>` grants the server
  that repository as its read root. Before, `mcp health cpg` always reported
  `targetRoot: unresolved`.
- `kuzushi run --option key=value` refuses an option the tool does not
  declare, with the same "Did you mean" message as an unknown `--input` key.
  Before, the value was dropped silently.
- A taint-iris-next agent answer that needs structured-output repair is no
  longer thrown away just because the provider reported no charge. The
  repair's spend stop now uses the labelled estimate and fails closed only
  when spend is neither metered nor priced.
- Bridge debug diagnostics now name the tools each call used and count them
  across the whole agent transcript (names only, no content), so MCP use can
  be audited. Live on Juice Shop, taint-iris-next's agent called
  `cpg_taint_paths`, `tree_sitter_query`/`node_at`, `threat_model_get`,
  `context_get`, `entry_points_list`, `x_ray_summary` and `findings_query`.
- `patch:reverify` reports the spend of the detector it replays. Before, its
  result carried no cost, so a re-verification that made model calls read
  "cost not recorded". It now shows the observed floor plus the token
  estimate.
- `patch apply` without a Fix selection now says how to create one: draft it
  in the shell with `patch <finding>`, then press `u` on its RESULT READY
  card. Before, it told the operator to press `u` on Fix, which does nothing
  when no Fix result card exists.
- A scan no longer ends partial (exit 1) just because a requested engine
  does not apply to the target, for example systems-hunt on TypeScript. That
  skip stays a visible warning. Skips for any other reason still leave the
  scan partial.
- `threat-intel:research` and `threat-intel:harvest` can now extract fix
  patterns. `ndiff:extract-fix-pattern` reads its declared `record` option as
  an already-fetched advisory and uses that advisory's primary patch
  reference. Previously every harvested advisory was skipped with "requires
  id, patchText, or patchUrl". A malformed `record` is refused rather than
  ignored.
- Json-typed tool options accept JSON object or array text from
  `--option key=value`, shell `set` and stored options, so
  `ndiff:hunt-variants --option pattern='{…}'` works. Other text passes
  through unchanged.
- Staged threat-model builds no longer fail after paying for every stage when
  the model leaves `targetElementIds` off a gap-fill threat. Such a threat now
  inherits the DFD links of the entry points it cites, marked
  `targetElementIdsSource: "entryPoints"`. A threat with nothing to inherit is
  dropped and its surface stays an honest gap. On Juice Shop the staged
  pipeline now accounts for 40 of 40 grounded surfaces.
- `threat-model:build` `budgetUsd` is enforced even when the provider does not
  report spend. The staged, gap-fill, refine and question-closer checks read
  the labelled token estimate, fail closed on unpriced unmetered spend, and
  settle the workspace spend ledger to the estimate. The build summary and
  the Run Focus header show `~$X estimated` rather than `>=$0.0000`.
- A `targetSubdir` taint-iris-next hunt builds cpg-rs graphs only for the
  languages present under its scan root. On a mixed-language repository, a
  TypeScript-only subtree used to fail the JavaScript build and drop to the
  heuristic linker. On Juice Shop `routes/` the hunt now yields 4 dataflow
  paths instead of 0.
- Tool results that report unresolved provider spend now carry the token
  estimate. The dispatch boundary tallies every model call it traces and
  fills in `estimatedCostUsd` when an engine reported only an observed
  floor. It skips the fill whenever the tally saw less than the tool itself
  observed.
- `triage:dedupe` and `triage:chain-hunt` list the groups and chains they
  propose, not only counts.
- Finding-scoped tools accept the `F-0001` aliases that `kuzushi findings`
  prints, as their `fingerprint` option already advertised. This covers
  `triage:run`, `variant:lift-pattern`, `variant:hunt`, `trace:expand`,
  `verify:exploit`, `deep-audit:run` and `classifier-gate:score`.
  Previously each one answered "no finding" for an alias.
- `variant:hunt` and `ndiff:hunt-variants` report their real spend instead of
  a hard-coded `$0.0000`. Shared run receipts show a labelled
  `~$X estimated (metering incomplete)` whenever a token-based estimate
  exists, and `trace:expand` now keeps that estimate.
- `x-ray:run` summarizes its verdict with the justification prose rather than
  the `### Justification` sub-heading. When provider spend is unmetered, its
  cost line reads `~$X estimated (provider spend unresolved)` or
  `>=$X (provider spend unresolved)` instead of a bare `$0.0000`.
- Offense review no longer fails when a threat cites a directory (for
  example `routes`). The directory's direct files stand in for it, within
  the existing file budget. On Juice Shop the engine produced 20 findings
  across 4 actors.
- `systems-hunt` reports `skipped` with its reason on a target that has no
  C/C++/Rust/Go/Zig production source, instead of failing the scan. The
  scan umbrella records a skipped engine's reason, its warning names it
  ("systems-hunt was skipped: … does not apply …"), and a partial scan's CLI
  error leads with that warning rather than a "completed" summary.

- `kuzushi scan --paths <dir>` with exactly one directory now scopes
  taint-iris-next through its `targetSubdir`. Before, the engine read
  evidence from the whole repository (Juice Shop's challenge snippets and
  frontend) even for a `routes/` scan. Other scopes stay repository-wide
  rather than guessing a subdirectory. CPG builds no longer print the
  upstream library's timing line on the scan's stderr.

- `kuzushi scan --paths` now scopes the agentic SAST engine. The umbrella's
  descriptor filter used to drop `paths`, so a scoped scan hunted (and paid
  for) the whole repository; the scope now becomes the engine's include
  patterns unless they are set explicitly. On Juice Shop `routes/`, the
  engine went from 0 findings to 8 real ones: SQL injection in login and
  search, `eval` and template injection, SSRF, zip path traversal, and two
  NoSQL injections.
- Agentic SAST declares `maxModelTurns` (default 20). The bridge tells the
  model when two turns remain, so it can finish with its own answer; the
  stop and the refusal of forced conclusions are unchanged. On Anthropic the
  opening prompt of an agent loop is cache-marked, because every turn
  re-sends it: the same hunt dropped from about $1.80 to about $0.43. A
  truncation's remediation now names the setting that applies (turn budget,
  MCP timeout, spend, or output tokens).
- The scan JSON and `--ci` summary no longer print an exact `costUsd` when
  provider spend is unresolved. `costUsd` is null, with `observedCostUsd`,
  `providerSpendUnresolved`, and `estimatedCostUsd` alongside it.

- Shell planner rows no longer say "needs model — run /model first" when a
  model is configured but the task's input cannot be prepared (for example
  `patch:finding` without a fingerprint). The row names the missing input.
  The patch view labels its build/test commands as `VALIDATION · N
  check(s)` rather than "TESTS · added", the Fix page shows its `updated`
  time as RFC 3339, and the Report header says "current findings" so it no
  longer reads as disagreeing with a completeness-all export.

- Model-written patch hunks are re-anchored against the exact source
  checkout during synthesis. A hunk with zero or one-sided context
  (`@@ -21,1 +21,1 @@`) is treated by `git apply` as anchored to the end of
  the file, so a correct mid-file edit was rejected ("patch does not
  apply") even with every removed line correct. Each hunk whose old block
  matches the source exactly once is re-emitted with real context and exact
  line numbers. Ambiguous, unmatched, new-file, or no-newline hunks pass
  through unchanged. On Juice Shop the hardcoded RSA key patch went from
  three `APPLY_FAILED` attempts to `SOUND` on the first.

- Run lifecycles no longer degrade on long float costs. A 17-digit estimate
  such as `0.10256119999999999` did not parse back to the identical f64, so
  the re-serialized run item failed its hash check and later reads found "no
  typed terminal outcome". serde_json now parses floats exactly
  (`float_roundtrip`).
- Agent tool results are capped at 24,000 characters, and the cut is shown to
  the model so it can narrow the query. Unbounded reads made a verify
  transcript reach 503,809 tokens against a 200,000-token window. A provider
  context-overflow rejection now carries a canonical operator detail
  instead of a bare HTTP 400.
- Structured-output truncation names the bridge's stop from a fixed
  vocabulary (model-turn limit, forced conclusion, MCP timeout, spend stop,
  output limit), and `verify:finding` declares `maxModelTurns` (default 12,
  1–40) so a deeper investigation is an explicit operator choice. A forced
  conclusion is still never accepted as a verdict.

- Verify with MCP tools no longer stops after the first Claude call. The
  bridge's observed-spend stop treated every Anthropic call as unpriceable
  and ended the agent loop with `observed_spend_incomplete`, which surfaced
  as "structured output failed". Kuzushi now sends its list-price rates with
  spend-stopped bridge requests, and the stop enforces tokens × rates (cache
  buckets priced apart from LangChain's inclusive input total). Mixed
  receipts, missing token counts, or unknown models still stop fail-closed.
  A structured-output repair now accepts estimated spend too.
- "structured output failed" now names an allowlisted cause: the typed
  runtime failure (for example the missing MCP sidecar), a refused repair,
  truncation, or an output still invalid after one repair. Raw provider text
  still never reaches the message. A failed tool keeps the cost its model
  calls observed instead of reporting it as unavailable.
- `patch:finding` refusals for a missing detector binding now say which run
  last observed the finding (for example a `sast:scan` umbrella run) and
  which detector to re-run on its own.

- Claude calls that report tokens but no charge (the LangGraph bridge and
  OAuth paths) are now priced locally from token usage and a versioned list
  price table. The estimate is carried beside observed spend, labelled `~$X
  (estimated)` and `estimatedCostUsd`, and never becomes `costUsd`. Triage
  cost caps and the shell session budget enforce against it instead of
  halting after the first unmetered call. Any unmetered call without an
  estimate still fails closed. The price table now matches current list
  prices (Haiku 4.5 is $1/$5 per MTok, Opus 4.5+ is $5/$25) and prices only
  exact model ids. Persisted cost reports gain an optional
  `estimatedUnmeteredUsd` field that older binaries reject.

- A RESULT READY card key never becomes composer text in Navigate mode (#172).
  A stale-frame re-press of the key that just resolved a card used to fall
  through to prompt typing. Five presses of `u` applied "Use map" once and
  left `uuuu` in the composer on the next page. That repeat is now absorbed
  with a notice. A card key pressed off the Workbench opens the pending card
  instead of applying it unseen, and resolving a card drops a draft made only
  of card letters. While a warning holds Esc, the footer says
  `Esc dismiss notice`.
- Setup states the selected target's path once, ahead of its facts, and no
  longer reports the shell's own bookkeeping files (indexes, locks, history)
  as "prior Kuzushi" work on a fresh target (#172).
- Map's PROJECT CONTEXT card renders every receipt row, where the old
  eight-row cap dropped rows silently. When the card has spare height, long
  summaries wrap instead of being cut with an ellipsis (#172 F5).
- A scan no longer merges distinct findings. dep-hygiene, cargo-audit,
  secret-scan and Terraform IaC findings now carry a discriminating identity
  input, so 15 different vulnerable packages in one `package.json` are 15
  findings, not one with `corroboration_count: 15`. The headless `sast:scan`
  count uses the same identity fold as the ledger, SARIF and `--fail-on`, and
  reports `observationsCount` beside it. On OWASP Juice Shop the headless
  count went from 67 to 130 and now matches the ledger. See RELEASING.md,
  "Structural producer identity migration".
- Every finding-persistence path now commits a typed `FindingDelta`. Before,
  a Scan result card could read `findings +0` after 73 new findings. A run
  that still records no delta is shown as `findings unmeasured`, never as a
  measured zero.
- `verify:finding`, `patch:finding` and `variant:hunt` gate on the effective
  review decision that Review and Prove display. A human-confirmed finding
  without automated triage can be verified, and a human rejection overrides
  a cached automated true positive. They previously refused with "Run
  triage:run first" right after Prove advertised `verify`.
- CodeQL results without a usable physical location are disclosed in
  `scan_errors` instead of vanishing (#290). Scan-time static-evidence
  indexing keeps the grounded results rather than failing the whole scan.
- Recon imports report parsed rows that name no usable host (#292), and
  campaign coverage and trend state an unreadable ledger as unmeasured
  (#291). Triage verdicts propagate across generations only on an exact
  producer fingerprint (#275).
- Threat-model grounding discloses its denominator and cap
  (`grounding: 40 of 70 surfaces (cap 40 · ≤2 rows/file)`) and records it
  in `coverage.grounding`.
- `threats summary` counts the actors a model names (its `actors` table, then
  the distinct `threats[].actor` values, then the DFD actor nodes) and
  reports `unknown`, not `0`, when none are named.
- The context rail no longer shows unmetered spend as a measured `$0.00`.
  Subscription and OAuth calls read `>=$X (metering incomplete)`, and a
  budget share over them is marked as a lower bound.
- The entry-point browser title names the rows a clipped list hides
  (`+N above` / `+N below`). The auth picker no longer says a provider
  "needs credentials" when an OAuth connection is stored. The catalog hint
  says `press e`, because `Esc, then e` closed the catalog. Review decisions
  and the export receipt show RFC 3339 UTC instead of raw epoch seconds.
- The DevEx harness writes valid provenance JSON (its sed escaper had been
  split by a stray newline), and `nav-mode` waits for a settled Navigate
  footer before a page key is sent.

- Typing a phase verb for a phase the engagement has already completed or
  passed now opens that phase's Workbench page instead of its planner. On an
  engagement in Review, `map` used to open "planning MAP · engagement is in
  Review — Enter runs MAP steps" when the operator only wanted to look at the
  accepted Map; it now lands on the Map page exactly as Shift+Tab would, and
  the page's hint row offers `plan map`. A phase the journey has not reached
  yet still opens its planner, and the new `plan <phase>` verb (like the
  longer `phase <phase>`) always does. Plain scripted sessions render the page
  for a completed phase and keep refusing planner-bound verbs.
- The Fix page hint row now says how to start remediation for the selected
  finding. When that finding has no patch draft or remediation record, the
  hint reads `patch F-0001 draft a patch` (with the selected alias) instead of
  a generic "patch displayed", so the review-gated Fix page no longer hides
  that `patch <alias>` works from any page.
- An idle shell no longer keeps showing a stale findings count after another
  process writes the same target's ledger. A headless `kuzushi run` could
  commit findings into the store's WAL — which the workspace watcher ignores —
  and the shell kept showing 176 findings while the ledger held 187. On the
  existing idle tick, at most every two seconds, the shell now stats the
  store's main and WAL files and reloads findings when that identity moved and
  the store's projection watermark differs from the one it last read.
- `recon:http-fingerprint` no longer leaves the program scope by following a
  redirect, and no longer files the response under an endpoint that only
  pointed at it. The fetch ran `curl -i -L`, so the dispatch gate weighed the
  requested target while curl sent up to fifty further requests to whatever
  `Location` named — a redirect to a host `.kuzushi/scope.toml` denies was
  probed anyway, which for a bounty program is a request the operator never
  authorized. The parser then read the *last* hop's status, headers, server,
  title, and technologies, while the recon store recorded the host and port of
  the *requested* target with a scheme guessed from the port number, so one
  service row mixed two endpoints and could call a cleartext service on 443
  `https`. The walk now fetches one hop at a time: each `Location` is resolved
  against the hop that sent it and weighed by the same scope rule the dispatch
  gate applies before any request reaches it, with a bound of 10 hops. The host,
  port, and scheme come from the URL that answered, the note records both the
  requested target and the `fingerprintedUrl`, and the result's `redirects`
  carries every URL fetched plus any redirect declined with its reason
  (`out-of-scope`, `hop-limit`). The completion line names the endpoint it
  registered and discloses both (`recon:http-fingerprint registered
  https://www.example.com:8443/app as https:8443 · followed 1 redirect from
  http://www.example.com/`). A target whose port no HTTP client can read is now
  refused too: `example.com:99999` parsed its port with `unwrap_or(default)` and
  registered a service on port 80 that nothing had probed.

- CI runs on GitHub-hosted runners by default. Pull-request CI and the Full
  CI sweep use `ubuntu-latest` (the quick gate is about four billed Linux
  minutes per run), and release darwin legs use hosted macOS. The owner's
  self-hosted Mac is now opt-in: dispatch with `self_hosted: true`, or set
  `KUZUSHI_RELEASE_SELF_HOSTED=true` for one release. Before, every routine job
  waited on that runner and queued indefinitely whenever it was offline.
- The campaign folds no longer present a findings ledger they could not read
  as an empty one. `campaign:status` folded its review decisions with
  `list_all_review_decisions().ok().unwrap_or_default()`, so an unopenable
  findings database produced `TREND  FP rate — (no decisions) · 0 confirmed`,
  and `campaign:status` then appended that fabricated zero to
  `.kuzushi/trend-history.jsonl`, where it dipped every sparkline drawn
  afterwards. `campaign:coverage` did the same with `list_all_findings()`, so
  a shard nobody could count reported the same `0` as a shard that is clean —
  in the one fold whose purpose is to answer "where have we looked and what
  did we find". A read that failed is now its own state: `TrendMetrics` carries
  `decisions_unreadable` (no FP rate, no cost-per-confirmed, `confirmed
  unknown` on the strip, `decisionsUnreadable` in `trend`), the history
  recorder refuses such a snapshot, and `campaign:coverage` states the
  degraded read beside its counts and reports `findingLedger` in its result
  data. An unreadable decision read leaves the confirmed counts resting on
  embedded triage verdicts that carry no review reversal, so it is disclosed
  as unmeasured rather than as a bound in either direction. An absent findings
  store still folds over an empty ledger, as it always has — there is no
  database to have failed.

- `recon:import` for amass and httpx now says how many parsed rows it dropped
  because they named no usable host. An amass line without a non-empty `name`,
  or an httpx line with no `host`, `input`, or parseable `url`, was skipped
  without a trace, so a dump that was partly or wholly unusable read the same
  as one that imported cleanly. Those rows are now counted when they are
  dropped and named beside the scope refusals on the output line
  (`recon:import amass imported 1 note from amass.jsonl · 1 out-of-scope, 2
  without a usable host skipped`). The tool result's `data` carries
  `skippedUnusable`, and the import note records it together with the amass
  `records` total. The httpx note's `ignored` field used to be derived by
  subtraction; it is now that same count.

- The entry-point browser no longer reports a real catalog's own numbers as
  unknown before a threat model exists. Every count on its `RECEIPT` line was
  read only out of the threat-model document's `entryPointCatalog` provenance
  block, so a freshly extracted 458-row catalog rendered `RECEIPT · catalog ? ·
  grounding ?/? limit · modeled ? · linked ? · status unknown · policy unknown`
  directly beneath a source receipt stating `catalog ready` — the same screen
  contradicting itself, with the page's own `458 extracted` header one line
  above. The record count now falls back to the catalog artifact's declared
  `total`, which the page already cross-checks against the rows it parsed, so
  the catalog states its size whether or not a model has been built. Grounding,
  modeled, linked, the recorded catalog status, and the selection policy are
  written only by `threat-model:build`; rather than print each as unknown when
  no model artifact exists, the line now says the model selection has not run.
  A model that does exist stays authoritative for all of them, and a model that
  exists but cannot be read still reports unknown, because then it truly is.

- `.kuzushi/scope.toml` now judges a `recon:nmap` target that names an address
  block by every address in it, instead of by the single host the string starts
  with. nmap takes blocks —
  `10.0.0.0/8`, `10.99.0-255.1`, `10.0.0.1,2` — and the gate read only the first
  reading of each, so it was wrong in both directions. A deny rule was reached
  by widening the target: `10.0.0.0/8` covers every address a `10.99.0.0/16`
  deny rule names, but its own network address falls outside that rule, so the
  target came back `Unknown` and the scan ran across the denied block. An allow
  list was satisfied by a network address while the scan continued past it:
  `10.0.0.0/7` matched a `10.0.0.0/8` allow rule and then reached
  `11.0.0.0/8`. And a plainly in-scope `10.0.0-255.5` was refused outright,
  because the literal matched no rule at all. A block is now refused when a CIDR
  deny rule overlaps it anywhere, and admitted when a CIDR allow rule contains
  all of it; a block of 256 addresses or fewer is additionally weighed one
  address at a time, so a rule written as a host glob or split across two
  `cidrs` entries still covers a `/24`. Blocks are weighed against a rule in
  either address family, as single hosts already were. The block reading stops
  at the nmap verb: `recon:subdomain`, `recon:http-fingerprint`, and the recon
  and bounty importers hand their target to curl or a parser, which resolve
  `10.0.0.1-2` as a domain name reaching whatever DNS answers with, so they keep
  judging it as the one host it is. Single-host targets, hostnames carrying a
  hyphen, and URLs are unaffected everywhere. nmap's other block form is refused
  rather than guessed: `<name>/<numbits>` resolves the name and then sweeps
  every address sharing those first bits, so `api.example.com/8` was judged as
  the bare host `api.example.com` and admitted by a `*.example.com` allow rule
  while the scan covered 2^24 addresses. The gate cannot resolve a name, so it
  cannot bound that block, and a block it cannot bound is never admitted — it is
  refused under an allow list and reported unknown under a deny-only file. A
  block whose base is an `inet_aton` shorthand address is bounded instead of
  refused, so `0xa.0.0.0/8` is weighed as exactly the addresses `10.0.0.0/8`
  names. The suffix reading is nmap's target grammar only: a bare base followed
  by one to three digits, so `api.example.com/path`,
  `https://api.example.com/8080/x`, and every `Host`-syntax caller are
  untouched. A block holding a single address is now weighed as a block as
  well: `10.0.0.5-5`, `10.0.0.5,5`, and `10.0-0.0.5` are valid nmap targets for
  exactly `10.0.0.5`, but their only host reading is the literal string, which
  parses as no address, so a `10.0.0.5/32` deny rule had nothing to match and a
  denied address was reached by respelling it. Because a block reading now
  covers those single addresses, admitting one also requires every address the
  target's own readings name to be in scope, so `010.0.0.5` — the block
  `10.0.0.5` to a decimal octet parser and the host `8.0.0.5` to an `inet_aton`
  one — is still refused unless the file names both.

- The shell's threat pages no longer present an unrated threat as a rated one.
  The threat-model normalizer keeps an impact it does not recognize verbatim
  with a warning, leaves an explicit `unknown` alone, and ranks both last — and
  the Stories, Scope, and STRIDE view models then read all of that as a band.
  Every impact outside the display mapping's five arms, the literal `unknown`
  included, became `MEDIUM`, as did a threat carrying no `impact` field at all,
  so an unrated threat sorted among the genuinely medium ones. The STRIDE
  rollup understated the same absence as `LOW`, which also toned an empty
  category as low rather than unmeasured while its own member rows already read
  `UNKNOWN`. All three now fail closed to the `Unknown` band the tone enums and
  rank tables already carried; `medium` keeps an explicit arm and `info` stays
  banded because the model stated it. The Scope page gained `info` and
  `unknown` buckets so those threats stop vanishing: without a bucket to land
  in they were dropped from the list *and* from the `SCOPE · N issues` total,
  which already understated the count for info-rated threats today.

- `bounty:import-har` (and `recon:import {"tool":"har"}`) no longer states HTTP
  facts the capture did not record. An entry with no `request.method` was stored
  as a `GET` — in the finding title, the evidence snippet, and the request line
  of the `request_blob` an operator reads as the raw message — so a partial HAR
  turned an unknown method into a specific, wrong one. A missing `httpVersion`
  asserted `HTTP/1.1` on both messages, and a missing response `status` rendered
  as `0`, which browsers also write for a request that never got a response, so
  absence and that observation read alike. Each unrecorded field is now shown as
  `?`, the spelling the sibling Burp importer already used for an unknown
  method; a recorded `0` still prints as `0`. The importer also stopped dropping
  a body the capture described but did not store: a form submission recorded
  only as `postData.params` and a response body kept only as `content.size`
  both rendered as headers followed by nothing, which reads as an observed empty
  body. Both now carry a disclosure in the evidence rationale, and neither is
  rebuilt into body text, because parsed parameters and a byte count do not name
  the bytes that were on the wire. A well-formed capture imports byte-for-byte
  as before.

- `entry-points:extract` no longer refuses a target too large to snapshot
  whole. `context:build` caps its own arrays to stay inside the snapshot byte
  budget and records `snapshotTruncation` when it does, and the extractor read
  that marker as grounds to bail: on a 3186-surface monorepo the snapshot
  capped `attackSurfaceMap.surfaces` at 2000 and `entry-points:extract` then
  failed with `entry-point catalog requires a complete context snapshot`,
  writing no `.kuzushi/entry-points.json` at all. Headless `kuzushi run`, the
  scan orchestrator, and the shell Map page were blocked identically, so a
  large repository got no entry-point catalog rather than a partial one. The
  catalog now records the coverage it was built from, and the 2000 real rows
  are kept and disclosed instead of discarded: the artifact carries
  `snapshotCoverage`, the tool reports `status: "partial"` with the reason and
  omitted-entry count in its summary, output, and warnings, the Entry points
  page warns `catalog coverage partial …`, and `entry_points:by_framework` /
  `entry_points:by_method` carry the same coverage so an empty filter never
  reads as proven absence. Consumers that ground on the catalog as the complete
  entry-point set — threat-model grounding, explicit catalog sources, and
  verification — still refuse a partial catalog, now naming what the snapshot
  withheld, and a catalog may not claim complete coverage of a snapshot that
  declared truncation. Recording no coverage is not a completeness claim
  either: the payload digest covers only the rows, so an artifact with no
  `snapshotCoverage` — one written before the field existed, or one it was
  removed from — reads as `unrecorded`, is disclosed as such on the Entry
  points page, and is refused by grounding until `entry-points:extract`
  rebuilds it.

- `recon:import` now says what it imported and what `.kuzushi/scope.toml`
  refused. Every native adapter gates each parsed entry against the scope file,
  but only the HAR and Burp importers disclosed the refusals: amass and httpx
  buried the count in a store note, and nuclei and nmap-xml counted it and threw
  the count away. All four then completed with `"<tool> completed for <path>"`,
  the same line whether a dump imported whole or the scope file denied every
  entry in it, so an import filtered down to nothing read as a successful one.
  The report now carries `skippedOutOfScope` and the output line names the rows
  that landed beside the entries that did not — `recon:import nuclei imported
  nothing from dump.jsonl · 1 out-of-scope skipped`. Reports for `recon:nmap`,
  `recon:subdomain`, and `recon:http-fingerprint`, which take one target and
  refuse it at dispatch, are unchanged.

- `.kuzushi/scope.toml` now judges a non-ASCII target by the domain a client
  resolves it to. DNS carries ASCII, so every client that accepts a Unicode
  host first maps it with UTS 46 and encodes the result as punycode — and that
  mapping case-folds, applies compatibility decompositions, and rewrites label
  separators. The gate compared only the written form, so
  `https://ａdmin.example.com/` (U+FF41) and `https://admin。example.com/`
  (U+3002) both reach `admin.example.com` while matching no rule naming it, and
  a rule written `bücher.example` matched no target written
  `xn--bcher-kva.example`. A deny-list file therefore returned `Unknown` and
  let recon dispatch and the amass/httpx/nuclei/nmap-xml/HAR/Burp import gates
  through. Each host reading the gate already weighs — raw, percent-decoded, or
  either URL-parser reading — now also yields the ASCII domain UTS 46 resolves
  it to, and it is that reading the IPv4-shorthand pass runs on next, so a
  shorthand address written in non-ASCII digits still names its dotted quad. A
  host rule gains the same ASCII spelling, and a rule written in punycode
  additionally gains the Unicode domain it encodes, so an allow list keeps
  admitting the asset the operator listed in whichever spelling they used. A
  host UTS 46 rejects — invalid punycode, a code point disallowed in a domain —
  names nothing a client can resolve, so it contributes no reading rather than
  a mangled one, and an ASCII target keeps exactly the verdict it had.

- `.kuzushi/scope.toml` CIDR rules now cover the shorthand IPv4 notations a
  real client resolves. The gate tested a candidate against a range only when
  `IpAddr::from_str` accepted it, which means only the dotted quad — so
  `http://2852039166/`, `http://0xa9.0xfe.0xa9.0xfe/`,
  `http://0251.0376.0251.0376/`, and `http://169.254.43518/` matched no rule,
  while browsers, `curl`, Go, and libc `inet_aton` reach 169.254.169.254
  through every one of them. A `169.254.0.0/16` deny list therefore returned
  `Unknown` and let recon dispatch and the amass/httpx/nuclei/nmap-xml/HAR/Burp
  import gates through. Each host reading the gate already weighs now also
  yields the dotted quad the URL Standard's IPv4 parser reads it as, and a
  host rule an operator spelled the same way is compiled in both forms, so
  neither side of the comparison depends on which notation was written. A host
  whose last label is not a number stays a domain, a host the parser fails on
  contributes no candidate rather than a guessed address, and a target already
  written as a dotted quad keeps exactly the verdict it had.

- `.kuzushi/scope.toml` can no longer be walked past with a percent-escaped
  host. The gate compared rules against the authority exactly as written, so
  `https://admin.example%2ecom/panel` matched no rule naming
  `admin.example.com` — while every browser, and any client following RFC 3986
  §3.2.2, percent-decodes the domain and reaches the denied host. A deny-list
  file therefore returned `Unknown` and let recon dispatch and the
  amass/httpx/nuclei/nmap-xml/HAR/Burp import gates through. Each of the two
  parser readings the gate already weighs is now weighed in its decoded form
  too: one deny match on either refuses the target, and an allow list has to
  cover both. An escape that decodes to a code point the URL Standard forbids
  in a domain (`/`, `:`, a literal `%`, a control) names no host a client can
  reach, so it contributes no candidate rather than a guessed one, and a
  target whose host carries no `%` keeps exactly the verdict it had.

- Capture imports no longer present an encoded payload as the raw HTTP
  message, and no longer drop entries without saying so. Burp marks a
  request/response `base64="true"` and HAR marks a body
  `encoding = "base64"` precisely when the payload is binary or compressed —
  a gzip'd response, an image, anything not UTF-8 text. `bounty:import-burp`
  answered a failed decode by storing the base64 text itself under
  `request_blob`/`response_blob`, and `bounty:import-har` never decoded a
  declared-base64 body at all, so evidence labeled `http-request` held
  base64 that an operator reading the finding had no way to recognize as
  undecoded. Both importers now decode the payload, keep the readable part
  of a non-UTF-8 body with its undecodable bytes shown as `U+FFFD`, and
  state in the evidence rationale exactly how the stored blob differs from
  what the capture carried; a field that does not decode keeps its literal
  text and says so. Decoding is now strict standard base64 (the `base64`
  crate, padded or unpadded), because the hand-rolled decoder accepted a
  truncated field — `"A"` decoded to an empty body and `"AAAAA"` dropped its
  last symbol, both as valid UTF-8, so the disclosure never fired on exactly
  the fields that needed it. Separately, an item with no URL was dropped from both
  importers with no counter, so `imported` plus `skippedOutOfScope` silently
  failed to add up to the capture's entry count. Those entries are now
  counted as `skippedUnusable` and named in the tool output line
  (`recon:import` and the two `bounty:import-*` verbs alike).

- A multi-language `codeql:scan` no longer hides the languages it failed to
  analyze. Per-language failures — a database that would not build, an
  analysis that died — were collected and then dropped whenever any other
  language produced a finding, so a run that never analyzed Java or C++
  reported `codeql: 4 findings under <target>` with nothing to say that two
  thirds of the repository went unscanned. This is the recommended
  invocation: the module recommender asks for `multiLanguage: true` whenever
  a target has more than one CodeQL language. Those failures now travel with
  the scan as `scanErrors`, and the report marks the run
  `(coverage incomplete: N scan errors)` and lists what was missed, matching
  what `semgrep:scan` already discloses. The hard failure when *no* language
  could be analyzed is unchanged; a run where one language succeeded with
  zero findings and another failed is now reported as an honest empty result
  with its gaps disclosed, rather than as `all language analyses failed` —
  a claim that was untrue whenever an analysis had in fact succeeded.

- The classifier gate no longer turns a response it could not read into a
  score. An unparseable answer became a neutral `0.5`, and `0.5` sits below the
  default `0.6` cold-start floor — so the fallback meant to keep a real bug from
  being rejected rejected it: the deep auditor never ran, and the finding was
  left carrying a persisted `NeedsReview` row whose confidence was `0.50` and
  whose rationale read `below adaptive triage threshold (score=0.50, …)`, a
  parse failure presented as a model judgement. An unreadable response is now
  `ParseDegraded`: it escalates to the deep auditor, trains no quantile,
  persists no triage verdict, and `classifier-gate:score` reports a null
  `score` with `parseDegraded: true` instead of a number nobody produced.
  Responses the gate can read are scored, thresholded, and recorded exactly as
  before. The score-only Rust API stays source-compatible: `should_deep_audit`
  still takes a bare score, and `LikelyVulnClassifier::score` remains as a
  deprecated wrapper that errors on an unreadable response instead of inventing
  one.

- `.kuzushi/scope.toml` can no longer be walked past with a URL that two
  parsers read as two different hosts. The gate extracted one host under RFC
  3986 rules, so `https://evil.test\@in-scope.host` presented as the in-scope
  host while a browser-derived client resolves `evil.test` — and an embedded
  tab, CR, or LF split the readings the same way. Recon dispatch and the
  amass/httpx/nuclei/nmap-xml/HAR/Burp import gates now weigh every host such a
  target could name: one deny match refuses it, and an allow list has to cover
  all of them. Ordinary targets carry none of those characters, so both
  readings agree and their verdicts are unchanged.

- Map's inventory no longer claims a web framework because a manifest happens
  to spell its name. Framework needles were matched as raw substrings of whole
  manifest text, so a Python package named `falcon-benchmarks` was reported as
  the Falcon web framework — a routing/deserialization surface claim carried by
  a coincidence. A needle now has to stand as a whole package token on a line
  that can declare a dependency, which also rules out comments and the
  manifest's own name/description/keywords fields. Declared dependencies,
  dotted Java and ASP.NET prefixes, Go module paths, and Cargo
  `[dependencies.<crate>]` headers all keep matching.

- The JOURNEY phase chip no longer flips to `Scan 2/5` partway through the
  first Map run on a target. Pre-ledger inference reads `.kuzushi/` artifacts,
  which Map tools write while the run is still going; it is now suppressed
  while a first-class Map or Scan attempt is in flight, so the chip stays on
  `Map 1/5` until an attempt actually completes and is accepted.

**Release process:**

- Routine CI now bills far fewer runner minutes without weakening a gate.
  Quick CI dropped its redundant post-merge `push: branches: [main]` run and
  skips prose-only pull requests, both CI workflows cache the Rust target
  directory, Full CI installs cargo-llvm-cov and cargo-mutants from
  checksum-verified release binaries instead of building them, its cron
  dropped from weekly to monthly, and the 90-minute mutation sweep now runs
  only behind an explicit `deep` input that release-candidate.yml always
  passes. Dependabot batches into one grouped monthly pull request per
  ecosystem. Release candidates run the same complete gauntlet as before.

- Every darwin release leg now runs on the owner's self-hosted Apple silicon
  runner, so a release spends no 10x-billed hosted macOS minutes. The native
  build, both local-tarball smokes, and both published-install smokes default to
  the `self-hosted, macOS, ARM64, kuzushi-mac` labels; the `darwin-x64` smokes
  execute the Intel payload there through Rosetta 2 under an x64 Node, and refuse
  loudly rather than skip when Rosetta or that Node is missing. Linux and Windows
  legs are unchanged, and `identity`, `assemble`, `publish-npm`, and
  `github-release` stay pinned to hosted `ubuntu-24.04` because they hold
  `NPM_TOKEN` or `contents: write`. A `hosted` workflow input — reachable on a
  tag push through the `KUZUSHI_RELEASE_HOSTED` repository variable — sends every
  darwin leg back to `macos-14` and `macos-15-intel` for one release. See
  [docs/quality/release-legs-self-hosted.md](./docs/quality/release-legs-self-hosted.md).
- `darwin-x64` is now cross-compiled on the Apple silicon release runner instead
  of on a separately billed Intel macOS build host. The release candidate builds
  five platform payloads on four runners: `macos-14` builds `darwin-arm64`
  natively and then `darwin-x64` through `--target x86_64-apple-darwin`,
  uploading each slug as its own `release-candidate-native-<slug>` artifact, so
  `assemble` still receives all five required slugs. The `darwin-x64` tarball and
  the published package are still installed and executed on a real
  `macos-15-intel` runner, so no execution evidence is traded away for the
  cheaper build.
- `scripts/build-native-runtime.mjs` accepts `--target <triple>` or
  `KUZUSHI_NATIVE_TARGET=<triple>` for the five supported Rust targets and
  forwards the selection to staging, which reads
  `target/<triple>/release` and publishes `native/<slug-for-triple>`. An
  unsupported triple is refused instead of mapped to a guessed slug, staging now
  honors `CARGO_TARGET_DIR`, and the executable suffix follows the target
  platform rather than the building host.
- Native and local-tarball smokes still refuse to execute a foreign platform
  payload. `KUZUSHI_SMOKE_ALLOW_ROSETTA=1` unlocks exactly one pairing —
  `darwin-x64` on a `darwin-arm64` host — and only when Rosetta 2 is actually
  installed; the run then executes through `/usr/bin/arch -x86_64` and records
  the host slug, the smoked slug, and `"translation": "rosetta"` in its receipt.
  No other pairing is ever unlocked, and nothing is smoked silently under the
  wrong architecture.
- The seven-item historical artifact cleanup gate is renamed the repository
- Routine CI now runs on one ephemeral self-hosted Apple-Silicon runner
  (`self-hosted, macOS, ARM64, kuzushi-mac`) on the owner's Mac, so a pull
  request costs no hosted minutes. `windows-compile` stays on
  `windows-latest`, and a new `hosted` workflow input puts every other job
  back on `ubuntu-latest` when the Mac is offline. The actionlint step no
  longer needs a Docker daemon: it runs the pinned 1.7.12 binary and refuses
  any other version. The patch-validation sandbox action is an explicit no-op
  off Linux, and `rust-cli` records in its job summary that bubblewrap and
  AppArmor were not exercised, because a green run there proves less than the
  same run on Linux. Setup, threat model, and teardown are in
  `scripts/runner/README.md`; de-registering the runner is now item 8 of the
  repository visibility gate.

- The historical artifact cleanup gate is renamed the repository
  visibility gate and now blocks making the repository public only. Creating
  the Alpha14 tag requires the candidate gate and a release commit equal to
  current `origin/main`. Recorded by the repository owner on 2026-08-28, on the
  reasoning that moving the `latest` dist-tag to a scrubbed Alpha14 reduces
  exposure for new installs and is the prerequisite for deprecating
  `0.24.0-alpha.10` and `0.24.0-alpha.12`. No gate item is cancelled and the
  repository stays private until every item has its receipt.

## v0.24.0-alpha.14 · candidate integrity and release preparation

_Release status: candidate only. This preparation change does not publish npm
packages, create a tag, or create a GitHub Release._

**Additive:**

- A recorded proof deferral is now visible wherever the finding is. The new
  headless `kuzushi proof defer <finding> --target <repo> --reason <text>`
  records the same operator decision as the shell's `proof defer` through one
  shared core service, the Prove page discloses it on the STATUS/NEXT strip of
  a selected finding (and in plain output), and `kuzushi finding` reports it
  beside the proof state. The deferral stays a decision, not evidence: it never
  moves proof confidence, the proof ladder, or a verification verdict, and it
  remains bound to the exact discovery generation it was recorded against.
- Successful phase attempts now keep the durable phase workspace primary with
  a compact action receipt, and operators can browse every phase page
  without changing reality-derived workflow progress.
- Local KWP modules now accept the canonical `scan`, `review`, and `prove`
  descriptor phases while retaining the deprecated `hunt` and `confirm`
  aliases. Module and contributor guidance now describes the shipped Rust/KWP
  surface instead of the retired TypeScript SDK.

**Security:**

- `kuzushi auth ping` no longer builds its own request envelope. The
  credential is now bound to the provider of the model being pinged, so a
  provider argument that disagrees with the model — including the default
  `anthropic` argument on a config whose model is `openai:*` — fails before any
  environment variable is read or any bridge process starts, instead of
  forwarding one provider's API key to another provider. The ping also runs
  through the shared runtime credential preflight used by scan and run, and a
  bridge that exits nonzero is now reported as a failure even when it printed a
  success document.
- Durable finding identity now rejects canonical fingerprint, deduplication,
  and source-signature overrides from KWP workers, keeps actor fingerprints as
  provenance only, and refuses exact-fingerprint reuse across different
  tool/rule structures or repository targets. New identities use a
  host-authenticated source-content locus when available, so line drift does
  not split one defect, distinct same-rule sinks remain separate, and
  cross-tool corroboration still converges.

**Fixed:**

- `kuzushi scan --since <ref>` and the shell's `scan since <ref>` now resolve
  the same changed-file scope through one shared helper. The CLI no longer
  writes paths the reference deleted into `.kuzushi/v3/since.txt`, and the
  resolved scope compiles into the canonical `sast:scan` `paths` and
  `diffBase` options, so `--since` narrows every engine instead of only the
  ones that read the scope file. Combined with `--paths`/`--shard` the
  effective scope is the intersection, disclosed as
  `scope: N files since <ref> ∩ M requested → K`. A reference that changed
  nothing — or an empty intersection — now refuses the scan instead of leaving
  an empty scope file that silently widened the run to the whole target. A
  `diffBase` already present in raw scan input must match `--since`; a
  mismatch is an explicit error.
- Enter no longer types a stray `j` into the shell composer. A carriage return
  that reaches the terminal while the line discipline is still translating CR
  to LF — the startup window before raw mode engages, and every
  external-process suspension — arrives from crossterm as Ctrl+J, and the
  composer inserted the bare letter instead of submitting, so `demo` became
  `demoj` and the command was never run. Line feeds are now folded into Enter
  at the key-dispatch boundary, and unbound Ctrl/Alt chords are refused by the
  line editor rather than typed as text.
- Shell command completion now anchors its fuzzy match: the first character
  you type must open the command or one of its words. Two stray keystrokes
  such as `xu` no longer draft `context build` (conte**x**t b**u**ild), which
  put a tool run one Enter away from a typo. Ordinary abbreviations (`cb`,
  `ctx`, `con`) are unchanged, and history and finding search keep the
  permissive match.
- Runtime-validation labels no longer read as a rejection of the scanner's
  claim when nothing ran. A harness that failed to build, blocked
  infrastructure, an unsupported language, and a finding with too little
  detail now read `not executed - …` instead of `execution_rejected - …` in
  the finding detail report and in JSON/JSONL exports. The durable
  `execution_rejected` proof-state token in `.kuzushi` artifacts is
  unchanged, so stored findings and their vocabulary still load as before.
- Ctrl+C now names the job it stops. The shell logged
  `abort requested for active worker` with no subject, which left an
  operator guessing when the running job had been backgrounded from a view
  they had since left. The stop request now reads
  `stop requested for <job> · <run-ref>` whenever the job hub knows the
  label, and the per-domain cleanup lines are unchanged.
- An unbuilt Map no longer wastes the terminal it was given. The readiness
  card is now a width-capped centered form rather than a status pane stretched
  across the whole body, and each project-context receipt row carries the
  state and next action the project model already knew — the Ratatui card and
  plain output project the same columns, collapsing to the compact
  section/summary row when the terminal cannot afford them.
- A refused phase rerun no longer discards the draft the operator just
  reviewed. Enter on the rerun review card consumes the pending review only
  once a launch exists, so a missing target, a stale phase prerequisite, or a
  saved input that no longer prepares leaves the reviewed draft — including
  every edited option — open where it was. The reason is disclosed on the card
  as a `REFUSED · DISPATCH` row and painted as a Workbench notice instead of
  only reaching the transcript.
- `workspace:export-findings format=sarif` now emits spec-valid URIs. The
  `WORKSPACE_ROOT` base is built as a real `file:` URI instead of an
  interpolated path, so a workspace root containing a space, a non-ASCII
  character, or a Windows drive letter no longer produces a document SARIF
  consumers reject. Result locations percent-encode their workspace-relative
  path, so a repository file such as `docs/My Notes.md` resolves instead of
  breaking the location. A `\` in a path is escaped rather than treated as a
  separator, because on Unix it is an ordinary filename character.

**Security and reliability:**

- A nonpublishing candidate workflow now binds the requested version and full
  commit SHA to reusable full CI, five required native builds, and five local
  installs of the exact root and platform tarballs.
- One release receipt records the commit, version, filename, byte size,
  SHA-256, and npm integrity for the root package, all five platform packages,
  all five native archives, and the exact-commit source archive. Publishing
  rehashes the same files and stops on any difference.
- Package checks now inspect the files actually reported by `npm pack`, reject
  unsafe paths and links, exclude bridge tests from the root package, and keep
  the existing 10 MiB root and 60 MiB platform package limits.
- Source export now refuses tracked `.kuzushi` runtime state and verifies that
  the archive is complete for its embedded commit before writing the final
  output.

**Release operations:**

- The tag workflow accepts only the package-version tag at current
  `origin/main`, reruns the complete candidate, publishes exact matching
  platform packages before the thin launcher, and applies npm's `latest`
  dist-tag explicitly.
- Public-release instructions now separate private candidate verification from
  publishing and require verified cleanup of quarantined historical root
  artifacts before repository visibility changes.

## v0.24.0-alpha.13 · operator experience and descriptor boundaries

_Release status: failed and unpublished. This version was superseded by
`0.24.0-alpha.14`; do not create or reuse an Alpha13 release tag._

**Additive:**

- Module and tool descriptor contracts now live in the dedicated
  `kuzushi-descriptor` crate, while the Rust registry remains the shared
  execution boundary for scan, shell, and run modes.
- Review now exposes complete decision history, operator-specific calibration,
  stronger conflict categories, proof-band ordering, and consistent
  false-positive dismissal.

**Security and reliability:**

- Revision drift and abandoned-run recovery remain fail-closed while the shell
  now volunteers authenticated staleness, commit distance, and one-shot repair
  notices. Untracked source also participates in dirty-worktree identity.
- Proof bands, Markdown bundles, JSON evidence origin, and SARIF severity/help
  now share the same evidence-grounded classification and remediation context.
- File-scoped rescans and exact retries dispatch through the normal shared tool
  boundary instead of filtering stale findings or falling back to replay.

**Fixed:**

- Printable typing and paste are lossless across picker and planner views, bare
  `demo` follows the displayed guidance, and Review-to-Prove navigation retains
  finding identity.
- Cancellation stays nonterminal until cleanup finishes, missing cost never
  renders as zero, recovered and background runs volunteer attention, and
  quiet model/tool work uses honest distinct disclosures.
- Setup, Prove, scene, configuration, cost, quit confirmation, and narrow-width
  views now explain empty, deferred, volatile, source, and readiness state
  instead of requiring operators to infer it.
- `.kuzushi/scope.toml` host rules are now matched case-insensitively and
  ignore a trailing root dot, so `ADMIN.example.com` and `admin.example.com.`
  can no longer slip past an `[out_of_scope]` rule written as
  `admin.example.com`. CIDR rules also match bare IPv6 literals such as
  `2001:db8::1`, which previously reached recon dispatch and bounty imports
  unchecked.
- Setup no longer reports `Map plan EMPTY` and `BLOCKED` for a target whose
  recommended Map artifacts already exist. That state now reads
  `NOTHING TO RUN`, names how many cached artifacts will be reused, and the
  Start Map action states that it records the explicit Map skip instead of
  promising a run. Nothing checked while the planner still recommends work
  remains a real blocker. A task the planner still recommends because an
  earlier attempt failed or was interrupted no longer forces the blocker
  either when a later run already left its artifact on disk: Setup now reads
  the same cached-artifact reality the plan editor shows.
- Advancing the guided journey from a non-picker view now honors
  `phases.stop_after` the same way the phase picker already did, so a bounded
  journey stops where it is configured to instead of walking to the next phase.

## v0.24.0-alpha.12 — complete cross-platform release

**Fixed:**

- Native release jobs now allow enough time for Windows to compile and execute
  the platform-specific process and atomic-write contracts before packaging.
- Linux x64, Linux arm64, macOS x64, macOS arm64, and Windows x64 are all
  hard-blocking release targets; npm and GitHub publication cannot proceed
  with a missing supported archive, and release-contract checks preserve that
  five-platform assembly requirement.
- Platform-specific imports no longer produce an unused-import warning during
  the Windows native build.
- Terminal Run Focus now exposes and honors its real Back binding from both
  Prompt and Navigate state, including reopened background runs, while live
  runs keep their existing mode-toggle and cancellation behavior.
- Map no longer advertises Tab before its embedded gallery owns that key.
- Linux DevEx receipts now capture stable octal path modes without filesystem
  counters, and the real-target J25 journey accepts the truthful locked-Scan
  disclosure.

## v0.24.0-alpha.11 — Windows-native release repair

**Security and reliability:**

- Anthropic OAuth responses now fail closed when the provider omits the
  content array or returns malformed tool-call identities or arguments, so
  invalid provider output cannot enter tool execution as an empty call.
- Campaign job children retain whole-tree supervision on Windows, and detached
  shell dispatchers use explicit platform process groups with tested direct-kill
  fallback behavior.

**Fixed:**

- Windows-native builds now keep `OsStrExt` in scope where paths are encoded
  for atomic run-history publication.
- JSONL path/handle verification on Windows reuses Kuzushi's stable Win32 file
  identity adapter instead of unstable standard-library metadata methods,
  preserving replacement detection without weakening the security boundary.
- Required CI now compiles the complete Windows workspace and runs the focused
  JSONL contract before a release tag, so Windows-only source regressions fail
  the quality gauntlet during pull-request validation.
- Mutation CI now emits auditable receipts for Rust-free changes, excludes
  compiler-inactive platform adapters by explicit platform names, and protects
  the campaign log-tail, process-group, termination-fallback, and workspace
  identity contracts with focused tests.

## v0.24.0-alpha.10 — public CPG, durable cancellation, complete release gates

**Additive:**

- The default product now builds and runs against the public Oxidized Joern
  v0.1.1 graph engine, including persisted graph reopen and witnessed
  TypeScript taint-path compatibility coverage.
- Headless `kuzushi scan` now carries cooperative cancellation through normal,
  requested-input, demo, and APK execution, with two-stage SIGINT handling and
  deterministic canceled/interrupted batch exits backed by durable run truth.

**Security and reliability:**

- Ordinary CI and tag releases now require the complete default product—Rust
  lint/tests, dependency policy, coverage, mutation, package verification,
  Node 22 compatibility, and native E2E—without a private-source credential.
- CPG source paths and persisted artifacts are authenticated against canonical
  roots and the shared decoder; imported threat models are rebound to the
  current workspace tree before verification.
- Wasmtime 46.0.2 closes RustSec-2026-0222 and RustSec-2026-0223, while clean
  runner cache/debug settings keep complete-product builds within hosted disk
  limits.

**Fixed:**

- Review-yield schemas are part of the explicit package contract, so published
  tarballs include the documented model, dataset, and training-example
  surfaces without weakening fail-closed inventory checks.
- The mutation gate uses cargo-mutants' zero-based shard contract and preserves
  the tested Git build identity inside source copies, keeping lifecycle and
  checkpoint tests valid before mutants run.
- Current-attempt journey counts, deterministic coverage execution, stale
  fixtures and snapshots, surface linting, and public-engine API semantics now
  agree with the complete product gate.

## v0.24.0-alpha.9 — evidence-grounded cockpit and hardened analysis

**Additive:**

- The five-phase cockpit now keeps the full Map/Scan/Review/Prove/Fix rail
  visible, distinguishes locked pages from durable completion, and reopens
  historical phase material without treating page visits as progress.
- Map embeds the real-data visualization gallery: a source-grounded system
  summary, concrete DFD inspection, entry-point browser, and component stack
  share selection and navigation with Map-scoped full-frame zoom.
- Threat-model results carry registered source-tree identity, findings compare
  honestly across scans, and the scan worklist exposes contributor provenance
  and degraded-analysis state.
- Taint, fuzzing, chain analysis, finding review, replay, and run-lifecycle
  surfaces gained additional persisted evidence and focused operator controls.

**Security and reliability:**

- Review, default bulk triage, and chain construction consume the accumulated
  relevant finding corpus. Later observations retain identity-scoped human
  decisions, while deterministic and nondeterministic scan misses preserve
  their distinct lifecycle meaning.
- CodeQL, CPG, workspace traversal, subprocess, model-runtime, and artifact
  persistence boundaries now authenticate inputs and snapshots more tightly,
  keep cancellation bounded, and fail closed instead of changing execution
  policy silently.
- Typed run items remain the authoritative lifecycle stream, with durability,
  integrity, comparison, and same-second ordering covered by shared reducers
  and cross-surface tests.

**Fixed:**

- Map and DFD navigation now reaches concrete components, nodes, flows, and
  boundaries at narrow and wide terminal sizes while preserving cursor and
  scroll state across tabs and zoom transitions.
- Accepting a newer Map correctly reopens Scan without deleting prior findings;
  Review, Prove, and Fix no longer derive completion from a selected page,
  filter, or transient Run Focus state.
- Release, architecture, model-safety, CRAP-risk, packaging, and Rust lint/test
  gates cover the expanded native control plane and evidence contracts.

## v0.24.0-alpha.8 — bounded runtime, truthful benchmarks, responsive shell

**Additive:**

- The benchmark system now carries corpus manifests, immutable provenance,
  exact scoring and matching contracts, spend evidence, SARIF ingestion, and
  real-model/regression workflows suitable for reproducible release gates.
- The operator shell gains richer activity, permission, keymap, onboarding,
  completion, run-history, and phase-cockpit projections backed by explicit
  application/view-model boundaries and asynchronous hydration.
- Native MCP and testing surfaces expand with additional structural-analysis,
  process, run-artifact, mock-runtime, and cross-platform contract coverage.

**Security and reliability:**

- File, subprocess, prompt, model-usage, run-ledger, and patch-snapshot paths
  are bounded and validated at their owning adapters, with explicit failure,
  cancellation, provenance, and cost states instead of silent fallback.
- Workbench finding/review projections are revision-cached, background event
  work is time-sliced and wake-coalesced, and Jobs history no longer performs
  filesystem recovery on the terminal paint path.
- Process identity, atomic artifact commits, worker deadlines, and untrusted
  structured-output repair now have executable quality and platform tests.

**Fixed:**

- Keystroke-to-paint latency for the 391-finding Workbench case drops from
  63.5 ms to 35.1 ms p95 in the pinned 60-sample black-box profile.
- Completion, compact-terminal, activity, keybinding, review-queue, and
  provenance views preserve truthful selection, loading, malformed, and empty
  states without rebuilding unrelated presentation data.
- TypeScript project discovery, bootstrap/pack verification, documentation
  drift checks, and CI benchmark contracts now fail explicitly on incomplete
  or contradictory inputs.

## v0.24.0-alpha.7 — native control plane, hardened execution, phase cockpit

**Additive:**

- The Rust-native control plane now ships the CLI and every advertised MCP
  server through one versioned native-runtime contract, with platform smoke
  checks covering packaged executables and external-engine health boundaries.
- The shell gains the phase cockpit, explicit prompt/navigation modes,
  generation-safe target hydration, durable run status semantics, and richer
  evidence, proof, and remediation projections without changing headless JSON
  contracts.
- KWP modules now carry explicit tool effect, approval, workspace, path, and
  protocol-version policy through the shared registry dispatch boundary.

**Security and reliability:**

- Workspace reads, writes, subprocesses, artifact ledgers, and finding proof
  replay now use bounded, target-confined adapters with explicit cancellation
  and interruption states.
- Registry preparation rejects unknown or unsafe input before dispatch, keeps
  model/runtime selection explicit, and prevents target-local steering or
  silent execution-policy fallback.
- Release builds use the workspace Rust toolchain and exercise native runtime,
  atomic-write, cancellation, recon-process, and MCP contracts on each target
  platform before publishing.

**Fixed:**

- `cargo test --workspace` release blockers: the BDD onboarding skip-path
  scenario now asserts the Workbench cockpit handoff, and Workbench snapshots
  include the findings ledger row.
- Single-tool run mode and shell background tools now share the same
  finding-store provisioning predicate. Tools such as `cargo-audit:scan`,
  `offense:chain`, `variant:*`, SBOM, secret scan, and Android APK finding
  producers no longer drift between modes.
- The npm postinstall check now warns when the package has no native Kuzushi
  binary for the current platform, with consumer-facing remediation steps.
- Release native builds are pinned to the same Rust toolchain version as CI
  (`1.88.0`) via `rust-toolchain.toml` and the release workflow.
- `kuzushi doctor` now checks Joern and nmap availability, and auth ping
  missing-credential failures include exact `export ...` remediation.
- Unknown tool options now report valid option names and close-match hints
  instead of author-facing metadata wording.
- Dev scripts no longer depend on `/home/user`, fixed `/tmp` filenames, or a
  hardcoded `~/go/bin/ascii-image-converter` path.

**Docs:**

- Release instructions now describe the full gate set, cross-platform native
  binary staging, pack verification, and CI-driven npm publish flow.
- Mode-parity and agent docs now describe `kuzushi run` as always emitting
  JSON, without a separate `--json` flag.
- The actionlint workflow now installs actionlint from the pinned `v1.7.12`
  tag instead of downloading from upstream `main`.

## v0.24.0-alpha.4 — CI gating, offline demo, multi-platform packaging, reliability

First release where the npm package ships the documented Rust CLI on every
green-built platform.

**Additive:**

- `kuzushi scan --fail-on low|medium|high|critical` exits 3 when blocking
  findings exist (CI gating); `--sarif <path>` writes SARIF 2.1.0 straight
  from the CLI. The reference workflow gates on high and uploads to
  GitHub Code Scanning.
- `kuzushi demo`: offline first-wow — scans a vendored vulnerable fixture
  with the deterministic engines; no API key, model, or external scanners.
- The npm publish pipeline stages every green platform build
  (linux-x64/arm64, darwin-x64/arm64, win32-x64); darwin-arm64 is now a
  required release build. One binary per platform — `kz` is an argv0 alias.

**Fixed:**

- Finding identity is stable and message-independent (FNV-1a v2
  fingerprints + one-time migration): LLM rephrasing no longer duplicates
  findings, and Rust toolchain bumps can no longer resurrect history.
- Reliability triad: the Node bridge runs under a wall-clock deadline with
  kill+retry (no indefinite hangs; transient 429s no longer kill agent
  loops); the findings store uses WAL + busy-timeout + transactional
  inserts; state JSON writes are atomic (temp+rename).
- Supply chain: the required `github:` dependency on randori-plugin is gone
  (it was a Claude Code plugin, not runtime code); optional plugin deps are
  SHA-pinned.
- Trust kit: descending CHANGELOG, honest SECURITY.md versions, and a
  stated privacy promise (local-first, zero telemetry).

**Fixed (pre-release, via the consolidation/quality merges):**

- CI is hard-blocking again end to end: the DDD boundary regressions from the
  phase-workflow/security-viz work are resolved (model-ranked recommendation is
  an explicit adapter concern; chrome-layout and threat-DFD renderers consume
  view models), and the BDD onboarding features now encode the phase-driven
  launch contract (Esc skips a phase and advances; past 掛 KAKE the shell opens
  the Workbench cockpit).
- The CRAP-risk gate fails loudly when its diff base cannot be resolved
  instead of silently checking 0 files on shallow CI checkouts.

**Additive:**

- New CI gates: `cargo fmt --check`, `cargo clippy -D warnings`, and
  `cargo deny check advisories licenses sources` (see `deny.toml`); Dependabot
  watches cargo, npm, and GitHub Actions ecosystems.
- The e2e npm-wrapper smoke job is hard-blocking (all three documented flake
  sources were fixed previously).

**Internal:**

- Historical working notes moved from the repository root to `docs/notes/`.

## v0.24.0-alpha.0 — Rust/LangGraph cutover

**Breaking:**

- The npm `kuzushi` binary now invokes the native Rust CLI through
  `bin/kuzushi-rs.mjs`.
- The `kuzushi-ts` npm binary, `pnpm dev:ts`, and `scripts/kuzushi-dev` source
  CLI helper are removed. TypeScript remains only for published library exports,
  migration reference code, and tests.
- The source-only TypeScript `shell` command no longer has a TypeScript/Ink
  implementation; it exits with Rust replacement commands.
- The legacy TypeScript/Ink TUI, mock TUI harness, and React/Ink dev
  dependencies are removed now that the Rust Ratatui shell covers the operator
  surface.
- The old `dist/cli*` TypeScript CLI outputs are excluded from the npm tarball.
- Operator docs now describe only the Rust command surface:
  `shell`, `scan`, `findings`, `config`, `auth`, `modules`, `tools`,
  `doctor`, `run`, `mcp`, and `pr-comment`. Unsupported TypeScript-era scan
  flags such as `--preset`, `--sarif`, and CLI `--model` are not advertised
  for the Rust path.

**Additive:**

- Native module/tool registry, npm-wrapper smoke coverage, and shell help tests
  verify that docs and help point at executable Rust surfaces.
- Runtime-backed tools use LangGraph through the Rust bridge and still
  require an explicit configured model. Missing models, scanner binaries,
  bridge commands, or plugin roots fail explicitly.
- `kuzushi doctor` is now the Rust preflight surface for config, `.kuzushi/v2`
  state writability, findings DB openability, optional scanner binaries,
  LangGraph bridge readiness, and model/auth setup. It reports credential
  environment variable names only, never secret values.
- `kuzushi --plain shell` plus `KUZUSHI_PLAIN=1`,
  `KUZUSHI_SCREEN_READER=1`, or `KUZUSHI_LOW_BANDWIDTH=1` force strict
  line-oriented shell output with no ANSI escapes, animation, or box drawing.

## v0.21.0-dev — Clean Code major refactor (never published as v1.0.0; folded into v0.24.0-alpha.0)

**Breaking:**

- Flat runtime credential config is removed. Replace
  `agentRuntimeConfig.apiKey` / `agentRuntimeConfig.baseUrl` with an explicit
  backend slot such as `agentRuntimeConfig.claude.apiKey`,
  `agentRuntimeConfig.piAi.apiKey`, or `agentRuntimeConfig.codex.apiKey`.
- `agentRuntimeConfig` object values must use backend slots. The old
  `{"apiKey":"...","baseUrl":"..."}` shape is rejected by `config set`.
- Legacy built-in SAST tool aliases are removed. Replace names such as
  `sast:semgrep`, `sast:codeql`, and `sast:triage` with `semgrep:scan`,
  `codeql:scan`, and `triage:run`.

**Internal:**

- Shell command dispatch now routes through a table-driven command registry
  instead of hand-written slash and bare-command ladders.
- Database schema bootstrap moved behind `src/store/schema.ts`; `src/store.ts`
  remains the public compatibility facade for existing imports.
- Patch synthesis output parsing moved behind a focused parser module with
  unit tests.

## v0.20.0 — Module SDK hardening

**Breaking:**

- `ToolExecutionContext.uiStore | datastore | workspace | events` now use
  narrow handle interfaces (`HostUiHandle`, `ToolOptionStore`, `WorkspaceHandle`,
  `ModuleEventScope`) declared in `src/modules/host-handles.ts`. The concrete
  host classes are structural supersets, so existing in-tree callers continue
  to work; third parties that cast to internal host classes must migrate to
  the narrow API.
- Tool names are now required to begin with `<module.id>:` at load time.
  Loader throws `ModuleLoadError{ code: "SHAPE_INVALID" }` on violation.
  Duplicate tool names within a module are rejected.
- Built-in module IDs `n-day-diff-hunter` and `variant-hunter` renamed to
  `ndiff` and `variant` to satisfy the prefix rule. Backward-compat load
  specifiers (`--load n-day-diff-hunter`) still work.
- MCP-bridged tools default to `headless: false`. Only tools advertising
  `annotations.readOnlyHint: true && !destructiveHint` auto-dispatch in
  `kuzushi run` / pipeline mode. Opt in via `CreateMcpModuleOptions.trustHeadless: true`.

**Additive:**

- `module.manifest.json` gains `kuzushiSdkVersion` (semver string). Omitting
  it produces a warn; a future release may require it.
- `ModuleLoadError` replaces plain `Error` throws across loader / registry /
  core. Codes: `MANIFEST_MISSING`, `MANIFEST_INVALID`, `REQUIREMENTS_UNMET`,
  `ENTRY_NOT_FOUND`, `SHAPE_INVALID`, `ID_MISMATCH`, `SDK_INCOMPATIBLE`,
  `CONFIG_INVALID`. `ModuleLoadError extends Error`, so existing
  `err.message` consumers keep working.
- `ToolExecutionContext.host = { sdkVersion, capabilities }` populated by
  `CopilotCore.executeTool`. Modules probe with
  `ctx.host?.capabilities.has("workspace")` before using optional capabilities.
- `ToolExecutionContext.logger?: ToolLogger` for structured diagnostics,
  distinct from human-facing `ctx.print`.
- New `kuzushi/modules` exports: `defineModule`, `defineTool`, `ModuleLoadError`,
  `HostUiHandle`, `ToolOptionStore`, `WorkspaceHandle`, `ModuleEventScope`,
  `ToolLogger`, `HostInfo`, `parseModuleSpecifier`, `ModuleRegistry`.
- Manifest validation now Zod-backed (`src/modules/schema.ts`). JSON schema
  published at `schemas/module.manifest.schema.json` for editor autocomplete.
- `configSchema` in the manifest is validated against `moduleConfig` before
  `init()`; mismatches raise `ModuleLoadError{ code: "CONFIG_INVALID" }`.
- MCP bridge: configurable `timeoutMs` (default 60 000), auth token via
  `CreateMcpModuleOptions.authToken` or `KUZUSHI_MCP_TOKEN` env, collision-safe
  derived module IDs.

**Tooling:**

- Historical note: the legacy TypeScript CLI scaffolder emitted
  `kuzushiSdkVersion` + `$schema` in generated manifests and used
  `defineModule` + `defineTool` in `src/index.ts`. The current Rust operator
  CLI does not expose a `kuzushi create-module` command.
- `kuzushi/testing` exports expanded: `createMockToolContext` covers every
  `ToolExecutionContext` field; new helpers `createMockEventScope`,
  `createFakeRuntime`, `assertToolResult`, `expectModuleShape`.

**Docs:** new [`docs/modules.md`](./docs/modules.md) consolidates the
module-authoring guide; [`docs/mcp-server-requirements.md`](./docs/mcp-server-requirements.md)
documents the MCP server contract; [`docs/devex/06-module-sdk-assessment.md`](./docs/devex/06-module-sdk-assessment.md)
captures the audit.

**Migration checklist for existing modules:**

1. Add `kuzushiSdkVersion` (and optionally `$schema`) to `module.manifest.json`.
2. `grep` every tool `name:` and confirm it starts with your module `id`.
   Use `defineTool<"<id>">({...})` to get a compile-time check.
3. Replace `ctx.uiStore as UIStore` / `ctx.workspace as WorkspaceManager`
   casts with narrow-interface usage; add methods to the narrow interfaces
   upstream if you need a new host capability.
4. Update `kuzushi/testing` consumers — override fields via
   `createMockToolContext(overrides)` instead of reaching into undocumented
   internals.
