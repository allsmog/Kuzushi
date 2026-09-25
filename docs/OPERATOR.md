# Kuzushi operator handbook

The single entry point for a new operator. It explains the four execution
modes, the cockpit decks and their keybindings, budget semantics, the pack
workflow, how to read the trend strip, and the troubleshooting notes that
newcomers hit first. Deeper contracts live in
[docs/modules.md](./modules.md) (module system),
[docs/assessments/mode-parity.md](./assessments/mode-parity.md)
(scan/shell/run parity matrix), and
[docs/operator-control-surfaces.md](./operator-control-surfaces.md)
(flags/options/env precedence).

A deterministic test
(`every_builtin_tool_is_documented_for_operators` in
`crates/kuzushi-core/src/modules/registry/tests.rs`) requires every
registered built-in tool name to appear in this file or in
`mode-parity.md`, so new tools cannot ship undocumented. If you add a
tool, add it to the capability catalog at the bottom of this file (or to
the parity matrix when it is an intentional mode asymmetry).

## 1. The four modes

| Mode | Invocation | Use it for | Exit codes |
| --- | --- | --- | --- |
| **shell** | `kuzushi [--target <path>]` | Interactive cockpit: Setup → Map/Scan/Review/Prove/Fix → Report; without a target, opens the target picker | n/a (interactive) |
| **run** | `kuzushi run <tool> [json]` | Headless single-tool execution, JSON on stdout | 0 completed/skipped · 2 prepare failed · 3 tool failed (`ok:false`) · 4 partial |
| **scan** | `kuzushi scan <target>` | Scan orchestration (the `sast:scan` umbrella) | `--fail-on` gate failures exit 3 |
| **ci** | `kuzushi ci <target>` | Deterministic regression gate over the findings ledger — no model calls | 0 clean · 1 gate tripped · 2 error |

Scan, shell, and run converge on the authorization-bound registry flow
(`prepare_dispatch_input` → authorization →
`dispatch_prepared_input_with_runtime`), so shared tool policy does not depend
on which mode launched it. Workspace/runtime context and presentation may
differ where the mode-parity contract says so. `kuzushi ci` is a separate
deterministic fold over persisted state, not a registry tool.

`kuzushi ci` details (see §6 for the gate semantics):

```sh
kuzushi ci <target> [--fail-on <severity>] [--update-baseline] [--summary <path>]
```

- Baseline: `.kuzushi/ci-baseline.json` (fingerprint set; create/refresh
  with `--update-baseline`).
- Machine summary: `.kuzushi/v3/reports/ci-summary.json` (or `--summary`).
- `--fail-on` defaults to `low`; a finding with unknown severity never
  trips the gate on severity grounds alone.

## 2. Cockpit decks and keybindings

The interactive shell's spine is `Setup → Workbench → Report`; Workbench
hosts the five durable pages (`Map`, `Scan`, `Review`, `Prove`, `Fix`,
keys `1..5`, `n`/`N` to cycle). The decks below are the operator surfaces
added around that spine. Global navigation: `j/k/↑/↓` move, `g/G` ends,
`Tab`/`[`/`]` cycle panes, `Z` zoom pane, `Esc` back.

After a foreground Map run started from Setup completes, Kuzushi opens its
recorded Map result. Press `Esc` to enter Navigate mode, then `u` (**Use map**)
to accept it, or inspect the result before deciding. Showing the result does
not accept it or start Scan. A result whose recorded source identity is missing
or no longer current stays available for inspection and asks you to run Map
again; it cannot advance the workflow.
Backgrounding with `b` returns to the launch view; background completion leaves
your current view in place. `/setup` reopens the Map configuration explicitly.

When exit confirmation is shown, `↑/↓` scroll one disclosure row, `PgUp/PgDn`
scroll one visible page, and `Home/End` reach the beginning/end. Exit and Stay
remain visible. The confirmation uses the full frame when ordinary shell chrome
would leave too little reading space. `n` or `Esc` restores the prior editor and
its unsaved draft; choosing `y` follows the disclosed exit/cancellation policy.

In Setup's Map plan or a phase planner, `Tab` focuses the selected tool's
options and `Enter` edits an option. The editor keeps the cursor visible while
you move with arrows, `Home/End` or word/line editing chords. `Delete` removes
the next character; `Ctrl+U` clears to the line start. Paste preserves Unicode
and line breaks, and `Shift+Enter` adds a line break. `Enter` or `Ctrl+S` validates
and saves the session option; `Esc` cancels. Saving does not launch the plan.
Invalid values remain editable; `PgUp/PgDn` reads a long validation message.
Outside the editor, `Ctrl+S` retains its separate persist-option action.

`Ctrl+T` opens Answers beside the workspace when there is room, or switches
between them in a compact terminal. While reading, `PgUp/PgDn` pages and
`Home/End` reaches either end. `Enter` opens a reply; within the reply, Enter
sends and `Shift+Enter` inserts a newline. `Esc` keeps an unsent draft.
OpenAI OAuth Ask replies appear as the model responds. The pane follows new text
until you scroll and labels the response as in progress. `Ctrl+C` cancels Ask;
unfinished text stays visible as incomplete and is not reused as a completed
answer. Other provider paths may still return their answer all at once.

Ask history now reopens after restarting on the same target. Restored answers
show their captured context; the next question rechecks the target revision,
Map and tool policy before reusing earlier questions and completed answers. A changed context starts
a fresh conversation. An interrupted or canceled turn stays incomplete. Recovery
restores its submitted question for editing when there is no newer reply draft. It
keeps your current model selection and never sends a request on its own.
`clear` prevents that target's cleared conversation from returning on restart.

Recovery uses the existing redacted session transcripts and retention setting.
It checks the 64 most recently started sessions, within 32 MiB of total reads and
8 MiB per file, and saves at most 12 earlier turns plus the current turn in a
512 KiB checkpoint. A limit or unreadable record is disclosed; older transcripts
without a context-bound checkpoint remain available through `kuzushi sessions`.
`--no-session-persistence` disables saving and recovery. Unsent drafts remain
session-local.

Completed answers show Markdown headings, lists, quotes and code. Code retains
indentation; `↪` marks a wrapped continuation. Links show their destinations,
and narrow tables become labeled records. In short terminals, duplicate footer
hints give way to answer text while reply and workspace controls stay visible.

### Campaign deck — `campaign [id]`

Shell presentation over the shared campaign artifacts (`plan.json` +
`queue.json`); headless parity is `campaign:status` + `kuzushi campaign
run`.

| Key | Action |
| --- | --- |
| `j`/`k`, `↑`/`↓` | move the job cursor |
| `Enter` | open the selected campaign's job list |
| `q` | back to the campaign list |
| `x` | include/exclude the selected job from dispatch |
| `w` | cycle dispatcher worker count |
| `L` | launch the detached dispatcher (`kuzushi campaign run`) |
| `K` | kill the running dispatcher |
| `e` | preview the job's (seasoned) prompt |
| `r` | refresh from disk |

The deck header carries the trend strip and, when at least two snapshots
exist, the history sparkline (§5).

### Coverage matrix — `coverage`

Shard × threat coverage fold over the campaign ledger (headless parity:
`campaign:coverage`). Cells show attempted/covered state so you can see
which planned combinations never ran; `campaign:plan` with gap-fill
consumes the same fold to requeue only uncovered cells. From the Review
page, `D` opens the related coverage **clusters** view (duplicates and
root-cause groups, without hiding distinct sinks).

### Review backlog — `B` on the Review page

An armed triage preset: one-key decisions are bound **only while the
backlog is active**, so ordinary browsing can never record a decision by
a stray keypress.

| Key | Action |
| --- | --- |
| `B` | toggle the backlog preset on/off |
| `c` | record **confirmed** for the cursored finding |
| `f` | record **rejected: false positive** |
| `d` | record **deferred** |
| `w` | record **needs review** |
| `s` | cycle the severity filter (critical → high → … → off) |
| `t` | cycle the tool filter (tools present in the ledger) |
| `X` | bulk-defer every visible finding — press `X` twice (first press arms a CONFIRM chip) |
| `u` | undo the last recorded batch (appends inverse decisions; nothing is deleted) |

Decisions are append-only events; the fold is latest-decision-wins, so a
reversal is one more decision, never an edit (§5).

### Report deck — `report`

The exit surface exports the findings ledger as SARIF, Markdown bundle, JSONL,
JSON, CSV, or VULN-FINDINGS, defaulting completeness to All. `j/k` selects a
format, `c` changes completeness, and `Enter` exports. New destinations start
under `.kuzushi/reports/`, outside the indexed source set. Each format retains
its own destination during the session. `e` opens the destination editor;
arrows, Home/End, Delete, Unicode and paste work inside that field. Enter or
Ctrl+S saves the path without exporting; Escape cancels the edit. Relative
paths resolve against the explicit target and use the shared output-path rules.

Success and failure show the attempted format, completeness, time and full
destination. Correct the path and retry after a failure. `PgUp/PgDn` reads
long reports and receipts; `Esc/q` returns to the originating view. Review
counts use the unfiltered finding ledger. Cost coverage describes up to 100
recent run records, distinguishing complete, incomplete, unavailable and
invalid records. A workspace spend total is unavailable: campaign and parent
scan records may include costs represented again by child runs. Report does
not add those overlapping amounts or present campaign-only spend as a total.

For a
CI-consumable **confirmed-only** SARIF (latest-decision-wins filter
applied), use `report:sarif` — default output
`.kuzushi/v3/reports/confirmed-findings.sarif`.

## 3. Budget semantics

Three independent ceilings; all are inclusive (`spent >= cap` trips) and
an unset budget means **not enforced**, never a hidden default:

1. **Setup budget (shell)** — the per-engagement ceiling set in the Setup
   deck. Must be positive and within the hard ceiling; enforcement halts
   model-backed work with a visible halt card.
2. **Campaign budget (`kuzushi campaign run --budget <usd>`)** — the
   inter-job ceiling. Checked **between dispatches**: when cumulative
   campaign spend crosses it, no further job starts; the running child is
   allowed to finish.
3. **Per-job budget (`--job-budget <usd>` and/or a plan row's
   `jobBudgetUsd`)** — the intra-job guard. When both are present the
   **tightest cap wins**; zero/negative values are ignored as unset. A
   child whose live cost meter crosses the cap is stopped and its queue
   row parks as `over-budget` — a parked over-budget job is **never
   auto-retried** (retrying would spend the same money on the same
   failure), and rate-limit sniffing cannot convert that park into a free
   retry. Re-plan or raise the cap (then `--resume`) to run it again.
   **Granularity caveat:** the guard reads live per-model-call cost from
   the child's trace, so its overshoot bound is one in-flight call. A
   tool that makes ONE big call for the whole job (e.g. single-shot
   agentic scans) reports cost only at the end and cannot be bounded —
   run such jobs with `strategy=chunked` so per-chunk calls give the
   guard telemetry to act on.
   **Kill-loses-findings caveat:** the guard SIGKILLs the child, and a
   chunked hunt persists findings only when it finishes — a killed run
   loses every finding it had gathered. Prefer the tool-level
   `budgetUsd` option (below) and keep `--job-budget` slightly above it
   as the backstop.
4. **Chunked-hunt run budget (`budgetUsd` tool option on
   `full-mode:hunt` / `agentic-sast:scan` with `strategy=chunked`)** —
   the graceful in-tool ceiling. Once accumulated observed chunk cost
   reaches it, the hunt stops dispatching new chunks, **keeps the
   findings from completed chunks**, persists them through the normal
   path, and reports every undispatched chunk ID in
   `failedChunkErrors` so a follow-up run with `failedChunkIds` can
   finish the plan. Workspace spend-cap exhaustion (`SpendError`) stops
   the same graceful way instead of aborting the hunt. Note the
   workspace spend caps themselves are *lifetime ledger* ceilings, not
   per-run budgets — `budgetUsd` is the per-run knob.

`kuzushi ci` performs no model work at all, so it needs no budget.

## 4. Campaign workflow (plan → run → status → gap-fill)

1. **Plan** — `campaign:plan` crosses shards × threats × models into a
   ranked job queue (threat-weight ranking, `maxJobs` cap; both the
   coverage skip and the cap are reported, never silent). Threat axis
   sources, in order: `modelsDir` (every `*.json` in the directory,
   sorted) when given, else the persisted workspace threat model, else an
   empty axis (one un-seasoned job per shard × model).
2. **Season** — with `seasonPrompts`, each threat-bearing job gets a
   prompt file under `.kuzushi/prompts/campaign/<campaignId>/<jobId>.md`
   carrying the workspace calibration fragment plus a "Campaign focus"
   section (threat, CWEs, and the rule that focus reorders attention but
   never filters findings). See §7 for the replace-vs-append subtlety.
3. **Run** — `kuzushi campaign run` is a detached dispatcher (own process
   group) that walks the queue with N workers. Jobs are ordinary
   `kuzushi run` invocations, so they show up in `jobs`/`runs`
   unchanged. Failure policy: transient failures retry with attempts
   left; rate-limit walls back off; `over-budget` parks permanently (§3).
4. **Status / resume** — `campaign:status` folds plan + queue into one
   snapshot (also rendered by the campaign deck) including the trend
   strip. Re-running `campaign:plan` in gap-fill mode drops
   already-covered shard × threat cells so a resumed campaign only pays
   for what never ran.

## 5. Trend and FP-rate interpretation

The trend strip (campaign deck, `campaign:status`, `kuzushi ci` output)
folds the review ledger with **latest-decision-wins** per finding — the
newest decision is each finding's truth; history is preserved but never
double-counted. Read it as:

- **decided / total** — triage progress over the ledger.
- **confirmed** — findings whose *latest* verdict is confirmed/to-fix.
  This same set feeds `report:sarif` and the `kuzushi ci` gate, so the
  three surfaces can never disagree about what "confirmed" means.
- **fp rate** — rejected-as-FP over decided. Rising FP rate after a
  prompt or pack change is your earliest calibration signal; falling
  confirmed-per-dollar with flat FP rate usually means the remaining
  shards are quieter, not that the scanner got worse.
- **spend** — cumulative model cost attributed to the campaign.

Every `campaign:status` records a snapshot (deduplicated when nothing
changed) to `.kuzushi/trend-history.jsonl`, capped at the last 90. With
two or more snapshots the deck shows a sparkline strip
(`HISTORY  fp ▁▂▇ · spend ▁▄█ · N snapshots`) so drift is visible at a
glance without opening the JSONL.

## 5.1 Review-yield census and dataset export

`kuzushi review-yield` turns the review ledger into an auditable training
corpus. Both subcommands need an explicit target and fail when the target has
no recorded findings database.

```sh
kuzushi --target <repo> review-yield census            # counts, plus --json
kuzushi --target <repo> review-yield export --out review-yield.jsonl
```

The census counts every decision and explains every exclusion: automated and
imported authors, policy outcomes (accepted risk, suppressed, deferred, still
open), conflicting human reversals, decisions with no usable read cutoff, and
identities with no snapshot from before the reviewer looked. The export writes
one JSONL row per durable identity plus a `<out>.manifest.json` sidecar
carrying the label policy, the frozen feature vocabulary, the census, and a
BLAKE3 digest over the manifest and every row. Features are read only from
finding snapshots that existed at or before the decision's read cutoff, so a
row can never contain the verdict it is supposed to predict. Paths, snippets,
messages, rationales, and reviewer identities never leave the workspace.

## 5.2 Review-yield model artifacts

A trained model is a single JSON file described by
`schemas/review-yield.model.schema.json`. The model path is always explicit —
there is no default location, no environment variable, and no auto-discovery.

```sh
kuzushi review-yield validate-model --model model.json          # plus --json
kuzushi --target <repo> review-yield score --model model.json   # plus --json
```

Loading fails closed. A missing or oversized file, malformed JSON, an
unsupported `schemaVersion`, a digest that does not match the artifact's own
bytes, an unknown key or node kind, an out-of-range rate, a child index out of
bounds, a cycle, a shared child, more than 127 nodes, a depth over 6, or a
feature schema this build does not read — each is an error with a named reason
and a nonzero exit, never a warning and never a substituted model. `score`
opens the artifact before the findings store, so a refused model never reaches
your data.

`score` is advisory. It prints one line per finding with the leaf's smoothed
positive rate, its 95% credible interval, its support, its entropy, and the
decision path that produced it — or the reason the finding could not be scored
(a missing feature, a category outside the training vocabulary, or a leaf below
the artifact's support floor). It does not reorder, filter, or hide anything in
your review queue, and it writes nothing.

## 5.3 Review yield in the shell (experimental)

Whether a trained model would have helped is only answerable if Kuzushi knows
what the queue looked like when you started reviewing something. The shell can
record that, explain what the model saw, and — if you ask it to — order the
queue by what the model knows. There is no flag and no environment variable:
this is operator-owned global config, because the section names a model file
and a scanned repository must not choose which model scores its own findings.

```toml
# $HOME/.kuzushi/v3/config.toml
[review_yield]
mode = "shadow"                          # off | shadow | visible | within-band | learn
model_path = "/models/review-tree.json"  # required whenever mode != off
```

In every mode but `off`, opening a finding for review — Enter on the review queue, or
`open <ref>` — appends one `review-session-started` event carrying the
finding's identity, the position it held in the queue you actually saw, the
position it would have held under the model, the queue size, its proof band and
severity, the model's digest, and a digest of the feature vector. The verdict
you later record links back to that session. Nothing else is written: no
feature values, no paths, no snippets, no rationale, no reviewer identity.

`visible` adds one section to the finding detail, and nothing else. It shows
the historical positive rate for findings that reached the same leaf, how many
prior reviewed examples that leaf holds and how they split, the 95% interval,
the outcome entropy, the model, and the comparisons the model made to get
there. When there is no signal, the section says which fact stopped it — a
missing input, a category the model never saw in training, a leaf below the
artifact's evidence floor, a finding with no durable identity — rather than
leaving a blank or a placeholder number.

Read it as what it says it is: an advisory historical reviewer-outcome signal.
It describes how reviewers ruled on findings that looked like this one. It is
not proof that this finding is exploitable, and it is not a decision. Yours is
the only verdict recorded.

Neither `shadow` nor `visible` changes anything else you see. The queue order,
the sort, the filters, and every other displayed value are identical with the
signal armed and off; tests compare the full ordered queue byte for byte on
both ordering paths to keep it that way. There is no score in the queue, no new
column, and no glyph that could be mistaken for a ranking cue. Moving the
cursor is not a session, and re-opening a finding you have not decided on is
the same session, not a second one.

Two further modes do move rows, and only ever *inside* one proof-confidence and
severity band. `within-band` puts the highest historical yield first.
`learn` puts the widest model knowledge gap first — the findings whose prior
reviewed examples are fewest and most mixed — so reviewing from the top
teaches the model the most. Read `learn` for exactly what it says: it ranks
what the *model* does not know, never how likely a finding is to be real. In
both, a band reorders only when every row in it carries the key that mode ranks
on; one row without it leaves the whole band in baseline order. While `learn` is
actually ranking a band on screen the queue shows one chip, `learn mode - model
knowledge-gap review`, and the finding detail explains the ordering beside the
numbers it uses; both disappear when nothing is being ordered. Setting `mode`
back to `off`, `shadow`, or `visible` returns the byte-identical baseline list.

The section is consumed only by the interactive shell — `run` and `scan` load
it like any other config and ignore it — and it fails closed in every
direction. A mode other than `off` with no `model_path` is a config load error,
not a silent downgrade. A model artifact that does not load leaves review yield
off with a stated reason; it is never partially applied and no other path is
tried. With `mode = "off"`, none of this runs: no model is loaded, no session is
recorded, no section is drawn, and decisions carry no session link.

## 6. The CI gate

`kuzushi ci` is deterministic: it reads the findings ledger, applies
latest-decision-wins, and fails (exit 1) when a **new confirmed finding**
appears whose fingerprint is not in `.kuzushi/ci-baseline.json` at or
above the `--fail-on` severity. Operational loop:

1. First adoption: `kuzushi ci <target> --update-baseline` to accept the
   current confirmed set.
2. Pipeline: plain `kuzushi ci <target> --fail-on high` — exit 1 blocks
   the merge; the JSON summary names the offending fingerprints.
3. After a fix or an accepted risk: re-run with `--update-baseline`.

Reversals are honored: a finding later rejected as FP leaves the
confirmed set automatically (no baseline edit needed).

## 7. Pack workflow

Packs hold product knowledge (shards, threat models, prompt fragments,
calibration) **outside** the kuzushi core — core stays generic. Authoring
workflow lives in your packs repository's `TEMPLATE/NEW-PACK.md`; the
tooling half:

- `pack:suggest-shards` — deterministic draft of a shard layout for a
  target tree (entry-point signal density ranking), written with evidence
  comments to `.kuzushi/v3/reports/suggested-shards.toml`. It never
  installs anything; copy the rows you agree with into the pack.
- `pack:lint` — structural gate over `pack.toml` and its products: shard
  scopes must exist (WARN over 50 files), every product needs a
  threat-model closure, severities/CWEs must be well-formed, prompts must
  live at `prompts/<module>/<verb>.md`. Errors fail the tool (exit 3
  under `kuzushi run`), so it can gate pack PRs.

## 8. Troubleshooting

- **`modelsDir` paths** — a relative `modelsDir` resolves against the
  *target root*, not your cwd; pass an absolute path when planning from
  outside the target. The directory must contain at least one `*.json`
  threat-model document or planning fails loudly.
- **Prompt replace vs append** — the `TRIAGE_PROMPT` option **replaces**
  the built-in triage prompt wholesale, so campaign seasoning for it
  embeds the full baseline text first. Every other prompt option
  **composes** with the tool's built-in prompt, so workspace overrides
  and seasonings for those must stay focus-only fragments — pasting a
  full baseline there appends a second, conflicting instruction set.
  Also: passing a prompt option explicitly bypasses the
  `.kuzushi/prompts/<module>/<verb>.md` auto-load; campaign seasoning
  re-carries that fragment for you, manual `kuzushi run` calls do not.
- **Non-TTY output** — every deck has a plain renderer
  (`crates/kuzushi-tui/src/renderer/plain/`): piping or scripting the
  shell serializes the same view models as text (Steps before Output, no
  ANSI/box-drawing dependency). Frame-only visualizations print a
  "renders in a TTY" note instead of garbage. `kuzushi run` always emits
  machine JSON; don't look for `--json`/`--ci` flags on it.
- **Bulk imports are slow by design** — the event-sourced store persists
  ~29 decisions/second (append + hash chain + projection per record), so
  `workspace:import-findings` on a multi-thousand-row ledger takes
  minutes. See
  [assessments/perf-baseline.md](./assessments/perf-baseline.md) for
  measured numbers; interactive use is unaffected.
- **Dynamic (`file://`) modules** — run in the brokered KWP Node worker
  and require a Node runtime new enough for its permission model; on
  older Node the worker refuses to start (registry tests for
  `dynamic_js_*` fail the same way). Built-ins are pure Rust and
  unaffected.
- **Model selection** — kuzushi never silently falls back to another
  model/provider/runtime. "Model not available" means fix the
  configuration (`models.toml`, `setg MODEL_<ROLE>`, Setup deck), not
  that a default will be chosen for you.

## 8.1 Log & artifact sensitivity policy

What each durable artifact may contain, decided and enforced (2026-07
hardening audit):

- **`items.jsonl` (per run) — typed and redacted by design.** Model lifecycle
  items record provider, selected model, latency, bounded usage and cost when
  known — never raw
  prompts or completions. Scanned source reaches disk only through the
  findings store (evidence snippets/provenance blobs), which is the
  product's job, not a logging side effect.
- **`.kuzushi/` git exposure — proven excluded, not just written.**
  Workspace init writes `.kuzushi/.gitignore` and then *proves* the
  effective policy with `git check-ignore` probes: generated state
  (`v3/runs`, `v3/log`, `v3/objects`, the sqlite files, worktrees) must be
  ignored and trackable config (`scope.toml`, prompts, `v3/config.toml`)
  must stay visible, or initialization fails loudly. A `git add -A` in the
  scanned repo cannot commit triage transcripts.
- **Campaign logs (`campaigns/<id>/logs/*.log`) — full fidelity, inside the
  excluded state dir.** Child stdout/stderr (which includes finding text)
  is deliberately durable for post-mortems; its sensitivity boundary is the
  target's `.kuzushi/` state dir, same as the findings store itself.
- **Bridge diagnostics — redacted and opt-in.** Descriptor options
  `bridgeVerbose` and `bridgeLogPath` emit or append request-scoped metadata
  only: provider, selected reasoning level, lengths, tool counts, stop class,
  and cost/usage when known. They do not record prompts, completions, or raw
  response bodies. The adapter-only emergency hooks
  `KUZUSHI_BRIDGE_DEBUG_DUMP=<path>` and
  `KUZUSHI_BRIDGE_DEBUG_FULL_PROMPT=<directory>` use the same metadata-only
  projection; despite the latter's legacy name, it does not write prompt text.
- **Session transcripts (`~/.kuzushi/v3/sessions/`) — redacted semantic
  timeline** (operator-owned store; run events link to target-scoped run
  artifacts by `runId` instead of duplicating payloads).

## 9. Capability catalog

One line per module so every registered tool is findable from here.
Shell `help`/`modules`/`tools` (backed by `catalog:modules` and
`catalog:tools`) show the live list with options; `router:show` explains
how a verb resolves and `config:show` dumps effective configuration.
`module-recommender:recommend` suggests engines for the active target.

**Scan umbrella & pipeline** — `sast:scan` orchestrates scanners then
triage/verify; `agentic-sast:scan` is the model-backed deep pass — its
hunt prompt folds in a digest of the persisted threat model
(`.kuzushi/threat-model.json`) when one exists, and the agent can query
attached MCP toolsets (including `findings:query` over prior findings
and `threat_model:threats`) before reporting;
`full-mode:hunt` runs the full engagement pipeline; `deep-audit:run`
drives the long-form audit loop. Hidden DAG-internal nodes (registered,
not operator-facing): `pipeline:approval-before-verification`,
`pipeline:taint-cwe-select`, `pipeline:task-selector`, and
`classifier-gate:score` (finding-classifier gate stage).

**Deterministic scanners** — `semgrep:scan`, `codeql:scan` (+
`codeql:create-db`), `cargo-audit:scan`, `govulncheck:scan`,
`iac-scan:scan`, `license-scan:scan`, `sbom-scan:scan`,
`secret-scan:scan`, `dep-hygiene:check`, `wasm-plugin:analyze`.

**Hunting engines (model-backed)** — `carlini-threat-hunt:run`
(adversarial per-threat review), `systems-hunt:systems-hunt` and its
stages (`systems-hunt:systems-context-gatherer`,
`systems-hunt:systems-invariant-extract`,
`systems-hunt:systems-trigger-synth`,
`systems-hunt:deep-semantic-cwe-select`,
`systems-hunt:deep-semantic-hunt`), `taint-iris:hunt`, the
taint-iris-next family (`taint-iris-next:hunt`,
`taint-iris-next:catalog`, `taint-iris-next:codeql-db`,
`taint-iris-next:dataflow-plan`, `taint-iris-next:import-sinks`,
`taint-iris-next:source-sink-trace`,
`taint-iris-next:finding-review`), `uaf-hunt:hunt`,
`exploit-chain:scan`, `offense:chain`, `offense-review:threat-hunt`,
`chrome-rce:scan` + `chrome-rce:review-trigger`, `vuln-scout:audit`,
`tob:audit` + `tob:skills` (Trail-of-Bits-style audit skills), and
variant analysis via `variant:hunt` + `variant:lift-pattern` with CVE
diff mining in `ndiff:fetch-cve`, `ndiff:extract-fix-pattern`,
`ndiff:hunt-variants`.

**Threat modeling & intel** — `threat-model:build`, `threat-model:read`,
`threat-model:verify` (grounds the persisted document against the
target: every cited path must exist with a sane line number, the
documented `provenance.revision` is compared to HEAD — tri-state, a
non-git target is unknown rather than failed — and coverage is
re-measured against fresh grounding surfaces; when the context snapshot
the entry-point catalog derives from no longer describes the target,
coverage falls back to the current surface scan, `groundingSource`
becomes `noncatalog`, `groundingDegraded` records why, and the verdict
is at best `stale` instead of an error; the `verified`/`stale`/`failed`
verdict is stamped onto the document, and
`write=false` reports without saving), `threat-model:import` (the
explicit front door for externally-authored documents: `path` or an
inline `document` is normalized, verified, stamped with `import`
provenance, and persisted — a user-edited live model is never
overwritten without `force=true` — then recorded in the versions
ledger with source `import`; the agentic-sast digest and carlini hunts
prepend a staleness warning when the live document's revision no
longer matches HEAD, and `threats use <n>` re-verifies after every
restore), `threat-model:methodologies`; the immutable-lineage verbs
`threat-model:models` (list lineages and their head revisions),
`threat-model:revisions` (list one lineage's immutable revisions),
`threat-model:diff` (compare two revisions, or lineage heads, by
`from`/`to`: threats added/removed/changed keyed by `stableId`, with
unmatched threats paired by a unique display `id` and counted as re-keyed, DFD
node/flow/boundary deltas, entry-point coverage, and methodology),
`threat-model:activate` (point the active head at an existing revision
without minting content), `threat-model:restore` (re-commit historical
content as a new revision and activate it), and `threat-model:adopt`
(commit a hand-edited compatibility mirror as a new revision); PASTA-style `randori:pasta` +
`randori:threat-model`; `threat-intel:discover` (target-local package inventory
only), `threat-intel:research` (explicit external action: bounded OSV package
queries followed directly by catalog harvest, with no hand-authored CVE JSON),
`threat-intel:harvest`, `threat-intel:apply`, `threat-intel:list`; lead generation
`threat-leads:build` + `threat-leads:read`; system X-ray `x-ray:run`,
`x-ray:read` (and the `x-ray:x-ray` alias verb); attack-surface
extraction `entry-points:extract`.

In a ready Map, use Tab with an empty composer to reach Entry points.
Arrows select an entry; Page Up/Page Down move through its evidence by the
visible detail height. In Navigate mode, `z` opens the same view full frame
and Enter follows a resolved DFD link. Counts, freshness and warning presence
stay above the browser; the complete source receipt and warnings are also
readable at the end of the selected entry's detail. Selecting another entry
starts its detail at the top.

**Findings lifecycle** — `triage:run` (prefilter → structured dedupe —
same tool+rule within 15 lines inherits the representative verdict with
a duplicate-of rationale; attack-chain findings are exempt and never
cluster — → per-cluster LLM verdicts, weighing the persisted
threat-model digest when one exists; `scope=all` triages every
untriaged finding across all runs and tools in one pass and defaults
the strategy to the code-reading deep auditor), `triage:chain-hunt`
(model-backed attack-chain composition over confirmed findings — two or
more findings where one enables or escalates another, validated against
real fingerprints and persisted as open `chains/model` findings for the
next triage pass), `triage:dedupe` (model-driven corpus dedupe across
all runs and tools: a judge model proposes duplicate groups over the
fingerprint-keyed ledger, code validates every membership, groups below
0.8 confidence escalate to one bounded code-reading confirmation pass,
and confirmed duplicates rekey onto their canonical finding with a
`false_positive`/`duplicate` verdict and `[duplicate_of=…]` rationale;
`dryRun=true` reports groups without writing, and `triage:run
dedupe=true` runs the same pass before bulk triage so settled
duplicates never burn triage spend), `verify:finding`,
`verify:exploit`, `patch:finding` (then `patch:reverify`),
`trace:expand` (bounded read-only agent that deepens a finding's
data-flow path and appends the recovered hops to the static-evidence
store as operator-requested `DataflowStep` nodes; drafted from the
Trace screen), `findings:list`, `findings:dismiss`, `findings:chains`
(deterministic entry→pivot→impact chain candidates over confirmed
findings, per code surface — no model calls; `C` on the Review page
opens the chain-artifacts view that renders the same fold),
`findings:ground` (runtime-free re-grounding of every open finding's
citation against the target tree: reports grounded / line-drift /
file-missing counts at the current revision and appends one audit
event per newly stale anchor — descriptive only, a missing file flags
the finding for honest triage and never retires it; imported findings
are grounded automatically at ingest, grounded rows gaining a real
disk citation and stale rows a `grounding:` message annotation plus a
prompt note in deep triage),
`suppress:add`, `suppress:list`, `suppress:remove`, `report:build`,
`report:sarif`.

**Workspace & context** — `workspace:status`,
`workspace:import-findings`, `workspace:export-findings`,
`context:build`, `context-lite:index`, `cpg:build` (in-process cpg-rs graphs),
`engagement:aim` (engagement scoping). `worklist:rank` is a deterministic,
read-only Map tool that ranks files from the persisted attack surface and
scan-coverage recommendations; `deep=true` additionally runs the Read-safe
systems-hunt scorer. Every row retains each contributor's raw evidence, and
the shell `worklist` command opens the same result in the visualization
gallery.

**Fuzzing (agentic-fuzz-engine)** — drives an external
agentic-fuzz-engine checkout (`afeRepo` option) against C/C++ targets;
when `afeRepo` is omitted the pinned engine revision is auto-cloned
once into `~/.cache/agentic-fuzz/engine-<rev8>` and reused (override
the pin with `afeRev`/`afeGitUrl`; pass `afeGitSshKey` when the
ambient ssh config cannot read the engine remote; a failed provision
skips the tool with guidance instead of failing the run). The
engine workspace lives outside the repo (default
`~/.cache/agentic-fuzz/kuzushi/<target>-<hash>`, override with
`workspaceRoot`) and the scanned tree stays read-only. `fuzz:run`
bootstraps idempotently (workspace init → sink scan → deterministic
generation from a `generatorSpec` → builds), runs bounded campaign
rounds (`rounds`/`fuzzSeconds`, engine-side disk/RSS guards), then
imports verified crashes as `vuln_source=fuzzing` findings with
impact-derived severity (write/exec primitive → high, everything else
capped medium). `fuzz:author` (Map phase, model-backed, `budgetUsd`)
runs a Rust-driven tool loop that authors harnesses for the engine's
parked workorders — writes are contained to the target's
harness/build-spec files, builds and smoke runs are the deterministic
verdict, and per-step model spend lands in the run trace. `fuzz:import`
folds an existing engine ledger into the findings store without running
the engine; `fuzz:prove` runs the engine's per-finding impact pass over
verified findings that lack an impact verdict and refreshes the import;
`fuzz:sweep` builds a sanitizer-variant fuzzer (`sanitizer` = `msan`
uninitialized-read oracle or `tsan` race oracle) and replays its corpus
in keep-going mode with benign-input baseline subtraction, reporting
input-dependent signature groups ranked write-first — omit `afeTarget`
to sweep every built target in turn (the engine rebuilds prebuilt dep
archives under the variant sanitizer from a target's
`.localfuzz/sanitizer-deps.json` recipe when one is declared);
`fuzz:differential` replays the corpus through N replay `commands`
(fork vs upstream, or one command as a metamorphic self-check) and
ranks divergences crash-split first — the silent-wrong-data oracle the
crash lane never fires on; omit `commands` for auto mode, where the
engine resolves and builds implementations from the target's
`.localfuzz/differential.json` recipe or its `bin/<t>/replay*`
binaries and honestly skips targets with fewer than two (omit
`afeTarget` too to replay every built target). Both sweep and
differential surface in the planner's Scan phase as opt-in tasks that
dispatch with no options;
`fuzz:status` is a read-only workspace probe. Campaign plan
rows dispatch both job tools with shard names mapped to engine targets
(`shard` → `afeTarget`); pass `seasonPrompts=false` when planning fuzz
campaigns — seasoned rows fail preparation by design.

**Coverage ledger** — `coverage:baselines` (latest receipt-backed scan
baseline per scope and phase) and `coverage:sweep` (deterministic
staleness verdicts — `changed`/`current`/`baseline-unreachable` — from a
whole-repo diff against each recorded baseline; `writeSkips=true`
advances unchanged baselines to HEAD as `sweep-skip` rows and refuses on
a dirty tree). `coverage:recommend` folds coverage gaps, staleness,
sink-gap density, and saturation into ranked scope-level scan
recommendations with mechanical evidence; the shell's Map page shows
the top rows as NEXT SCANS inside the HOT MODULES pane (hydrated in
the background, identical in plain output).

**Fleet (multi-target)** — operator-global tools over
`~/.kuzushi/v3/fleet/`: `fleet:register` (targets.toml registry,
idempotent by id), `fleet:ingest` (rebuilds the derived corpus.sqlite3
from every registered target's findings store — per-target stores stay
the truth; contract violations become counted quality flags, never
dropped rows), `fleet:status` (per-target scorecard: baselines,
last-scanned revision, open critical/high, drift count), and
`fleet:findings` (cross-target corpus queries by class/severity), and
`fleet:diff-findings` (join one target's corpus across two revisions by
dedup cluster; each cluster is labeled `branch-delta`, `backport-gap`,
or `both`). The separate `kuzushi-fleet` binary is the remote transport
plane (doctor/stage/launch/status/pull over ssh+tmux with staging
guards and a recency-cutoff pull into the fleet inbox). Baselines are written automatically when a completed run
with git provenance reaches its terminal receipt; no run, no coverage
claim.

**Recon & bounty intake** — `recon:nmap`, `recon:subdomain`,
`recon:http-fingerprint`, `recon:import` (amass/httpx/nuclei/nmap-xml),
`bounty:import-har`, `bounty:import-burp` — all scope-gated by
`.kuzushi/scope.toml`.

**Android APK surface** — `android-apk:scan` umbrella over
`android-apk:prepare`, `android-apk:manifest-scan`,
`android-apk:code-scan`, `android-apk:fileprovider-scan`,
`android-apk:network-security-config`, `android-apk:native-libs`,
`android-apk:hybrid-detect`, `android-apk:sast-handoff`,
`android-apk:check-env`.

**Binary exploitation (pwn, CTF/authorized-lab use)** —
`pwn:profile-binary`, `pwn:menu-probe`, `pwn:heap-uaf-scan`,
`pwn:reverse`, `pwn:run-candidates`, `pwn:auto-solve`,
`pwn:exploit-run`, `pwn:calibrate-local`, `pwn:state`.

**Prompt-injection armor** — `prompt-armor:scan`,
`prompt-armor:analyze`, `prompt-armor:attack`, `prompt-armor:diff`,
`prompt-armor:report`, `prompt-armor:config`.

**Compliance (shinsa)** — `shinsa:scan`, `shinsa:quick-check`,
`shinsa:nist-scan`, `shinsa:nist-quick-check`, `shinsa:frameworks`.

**Vendor assessment** — `vendor-assessment:assess`,
`vendor-assessment:scope`, `vendor-assessment:attach`,
`vendor-assessment:prompts`.

**Campaign & packs** — `campaign:plan`, `campaign:status`,
`campaign:coverage`, `pack:lint`, `pack:suggest-shards` (§4, §7).
