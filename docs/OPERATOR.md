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
| **shell** | `kuzushi --target <path>` | Interactive cockpit: Setup → Map/Scan/Review/Prove/Fix → Report | n/a (interactive) |
| **run** | `kuzushi run <tool> [json]` | Headless single-tool execution, JSON on stdout | 0 completed/skipped · 2 prepare failed · 3 tool failed (`ok:false`) · 4 partial |
| **scan** | `kuzushi scan <target>` | Scan orchestration (the `sast:scan` umbrella) | `--fail-on` gate failures exit 3 |
| **ci** | `kuzushi ci <target>` | Deterministic regression gate over the findings ledger — no model calls | 0 clean · 1 gate tripped · 2 error |

All four converge on the same registry boundary
(`prepare_tool_input` → `dispatch_prepared_tool_with_runtime`), so a tool
behaves identically regardless of the mode that launched it; only
workspace/runtime context preparation differs.

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

The exit surface. Exports the findings ledger in five formats (SARIF,
Markdown bundle, JSONL, JSON, CSV — presented in that order) via
`workspace:export-findings`, defaulting completeness to All. For a
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

- **`trace.jsonl` (per run) — redacted by design.** LLM calls record model,
  provider, latency, cost, `prompt_len`, and a `prompt_hash` — never raw
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
- **`~/.kuzushi/bridge-debug.log` — redacted, opt-in verbose.** The
  claude-cli bridge never embeds model output (which carries scanned
  source) in errors or this log; stdout bodies are summarized as byte
  counts and stderr diagnostics are capped. Set `KUZUSHI_BRIDGE_LOG_RAW=1`
  to opt into raw bodies while debugging.
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
`threat-model:methodologies`; PASTA-style `randori:pasta` +
`randori:threat-model`; `threat-intel:discover`, `threat-intel:harvest`,
`threat-intel:apply`, `threat-intel:list`; lead generation
`threat-leads:build` + `threat-leads:read`; system X-ray `x-ray:run`,
`x-ray:read` (and the `x-ray:x-ray` alias verb); attack-surface
extraction `entry-points:extract`.

**Findings lifecycle** — `triage:run` (prefilter → structured dedupe —
same tool+rule within 15 lines inherits the representative verdict with
a duplicate-of rationale — → per-cluster LLM verdicts, weighing the
persisted threat-model digest when one exists), `verify:finding`,
`verify:exploit`, `patch:finding` (then `patch:reverify`),
`findings:list`, `findings:dismiss`, `findings:chains` (deterministic
entry→pivot→impact chain candidates over confirmed findings, per code
surface — no model calls; `C` on the Review page drafts it),
`suppress:add`, `suppress:list`, `suppress:remove`, `report:build`,
`report:sarif`.

**Workspace & context** — `workspace:status`,
`workspace:import-findings`, `workspace:export-findings`,
`context:build`, `context-lite:index`, `cpg:build` (Joern CPG),
`engagement:aim` (engagement scoping).

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
