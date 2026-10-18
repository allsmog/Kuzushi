# Operator Control Surfaces

Kuzushi tool behavior is driven by canonical tool options. CLI flags, shell
commands, persisted option stores, and direct `run` input all converge on
`ModuleRegistry::prepare_dispatch_input`. Its `prepare_tool_input` stage owns
descriptor option merging and validation before workspace, prompt, execution,
and authorization bindings are added. Authorized prepared values then execute
through `dispatch_prepared_input_with_runtime` or its observed variant.

## Canonical Boundary

Every operator-facing tool setting belongs in the tool descriptor as an
`OptionSpec`. Add aliases only for compatibility with older names or CLI
spellings. The preparation boundary:

- merges stored option values for the selected tool;
- overlays explicit JSON input;
- canonicalizes aliases to descriptor names;
- coerces typed values (`bool`, `number`, `stringList`, `json`, etc.);
- rejects unknown option keys instead of silently carrying them through.

Precedence is:

1. global option store;
2. workspace option store;
3. session option store;
4. explicit tool input.

Explicit input therefore wins over `--option`, shell `set`, and persisted
options.

### Prompt provenance

Prompt options have an authority split at this same boundary:

- explicit inline text from direct tool input, a shell session option, or the
  operator-owned global option store is operator-controlled and may replace a
  tool's editable instruction template;
- a prompt path inside the target and an automatically discovered
  `<target>/.kuzushi/prompts/<module>/<verb>.md` file are target-controlled,
  so their text is wrapped as untrusted optional focus/context below the
  descriptor's immutable built-in safety and output-contract instructions;
- `<target>/.kuzushi/v3/options.json` may not set descriptor prompt keys, even
  when explicit input would otherwise override them.

Every raw inline prompt value and target prompt file has a 65,536-byte UTF-8
ceiling. The canonical preparation boundary rejects larger values with the
option name and limit before runtime dispatch; it never truncates them or
reinterprets an oversized inline value as a path. Immutable built-in policy and
the encoded untrusted-data envelope are added after this raw-content check.

Passing a repository path does not convert its contents into operator
authority. Use inline one-shot input, shell `set`, or home-scoped `setg` when a
full prompt replacement is intentional. This rule applies identically to
scan, shell, and run because all three use canonical registry preparation.

### Deep-auditor dataflow tools (`taintTools`)

`triage:run` and `deep-audit:run` expose a non-advanced `taintTools` enum
(alias `taint_tools`, default `available`) that governs the in-process
CPG-taint dataflow tool offered to the deep auditor:

- `off` — never touches the code property graph on disk; the auditor stays
  grep-only.
- `available` — offers `cpg_taint_paths` backed by an existing
  `<target>/.kuzushi/cpg-rs/` graph. No graph on disk degrades to grep-only
  (surfaced on the Health page and a run notice); it never builds implicitly.
- `build` — builds the graph first, then offers the tool.

The auditor's `cpg_taint_paths` tool and its method-step prompt are advertised
from a single readiness predicate, so a registered tool and the system prompt
can never disagree, and tool *availability* alone never moves a proof rung or
confidence chip. Because `triage:run` forwards its whole prepared input into the
`deep-audit` path, setting `taintTools` once flows to every deep audit in the
run. This is a Review-phase knob, not a Setup row.

### Risk worklist (`worklist:rank`)

`worklist:rank` ranks the target's files by aggregated risk contributors
(attack-surface, findings, and — when a `<target>/.kuzushi/cpg-rs/` graph
exists — CPG flow reach). It reads the durable `context-snapshot.json`; with no
snapshot the worklist is empty and names the two commands that create it
(`context:build`, then `worklist:rank`). It is deterministic and takes no model
knobs; `limit` (default 5 in the Map section, all on the scene page) caps the
returned rows. Each row carries a raw citation (`A92`, `F17`) and its normalized
pair, contributor states (`Live` / `Unavailable{reason}` / `Degraded{reason}` /
`NotRequested`), and an `unranked` count for files with zero signal — the same
truth the shell `worklist` verb, the Map `WORKLIST` section, and the scene
Worklist page render. Missing signals degrade visibly (`⚠ degraded — no cpg
graph`); ranks stay contiguous and are never zero-filled to hide a dropped
contributor.

Within each stored scope there is also a target axis. Values are merged in
specificity order: `all` first, then `module:<id>`, then `tool:<module:verb>`.
That means a tool-specific value beats a module value, and a module value beats
an all-tools value within the same scope. Shell `set <key> <value>` writes a
session value for the focused tool; `setg <key> <value>` writes a global
all-tools value, so use it only for names that should apply to every tool that
declares the same option.

## CLI

`kuzushi run` accepts repeatable session-scoped overrides:

```bash
kuzushi --target . run semgrep:scan \
  --option config=p/default \
  --input '{}'
```

`--option key=value` is parsed as a raw string, then coerced by the target
tool's descriptor. Use `--input` for structured values that are easier to read
as JSON. If both are present for the same canonical option, `--input` wins.

`target` is descriptor-typed, not globally synonymous with a repository path.
For a `path` option (for example a scanner target), inline JSON or a session
`--option` may establish the workspace when `--target` is absent; when a
workspace is already explicit, the resolved path must remain inside it.
Persisted `target`/`cwd` values are checked at the shared dispatch boundary and
cannot steer execution outside the workspace that owns the finding store and
run artifacts. For a `string` option (for example `recon:nmap` or
`offense:chain`), `target` remains a host/URL and a separate `--target <repo>`
is still required for workspace-backed state.

`kuzushi scan` is a shorthand for `sast:scan`. Flags such as `--mode`,
`--tasks`, `--triage`, `--budget`, `--since`, `--include-worktree`,
`--fail-on`, and `--sarif` compile into sparse `sast:scan` JSON input or
scan-gate policy, then go through the same preparation path as
`kuzushi run sast:scan` where they are tool input.

`kuzushi scan --trials N --workers W` compiles that canonical prepared input
into a dedicated `scan-batch` campaign. Trials are logical samples; dispatcher
retries remain attempts within a trial and never increase occurrence. The plan
freezes its equivalence key, exact threat-model revision, requested/effective
worker count, resource-safety decision, and gate policy before the first child
launches. Unknown or workspace-exclusive resource claims clamp the batch to
one worker with a named reason. The controller emits one identity-folded SARIF
and one final gate receipt after folding the available trial outcomes. A
dispatcher failure remains an operational error even when the security gate
would also fail. Inspect a batch with `kuzushi findings batch <batch-id>
[--json]`; run the read-only migration audit with `kuzushi findings
identity-audit [--json]`.

The identity audit's JSON envelope is content-bound by `reportSha256` and
`corpusWatermark`. To authorize basis-aware defaults, author a request matching
`schemas/finding-identity-audit-approval-request.schema.json` and run:

```sh
kuzushi --target /repo findings identity-audit approve --from approval.json
```

Every suspicious `identityId` needs an `accepted` or `fixed` disposition and a
nonempty rationale. The receipt is written atomically to the operator-owned
`$HOME/.kuzushi/v3/identity-audit-approvals/` store and is valid only for the
canonical target and exact current audit/corpus digests. Target-local receipts
are ignored. Missing, stale, mismatched, malformed, or incomplete approval
keeps omitted `identityFold` at `legacy` and omitted `identityReconcile` at
`off`; valid approval promotes those omitted defaults to `safe` and `auto`.
Supplying either descriptor option explicitly is the documented operator
override. `modelDedupe` remains `off` by default.

The same resolved `identityFold` reaches the exports an interactive session
writes: the Report route and `workspace export findings` bind the policy their
own ledger resolved, so an export presents the finding set the Review ledger
does rather than a reader-local count. `kuzushi findings export` and
`workspace:export-findings` hold no resolved policy and still read under the
conservative run-scope fold; binding one there means resolving it with no
ledger in hand, which the identity-audit evidence reader refuses before a
findings store exists.

#### Changed-file scope (`--since`, `--paths`, `--shard`)

`kuzushi scan --since <ref>` and the shell's `scan since <ref>` resolve the
same scope through one shared helper,
`kuzushi_core::workspace::changed_scan_input`. It lists the files the
reference changed, drops the ones it deleted, and both modes then scope the
identical set. `--include-worktree` adds uncommitted edits.

The resolved scope compiles into the canonical `sast:scan` options `paths` and
`diffBase`, so engines are narrowed through the shared input, not only the
ones that read `.kuzushi/v3/since.txt`. That scope file is still written, from
the same effective list, for `full-mode:hunt`.

Changed files are file scopes. Engines that read exact files (secret scanning
and Semgrep) scan only those files. Engines that only scan directories refuse
the scan and name themselves, rather than scanning each file's parent
directory; choose `--tasks` that read exact files, or pass a directory scope
and review the larger scope.

Precedence when `--since` meets `--paths` or `--shard`:

1. `--paths`/`--shard` resolve first into the `paths` input, as today.
2. `--since` resolves the changed files, then narrows to the **intersection**
   of the two (target-relative, normalized; a root covers whole path
   components, so `src` covers `src/*` but not `srclib/*`). The scope
   line discloses it as `scope: N files since <ref> ∩ M requested → K`.
3. `--since` never widens. A requested root that cannot name a target-relative
   diff path narrows to nothing rather than falling back to every change.
4. An empty scope — nothing changed, or an empty intersection — **refuses the
   scan** with `--since <ref>: no existing changed files …` on stderr and
   exit 1, writing no run artifact. It does not fall back to scanning the
   whole target.
5. A `diffBase` already present in raw `sast:scan` JSON input must equal the
   `--since` reference; a mismatch is an explicit error, not a silent winner.

Global `--load <specifier>` is supported for shell and headless `run`.
For local file/path modules, trust is digest-pinned in `kuzushi.lock`: approve
the exact resolved bundle with `kuzushi kwp approve <specifier>` before
loading it. The host hashes the canonical bundle and checks its approval
before importing module bytes. `[operator].trusted_modules` remains only for
explicitly trusted `package:<npm-name>` compatibility specifiers and is not the
local-worker trust boundary; file-URL aliases and local-resolving package
payloads are rejected.
A headless dynamic invocation must still pass an explicit global
`--target <workspace>` so an inline `target`/`cwd` value cannot bootstrap
workspace policy or artifact placement from process cwd.

`kuzushi scan` rejects `--load` with guidance to use `kuzushi run`; it does not
silently discard the specifier or reinterpret a dynamic tool as a scan task.
All other non-shell/non-run commands reject it for the same reason.

`kuzushi run --autonomy <recon|scan|review|prove|fix>` sets the autonomy ceiling
for that run. The shared dispatch gate refuses any tool whose engagement phase
sits above the rung (`recon`→map, `scan`→scan, `review`→review,
`prove`→prove, `fix`→fix)
with an actionable error — it never silently runs or substitutes it. Omitted =
`fix` (unconstrained, matching prior behavior). The requested rung is clamped
by `[phases].stop_after`; an unrecognized or numeric rung is a hard error.
`hunt` and `confirm` remain deprecated input aliases for `scan` and `prove`
for one major release.

### Session persistence

Interactive, plain, and scripted shell launches write a redacted semantic
transcript under `~/.kuzushi/v3/sessions/`. The transcript records target
provenance, submitted commands, major view changes, run identifiers, questions,
visible agent turns, and terminal outcomes; it does not record keystrokes,
environment values, credentials, or streaming deltas. Detailed tool payloads
remain in target-scoped run artifacts.

`kuzushi sessions list|show|export|prune` operates on this global store. The
global `--target` filters `sessions list`; it does not relocate the store.
`--no-session-persistence` (alias `--ephemeral`) opts out for one shell launch
and is rejected for other commands. The home-scoped setting
`operator.session_retention_days` defaults to 30 and cannot be supplied by a
target project. See [Durable shell session transcripts](architecture/session-transcripts.md).

## Shell

The Rust shell uses the same descriptors:

- `show options [tool]` lists accepted names, aliases, types, and values.
  The interactive browser selects one setting with arrows or `j/k`; wide
  terminals show list and detail together. `PgUp/PgDn` pages the selected
  detail, and `s/a/m` switches Standard, Advanced and Missing views.
  Enter opens an editable setting. Enter or Ctrl+S saves for this session;
  Ctrl+G explicitly saves globally. Role model options retain their existing
  global scope, which the editor names before saving. Escape keeps the field
  draft and cursor for reopening. Shift+Enter inserts a newline; multiline
  paste stays in the field. Validation preserves invalid drafts and stored
  values. Page keys reveal long validation errors. Exit discloses unsaved
  option drafts without echoing their contents. Drafts are process-local.
  Workflow-supplied structured references remain visible and read-only in
  this browser; their approved plan or context picker owns edits. Stored
  defaults never mutate the frozen inputs of an already approved run.
  A global save keeps any higher-priority session or workspace override and
  discloses that effective scope. Failed persistence is reported as a value
  changed in memory, with a retry action, rather than a saved setting.
- `set <key> <value>` writes a session option for the focused tool.
- `unset <key>` clears a session option.

Cargo audit supports `binary`, `advisoryDb`, `offline`, `allowStale`,
`timeoutMs` and `maxLockfileBytes`. Its SAST equivalents are
`cargoAuditBinary`, `cargoAuditAdvisoryDb`, `cargoAuditOffline`,
`cargoAuditAllowStale`, `cargoAuditTimeoutMs` and `cargoAuditMaxLockfileBytes`.
They require the Cargo audit task and use shared descriptor validation.
Default network mode permits database updates and yanked-package checks;
select offline explicitly to disable both. Stale-data consent is separate.
Approval shows the frozen settings. The default job time allowance is 600000
ms across lockfile captures and roots; the maximum is 86400000 ms. Each capture
defaults to 16 MiB with a 64 MiB maximum. Source authentication is separate.
The selected directory must contain a regular Cargo.lock. Source reachability
and nested lockfiles are not inspected, and an exact-file scope is refused.
Captured lockfile hashes appear in the run receipt. The source SHA does not
establish advisory database freshness or actual dependency deployment.
- `setg <key> <value>` writes a global option.
- `unsetg <key>` clears a global option.
- `scan` prepares `sast:scan` input from the option store before dispatch.
- `autonomy [recon|scan|review|prove|fix]` (alias `posture`) reads or sets the
  always-visible autonomy dial; `Ctrl+↑`/`Ctrl+↓` raise/lower it one rung. The
  requested rung is stored globally as `ui.autonomy`, then clamped by the
  active target's `[phases].stop_after`. The applied rung never changes
  workflow reality and headless `run` keeps its explicit `--autonomy` policy.

The interactive route is
`Target → Setup → Map ↔ Run Focus → Scan ↔ Run Focus → Review → Prove ↔ Run
Focus → Fix ↔ Run Focus → Report`:

Run Focus task rows, status, cost, artifacts/findings, questions, terminal
outcome, and `NEXT` action are source-backed projections of committed typed run
items. A replayed run and a live run use the same reducer. Legacy runs disclose
lossy reconstruction instead of presenting inferred catalog tasks as runtime
truth.

- `setup` opens the aggregate readiness surface. Its Model, Credentials,
  Prompt, and Budget blockers are derived from the selected Map plan. A
  deterministic runtime-free plan needs no model; any model-backed task must
  name an explicitly selected compatible model with its actual API-key, OAuth,
  or session credential. An unset budget is `not enforced`; a set budget must
  be positive and remain within the configured hard ceiling.
  Cost labels this as an `observed stop` and the maximum permitted value as
  `max stop setting`. A request can overspend before its receipt arrives;
  approved provider-call limits remain enforced separately.
- The Map setup row owns methodology, whole-repository versus bound leaf
  scopes, bounded all-scope expansion, design-document paths, and operator
  context. These are descriptor options, so headless and shell dispatch
  prepare the same input. Scoped work keeps the workspace root (artifacts and
  model store) separate from the canonical descendant analysis root (source
  evidence).
- `threats models` lists immutable lineages; `threats activate
  <model-id>[@<revision-id>]` changes only the active pointer; `threats
  revisions <model-id>` lists content history; `threats diff <from> <to>`
  runs `threat-model:diff` over two revision ids (`tmr_…`) or lineage heads
  (`tm_…`), while bare `threats diff` still inspects mirror edits; and
  `threats restore <revision-id>` creates a revision from historical
  content. A divergent
  hand-edited compatibility mirror blocks activation until the operator
  explicitly adopts or discards it.
- `scan batch [--prior-run <run-id>]` (or `b` on Scan in Navigate mode)
  opens the finite study form. Prepare a draft, inspect its frozen source and
  context, enter total calls and protected review calls explicitly, then review
  and approve the allowance. Approval starts no jobs. Open approved jobs and
  press `L` separately to start the detached controller. The form defaults to
  three discovery passes, one worker and one attempt per job; cost estimates
  require an exact named prior scan receipt and are never dollar guarantees.
  `a` in the campaign deck reopens the saved plan and durable allowance after
  restart. Editing work creates a new draft under the same investigation;
  consumed calls and unresolved reservations remain. `batch <batch-id>` opens
  its occurrence report and scopes Review; `batch clear` removes that filter.
  A fresh scan form inherits the accepted Map's recorded investigation, its
  current consumption and protected review. This also works after restart;
  the newly drafted scan work requires separate approval. Budget row details
  show consumption and remaining calls with paging at narrow widths. Missing
  recorded accounting or changed source blocks implicit continuation rather
  than offering a fresh budget. Older Map results without an accounting
  reference remain readable; prior spending is not inferred.
  A call-bound study with no dollar ceiling can execute despite unavailable
  dollar pricing. All jobs and requests still require finite approval and
  durable reservations. Unknown prices do not appear as zero charges or as a
  false halted state. Dollar-capped campaigns retain their evidence requirement.
- `scopes` pins the default job count for all included discovery boundaries.
  Selected-boundary details compare that total with the focused or marked set
  for the next study. Splits, exclusions and shared-discovery edits recompute
  the preview. These counts do not approve work or estimate provider requests
  or dollar cost; the study reviews engines, exact context and allowance.
- `coverage:sweep` and `coverage:baselines` use normal tool cancellation for
  historical source inspection. A stopped sweep interrupts Git/SQL work and
  rolls back uncommitted skip rows. An explicit retry is separate work. Even a
  completed skip does not establish complete coverage or a fixed finding.
- Automatic scan advice, `worklist:rank` and `coverage:recommend` read saved
  evidence without comparing Git history. Current source is not checked.
  `coverage:recommend` accepts explicit `compareSource=true`. Comparisons and
  `coverage:sweep` default to `maxSourceComparisons=32` and `maxDiffBytes=8388608`,
  including skip revalidation in the same operation. A limit stops before new
  baseline writes and requires an explicit new action to change the allowance.
  These limits count diff requests and stdout bytes, not dollars or total RAM.
- In the study form, Enter on Source and context opens the immutable revision
  browser. Arrows choose a revision; Enter reads its exact document; Tab switches
  between summary and complete document; Page Up/Down scroll the detail. `a`
  uses the inspected revision, or explicitly omits threat-model context. Escape
  returns with the study draft unchanged. Selection never changes the active
  workspace threat model; changed context requires a newly prepared and approved
  study plan while preserving investigation accounting.
- After inspecting a revision, `v` opens that revision's data-flow diagram.
  Arrows select components, flows and trust boundaries; Enter toggles full
  details with linked context and recorded source evidence. Page Up/Down and
  Home/End read those details. Escape returns to the same context preview;
  reopening retains the selected element and reading position. This reader
  never switches the active Map, selects context for scans, or starts generation.
  Grounding status remains visible, and small terminals provide a detail-only
  projection when the graph cannot fit. Plain output includes all elements and
  the exact context identity, rather than only the selected element.
- `g` in that context browser opens generation planning. `t` edits total calls,
  `r` edits the protected review allocation, and Enter prepares one source-only
  context job. Review the frozen source and selected model; Tab shows formatted
  exact options. Enter opens the existing allowance approval, then opens the
  approved job. `L` in the campaign deck starts it. No generation starts from
  preparation or approval. After completion, `a` reopens review and Enter
  inspects the exact revision recorded by that run. Selecting it for scans is
  separate from generation and does not change the active workspace model.
  `n` opens a new generation draft; approving it retains investigation spending.
  The initial action is repository-wide with one worker and one attempt.
- `ask <question>` and `threats ask <question>` answer in the existing inline
  transcript. Threat questions attach the smallest current scene slice;
  `--whole-model` is explicit. Target/model text and assistant history are
  byte-bounded and fenced as untrusted content. History is reused only while
  target, worktree identity, exact model reference, and policy version match.
  An Ask may run beside one scan only after the bridge acknowledges its narrow
  read-only policy, effective tools, and read roots; no acknowledgement means
  no concurrent start.
- `workbench` opens the Map/Scan/Review investigation journey. `Shift+Tab`
  cycles these pages and Report while preserving the shared draft and cursor;
  Navigate-mode `1..3` selects the phase directly. Historical Prove/Fix artifacts
  and exact compatibility dispatch remain outside this guided journey. The selected interaction mode and durable reality
  are disclosed separately, and page navigation never changes workspace
  reality, autonomy, model, permissions, or evidence.
- Remaining prose on a Workbench page is compiled as intent for that selected
  phase, after known commands and explicit `run <tool>` parsing. Descriptors,
  option preparation, autonomy, authorization, and no-silent-fallback policy
  still own dispatch. A future-phase submission explains its missing durable
  prerequisite instead of rerouting work.
- `findings` and `open <id>` open Review, `next` (`continue`) invokes the
  current phase planner, and `report` opens the dedicated export exit.
- A phase verb (`map`, `scan`, `review`, `prove`, `fix`) opens that phase's
  Workbench page once the phase is complete or passed, whose hint row then
  offers `plan <phase>`; a phase not yet reached opens its planner.
  `plan <phase>` always opens the planner.
- `activity` opens Run Focus. Foreground Run Focus owns input in Navigate mode
  and identifies its origin, for example `RUN FOCUS · SCAN`;
  `s` accepts only a valid `run <tool> …` steer command and `b` backgrounds
  without cancelling, restoring the exact captured workflow origin. The final
  chain → plan → steer outcome restores that origin with one receipt. Manual
  inspection and background work never auto-return.
- Help, Controls, and Capabilities are contextual modals. Jobs, Replay, Trace,
  and visualizations are contextual full-frame decks. Replacing one contextual
  surface retains the original workflow origin; Esc restores that exact route
  and input mode.
- Report orders SARIF, Markdown bundle, JSONL, JSON, CSV, and external scanner findings;
  defaults completeness to All; cycles All/Open/Complete; and permits editing
  target-relative output paths. Its defaults are `report.sarif`, `report/`,
  `findings.jsonl`, `findings.json`, `findings.csv`, and `VULN-FINDINGS.json`. Export success or
  failure remains on Report with format, count, completeness, absolute
  path/error, and timestamp.
  The destination header keeps the export outcome visible while reading.
  `e` edits the path; compact footers show `e path` beside `Enter export`.
  Markdown bundles build their files, investigation receipt and manifest in a
  private sibling directory before publishing the completed directory. Failed
  builds leave the destination retryable. Existing files, symbolic links and
  nonempty directories are preserved; choose another destination for a new bundle.
  Revealing a destination requires explicit `o` and is an argument-safe
  platform action, never an automatic side effect.
  A selected study is recovered from authenticated Scan references, including
  after restart without visiting Campaign. `s` switches between that study and
  workspace history; `p` shows full provenance and export receipt details.
  Scope changes preserve format, destination, composer and return origin.
  Loading or damaged study receipts block export until ready or until the
  operator explicitly chooses workspace history. No silent scope substitution
  occurs. Report shows fixed work, retained observations, source/context,
  unknown costs and the shared investigation's call allowance before long paths.
  Its sidebar omits process-local session cost to avoid conflicting totals.
  Page/Home/End navigation reaches the complete wrapped document at all supported
  widths. Study exports write the same local investigation receipt through the
  shared exporter as `workspace:export-findings campaignId=<id>` and
  `kuzushi export --campaign-id <id>`. Export starts no model or follow-up work.
  Interactive exports run one at a time. Read Report or return to the workflow
  composer while writing continues. The submitted selection shows `EXPORTING`; another export request
  is refused without queuing. Completion preserves page, draft, cursor and scroll.
  Cache updates retain the submitted selection's receipt; changed targets, scope,
  format or destination do not inherit it. Exit waits for the export result.
  The shared exporter reads a consistent findings snapshot and checks for ledger
  commits during preparation. Changed records require an explicit refresh and
  retry before publication. CLI and scripted exports return synchronously.
- Root-shell agent runs may display a reliable operator-question card in Run
  Focus. Questions are capped, cancellable, backgroundable, redacted in run
  artifacts, and never exposed to modules, subagents, bridge-owned loops, or
  headless stdin. The root planner uses the same multi-step agent turn: it may
  call `request_user_input`, consume the answer, and continue planning without
  serializing a deferred `ask` proposal. The first operator edit snoozes any
  auto-resolution deadline; submit/cancel remain visibly pending until the
  worker persists and acknowledges the outcome. Jobs renders such runs as
  `WAITING INPUT`.
- Completed foreground phase attempts restore their exact origin and leave a
  restart-safe result card. Selecting or discarding records a disposition over
  immutable run references; selecting a patch never applies it.

Session options last only for the shell process. Global options are persisted.
Workspace option files are loaded when present and preserved by the same store
format.

## Stored Paths

| Scope | Path |
| --- | --- |
| Global | `~/.kuzushi/v3/options.json` |
| Workspace | `<target>/.kuzushi/v3/options.json` |
| Session | in memory only |

Config uses separate paths:

| Config | Path |
| --- | --- |
| Global config | `~/.kuzushi/v3/config.toml` |
| Workspace config | `<target>/.kuzushi/v3/config.toml` |

Use config for durable runtime/provider defaults and global policy, not for
per-tool behavior. Current runtime/policy config includes:

### Interactive keybindings

Home-scoped `operator.keybindings` may replace or remove shell bindings without
recompiling Kuzushi. Each entry names a context and action; an empty `bindings`
array explicitly unbinds that action. Bindings accept one stroke or a two-stroke
chord, including literal `backtab`, modifiers such as `ctrl+g`, arrows, and
navigation keys:

```toml
[[operator.keybindings]]
context = "workbench"
action = "cycle_phase"
bindings = ["backtab", "g p"]

[[operator.keybindings]]
context = "global"
action = "command_palette"
bindings = ["ctrl+g"]

[[operator.keybindings]]
context = "phase_result"
action = "continue"
bindings = ["ctrl+n"]
```

Contexts are `global`, `composer`, `workbench`, `phase_result`, `question`,
`run_focus`, `picker`, `report`, and `modal`. Phase-result actions are `select`,
`continue`, `open`, `refine`, `run_again`, `regenerate`, and `discard`. Runtime
dispatch, footers, operator-question hints, and phase-result cards all consume
the same resolved bindings; an unbound action is never advertised with its old
key. Duplicate bindings within one context, unknown actions, malformed strokes,
and duplicate context/action entries reject the new map atomically; the previous
valid map remains active. The shell polls the global config and hot-reloads only
keybindings, so a config edit cannot silently change the active model, provider,
runtime, or permission policy. Project config may not set
`operator.keybindings`.

```toml
model = "openai:gpt-4.1"

[runtime]
thinking_level = "high"
worker_watchdog_timeout_ms = 21600000
# langgraph_bridge_command = ["node", "scripts/langgraph-bridge.mjs"]

[operator]
session_budget_usd = 2.50
spend_hard_ceiling_usd = 10.00
trusted_workflow_auto_accept = false
# Deprecated compatibility list; local workers use kuzushi.lock approvals.
trusted_modules = ["package:trusted-module"]

[[operator.signature_keys]]
key_id = "trusted-author"
algorithm = "ed25519"
public_key = "base64-encoded-ed25519-public-key"

[phases]
# Canonical ceiling: map, scan, review, prove, or fix.
stop_after = "review"

[phases.scan]
budget_usd = 1.25
concurrency = 2
strategy_cap = 3
prompt_variant = "deep"

[phases.review]
budget_usd = 0.50

[phases.prove]
confirmation_depth = "sampled"
```

Phase templates are the durable guided-workflow surface. They belong in
config, not environment variables. Project configs may set `[phases]` fields;
`model`, runtime, and `[operator]` fields remain global-only because a target
repository must not redirect model choice, credentials, process execution, or
operator trust policy.

For one major release, `[phases.hunt]` loads as `[phases.scan]` and
`[phases.confirm]` loads as `[phases.prove]`, with a deprecation warning.
Supplying an alias and its replacement together is a hard error, and all saved
configuration uses only `scan`, `review`, and `prove`.

Report is intentionally absent from `[phases]`: it is a workflow exit, not a
phase or autonomy rung.

`operator.signature_keys` are global trust roots for non-empty KWP lockfile
`signatureChain` entries. They verify
`ed25519:v1:<keyId>:<base64Signature>` over the module id, digest, descriptor
hash, and version. Host-mounted MCP aliases and fuzz executors likewise belong
under global `operator.mcp_mounts` and `operator.fuzz_executors`, never in
target-owned configuration.

## Model Selection

Runtime-backed tools never choose a fallback model. They use an explicit
provider:model value or fail before calling the runtime.

For descriptor-backed module tools that declare `model`, the effective model is:

1. explicit tool input such as `--input '{"model":"openai:gpt-5.5"}'`;
2. `KUZUSHI_MODEL` / `KUZUSHI_V2_MODEL`, canonicalized at the config boundary;
3. global config `~/.kuzushi/v3/config.toml` `model = "provider:model"`.

Supported LangGraph bridge providers: `anthropic:*` (ANTHROPIC_API_KEY or
stored OAuth), `vertex-anthropic:*` (Claude on Google Vertex AI — the secret
is GCP Application Default Credentials, so `runtime.api_key_env` is
`ANTHROPIC_VERTEX_PROJECT_ID` and carries the GCP project id, which the
bridge can also resolve from ADC; `CLOUD_ML_REGION` selects the endpoint and
defaults to `global`), `openai:*` (OPENAI_API_KEY), and OpenAI
subscription-backed model selectors (stored OAuth). Vertex model ids use the
Vertex naming scheme (for example
`vertex-anthropic:claude-sonnet-4-5@20250929`).

Stored OAuth credentials require a nonempty access token and a numeric expiry.
The bridge attempts refresh when needed, then rejects an expired or malformed
credential before constructing the model client. Failed refresh preserves the
stored credential and reports authentication failure. A subscription selector
does not switch to an API-key client after this failure.

`threat-model:build maxOutputTokens` requests a maximum from the model adapter.
The LangGraph OpenAI subscription OAuth adapter currently does not enforce an
output-token ceiling. Context planning labels the value as requested output;
approved investigation allowances enforce provider-request counts, including
internal turns and potentially billable retries. OAuth token and dollar
consumption remain uncertain.

Role-routed tools then resolve their role model with this precedence:

1. the request's explicit model, when it is non-empty and different from the
   operator default;
2. global option-store role override, e.g. `setg MODEL_DEEP_AUDITOR openai:gpt-5.5`;
3. home `~/.kuzushi/models.toml` `[roles.<role>] primary`;
4. the operator default from config/env/tool input;
5. home `~/.kuzushi/models.toml` `default_model`.

If a request model is exactly the operator default, the router treats it as the
default placeholder so role-specific routes and `MODEL_<ROLE>` overrides still
apply. This is intentional: callers pass the default model to preserve
no-silent-fallback validation, while the router owns role selection.

### Tie-break escalation to a different model

A split consensus verdict — an even panel vote in `verify:finding`, or a tied
deep-audit consensus — can be handed to a **different, operator-named** model
to break the tie. Escalation is never inherited: absence leaves the split
verdict standing, and a same-model or invalid escalation is refused and
disclosed, never silently substituted.

- `verify:finding` reads the `escalationModel` option (alias
  `escalation_model`, advanced): a `provider:modelId` spec that must differ
  from `model`. It runs one extra pass only when the panel splits evenly, adopts
  that pass's verdict, and keeps the `consensus` block visible (unanimity is
  never forged). A refusal surfaces as a completed-with-warning, and the durable
  verification note records the gate/panel/tie-break stage ladder.
- `verify:finding` also reads the `gateModel` option (alias `gate_model`,
  advanced): a cheap-tier `provider:modelId` plausibility gate that runs before
  the full panel. Only its NOT-exploitable verdict is trusted (rejection-only) —
  an exploitable gate verdict escalates to the full-strength `model` panel; unset
  means no gate. A malformed spec is accepted at `setg` but rejected legibly at
  dispatch (`verify:finding gateModel is not a valid model spec`), never silently
  dropped or defaulted. The Prove `MODEL LADDER` card discloses the gate, panel,
  and escalate-on-tie rows in execution order and drafts the same models into the
  verification command.
- The deep auditor uses the `triage_escalation` router role. Set it with
  `setg MODEL_TRIAGE_ESCALATION provider:modelId` or
  `~/.kuzushi/models.toml [roles.triage_escalation] primary`. The escalation
  model resolves from **explicit sources only** — the `MODEL_TRIAGE_ESCALATION`
  option override and the models.toml route — and never falls through to the
  operator default or the router default. A tie with no named escalation stays
  `needs_review`; an escalation that is itself inconclusive keeps `needs_review`
  rather than forging a decision.

Target-local model control is rejected. `<target>/.kuzushi/v3/config.toml` must
not set `model`, and `<target>/.kuzushi/models.toml` is not loaded. Put durable
model policy in the operator's home config/models files, or pass a one-shot
tool `model` input.

Program scope is a separate durable target policy file, not an option-store
entry:

```toml
# <target>/.kuzushi/scope.toml
[in_scope]
hosts = ["example.com", "*.example.com"]
cidrs = ["10.0.0.0/8"]

[out_of_scope]
hosts = ["admin.example.com"]
```

When an allow list is present, unmatched hosts/IPs are out of scope. With only
deny rules, unmatched targets remain unknown rather than explicitly allowed.

Host matching is case-insensitive and ignores a trailing root dot, so one rule
covers `admin.example.com`, `ADMIN.example.com`, and `admin.example.com.`. CIDR
rules match bare IPv6 literals (`2001:db8::1`) as well as bracketed ones
(`[2001:db8::1]:8443`), and an IPv4 rule also covers the IPv4-mapped IPv6
spelling of the addresses it names, so `10.99.0.0/16` denies `::ffff:10.99.0.1`
too.

`recon:nmap` is the one verb whose target names an address block rather than a
host — `10.0.0.0/8`, `10.99.0-255.1`, `10.0.0.1,2` all go straight to nmap — and
its targets are judged as every address in the block. A CIDR deny rule refuses
the block as soon as it overlaps it, and a CIDR allow rule admits it only by
containing all of it, so widening the target cannot reach past the scope file. A
block of 256 addresses or fewer is additionally weighed one address at a time,
which is what lets a rule written as a host glob (`10.0.0.*`) or split across
two `cidrs` entries cover a `/24`. A wider block is left to the CIDR rules
alone, so name addresses under `cidrs` rather than as host globs. A block that
holds one address counts as a block too, so a respelling such as `10.0.0.5-5`
is judged as the `10.0.0.5` it scans. nmap also accepts `<name>/<numbits>`
(`scanme.nmap.org/16`), which resolves the name and then sweeps every address
sharing those first bits; the scope file cannot resolve a name, so it cannot
bound that block and never admits it — such a target is refused when an
`[in_scope]` list is present and reported unknown under a deny-only file. Write
the block as a CIDR under `cidrs` if you mean to scan it.

Every other verb — `recon:subdomain`, `recon:http-fingerprint`, the recon and
bounty importers — reads its target as a single host, because that is what curl
and the importers do with it: `10.0.0.1-2` is a domain name to them and resolves
to whatever DNS answers with, so it is judged as the one host it is and not as
the pair it reads like.

A redirect is not consent to leave the scope file. `recon:http-fingerprint`
follows redirects one hop at a time and judges each `Location` by the same rule
before the request is sent, so a redirect to a host the file refuses is declined
and named rather than probed. The walk stops after 10 hops, and
`timeoutSeconds` bounds each hop rather than the chain. The endpoint that
answered — not the target that was asked for — is what the recon store records,
including the scheme the fetch actually spoke, and the result's `redirects`
carries every URL fetched plus any redirect declined with its reason.

## Patch application and re-verification

`PatchResult` controls patch synthesis and disposable-worktree validation only.
A `SOUND` patch is a draft until an operator applies the reviewed diff. Apply
creates an append-only `PatchLifecycleRecorded` v3 event keyed by
`applicationId`; its projection records target and durable finding identity,
patch run id, diff hash, optional base commit, relative touched paths with
before/after hashes, actor/timestamps, reverify run id, state, and outcome
detail. Applying never clears the state that proves the application occurred.

Re-verification is the descriptor-backed headless tool:

```bash
kuzushi --target . run patch:reverify \
  --input '{"applicationId":"application-id-from-apply-receipt"}'
```

`applicationId` is required. Registry preparation binds the originating
detector, its exact original tool input, and the explicit workspace. The tool
refuses attribution when touched-file hashes changed after apply. It never
substitutes a detector, target, runtime, provider, or model:

- deterministic successful absence → `Verified`;
- rediscovery → `StillVulnerable`;
- nondeterministic absence → `NotRediscovered`;
- unavailable comparison → `Inconclusive`;
- cancellation/process loss → `Interrupted`;
- changed touched-file hashes → `ChangedSinceApply`.

Only `Verified` promotes the related patch result to `PatchStatus::Verified`.
All inconclusive outcomes preserve the earlier `SOUND` synthesis result.

Finding exports expose remediation metadata additively in JSON/JSONL/Markdown,
SARIF properties, and flattened CSV columns: application id, patch run id,
application state, reverify outcome/run id, diff hash, and touched paths.

Export evidence-state labels describe evidence, not identity metadata. A
constructor-generated source signature and an automatic source-occurrence row
remain identity metadata only. `source_linked` requires explicit source-grounded
static proof; a finding with no observed evidence, model reasoning, independent
corroboration, or static grounding remains `message_only`.

## Suppression rules

Suppression is one composable primitive. Mute a false positive, gate a scope,
filter a severity band, or honor an in-source ignore comment — all compile into
a single `SuppressionRule` (predicate + reason + statement + actor + optional
expiry). Suppression **annotates, never hides**: a suppressed finding stays in
every default list with a `status:suppressed` tag, is emitted in SARIF with a
standard `result.suppressions[]` entry, and is skipped by `--fail-on`. Exclude
suppressed findings explicitly with the existing filter grammar.

Rules live in a durable, target-local file (like `scope.toml`, target-authored
and therefore only allowed to *annotate*, never to silently change security
policy):

```toml
# <target>/.kuzushi/v3/suppressions.toml
version = 1

[[rule]]
reason = "false-positive"     # false-positive | acceptable-risk | wont-fix |
                              # used-in-tests | no-time-to-fix | out-of-scope
statement = "Sanitizer applied upstream; taint path infeasible."  # required
actor = "shayaun"
created_at_unix = 1783468800
expires_at_unix = 1791244800  # optional; omit = never. `expires = "YYYY-MM-DD"`
                              # is an accepted alias (not both).

[rule.match]                  # at least one key required
finding_id = "FI-3A2B9C01"    # alias | identity id | fingerprint prefix
rule_id = "rust.sqli.tainted-query"
path = "tests/**"             # globset, matched against Finding.file_path
tool = "semgrep"
module = "taint-iris"
severity_below = "medium"     # mutes strictly below the band (never Unknown)
scope_status = "out-of-scope" # in-scope | out-of-scope | unknown
```

Author rules with the `suppress:add|list|remove` tool (or the `kuzushi suppress`
CLI, which also keeps the legacy whitebox store in sync). Expiry is
read-time-authoritative; a reconcile sweep at scan start and target load appends
`SuppressionExpired` so lapsed rules **auto-reopen** findings visibly via the
event log. In-source `# kuzushi-ignore: <target> — <reason>` comments follow
Semgrep `nosemgrep` semantics: the finding is still emitted, then marked
suppressed; malformed comments suppress nothing and are surfaced by
`suppress:list`.

## Review-yield ordering

The review-yield signal is an advisory, historical reviewer-outcome rate. It is
off by default and configured entirely through the operator-owned global config
— there is no flag and no environment variable.

```toml
# $HOME/.kuzushi/v3/config.toml
[review_yield]
mode = "within-band"                     # off | shadow | visible | within-band | learn
model_path = "/models/review-tree.json"  # required whenever mode != off
```

| Mode | What it does |
| --- | --- |
| `off` (default) | Nothing is loaded, scored, recorded, or shown. |
| `shadow` | Scores and records what a prospective ranking would have been. The operator sees nothing and review order is unchanged. |
| `visible` | Also explains the signal in the finding detail. Review order is still unchanged. |
| `within-band` | Also orders review rows *inside* a proof-confidence and severity band, highest historical yield first. |
| `learn` | The same band-bound ordering, keyed on the model's knowledge gap instead: findings the model has least evidence about first — widest leaf entropy, then fewer prior examples. |

`within-band` and `learn` are the only modes that move a row, and neither moves
anything across a band. They differ only in what they rank a complete band by.
A band reorders only when every row in it carries the key that mode ranks on;
one row without it leaves that whole band in baseline order, because ranking a
scored row against an unscored one would assert a comparison the evidence does
not support. Setting `mode` back to `off`, `shadow`, or `visible` restores the
byte-identical baseline order.

`learn` is advisory emphasis for building the review corpus, not a claim about
the findings it lifts. A row near the top is one the model knows little about —
its prior reviewed examples are few and mixed — which is a fact about the
model, never about whether the finding is exploitable. Rows below the
artifact's evidence floor are ineligible and freeze their band rather than
sorting to the front. Its v1 score is leaf entropy and leaf support only;
under-represented tool families and languages, unseen or drifting categories,
and baseline-versus-tree disagreement are deferred until census data shows the
corpus can support them. While Learn is actually ranking a band of the queue on
screen, the review queue carries one chip — `learn mode - model knowledge-gap
review` — and the finding detail explains the ordering beside the two numbers
it uses. An armed mode whose every band is frozen shows neither, because
nothing is being ordered.

Rules that keep this honest:

- **Global config only.** A project's `<target>/.kuzushi/v3/config.toml` that
  sets `[review_yield]` — either field — fails to load and names the file. The
  section points at a model artifact, so a scanned repository that could set it
  would choose which model scores its own findings. Same trust rationale as
  `model`, `runtime`, and `phases`. Commands that only read persisted state —
  `kuzushi findings`, `kuzushi finding`, `kuzushi runs` — load no target config
  at all, so that file neither arms them nor stops them; the rejection above is
  what the config-loading surfaces do.
- **No default artifact.** `model_path` is required whenever `mode` is not
  `off`, and nothing is ever downloaded or substituted. A mode without a path
  is a config load error, not a silent downgrade to `off`.
- **No silent fallback.** If the named artifact fails to load, hash, or match
  the feature schema, the shell reports the rejection and runs with review
  yield off. It never falls back to a different mode or a different artifact.
- **Shell only.** The section is consumed by the interactive shell, which is
  where interactive review happens. `kuzushi scan` and `kuzushi run` load the
  config like any other command and ignore it.
- **The backlog preset is never model-ordered.** Its promise is
  worst-severity-first; review yield does not touch it in any mode.
- **Exports are never model-ordered.** Export row order is the severity-major
  alias order in every mode. An export from a session with the signal armed
  carries a `metadata.reviewYield` block naming the mode and the loaded model
  id, so a reader can tell what the operator reviewed under. `modelId` is
  absent when no artifact loaded.

## Environment Variables

Environment variables remain appropriate for secrets and process integration:
provider API keys, OAuth bootstrap, `PATH`/`HOME`/`EDITOR`, terminal/plain-mode
presentation, test hooks, and documented emergency debug toggles.

Ordinary product behavior should not depend on new env vars. Prefer:

- tool options for scanner binaries, MCP/CodeQL tuning, prompt knobs,
  and plugin roots;
- config for runtime/provider defaults, model, bridge command, thinking level,
  budgets, approval policy, host-mounted MCP aliases, and host-mounted fuzz
  executors.

Compatibility env vars such as `KUZUSHI_MODEL`, `KUZUSHI_V2_MODEL`,
`KUZUSHI_API_KEY_ENV`, `KUZUSHI_BASE_URL`, `KUZUSHI_LANGGRAPH_BRIDGE`,
`KUZUSHI_ANTHROPIC_OAUTH`, and `KUZUSHI_ANTHROPIC_OAUTH_CREDENTIALS` may still
be read at config boundaries. Presentation flags such as `KUZUSHI_PLAIN`,
`KUZUSHI_SCREEN_READER`, and terminal accessibility variables remain
presentation concerns.

LangGraph bridge invocations have a 600,000 ms wall-clock ceiling by default.
The existing adapter-boundary `KUZUSHI_BRIDGE_TIMEOUT_MS` override accepts only
a positive integer; invalid or zero values fail closed instead of restoring an
unbounded wait. Cancellation and pipe-failure guards can still stop a bridge
earlier.

Agent-backed tools expose `mcpToolTimeoutMs`, `bridgeVerbose`, and
`bridgeLogPath` as descriptor options. The last two emit metadata-only
diagnostics. Adapter-only emergency hooks `KUZUSHI_BRIDGE_DEBUG_DUMP` and
`KUZUSHI_BRIDGE_DEBUG_FULL_PROMPT` use that same redacted projection; the
legacy `FULL_PROMPT` name does not cause prompt text to be written.

Some existing scanner/tool adapters still read compatibility env vars for
local binaries, caches, timeouts, or external toolchain integration (for
example CodeQL, Clang, and rev.ng). Treat those as legacy adapter-boundary
exceptions: do not add new product behavior env vars, and migrate touched knobs
toward declared options or config.

### Setup context studies

When the selected Map plan includes model-backed threat-model generation, the
Allowance row opens the same context-study review as Start Map. The supported
combination includes the selected repository-context and entry-point preparation
jobs. Set total calls with `t` and protected review with `r`; Enter prepares the
fixed plan, and a second Enter opens its explicit approval. Tab shows all frozen
inputs. Approval starts no job; the campaign's visible `L` action launches them.
Esc returns to the original Setup row with its selection, draft and investigation
accounting intact. `n` prepares a separately approved replacement under that same
investigation. `campaign <id>` and `a` recover a saved plan after restart.
Unsupported Map combinations are explained before any job starts. Dollar costs
can be unavailable; the call allowance is distinct from the legacy observed USD
spending stop used by other interactive work.

The campaign reader offers `PgUp`/`PgDn` for complete job and occurrence details,
with a visible row position when its document exceeds the viewport. Paging keeps
job selection and the composer draft; refreshing retains the reading position.
Pasting while navigating explicitly moves input to the composer and preserves
its cursor and held draft. A multiline paste retains its complete text in the
existing paste block. Neither paste form submits work; Enter remains required.
Editors and confirmation surfaces retain their own paste ownership.

Returning to a saved context plan refreshes its result as well as its allowance.
The result view's Enter action inspects the exact generated revision. After
inspection, `a` selects it for the finite scan study, and `v` opens its DFD.
Missing or stopped generation shows the recorded problem and opens job
inspection. A new draft still requires `n`, preparation and approval. The
completed context job screen keeps the full recovery explanation and labels
missing cost receipts as unavailable. It offers context-result review once
all its jobs are complete.

On a completed readable result, `m Review Map` records or reopens that exact
context as a durable Map awaiting acceptance. Review starts no work and does not
select the context. Its foreground result opens Map, where `u` accepts it.
The same controls remain visible at 40×12 through 160×48. A changed repository
refuses a new handoff and offers historical inspection or a separately approved
draft. Background completion retains the current view and any unsent draft.

Durable Map and its DFD show the context recorded by that attempt, independently
of the globally active model. The receipt distinguishes awaiting review,
accepted and historical source, and retains the context's grounding verdict.
Missing recorded evidence offers Map run inspection. Preparing replacement
context remains an explicit Map plan action. Global context editors continue
to edit the active model.

The study form inherits accepted Map context before shared dispatch binds
defaults. Explicit stored context choices, including `null`, take precedence.

The context picker also offers `m Map` after Enter has inspected the selected
revision. This reviews its existing producing run without regeneration or
global activation. The Map result then requires explicit selection, including
acknowledgement for partial evidence. A missing producing run, damaged result
or changed source explains why a current Map receipt cannot be recorded.
Reading historical context remains available. All controls, including Map
review and back, remain visible in the narrow layout.
Inspecting a generated revision retains its originating completed result.
Back restores that result's options and scroll without selecting context or
changing allowance. Explicit **use** leaves the inspector for study preparation.
A pending Map can be inspected without replacing the accepted revision used by
a new study. Missing accepted evidence blocks preparation. Existing frozen
study inputs are retained when reopening their plan.

The shell's **repo index** status names its optional source index separately
from accepted threat-model context. Stale and unverified indexes retain those
qualifications. Summary uses a pageable document when its description cannot
fit; Page Up at the document start stays there, and page steps follow visible
rows. The sidebar's session dollar cap and recorded session spend describe the
current shell process. Report owns prior investigation usage and allowance.

Review's **Decision source** names the recorded observation, commit, branch and
dirty state behind the effective verdict. A later observation is separate and
can prompt reassessment. Full commits and snapshot ids remain in provenance.
Missing captures and unreadable metadata stay explicit; no new verdict is
created automatically. An explicit `decision <verdict> <reason>` records the
operator's new decision against the displayed observation and retains earlier
decisions. At narrow widths, Enter or `open <id>` reveals finding detail and
PgUp/PgDn reads its complete document. Reading this history performs no model
work and does not repair run metadata.


## Findings navigation

`findings:list` declares `cursor` and `anchor` as advanced string options and
`order` as `ledger|confidence`, defaulting to `ledger`. Pages retain the 500-row
ceiling. A returned cursor continues the same target/query/ledger snapshot;
changes require a fresh request. An anchor keeps its finding in the current
query after an update. Do not combine cursor and anchor. The shared registry
validates these options in shell/run dispatch.

The interactive Review list uses confidence order over all matching rows.
Ctrl+N and Ctrl+P move between pages in empty Navigate mode. Local search is
page-local; Ctrl+F prepares the complete-ledger filter. Query changes reset page
position. This navigation performs local reads and never adds scan jobs or
model spending.

An explicitly opened finding can stay pinned outside the query or component.
Review detail and manual decisions use that identity. The list discloses the pin
and its action target; list navigation releases it. Aliases are withheld after
the ledger or grouping policy changes. The captured read watermark remains, so
an older pin cannot overwrite a newer decision without reopening the finding.
The cache keeps current findings' decision history independently of the list.

Passive refresh can recover once to the first page when its selected row leaves
the query. It retains the filter and recorded decisions and publishes a notice.
Explicit cursor or anchor requests remain strict errors when invalid or missing.
Recovery does not issue model requests or create discovery work.

### Manual context copies

In study context, inspect the exact revision with Enter, then use `e` to edit.
Enter opens a field; multiline paste and cursor keys stay in that field.
Ctrl+S opens the change review. Enter there saves a new inactive copy through
`threat-model:revise`; it does not update an accepted plan or the active model.
Inspect the new copy, then explicitly select it with `a` for a new study draft.
Back keeps session drafts and cursors. `d` opens a separate discard confirmation.
An interrupted or failed save keeps edits and asks for catalog inspection before
retrying. The global active-context editors retain their existing explicit
behavior. Copied context retains its original source binding and needs a new
grounding check after edits.

In the manual copy editor, `g` prepares regeneration of the selected explanatory
field. Save or explicitly discard pending human text first. The generation form
offers `G` for multiline guidance, `M` for the model, `t` for total calls, `r` for
protected review calls, `Tab` for exact options and page keys for the full plan.
Guidance uses Enter for a newline and Ctrl+S to include it. Back keeps its draft
and cursor; an unsaved guidance draft blocks plan preparation. Each new plan
requires review, allowance approval and an explicit job start. Saving the result
does not select or activate it. Inspect it, use `d` in the context chooser to
compare before/after text, then `a` to bind it to a separately approved study.
Comparison reads the exact saved parent without a model request. A failed parent
read offers Enter to retry locally or Esc to return to the candidate.

In the study context browser, `c` checks the inspected exact revision against
its recorded source. `Space` lists every action with keyboard selection and
back. Checking makes no model requests. A saved check stays inactive and needs
inspection before `a` can select it for a new study plan. Failed structural
checks remain visible. A changed content tree, even at the same SHA, or a new
SHA, even with identical content, stops checking historical context. The check
does not refresh that context or claim that findings were fixed. Inspect
Activity and the catalog after a canceled or uncertain outcome before retrying.
The browser distinguishes the last recorded check from source identity captured
at inspection. Changed SHA, content, dirty state and unknown identity remain
visible after an exact read and restart. Source is rechecked on the next action;
an inspection receipt is not continuous filesystem monitoring.

### Interactive manual decision saves

`decision` and `dismiss` retain the selected finding, target, read watermark and
review session while one background save settles. Review shows `saving <alias>`
and keeps its recorded decision separate. A second decision or suppression is
refused with an instruction to retry from command history. There is no pending
write queue or automatic retry. Exit waits for the save result. A changed target
receives a notice naming the original target without changing its current view.
A missing result requires ledger inspection before retrying. Synchronous callers
use the same Core service and journal guards. Suppression-rule writes are still
synchronous; their aliases resolve across the complete policy-projected ledger.

### Budgeted lesson drafts and exports

Open a human-confirmed finding in Review, then `lessons`. Press `g` for one
model-proposed lesson. The existing study form owns the selected model,
generation options, guidance and allowance. Prepare the fixed job, inspect its
exact confirmation and observation, approve its allowance, then start it
separately. Generation uses Learning calls, preserving the protected Review
allocation. It returns a draft; `a`, `r` and `t` still require a reason and an
explicit confirmation. Acceptance and inclusion in a context copy are separate.

`findings:lesson-generate` declares `findingId`, optional frozen `originRef`,
`guidance`, `maxSourceBytes`, `maxOutputTokens`, `thinkingLevel`, `model` and
required `allowanceRef`. It uses recorded captured source, discloses omissions,
and makes one tool-free synthesis request. Invalid output has no repair loop.
The adapter may not enforce the requested output-token ceiling; provider calls
and attempts remain limited by the approved allowance. Dollar consumption is
uncertain. A failed job stays visible, and another draft needs separate approval.

Report includes current lesson records linked to its included finding
generations. JSON, JSONL, SARIF and Markdown bundle retain text, exact references,
origin, review state, generation receipt and current context eligibility. CSV
and the compatibility findings format disclose that lessons are omitted.
Historical guidance does not establish a finding verdict or a fix at another
source revision. Exported lessons stay outside automatic artifact context.

### Context comparison in a fixed study

The declared `campaign:study contextBaselineRunId` option names one completed,
authenticated SAST run. `baselineRunId` remains the separate historical usage
selector. Selecting another usage record does not change the context baseline.
Candidate context is selected through `scanInput.threatModelRef`; only that
condition may differ. Planning and approval reject other condition changes.

The study form's **Context comparison** row binds the explicit baseline and
reads its existing allowance. It does not approve work. Choose a different
exact context, prepare the draft, review the retained call limits and protected
review allocation, approve that specific plan, and start its frozen jobs
explicitly. A read failure keeps the draft and spending account, blocks work,
and offers `r` for a read-only retry. Esc dismisses an error banner when needed.

Once frozen, Enter on Context comparison opens actual candidate passes. Arrows
select, Enter compares with the named baseline, `r` refreshes recorded outcomes,
Esc returns, and `x` clears the comparison. Comparison preserves decisions and
selection on return and makes no model request. Completed work and spending
survive edits and restart. A changed context can change consumption; historical
usage is not a calibrated candidate estimate. Dollars remain unknown without
complete price receipts. Every candidate still requires its own explicit finite
plan and allowance approval within the shared investigation.

### Context cases and recorded outcomes

**Context cases** opens the finite case editor. Inspect an exact context in the
existing reader, then `+` includes it or `b` includes it as the explicit baseline.
In the case editor, arrows select; `b` chooses the baseline, `p` edits only that
case's repetitions, `x` removes it, and `c` clears the cases while retaining
spending. **Discovery passes** sets the default for newly added cases. Existing
cases retain their own counts.

`v` reads recorded results after the plan is frozen. Arrows select a case and
Enter opens its pass list. `b` chooses a completed baseline pass explicitly;
Enter on a candidate pass opens the existing comparison. Esc restores the exact
case/pass selection. `PgUp/PgDn` reads long selected-case details, `r` refreshes
results, and no comparison action starts work. Pending or unavailable finding
snapshots display pending counts instead of an apparent zero result.

Every case retains a separate recurrence denominator and exact context. The
entire workload shares the approved allowance. Failed accounting reads retain
known consumption and limits; `r` retries the read. Unknown dollar costs remain
unavailable. Edits need a replacement plan approval and cannot grant additional
work implicitly.

From recorded matrix results, `R` opens Report for the exact saved plan. The
reader checks its digest in the background. Esc restores the selected case and
pass. Reopening refreshes decisions and outcomes without starting jobs. A missing
or changed receipt blocks the scoped export; `s` explicitly chooses workspace
history. The report names recorded source and does not imply current-source
applicability when it has not been checked. `p` shows per-case context and
condition references. All export formats retain the investigation receipt.

Matrix dispatch saves its completed or partial result for explicit Scan
acceptance. The Scan result controls offer Use only when the recorded source
can support progression. Partial work requires acknowledgement. Reopening a
completed plan does not add jobs or select the result. After acceptance,
ordinary Report entry uses the matrix's exact run set and keeps every case's
recurrence separate. Historical or unverifiable source remains disclosed.

At the discovery call limit, fixed model work pauses before another job attempt.
Protected review calls remain available for their intended phase. The campaign
surface offers plan/allowance review and partial/report access. Starting with an
exhausted allowance is refused before a dispatcher launches. A specific approved
revision can resume the original unstarted jobs; it does not add jobs or repeat
completed ones. Unstarted parked work appears as pending in occurrence reports.
Runtime-free work can continue without provider capacity. Cancellation and
unresolved reservations never return committed calls to the allowance.

### Component maps with unknown relationships

An accepted Map can show recorded components before data flows are known.
Summary states the source description and the unknown relationships; DFD shows
the recorded node and its linked context without inventing connections. A
component map does not establish complete architecture coverage. Generated
repository-scope placeholders still require source or design context.

At 12 rows or fewer, idle Map navigation keeps the document visible.
`PgUp/PgDn` reads Summary, `Enter` opens its selected DFD component, and a second
`Enter` opens linked context. `Enter` returns to topology. `Esc` returns input to
the command prompt. Active work, input drafts and pending decisions retain their
normal controls. Accepted Map context remains tied to its exact revision even
when another context is active.

### Inspecting tools outside supported defaults

When a filter has only Experimental or Compatibility matches, arrows select a
tool and Enter opens its settings. Settings Escape returns to the same filter
and selected tool. During field editing, Escape keeps that field's draft first;
the next Escape returns to tools. Support Escape gives input to the composer.

Inspection starts no work and leaves supported defaults unchanged. Every match
is reachable, including lists larger than five tools. Drafts and cursor position
survive navigation; a warning takes Escape before back-navigation. Plain output
shows the same selection and support information. Mixed supported and
experimental matches retain the existing tools projection.
