<img src="kuzushi-logo.png" alt="Kuzushi" width="200" />

# Kuzushi

Kuzushi is an evidence-backed repository security workbench.

It does not try to be another generic coding assistant. It scans real
codebases, preserves evidence, ranks likely vulnerabilities, and helps teams
move from suspicion to verification to remediation.

Use Kuzushi when you need more than "AI says this looks wrong": you need a
finding, the code path behind it, the current proof state, and a defensible
next action.

The primary operator path is the native Rust CLI and Ratatui shell. The npm
`kuzushi` binary, plus the shorter `kz` alias, invokes that native CLI through
`bin/kuzushi-rs.mjs`.

## Product Focus

Kuzushi's current product is deliberately narrower than its long-term research
roadmap: local-first repository security investigation for serious AppSec and
product-security operators. The core contract is evidence, not chat:

1. build or refresh repository context;
2. scan with deterministic and model-backed tools;
3. persist findings, traces, proof state, and run artifacts;
4. inspect one finding's evidence and current proof level;
5. choose the next action: suppress, verify, patch, or report.

Roadmap surfaces such as binary exploitation, broad pentest automation,
governance packs, and defensive operations should reinforce that evidence
workflow before they become primary product surfaces.

## Current Snapshot Highlights

This snapshot tightens the path from scanner output to human review:

- Findings have durable identities, source signatures, corroborating source
  rows, static proof state, latest runtime verification, run provenance, and
  safe HTTP capture markers through list/detail/export surfaces.
- Scanner-owned triage and human review decisions are intentionally separate.
  `decision` appends a human verdict and rationale that carries forward by
  durable identity; it does not rewrite detector output or claim that a scanner
  result was confirmed by the machine.
- Workspace persistence is v3-first: append-only event log segments under
  `.kuzushi/v3/log/`, the projection DB at `.kuzushi/v3/index.sqlite3`, and
  replayable run artifacts under `.kuzushi/v3/runs/<runId>/`.
- The Rust workbench is the primary shell landing surface. It presents attack
  surface, findings, details, activity, and generated artifact context without
  replacing domain terms such as severity, confidence, status, decision, proof,
  and verification with generic UX labels.
- Run comparison, export preview/write, review queues, failure handoff, and
  Activity summaries all read from persisted run/projection state rather than
  transient shell-only state.
- Model and runtime policy remains explicit. Missing credentials, incompatible
  provider/model pairs, absent plugin roots, and unknown tool options fail with
  actionable errors instead of silently choosing another provider, model, or
  behavior path.
- Legacy `taint-iris:hunt` compatibility routes through the current Taint IRIS
  Next path, while public discovery and report labels keep defensive scanner
  terminology precise.

## Privacy & Data Flow

Kuzushi is local-first and ships **no telemetry**. Findings, evidence, run
artifacts, and suppressions live under `.kuzushi/` in your workspace and never
leave your machine. The only bytes that go anywhere are the prompts sent to
the model provider **you** configure (and nothing is sent at all until you
configure one — the deterministic scanners run fully offline). Model and
runtime selection is explicit: Kuzushi never silently falls back to a
different provider or model.

## Install

```bash
npm install -g kuzushi
kuzushi --help
kz --help
```

From a source checkout:

```bash
pnpm setup
pnpm dev -- --help
pnpm build:native
node bin/kuzushi-rs.mjs --help
```

The published `kuzushi` command resolves `native/<platform>-<arch>/kuzushi`,
and the published `kz` alias resolves `native/<platform>-<arch>/kz`; both then
fall back to local Cargo build outputs for the invoked name. Set
`KUZUSHI_NATIVE_BIN` to point the wrapper at a specific binary.

## Quick Start

This is the golden path. It is the workflow new operators should try before
touching advanced modules or deferred plugin-backed tools.

```bash
# 90-second offline proof: scan a vendored vulnerable fixture with the
# deterministic engines. No API key, no model, no external scanners.
kuzushi demo

# Check config, local state, scanners, and the LangGraph bridge.
kuzushi doctor --target .

# Build the repository context snapshot used by shell and model-backed tools.
kuzushi --target . run context:build --input '{}'

# Run the standard native scan path with deterministic CI-style progress.
kuzushi scan . --mode standard --ci

# Inspect persisted findings.
kuzushi findings --target . --limit 10

# Inspect one finding's evidence, proof state, verification, and next action.
kuzushi finding F-0001 --target .

# Record a human review decision without mutating scanner triage output.
kuzushi decision F-0001 --target . \
  --verdict confirmed \
  --reason "reviewed source-linked evidence and accepted the finding"

# Render a markdown PR/security review summary from persisted findings.
kuzushi pr-comment --target . > kuzushi-report.md

# Or export the canonical persisted projection.
kuzushi export --target . --format json --completeness complete --out findings.json
```

Fresh native state is stored under `.kuzushi/v3/`; scan, shell, and headless
run summaries remain under `.kuzushi/v3/runs/<runId>/`.
`kuzushi doctor --target .` runs a Rust preflight over config, writable state,
findings DB openability, optional scanner binaries, and the LangGraph
bridge without printing credential values.

To see the workflow without real provider credentials or LLM spend, run the
deterministic fixture:

```bash
examples/first-wow/run.sh
```

It scans a tiny vulnerable app through a demo-only Semgrep fixture, persists
findings in a temporary copy of the app, prints `findings`, and writes a
markdown PR comment report path.

## Native CLI

```text
kuzushi [--target <path>] [--plain] [command]
kz [--target <path>] [--plain] [command]
```

Bare `kuzushi` starts the shell with the `kuzushi>` prompt; bare `kz` starts
the same shell with the compact `kz>` prompt.
Use `--plain` or `KUZUSHI_PLAIN=1` to force line-oriented output with no ANSI
escapes, animation, or box drawing. `KUZUSHI_SCREEN_READER=1` and
`KUZUSHI_LOW_BANDWIDTH=1` are aliases for the same strict plain shell mode.
The interactive shell leaves normal terminal text selection/copy available by
default. Set `KUZUSHI_MOUSE_CAPTURE=1` only if you want mouse-wheel handling
inside the TUI and your terminal still gives you a selection modifier.

| Command | Purpose |
| --- | --- |
| `kuzushi shell [--target <repo>]` | Start the Ratatui shell. |
| `kuzushi demo` | Scan a vendored vulnerable fixture offline — no API key, no model, no external scanners. The fastest way to see a real finding with evidence. |
| `kuzushi scan <repo> [--mode standard\|whitebox-static] [--tasks a,b] [--triage] [--json] [--ci] [--fail-on low\|medium\|high\|critical] [--sarif out.sarif]` | Run the Rust SAST umbrella executor and persist findings. `--fail-on` exits 3 when findings at/above the severity exist (CI gating); `--sarif` writes a SARIF 2.1.0 export for Code Scanning upload. Descriptor-backed inputs also support `verifyWhen`, `verifyMax`, and `verifyVotes` for post-triage verification selection. |
| `kuzushi findings --target <repo> [--severity high,critical] [--verdict true_positive] [--name text] [--file-path path] [--vuln-source sarif,...] [--limit 50] [--json]` | List persisted findings. |
| `kuzushi finding <F-0001\|fingerprint-prefix> --target <repo> [--json]` | Inspect one finding's evidence, proof state, verification summary, patch result, and next action. |
| `kuzushi decision <F-0001\|fingerprint-prefix> --target <repo> --verdict confirmed\|rejected_false_positive\|suppressed\|deferred\|accepted_risk\|needs_review --reason <text> [--json]` | Append a human review decision for a persisted finding. This carries forward by durable identity and does not mutate scanner triage. |
| `kuzushi runs list [--status completed,failed]\|show <runId>\|trace <runId>\|diff <a> <b>\|prune --target <repo>` | Inspect, compare, or prune replayable summaries, result artifacts, and trace JSONL under `.kuzushi/v3/runs/<runId>/`. |
| `kuzushi export --target <repo> --out <path> [--format json\|jsonl\|sarif\|csv\|markdown-bundle] [--completeness all\|open\|complete] [--preview] [--allow-empty]` | Export or preview the canonical persisted findings projection with review state and provenance. |
| `kuzushi suppress <F-0001> --target <repo> --reason <text> [--days 90]` | Record an expiring, evidence-backed suppression; findings remain visible in audit/report output. |
| `kuzushi suppressions --target <repo>` | List suppression memory and the audit store path. |
| `kuzushi permissions [--target <repo>]` | Show the current model fallback, approval, headless-run, and sandbox policy summary. |
| `kuzushi pr-comment --target <repo> [--repo owner/name] [--run-url url] [--git-sha sha]` | Render persisted findings as a markdown PR/security review comment. |
| `kuzushi modules [--json]` | List visible native modules. |
| `kuzushi tools [--json]` | List visible executable tool descriptors. |
| `kuzushi doctor [--target <repo>] [--json]` | Check config, local state, findings DB openability, scanner binaries, bridge readiness, and model/auth setup. |
| `kuzushi run <module:tool> --input '<json>' [--option key=value]` | Execute one explicit tool through the Rust registry. Use global `--target` for workspace-backed tools; `run .` is shell-only focused-module shorthand. |
| `kuzushi mcp serve\|health <backend>` | Run or health-check a local MCP server over stdio. Backends: `gtags`, `clang`, `joern`, `tree-sitter`, `codeql`, `revng`. |
| `kuzushi auth ping [provider] [--model <spec>]` | Round-trip a 1-token request to verify credentials, network, and bridge. Interactive provider login is handled inside `kuzushi shell`. |
| `kuzushi config show` | Print effective config. |
| `kuzushi config init [--force]` | Write the default global config. |
| `kuzushi config path` | Print the global config path. |

Examples:

```bash
kuzushi doctor --target . --json
kuzushi scan . --mode standard --tasks semgrep,secret-scan --json
kuzushi scan . --tasks agentic-sast --triage --json
kuzushi findings --target . --severity high,critical --limit 10
kuzushi finding F-0001 --target .
kuzushi decision F-0001 --target . --verdict confirmed --reason "reviewed source-linked evidence"
kuzushi runs list --target .
kuzushi runs list --target . --status failed,partial
kuzushi runs diff run-a run-b --target . --json
kuzushi runs prune --target . --older-than-days 30 --keep-last 20 --dry-run
kuzushi export --target . --out findings.json --format json --completeness all
kuzushi export --target . --out complete.sarif --format sarif --completeness complete
kuzushi export --target . --out preview.json --format json --preview --allow-empty
kuzushi permissions --target .
kuzushi pr-comment --target . --repo allsmog/Kuzushi > kuzushi-report.md
kuzushi --target . run context:build --input '{}'
kuzushi --target . run semgrep:scan --input '{"config":"p/default"}'
kuzushi --target . run semgrep:scan --option config=p/default --input '{}'
kuzushi --target . run findings:list --input '{"severity":["high"],"limit":10}'
kuzushi --target . run triage:run --input '{"fingerprints":["abc123"]}'
```

Agentic tools require an explicit model. Set it in config or with
`KUZUSHI_MODEL=provider:model`, for example:

```bash
kuzushi config init
KUZUSHI_MODEL=openai:gpt-4.1 kuzushi scan . --tasks agentic-sast --json
```

Kuzushi does not silently choose a fallback model. If a runtime-backed tool has
no explicit model or an incompatible model/provider pair, startup or dispatch
fails with an actionable error.

## Options And Config

Tool behavior is driven by typed tool descriptors. Shell `set`/`setg`,
headless `run --option`, and `scan` flags all converge on the same canonical
preparation path before registry dispatch. Unknown keys fail unless the tool
declares a compatibility alias.

Precedence is global options, workspace options, session options, then
explicit JSON input. That means `--input` wins over `--option` when both set
the same canonical key.

| Surface | Purpose |
| --- | --- |
| `show options [tool]` | Inspect accepted option names, aliases, types, defaults, and current values. |
| `set <key> <value>` | Set a shell-session option for the focused tool. |
| `setg <key> <value>` | Persist a global option in `~/.kuzushi/v3/options.json`. |
| `kuzushi run <tool> --option key=value` | Apply a one-shot session option before `--input` is merged. |
| `kuzushi scan ...` | Compile scan flags into canonical `sast:scan` input. |

Persistent state lives in `~/.kuzushi/v3/options.json` and
`<target>/.kuzushi/v3/options.json`. Config remains separate for model,
runtime, bridge, budget, and approval policy. Project configs may set guided
phase fields, but model/runtime/operator policy is operator-owned and must live
in home config/models files, env bootstrap, or explicit tool input. See
[docs/operator-control-surfaces.md](docs/operator-control-surfaces.md).

## Review And Data Semantics

Kuzushi keeps scanner facts, model judgments, and human decisions distinct:

- **Scanner output** is the detector or tool result: rule id, severity,
  confidence, evidence, source location, raw result hash, and provenance.
- **Static proof state** is what the deterministic or static pipeline can
  support from artifacts such as SARIF, Semgrep, CodeQL, snapshots, and stored
  evidence.
- **Runtime verification** is an explicit verification result with its own
  proof level, verdict, cost, and run context.
- **Human review decision** is an append-only operator decision recorded by
  `kuzushi decision` or suppression flows. It has a human author and rationale,
  carries forward through run diffs by durable identity when safe, and is
  exported alongside scanner data without overwriting scanner triage.

Reports, exports, Workbench rows, and run diffs must preserve those meanings.
Avoid replacing them with generic labels such as "fixed", "done", or "AI
confirmed" unless the underlying state explicitly proves that claim.

## Rust Shell

The shell routes slash commands and their bare equivalents through the Rust
command parser. Help is grouped by workflow; `?` opens help, while `?text`,
`ask <question>`, and `/ask <question>` are explicit agent-chat routes.
Unknown prose does not silently dispatch to a model.
Piped shell output automatically uses the same strict plain renderer as
`--plain`.

| Command | Purpose |
| --- | --- |
| `/help` | Show grouped shell help. |
| `/modules`, `/tools`, `/use <module>`, `/back` | Browse modules/tools, focus a module, and step back. |
| `/run <tool> [json]`, `run . [json]`, `/scan [target]` | Dispatch a tool or start the native scan path. In the shell, `run .` resolves to the focused module's primary tool; from a terminal use `kuzushi run <module:tool>`. |
| `/ask <question>`, `ask <question>`, `?text` | Ask an explicit agent question with the configured model. |
| `/options [tool]`, `show options [tool]`, `show advanced [tool]`, `show missing [tool]` | Inspect typed Rust tool options and missing required values. |
| `/set <key> <value>`, `setg <key> <value>`, `/unset <key>`, `unsetg <key>` | Set or clear session/global option values for subsequent runs and scans. |
| `/tasks`, `/task block <id>`, `/task allow <id>`, `/task toggle [id]`, `/task mode auto\|manual\|toggle`, `/task reset` | Configure SAST task selection for `sast:scan` and shell scans. |
| `/context`, `/context build`, `/context status`, `/context regen <slice>` | View or rebuild the local context snapshot. |
| `/kb [module]`, `attachments`, `attach <path-or-url>`, `detach <id>`, `reparse <id>` | Manage local `.kuzushi/v3/` KB attachments; URL attachments are metadata-only. |
| `/workspace`, `workspace export findings <path> [format] [--allow-empty]`, `findings export <path>` | Show workspace state and export findings as JSON, JSONL, SARIF, CSV, or markdown bundle. |
| `/findings`, `/open <alias-or-fingerprint>`, `/show aliases [prefix]` | Load findings and open deterministic aliases such as `F-0001`. |
| `/show runs`, `/replay <runId>`, `/trace <runId>`, `/since <git-ref>` | Inspect replayable run artifacts and diff-scoped findings. |
| `/threats [dfd\|stride\|stories\|scope\|summary\|1..4]`, `/threats edit`, `/threats regen`, `/threats apply`, `/threats reject`, `/threats ask <question>` | Switch threat-model views or request and review a threat-model patch. |
| `/auth`, `/auth login <provider>`, `/provider`, `/backend`, `/model [choice]`, `/cost`, `/config`, `/permissions` | Show credential status without secrets, select explicit models, and report known cost/config/approval state. |
| `/history`, `/clear`, `/load <specifier>`, `/pause`, `/resume [runId]`, `/story` | Session utilities and precise replacement messages for unsupported legacy live-control paths. |
| `/prompts`, `/prompt <verb>`, `/tune`, `/actor <n>`, `/plan <english>` | Prompt, tuning, transcript, and planner surfaces. |
| `/quit`, `exit`, `/exit` | Exit. |

## Phase-Driven Workflow (組 → 崩 → 作 → 掛)

Launching the shell against a target opens a guided, four-phase engagement —
named after the judo throw Kuzushi is named for — instead of a flat task list.
Each phase opens a picker that announces what it is for and pre-checks a
dependency-correct task set:

| Phase | | Focus |
| --- | --- | --- |
| 組 **KUMI-KATA** | map | establish the grip — context, entry points, threat model, CPG/CodeQL, and reverse-engineering for binary/APK targets |
| 崩 **KUZUSHI** | hunt | break the target's balance — secrets, semgrep, CodeQL, taint, agentic SAST, threat-model-driven and systems hunts |
| 作 **TSUKURI** | confirm | commit the entry — triage then verify findings |
| 掛 **KAKE** | fix | finish the throw — patch and report |

- **Target-aware preselection.** The target is classified (source / JVM /
  Android APK / native binary) and each phase pre-checks the relevant tasks —
  e.g. reverse-engineering and `x-ray` are preselected for an APK, not a source
  tree. When a model is configured, the **session model** ranks the tools and
  refines the preselection (deterministic rule catalog otherwise; never a
  silent model fallback).
- **Reuse, don't rebuild.** Cached artifacts (CPG, CodeQL DB, context snapshot)
  are detected and reused by default — press `g` on a row to force a rebuild.
- **Dependency-aware failure.** If a task fails, only the tasks that depended on
  it are skipped; the independent rest of the queue keeps running.
- **Retry gate.** After 掛 KAKE, a `y`/`n` gate offers to re-run failed tasks
  with an auto-adjusted parameter when the cause is known (e.g. a joern
  `OutOfMemoryError` → re-run `cpg:build` with a larger `-J-Xmx`; see the
  `heapMb` option), unblocking the dependents that were skipped.

`cpg:build` accepts a `heapMb` option (defaulting to ~75% of physical RAM) and
classifies heap-exhaustion failures with an actionable message instead of an
opaque crash. The Activity view's OUTPUT pane starts on findings and switches
directly between generated security artifacts, including the threat model's
data-flow diagram (boxes, trust zones, flows) once a threat model exists.

## Built-In Modules

`kuzushi modules` is the source of truth for the visible native registry. The
current built-ins are:

| Module | Primary tools |
| --- | --- |
| `catalog` | `catalog:modules`, `catalog:tools` |
| `config` | `config:show` |
| `router` | `router:show` |
| `module-recommender` | `module-recommender:recommend` |
| `workspace` | `workspace:status`, `workspace:export-findings` |
| `context` | `context:build` |
| `sast` | `sast:scan` |
| `full-mode` | `full-mode:hunt` |
| `classifier-gate` | `classifier-gate:score` |
| `deep-audit` | `deep-audit:run` |
| `smoke` | `smoke:next-step` |
| `semgrep` | `semgrep:scan` |
| `codeql` | `codeql:scan` |
| `cargo-audit` | `cargo-audit:scan` |
| `govulncheck` | `govulncheck:scan` |
| `iac-scan` | `iac-scan:scan` |
| `exploit-chain` | `exploit-chain:scan` |
| `agentic-sast` | `agentic-sast:scan` |
| `offense-review` | `offense-review:threat-hunt` |
| `taint-iris-next` | `taint-iris-next:dataflow-plan`, `taint-iris-next:source-sink-trace`, `taint-iris-next:finding-review` |
| `threat-intel` | `threat-intel:list`, `threat-intel:apply`, `threat-intel:harvest` |
| `triage` | `triage:run` |
| `verify` | `verify:finding`, `verify:exploit` |
| `patch` | `patch:finding` |
| `findings` | `findings:list` |
| `report` | `report:build` |
| `threat-model` | `threat-model:build`, `threat-model:read`, `threat-model:methodologies` |
| `threat-intel` | `threat-intel:discover`, `threat-intel:list`, `threat-intel:apply`, `threat-intel:harvest` |
| `threat-leads` | `threat-leads:build`, `threat-leads:read` |
| `randori` | `randori:pasta`, `randori:threat-model` |
| `x-ray` | `x-ray:run`, `x-ray:read` |
| `dep-hygiene` | `dep-hygiene:check` |
| `secret-scan` | `secret-scan:scan` |
| `license-scan` | `license-scan:scan` |
| `sbom-scan` | `sbom-scan:scan` |
| `variant` | `variant:lift-pattern`, `variant:hunt` |
| `ndiff` | `ndiff:fetch-cve`, `ndiff:extract-fix-pattern`, `ndiff:hunt-variants` |
| `android-apk` | `android-apk:scan` |
| `entry-points` | `entry-points:extract` |
| `cpg` | `cpg:build` |
| `codeql-db` | `codeql:create-db` |
| `bounty` | `bounty:import-har`, `bounty:import-burp` |

Internal DAG modules such as `context-lite`, `pipeline`, and `systems-hunt`
stay hidden from `kuzushi modules`; `systems-hunt:*` entries are internal DAG
nodes selected through `sast:scan`, not public catalog tools. Deferred
compatibility and product-quarantine modules are also hidden from the public
catalog and shell completions, but remain executable by exact tool name for
operators who opt into them: `carlini-threat-hunt`, `classifier-gate`,
`chrome-rce`, `deep-audit`, `exploit-chain`, `full-mode`, `pwn`,
`threat-leads`, `uaf-hunt`, and `vendor-assessment`. Legacy folded tools such
as `taint-iris:hunt`, `taint-iris-next:hunt`, `randori:threat-model`,
`verify:exploit`, and the granular `android-apk:*` sub-scans are exact-name
compatibility entries; prefer the visible umbrella tools and descriptor options
shown above.

Optional plugin-backed adapters (`prompt-armor`, `shinsa`, `tob`, and
`vuln-scout`) self-hide when their plugin package is absent. When installed,
their canonical descriptor rows surface; legacy quick/deep aliases remain
exact-name compatibility entries where applicable.

Per-module operator guides live under `docs/`: [`docs/x-ray.md`](./docs/x-ray.md)
for repository analysis reports and [`docs/pwn.md`](./docs/pwn.md) for the
binary-exploitation workflow.

## External Dependencies

Native deterministic tools run without an LLM: `module-recommender`,
`context`, `findings`, `dep-hygiene`, `secret-scan`, `license-scan`, `sbom-scan`,
`iac-scan`, `govulncheck`, and local artifact readers.

`license-scan` checks package manifest license declarations, top-level
repository `LICENSE`/`COPYING` consistency, and SPDX source headers that
disagree with manifest licenses. Set `requireSourceSpdxHeaders` on
`license-scan:scan` to require SPDX headers on source files.

`sbom-scan` extracts first-party npm, Cargo, and Python dependency inventory
with package URLs, SHA-256 digests for recognized lockfiles, npm package-lock
dependency edges, and CycloneDX/SPDX JSON projections in the tool result.

Subprocess-backed tools require the operator to install or configure binaries:

| Tool | Dependency |
| --- | --- |
| `semgrep:scan` | `semgrep`, or pass `{"binary":"/path/to/semgrep"}`. |
| `codeql:scan` | CodeQL CLI, or pass `{"binary":"/path/to/codeql"}`. |
| `govulncheck:scan` | `govulncheck`, installed through the Go toolchain. |
| `recon:nmap` | `nmap`, or pass a binary override. |
| `recon:subdomain`, `recon:http-fingerprint`, online `ndiff:fetch-cve` | `curl`, unless using offline/local input. |

LangGraph-backed tools require Node, `@langchain/langgraph`,
`@langchain/openai` or `@langchain/anthropic`, a configured model, and provider
credentials. A custom bridge should be supplied through
`runtime.langgraph_bridge_command` in config; `KUZUSHI_LANGGRAPH_BRIDGE` is the
bootstrap override.

Deferred plugin-backed wrappers also require exact tool invocation plus
explicit plugin roots:

| Module | Preferred option | Compatibility env var |
| --- | --- | --- |
| `vuln-scout` | `pluginRoot` | `KUZUSHI_VULN_SCOUT_PLUGIN` |
| `tob` | `pluginRoot` | `KUZUSHI_TOB_SKILLS_DIR` |
| `shinsa` | `pluginRoot` | `KUZUSHI_SHINSA_PLUGIN` |
| `prompt-armor` | `pluginRoot` | `KUZUSHI_PROMPT_ARMOR_PLUGIN` |

Missing subprocesses, models, bridges, or plugin roots fail explicitly. They do
not silently succeed and they do not substitute a different model.

## Artifacts And State

| Path | Produced by |
| --- | --- |
| `~/.kuzushi/v3/config.toml` | `kuzushi config init` |
| `.kuzushi/v3/config.toml` | Optional project override |
| `~/.kuzushi/v3/options.json` | persisted global tool options from shell `setg` |
| `.kuzushi/v3/options.json` | optional project/workspace tool option overrides |
| `.kuzushi/v3/index.sqlite3` | scan, shell, and run-mode tool persistence |
| `.kuzushi/v3/log/events-*.jsonl` | append-only event log for v3 projection, review decisions, run lifecycle, verification, patch attempts, and audit events |
| `.kuzushi/v3/objects/blake3/` | content-addressed blobs, JSON objects, snapshots, and derived payloads referenced by artifacts/events |
| `.kuzushi/v3/scene-taint-flow.json` | persisted attack-path snapshot for `/scene`, Activity, and workbench views |
| `.kuzushi/v3/scene-exploit-chains.json` | persisted exploit-chain snapshot for `/scene`, Activity, and workbench views |
| `.kuzushi/v3/strategy-queue.jsonl` | persisted strategy proposals, status, outcome, cost, and correction history |
| `.kuzushi/v3/attachments.json` | Rust shell KB attachments |
| `.kuzushi/v3/artifact-kb.sqlite3` | Local artifact knowledge search index |
| `.kuzushi/context-snapshot.json` | `context:build` |
| `.kuzushi/threat-model.json` | `threat-model:*`, `randori:*`, and threat-model readers |
| `.kuzushi/v3/latest` | latest completed, partial, failed, skipped, or running run id |
| `.kuzushi/v3/runs/<runId>/run.json` | canonical run metadata, status, cost, LLM audit, and artifact list |
| `.kuzushi/v3/runs/<runId>/events.jsonl` | tool lifecycle events |
| `.kuzushi/v3/runs/<runId>/trace.jsonl` | ordered trace steps for replay and activity views |
| `.kuzushi/v3/runs/<runId>/failures.json` | bounded failure handoff context, empty when no failure is recorded |
| `.kuzushi/v3/runs/<runId>/report.md` | generated or placeholder Markdown report; promoted from `reportMarkdown` and `data.reportMarkdown` output fields |
| `.kuzushi/v3/runs/<runId>/artifacts.json` | canonical artifact manifest for the run |
| `.kuzushi/v3/runs/<runId>/input.json` | prepared tool input for direct tool runs |
| `.kuzushi/v3/runs/<runId>/result.json` | tool result envelope for direct tool runs |
| `.kuzushi/v3/runs/<runId>/report.sarif` | optional SARIF report promoted from `reportSarif` and `data.reportSarif` output fields |
| `.kuzushi/v3/runs/<runId>/<declared artifact>` | producer-declared sidecar artifacts such as context, attack-surface, findings, proof, or module-owned reports; only present when explicitly declared in `artifacts.json` |
| `.kuzushi/v3/runs/<runId>/triage.jsonl` | `sast:scan --triage` and post-scan triage |
| `.kuzushi/v3/runs/<runId>/verify.jsonl` | `sast:scan` with verify/auto-patch inputs |
| `x-ray/` | `x-ray:run` |
| `.kuzushi/vendor-assessment/` | vendor assessment tools |
| `.prompt-armor/` | PromptArmor deterministic config/report tools |

Machine-readable run schemas live under `schemas/run.*.schema.json` and ship
through the npm subpath `kuzushi/schemas/*`. They document the canonical
camelCase run metadata/event/failure fields such as `runId` and
`startedAtUnix`, plus canonical snake_case trace fields. Obsolete compatibility
aliases are rejected instead of normalized.

See [docs/rust-migration-status.md](docs/rust-migration-status.md) for the
module-by-module cutover ledger, intentional removals, artifact compatibility
notes, and TypeScript retention audit.

## Development

```bash
pnpm setup
cargo fmt --all
cargo test --workspace
cargo build --workspace
pnpm test:e2e
pnpm verify:pack
```

Useful package scripts:

| Script | Purpose |
| --- | --- |
| `pnpm dev -- <args>` | Run the native Rust CLI from source. |
| `pnpm build:native` | Build and stage the native binary for npm packaging. |
| `pnpm build` | Compile retained TypeScript library exports. |
| `pnpm test` | Run retained TypeScript unit/reference tests. |
| `pnpm test:rust` | Run `cargo test --workspace`. |
| `pnpm test:e2e` | Run the native smoke test. |
| `pnpm quality:crap-risk` | Gate changed production Rust/JS/TS code with the CRAP-risk < 7 proxy. |
| `pnpm doctor` | Run source-checkout development diagnostics; use `kuzushi doctor` for Rust CLI preflight. |
| `pnpm check:docs` | Guard port-contract docs, public docs/workflows, stale Rust CLI command examples, and retired TS runtime imports. |
| `pnpm export:source [path]` | Create a clean source tarball from tracked files with local state excluded. |

Design and audit documents for the current UX/data redesign live at the repo
root:

- [`ACCEPTED_FABLE_RECOMMENDATIONS.md`](./ACCEPTED_FABLE_RECOMMENDATIONS.md)
  maps generic UX recommendations back to real scanner semantics.
- [`REAL_IMPLEMENTATION_SPEC.md`](./REAL_IMPLEMENTATION_SPEC.md) is the
  implementation-ready spec for UX, TUI, CLI, data, state, persistence,
  reporting, migration, and tests.
- [`DOMAIN_RISK_REVIEW.md`](./DOMAIN_RISK_REVIEW.md) records wording,
  confidence/status, report, data-loss, and review-workflow risks.
- [`GPT_IMPLEMENTATION_BRIEF.md`](./GPT_IMPLEMENTATION_BRIEF.md) captures the
  implementation priorities, constraints, files to inspect, and required tests.
- [`REDESIGN_COMPLETION_AUDIT.md`](./REDESIGN_COMPLETION_AUDIT.md) records the
  commands and evidence used to verify this branch.

## TypeScript Retention

The old TypeScript/Ink CLI is no longer the npm runtime path:

- `bin.kuzushi` and `bin.kz` point to `bin/kuzushi-rs.mjs`.
- The `kuzushi-ts` npm bin is removed.
- The `dev:ts` package script and `scripts/kuzushi-dev` source CLI helper are
  removed.
- The source-only `src/cli.ts shell` route now exits with a Rust replacement
  message; the TypeScript/Ink shell implementation has been deleted.
- The old `dist/cli*` TypeScript CLI build outputs are excluded from the npm
  tarball.

Retained TypeScript is classified as one of:

- Published library/API surface: `dist/`, `kuzushi/modules`, and
  `kuzushi/testing`.
- Reference implementation for migration parity: legacy `src/modules/`,
  `src/agents/`, scanner normalization, and report helpers.
- Non-visual UI support code: `UIStore`, CI/plain-text output helpers,
  formatting helpers, and migration/reference fixtures. There is no retained
  TypeScript/Ink interactive TUI.

Do not add new runtime CLI behavior in TypeScript. New product execution paths
belong in `crates/kuzushi-core`, `crates/kuzushi-cli`, `crates/kuzushi-tui`,
or `crates/kuzushi-openai`.
