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
- Each run records an authoritative typed, hash-chained lifecycle stream at
  `.kuzushi/v3/runs/<runId>/items.jsonl`. One reducer projects it, so live Run
  Focus, `runs replay`, plain output, and the JSON projection are the same
  answer rather than four hand-maintained renderings; cross-surface equivalence
  is test-enforced.
- Run integrity is disclosed, not assumed. A stream that fails its hash chain,
  sequence, or text policy stops at the last valid prefix and reports the
  degradation. A recorded completion whose evidence is degraded or whose
  durability failed is quarantined to `partial` and offers only run inspection,
  so a damaged log can never route an operator to a Report it did not earn.
- Every operator-visible lifecycle string is redacted, control-escaped, and
  bounded by construction, and that policy is checked again on read rather
  than trusted from the writer.
- Shell causality is recorded separately as redacted semantic JSONL under
  `~/.kuzushi/v3/sessions/`; `kuzushi sessions list|show|export|prune` inspects
  that global operator-owned history without treating it as target evidence.
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

Kuzushi is local-first and ships **no first-party telemetry**. Findings,
evidence, run artifacts, and suppressions live under `.kuzushi/` in your
workspace; redacted shell session transcripts live under
`~/.kuzushi/v3/sessions/` and expire after 30 days by default. Network access is
tool-dependent: configured model providers receive
prompts only when you invoke model-backed tools, while external scanners chosen
automatically or explicitly may fetch rules or contact services according to
their own documented behavior. Kuzushi disables Semgrep metrics, but registry-backed
configs such as `auto` still fetch rules. `kuzushi demo` and the fully bundled
task list in Quick Start are the zero-network paths. Model and runtime selection
is explicit: Kuzushi never silently falls back to a different provider or
model.

Operator-visible run lifecycle text is redacted by construction rather than by
convention: every such string is routed through the shared redaction policy,
control-escaped, and length-bounded before it is written, and the same policy is
re-applied when the stream is read back. Bridge failures surface as a fixed set
of error classes instead of raw provider or subprocess output, and `trace.jsonl`
carries no prompts or model-response previews.

## Install

Kuzushi requires Node.js 22 or newer. The npm package declares this in
`engines.node`; upgrade Node before installing if `node --version` reports an
older major version.

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

The published `kuzushi` command resolves `native/<platform>-<arch>/kuzushi`.
The `kz` command is an argv0 alias over that same binary, so the package does
not duplicate it. Each platform directory also contains the sibling
`kuzushi-mcp-*` servers advertised by the CLI, and the wrapper places that
private runtime directory first on the child `PATH`. Set `KUZUSHI_NATIVE_BIN`
to point the wrapper at a specific CLI binary.

The npm installation is the complete product distribution: it installs the
Node bridge dependencies and ships the LangGraph and trusted dynamic-module
host scripts alongside the native runtime. GitHub's platform-specific native
archives contain the CLI plus its MCP server siblings, but intentionally omit
the Node dependency tree; use the npm tarball or a source checkout for
model-backed and trusted dynamic-Node tools.

Release platform policy is explicit:

| Platform payload | Release status |
| --- | --- |
| `linux-x64` | Required; a failed build blocks publication. |
| `darwin-arm64` | Required; a failed build blocks publication. |
| `linux-arm64`, `darwin-x64`, `win32-x64` | Best effort; included in npm and GitHub artifacts only after that matrix leg succeeds. |

## Quick Start

This is the golden path. It is the workflow new operators should try before
touching advanced modules or deferred plugin-backed tools.

Kuzushi writes target-local state below `.kuzushi/`. On first initialization
it creates `.kuzushi/.gitignore` when that file is absent. The generated policy
keeps databases, traces, locks, findings, and other runtime state local, while
leaving `.kuzushi/scope.toml`, `.kuzushi/prompts/**`, and
`.kuzushi/v3/config.toml` available for deliberate team versioning. Review
those project files before committing them; never commit credentials or an
unreviewed live state tree. Do not add a parent-level blanket `.kuzushi/`
rule: Git will then hide the deliberately trackable exceptions before the
child policy can re-include them. Ignore credentials by their exact path.

```bash
# 90-second offline tour: scan a vendored vulnerable fixture with the
# deterministic engines. It records scanner signals and honest signal_only
# proof states; it does not claim source-grounded confirmation.
kuzushi demo

# Check config, local state, scanners, and the LangGraph bridge.
kuzushi doctor --target .

# Build the repository context snapshot used by shell and model-backed tools.
kuzushi --target . run context:build --input '{}'

# Fully bundled offline scan: no API key, model, or external scanner required.
kuzushi scan . \
  --tasks dep-hygiene,secret-scan,license-scan,iac-scan \
  --ci

# Optional Semgrep pass after installing Semgrep. Auto-selected default scans
# visibly skip an unavailable Semgrep; explicitly requesting it stays fail-closed.
kuzushi scan . --mode standard --tasks semgrep --ci

# Inspect persisted findings. A clean repository may legitimately list none.
kuzushi findings --target . --limit 10

# If the list contains an alias, use that displayed alias to inspect and review
# the finding. Skip these optional steps when the list is empty:
#   kuzushi finding <displayed-alias> --target .
#   kuzushi decision <displayed-alias> --target . --verdict confirmed \
#     --reason "reviewed the scanner signal and source before accepting it"

# Render a markdown PR/security review summary from persisted findings.
kuzushi pr-comment --target . > kuzushi-report.md

# Or export the canonical persisted projection, including an honest empty list.
kuzushi export --target . --format json --completeness complete \
  --allow-empty --out findings.json
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
| `kuzushi demo` | Scan a vendored vulnerable fixture offline — no API key, no model, no external scanners. It records real scanner signals and redacted locations at the honest `signal_only` proof state; it does not claim source-grounded proof. |
| `kuzushi scan <repo> [--mode standard\|whitebox-static] [--tasks a,b] [--triage] [--json] [--ci] [--fail-on low\|medium\|high\|critical] [--sarif out.sarif]` | Run the Rust SAST umbrella executor and persist findings. `--fail-on` exits 3 when findings at/above the severity exist (CI gating); `--sarif` writes a SARIF 2.1.0 export for Code Scanning upload. Descriptor-backed inputs also support `verifyWhen`, `verifyMax`, and `verifyVotes` for post-triage verification selection. |
| `kuzushi findings --target <repo> [--severity high,critical] [--verdict true_positive] [--name text] [--file-path path] [--vuln-source sarif,...] [--limit 50] [--json]` | List persisted findings. |
| `kuzushi finding <F-0001\|fingerprint-prefix> --target <repo> [--json]` | Inspect one finding's evidence, proof state, verification summary, patch result, and next action. |
| `kuzushi decision <F-0001\|fingerprint-prefix> --target <repo> --verdict confirmed\|rejected_false_positive\|suppressed\|deferred\|accepted_risk\|needs_review --reason <text> [--json]` | Append a human review decision for a persisted finding. This carries forward by durable identity and does not mutate scanner triage. |
| `kuzushi runs list [--status completed,failed]\|show <runId>\|replay <runId> [--json]\|trace <runId>\|diff <a> <b>\|prune --target <repo>` | Inspect, replay, compare, or prune runs under `.kuzushi/v3/runs/<runId>/`. `replay` reduces the authoritative typed `items.jsonl` lifecycle and reports projection health; `--json` emits the machine-readable projection. `trace` prints non-authoritative diagnostics. |
| `kuzushi export --target <repo> --out <path> [--format json\|jsonl\|sarif\|csv\|markdown-bundle] [--completeness all\|open\|complete] [--preview] [--allow-empty]` | Export or preview the canonical persisted findings projection with review state and provenance. |
| `kuzushi suppress <F-0001> --target <repo> --reason <text> [--days 90]` | Record an expiring, evidence-backed suppression; findings remain visible in audit/report output. |
| `kuzushi suppressions --target <repo>` | List suppression memory and the audit store path. |
| `kuzushi permissions [--target <repo>]` | Show the current model fallback, approval, headless-run, and sandbox policy summary. |
| `kuzushi pr-comment --target <repo> [--repo owner/name] [--run-url url] [--git-sha sha]` | Render persisted findings as a markdown PR/security review comment. |
| `kuzushi modules [--json]` | List visible native modules. |
| `kuzushi tools [--json]` | List visible executable tool descriptors. |
| `kuzushi doctor [--target <repo>] [--json]` | Check config, local state, findings DB openability, scanner binaries, bridge readiness, and model/auth setup. |
| `kuzushi run <module:tool> --input '<json>' [--option key=value]` | Execute one explicit tool through the Rust registry. Use global `--target` for workspace-backed tools; `run .` is shell-only focused-module shorthand. |
| `kuzushi mcp serve\|health <backend>` | Run or health-check a shipped local MCP server over stdio. Backends: `gtags`, `clang`, `joern`, `tree-sitter`, `codeql`, `revng`, `context`, `entry-points`, `threat-model`, `threat-intel`, `x-ray`. |
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
kuzushi decision F-0001 --target . --verdict confirmed --reason "reviewed scanner signal and source"
kuzushi runs list --target .
kuzushi runs list --target . --status failed,partial
kuzushi runs replay <runId> --target .
kuzushi runs replay <runId> --target . --json
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
| `/show runs`, `/replay <runId>`, `/trace <runId>`, `/since <git-ref>` | Inspect replayable run artifacts and diff-scoped findings. `/replay` reduces the run's typed lifecycle projection; `/trace` shows non-authoritative diagnostics. |
| `/threats [dfd\|stride\|stories\|scope\|summary\|1..4]`, `/threats edit`, `/threats regen`, `/threats apply`, `/threats reject`, `/threats ask <question>` | Switch threat-model views or request and review a threat-model patch. |
| `/auth`, `/auth login <provider>`, `/provider`, `/backend`, `/model [choice]`, `/cost`, `/config`, `/permissions` | Show credential status without secrets, select explicit models, and report known cost/config/approval state. |
| `/session`, `/history`, `/clear`, `/load <specifier>`, `/pause`, `/resume [runId]`, `/story` | Show durable transcript health plus session utilities and precise replacement messages for unsupported legacy live-control paths. |
| `/prompts`, `/prompt <verb>`, `/tune`, `/actor <n>`, `/plan <english>` | Prompt, tuning, transcript, and planner surfaces. |
| `/quit`, `exit`, `/exit` | Exit. |

## Phase-Driven Workflow (Map → Scan → Review → Prove → Fix)

Launching the shell against a target opens a guided five-phase engagement
instead of a flat task list. `Shift+Tab` moves between the five interaction
modes without changing the shared draft or the durable reality checkpoint.
Each phase announces what it is for and constrains planning to its own
descriptor-backed tools:

| Phase | | Focus |
| --- | --- | --- |
| ◇ **MAP** | map | establish context, scope, entry points, threat models, indexes, CPGs, and CodeQL databases |
| ▦ **SCAN** | scan | run secrets, Semgrep, CodeQL, taint, agentic SAST, and semantic hunts to create candidate observations |
| ▣ **REVIEW** | review | triage, classify, dismiss, defer, and persist durable review decisions |
| ◎ **PROVE** | prove | verify actionable findings and retain empirical evidence with run provenance |
| ◆ **FIX** | fix | draft, approve, apply, detector-bound re-verify, and report remediation |

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
- **Retry gate.** In Fix, a `y`/`n` gate offers to re-run failed tasks
  with an auto-adjusted parameter when the cause is known (e.g. a joern
  `OutOfMemoryError` → re-run `cpg:build` with a larger `-J-Xmx`; see the
  `heapMb` option), unblocking the dependents that were skipped.

`cpg:build` accepts a `heapMb` option (defaulting to ~75% of physical RAM) and
classifies heap-exhaustion failures with an actionable message instead of an
opaque crash. The Activity view's OUTPUT pane starts on findings and switches
directly between generated security artifacts, including the threat model's
data-flow diagram (boxes, trust zones, flows) once a threat model exists.

## Capabilities and engines

The interactive product is organized around six operator capabilities rather
than a scanner catalog:

| Capability | Canonical boundary | What the operator does |
| --- | --- | --- |
| Recon | `recon:*` | import or collect target evidence |
| Threat map | `threat-model:*` | map boundaries, flows, and attack surface |
| Scan | `sast:scan` | run a target-aware composition of candidate-generating engines |
| Review | `findings:*` | triage, suppress, defer, or record a terminal review decision |
| Verify | `verify:finding` | corroborate a selected claim with proof |
| Fix | `patch:finding` | review remediation and export the result |

The shell opens on the phase Workbench. `modules` opens a small contextual
**Capabilities** overlay; press `e` in Navigate mode to reveal direct engines
and installed integrations. `tools [query]` remains the exhaustive expert
inventory, while `kuzushi modules --json` and `kuzushi tools --json` are the
machine-readable registry views.

Individual engines such as Semgrep, CodeQL, cargo-audit, secret scanning,
Taint IRIS Next, and offense review remain real descriptor-backed tools. They
are composed by `sast:scan` or selected deliberately from Expert mode rather
than presented as competing products. Context, entry-point, CPG, CodeQL DB,
triage, suppression, report, configuration, and workspace modules are support
steps folded into their owning capability.

Compatibility facades remain exact-runnable for the migration window but do
not appear in discovery. See [`docs/api-compatibility.md`](./docs/api-compatibility.md)
for successor commands. Optional adapters (`prompt-armor`, `shinsa`, `tob`,
and `vuln-scout`) are no longer activated merely because a development package
exists in `node_modules`; an operator must configure the corresponding adapter
explicitly.

Run `kuzushi tools --json` for the current canonical tool inventory. Per-engine
guidance remains under `docs/`, including [`docs/x-ray.md`](./docs/x-ray.md).

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

The npm and native release payloads include every `kuzushi-mcp-*` server.
Some servers wrap an operator-installed analysis engine: `gtags` needs GNU
GLOBAL, `clang` needs clangd, `joern` needs Joern (or `JOERN_SERVER_URL`),
`codeql` needs CodeQL plus a database, and `revng` needs its documented
container runtime. `tree-sitter` and the artifact readers are self-contained;
their `health` commands work without those external engines.

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
| `.kuzushi/.gitignore` | first target-state initialization; ignores generated state while keeping `scope.toml`, `prompts/**`, and `v3/config.toml` shareable |
| `.kuzushi/v3/config.toml` | Optional project override |
| `~/.kuzushi/v3/options.json` | persisted global tool options from shell `setg` |
| `.kuzushi/v3/options.json` | optional project/workspace tool option overrides |
| `.kuzushi/v3/index.sqlite3` | scan, shell, and run-mode tool persistence |
| `.kuzushi/v3/log/events-*.jsonl` | append-only event log for v3 projection, review decisions, verification, patch attempts, audit events, and idempotently bridged terminal run facts. Per-run lifecycle lives in `runs/<runId>/items.jsonl`; run replay reduces that per-run stream and never reconstructs from this log |
| `.kuzushi/v3/objects/blake3/` | content-addressed blobs, JSON objects, snapshots, and derived payloads referenced by artifacts/events |
| `.kuzushi/v3/scene-taint-flow.json` | persisted attack-path snapshot for `/scene`, Activity, and workbench views |
| `.kuzushi/v3/scene-exploit-chains.json` | persisted exploit-chain snapshot for `/scene`, Activity, and workbench views |
| `.kuzushi/v3/strategy-queue.jsonl` | persisted strategy proposals, status, outcome, cost, and correction history |
| `.kuzushi/v3/workflow/phase-attempts.jsonl` | workflow-v1 phase attempt ledger; still written for compatibility |
| `.kuzushi/v3/workflow/phase-attempts.v2.jsonl` | schema-v2 phase attempt ledger. Reference-only: attempts point at runs by id instead of duplicating run facts, and a receipt is refused rather than built from a degraded projection |
| `.kuzushi/v3/attachments.json` | Rust shell KB attachments |
| `.kuzushi/v3/artifact-kb.sqlite3` | Local artifact knowledge search index |
| `.kuzushi/context-snapshot.json` | `context:build` |
| `.kuzushi/threat-model.json` | `threat-model:*`, `randori:*`, and threat-model readers |
| `.kuzushi/v3/latest` | latest completed, partial, failed, skipped, or running run id |
| `.kuzushi/v3/runs/<runId>/run.json` | canonical run metadata, status, cost, LLM audit, and artifact list |
| `.kuzushi/v3/runs/<runId>/items.jsonl` | authoritative typed, hash-linked run lifecycle for new runs; live Run Focus, replay, plain output, and APIs reduce this stream |
| `.kuzushi/v3/runs/<runId>/events.jsonl` | compatibility projection of typed lifecycle items during the migration window; authoritative only for legacy runs |
| `.kuzushi/v3/runs/<runId>/trace.jsonl` | non-authoritative bounded diagnostics and model/tool audit during the migration window |
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

`items.jsonl` does not yet have a published JSON Schema. Until it does, consume
it through `kuzushi runs replay --json` or the `kuzushi_core::run_lifecycle`
Rust types rather than parsing the stream directly.

Typed run lifecycle and phase attempts are in a compatibility window: new runs
write authoritative `items.jsonl` while dual-writing the compatibility
`events.jsonl` and diagnostic `trace.jsonl`, and new phase attempts write
`phase-attempts.v2.jsonl` alongside the unchanged workflow-v1 record. Readers
prefer the typed and v2 data and disclose lossy fallback for legacy runs that
predate it. Nothing is rewritten in place. See
[RELEASING.md](./RELEASING.md) for the migration plan.

Current implementation boundaries are documented in
[docs/modules.md](docs/modules.md),
[docs/assessments/mode-parity.md](docs/assessments/mode-parity.md), and
[docs/architecture/domain-boundaries.md](docs/architecture/domain-boundaries.md).

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
| `pnpm build:native` | Build and stage the CLI plus all shipped MCP server binaries for npm packaging. |
| `pnpm build` | Compile retained TypeScript library exports. |
| `pnpm test` | Run retained TypeScript unit/reference tests. |
| `pnpm test:rust` | Run `cargo test --workspace`. |
| `pnpm test:e2e` | Run the native smoke test. |
| `pnpm quality:crap-risk` | Gate changed production Rust/JS/TS code with the CRAP-risk < 7 proxy. |
| `pnpm quality:architecture` | Gate DDD boundaries, artifact/result-envelope contracts, env discipline, and the dispatch and run-lifecycle boundaries. |
| `pnpm quality:model-safety` | Gate the no-silent-fallback model/runtime policy. |
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

- Published compatibility SDK source: `src/modules/`, `src/testing/`,
  `src/agent-runtime/types.ts`, `src/bus/types.ts`, and the public root types;
  these build the `kuzushi`, `kuzushi/modules`, and `kuzushi/testing` exports.
- TypeScript-only benchmark, code-generation, and packaging tooling that
  validates those exports and the native release wrapper.

There is no retained TypeScript scanner runtime or interactive TUI.

Do not add new runtime CLI behavior in TypeScript. New product execution paths
belong in `crates/kuzushi-core`, `crates/kuzushi-cli`, `crates/kuzushi-tui`,
or `crates/kuzushi-openai`.
