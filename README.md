<img src="kuzushi.png" alt="Kuzushi" width="200" />

# Kuzushi

Kuzushi is an open-source AI cybersecurity copilot. The primary product path is
the native Rust CLI and Ratatui shell; the npm package is a thin wrapper around
that native binary.

## Install

```bash
npm install -g kuzushi
kuzushi --help
```

From a source checkout:

```bash
pnpm setup
pnpm dev -- --help
pnpm build:native
node bin/kuzushi-rs.mjs --help
```

The published `kuzushi` command resolves `native/<platform>-<arch>/kuzushi`
first, then local Cargo build outputs. Set `KUZUSHI_NATIVE_BIN` to point the
wrapper at a specific binary.

## Quick Start

```bash
# Start the Rust terminal shell.
kuzushi

# Run the default native scan path against a repo.
kuzushi scan .

# Persisted findings can be reviewed headlessly.
kuzushi findings --target .

# Or execute one tool through the same Rust registry.
kuzushi --target . run secret-scan:scan --input '{}'
```

Fresh native state is stored under `.kuzushi/v2/`; scan-run summaries and
triage/verification JSONL remain under `.kuzushi/runs/<runId>/`.

There is no Rust `kuzushi doctor` subcommand in this cutover. In a source
checkout, `pnpm doctor` runs the read-only development environment diagnostic.

## Native CLI

```text
kuzushi [--target <path>] [command]
```

Bare `kuzushi` starts the shell.

| Command | Purpose |
| --- | --- |
| `kuzushi shell [--target <repo>]` | Start the Ratatui shell. |
| `kuzushi scan <repo> [--tasks a,b] [--triage] [--json]` | Run the Rust SAST umbrella executor and persist findings. |
| `kuzushi findings --target <repo> [--severity high,critical] [--verdict true_positive] [--name text] [--file-path path] [--limit 50] [--json]` | List persisted findings. |
| `kuzushi modules [--json]` | List visible native modules. |
| `kuzushi tools [--json]` | List visible executable tool descriptors. |
| `kuzushi run <module:tool> --input '<json>'` | Execute one tool through the Rust registry. Use global `--target` for workspace-backed tools. |
| `kuzushi config show` | Print effective config. |
| `kuzushi config init [--force]` | Write the default global config. |
| `kuzushi config path` | Print the global config path. |

Examples:

```bash
kuzushi scan . --tasks semgrep,secret-scan --json
kuzushi scan . --tasks agentic-sast --triage --json
kuzushi --target . run semgrep:scan --input '{"config":"p/default"}'
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

## Rust Shell

The shell routes slash commands and their bare equivalents through the Rust
command parser. Useful commands:

| Command | Purpose |
| --- | --- |
| `/help` | Show shell help. |
| `/modules` | Browse visible native modules. |
| `/tools` | Show executable tool descriptors. |
| `/use <module>` | Focus a module. |
| `/run [tool] [json]` | Run a tool; focused modules can omit the prefix when unambiguous. |
| `/scan [target]` | Start a native scan in the shell. |
| `/findings` | Load persisted findings. |
| `/open <fingerprint-or-prefix>` | Open a finding. |
| `/model [provider:model]` | Show or set the in-memory shell model. |
| `/config` | Show runtime/model config in the shell. |
| `/threats [dfd|stride|stories|scope|summary|1..5]` | Switch threat-model views. |
| `/prompts`, `/prompt <verb>` | Inspect prompt override surfaces. |
| `/show runs`, `/replay <runId>`, `/trace <runId>` | Inspect scan-run artifacts. |
| `/since <git-ref>` | Switch to a diff-scoped findings view. |
| `/back` | Step up one view. |
| `/quit` | Exit. |

`?` is currently an alias for help in the Rust shell; agent chat is not
advertised as a shell route in this cutover.

## Built-In Modules

`kuzushi modules` is the source of truth for the visible native registry. The
current built-ins are:

| Module | Primary tools |
| --- | --- |
| `context` | `context:build` |
| `sast` | `sast:scan` |
| `semgrep` | `semgrep:scan` |
| `codeql` | `codeql:scan` |
| `agentic-sast` | `agentic-sast:scan` |
| `carlini-threat-hunt` | `carlini-threat-hunt:run` |
| `taint-iris` | `taint-iris:hunt` |
| `taint-iris-next` | `taint-iris-next:hunt` |
| `triage` | `triage:run` |
| `verify` | `verify:finding` |
| `patch` | `patch:finding` |
| `findings` | `findings:list` |
| `threat-model` | `threat-model:build`, `threat-model:read`, `threat-model:methodologies` |
| `randori` | `randori:pasta`, `randori:threat-model` |
| `x-ray` | `x-ray:run`, `x-ray:read` |
| `vendor-assessment` | `vendor-assessment:attach`, `vendor-assessment:scope`, `vendor-assessment:prompts`, `vendor-assessment:assess` |
| `chrome-rce` | `chrome-rce:scan`, `chrome-rce:review-trigger` |
| `dep-hygiene` | `dep-hygiene:check` |
| `secret-scan` | `secret-scan:scan` |
| `variant` | `variant:lift-pattern`, `variant:hunt` |
| `ndiff` | `ndiff:fetch-cve`, `ndiff:extract-fix-pattern`, `ndiff:hunt-variants` |
| `vuln-scout` | `vuln-scout:audit` |
| `tob` | `tob:audit`, `tob:skills` |
| `shinsa` | `shinsa:scan`, `shinsa:quick-check`, `shinsa:nist-scan`, `shinsa:nist-quick-check`, `shinsa:frameworks` |
| `prompt-armor` | `prompt-armor:scan`, `prompt-armor:analyze`, `prompt-armor:attack`, `prompt-armor:diff`, `prompt-armor:report`, `prompt-armor:config` |
| `recon` | `recon:nmap`, `recon:subdomain`, `recon:http-fingerprint` |
| `iac-scan` | `iac-scan:scan` |
| `catalog` | `catalog:modules`, `catalog:tools` |
| `config` | `config:show` |
| `workspace` | `workspace:status` |

Internal DAG modules such as `context-lite`, `pipeline`, and `systems-hunt`
stay hidden from `kuzushi modules`.

## External Dependencies

Native deterministic tools run without an LLM: `context`, `findings`,
`dep-hygiene`, `secret-scan`, `iac-scan`, Chrome RCE native checks, and local
artifact readers.

Subprocess-backed tools require the operator to install or configure binaries:

| Tool | Dependency |
| --- | --- |
| `semgrep:scan` | `semgrep`, or pass `{"binary":"/path/to/semgrep"}`. |
| `codeql:scan` | CodeQL CLI, or pass `{"binary":"/path/to/codeql"}`. |
| `recon:nmap` | `nmap`, or pass a binary override. |
| `recon:subdomain`, `recon:http-fingerprint`, online `ndiff:fetch-cve` | `curl`, unless using offline/local input. |

pi-agent-core-backed tools require Node, `@mariozechner/pi-agent-core`,
`@mariozechner/pi-ai`, a configured model, and provider credentials. A custom
bridge can be supplied through `runtime.agent_bridge_command` in config or
`KUZUSHI_AGENT_BRIDGE`.

Plugin-backed wrappers also require explicit plugin roots:

| Module | Environment variable |
| --- | --- |
| `vuln-scout` | `KUZUSHI_VULN_SCOUT_PLUGIN` |
| `tob` | `KUZUSHI_TOB_SKILLS_DIR` |
| `shinsa` | `KUZUSHI_SHINSA_PLUGIN` |
| `prompt-armor` | `KUZUSHI_PROMPT_ARMOR_PLUGIN` |

Missing subprocesses, models, bridges, or plugin roots fail explicitly. They do
not silently succeed and they do not substitute a different model.

## Artifacts And State

| Path | Produced by |
| --- | --- |
| `~/.kuzushi/v2/config.toml` | `kuzushi config init` |
| `.kuzushi/v2/config.toml` | Optional project override |
| `.kuzushi/v2/findings.sqlite3` | scan, shell, and run-mode tool persistence |
| `.kuzushi/context-snapshot.json` | `context:build` |
| `.kuzushi/threat-model.json` | `threat-model:*`, `randori:*`, and threat-model readers |
| `.kuzushi/runs/<runId>/summary.json` | `sast:scan` |
| `.kuzushi/runs/<runId>/triage.jsonl` | `sast:scan --triage` and post-scan triage |
| `.kuzushi/runs/<runId>/verify.jsonl` | `sast:scan` with verify/auto-patch inputs |
| `x-ray/` | `x-ray:run` |
| `.kuzushi/vendor-assessment/` | vendor assessment tools |
| `.prompt-armor/` | PromptArmor deterministic config/report tools |

See [docs/rust-migration-status.md](docs/rust-migration-status.md) for the
module-by-module cutover ledger, intentional removals, artifact compatibility
notes, and TypeScript/Ink retention audit.

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
| `pnpm doctor` | Run source-checkout diagnostics. |

## TypeScript Retention

The old TypeScript/Ink CLI is no longer the npm runtime path:

- `bin.kuzushi` points to `bin/kuzushi-rs.mjs`.
- The `kuzushi-ts` npm bin is removed.
- The `dev:ts` package script and `scripts/kuzushi-dev` source CLI helper are
  removed.
- The old `dist/cli*` TypeScript CLI build outputs are excluded from the npm
  tarball.

Retained TypeScript is classified as one of:

- Published library/API surface: `dist/`, `kuzushi/modules`, and
  `kuzushi/testing`.
- Reference implementation for migration parity: legacy `src/modules/`,
  `src/agents/`, scanner normalization, and report helpers.
- Test-only or fixture UI code: Ink/React components, mock TUI scenarios, and
  Vitest suites that preserve expected behavior while the Rust shell matures.

Do not add new runtime CLI behavior in TypeScript. New product execution paths
belong in `crates/kuzushi-core`, `crates/kuzushi-cli`, `crates/kuzushi-tui`,
or `crates/kuzushi-openai`.
