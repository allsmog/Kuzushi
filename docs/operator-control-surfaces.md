# Operator Control Surfaces

Kuzushi tool behavior is driven by canonical tool options. CLI flags, shell
commands, persisted option stores, and direct `run` input all converge on
`ModuleRegistry::prepare_tool_input`.

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

`kuzushi run --autonomy <recon|hunt|confirm|fix>` sets the autonomy ceiling
for that run. The shared dispatch gate refuses any tool whose engagement phase
sits above the rung (`recon`→map, `hunt`→hunt, `confirm`→confirm, `fix`→fix)
with an actionable error — it never silently runs or substitutes it. Omitted =
`fix` (unconstrained, matching prior behavior). The requested rung is clamped
by `[phases].stop_after`; an unrecognized rung is a hard error.

## Shell

The Rust shell uses the same descriptors:

- `show options [tool]` lists accepted names, aliases, types, and values.
- `set <key> <value>` writes a session option for the focused tool.
- `unset <key>` clears a session option.
- `setg <key> <value>` writes a global option.
- `unsetg <key>` clears a global option.
- `scan` prepares `sast:scan` input from the option store before dispatch.
- `autonomy [recon|hunt|confirm|fix]` (alias `posture`) reads or sets the
  always-visible autonomy dial; `Ctrl+↑`/`Ctrl+↓` raise/lower it one rung. The
  dial is the same ceiling `kuzushi run --autonomy` sets; it is session-scoped
  and clamped by `[phases].stop_after`.

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
# Optional phase boundary for guided runs: map, hunt, confirm, or fix.
stop_after = "hunt"

[phases.hunt]
budget_usd = 1.25
concurrency = 2
strategy_cap = 3
prompt_variant = "deep"
confirmation_depth = "sampled"
```

Phase templates are the durable guided-workflow surface. They belong in
config, not environment variables. Project configs may set `[phases]` fields;
`model`, runtime, and `[operator]` fields remain global-only because a target
repository must not redirect model choice, credentials, process execution, or
operator trust policy.

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

## Environment Variables

Environment variables remain appropriate for secrets and process integration:
provider API keys, OAuth bootstrap, `PATH`/`HOME`/`EDITOR`, terminal/plain-mode
presentation, test hooks, and documented emergency debug toggles.

Ordinary product behavior should not depend on new env vars. Prefer:

- tool options for scanner binaries, MCP/CodeQL/Joern tuning, prompt knobs,
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

Some existing scanner/tool adapters still read compatibility env vars for
local binaries, caches, timeouts, or external toolchain integration (for
example CodeQL, Joern, Clang, rev.ng, and MCP bridge knobs). Treat those as
legacy adapter-boundary exceptions: do not add new product behavior env vars,
and migrate touched knobs toward declared options or config.
