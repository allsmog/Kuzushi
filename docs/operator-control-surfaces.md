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

`kuzushi scan` is a shorthand for `sast:scan`. Flags such as `--mode`,
`--tasks`, `--triage`, `--budget`, `--since`, `--include-worktree`,
`--fail-on`, and `--sarif` compile into sparse `sast:scan` JSON input or
scan-gate policy, then go through the same preparation path as
`kuzushi run sast:scan` where they are tool input.

Global `--load <specifier>` is supported for shell and headless `run`.
Specifier trust is controlled by `[operator].trusted_modules`; the dynamic
Node bridge only loads trusted specifiers. Untrusted analyzers belong in the
v3 sandbox plugin path.

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
trusted_modules = ["file:///absolute/path/to/my-module"]

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

## Environment Variables

Environment variables remain appropriate for secrets and process integration:
provider API keys, OAuth bootstrap, `PATH`/`HOME`/`EDITOR`, terminal/plain-mode
presentation, test hooks, and documented emergency debug toggles.

Ordinary product behavior should not depend on new env vars. Prefer:

- tool options for scanner binaries, MCP/CodeQL/Joern tuning, prompt knobs,
  and plugin roots;
- config for runtime/provider defaults, model, bridge command, thinking level,
  budgets, and approval policy.

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
