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
`--tasks`, and `--triage` compile into sparse `sast:scan` JSON input, then go
through the same preparation path as `kuzushi run sast:scan`.

## Shell

The Rust shell uses the same descriptors:

- `show options [tool]` lists accepted names, aliases, types, and values.
- `set <key> <value>` writes a session option for the focused tool.
- `unset <key>` clears a session option.
- `setg <key> <value>` writes a global option.
- `unsetg <key>` clears a global option.
- `scan` prepares `sast:scan` input from the option store before dispatch.

Session options last only for the shell process. Global options are persisted.
Workspace option files are loaded when present and preserved by the same store
format.

## Stored Paths

| Scope | Path |
| --- | --- |
| Global | `~/.kuzushi/v2/options.json` |
| Workspace | `<target>/.kuzushi/v2/options.json` |
| Session | in memory only |

Config uses separate paths:

| Config | Path |
| --- | --- |
| Global config | `~/.kuzushi/v2/config.toml` |
| Workspace config | `<target>/.kuzushi/v2/config.toml` |

Use config for durable runtime/provider defaults and global policy, not for
per-tool behavior. Current runtime/policy config includes:

```toml
model = "openai:gpt-4.1"

[runtime]
thinking_level = "high"
# langgraph_bridge_command = ["node", "scripts/langgraph-bridge.mjs"]

[operator]
session_budget_usd = 2.50
spend_hard_ceiling_usd = 10.00
trusted_workflow_auto_accept = false

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
runtime and `[operator]` fields remain global-only because a target repository
must not redirect credentials, process execution, or operator trust policy.

## Environment Variables

Environment variables remain appropriate for secrets and process integration:
provider API keys, OAuth bootstrap, `PATH`/`HOME`/`EDITOR`, terminal/plain-mode
presentation, test hooks, and documented emergency debug toggles.

Ordinary product behavior should not depend on new env vars. Prefer:

- tool options for scanner binaries, MCP/CodeQL/Joern tuning, prompt knobs,
  and plugin roots;
- config for runtime/provider defaults, model, bridge command, thinking level,
  budgets, and approval policy.

Compatibility env vars such as `KUZUSHI_MODEL`, `KUZUSHI_LANGGRAPH_BRIDGE`, and
legacy plugin root variables may still be read at config or adapter boundaries,
but modules and domain code should receive resolved values instead of reading
the process environment directly.
