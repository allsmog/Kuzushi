# Kuzushi modules

This document describes the module surfaces implemented by the current Rust
product. Kuzushi has two authoring paths:

- First-party capabilities are Rust descriptors plus Rust executors registered
  in `ModuleRegistry`.
- Third-party local capabilities are single-file JavaScript workers using the
  brokered Kuzushi Worker Protocol (KWP).

There is no TypeScript authoring SDK and the npm package does not export
`kuzushi/modules` or `kuzushi/testing`. The published package contains the
public schemas, native launcher, and Node support files used by the Rust
product.

Companion docs: [`mcp-server-requirements.md`](./mcp-server-requirements.md)
for MCP-bridged modules; [`api-compatibility.md`](./api-compatibility.md)
for legacy aliases and route compatibility; [`module-maturity.md`](./module-maturity.md)
for Core, Labs, and Compatibility discovery policy;
[`devex/06-module-sdk-assessment.md`](./devex/06-module-sdk-assessment.md)
for the historical SDK audit that shaped the current surface.

## Sources of truth

Use these in descending order when documentation and code disagree:

1. `schemas/module.manifest.schema.json` for the published compatibility
   manifest shape.
2. Rust descriptor and registry types under
   `crates/kuzushi-core/src/modules/` for live product behavior.
3. `scripts/kuzushi-dynamic-module-host.mjs` and
   `crates/kuzushi-core/src/modules/dynamic_loader.rs` for the dynamic worker
   protocol.
4. `examples/kwp/agentic-fuzz/` for an executable local-worker example.

Changing a public schema or persisted `.kuzushi` contract requires a migration
section in `RELEASING.md`, documentation, and focused compatibility tests.

## Rust built-ins

A live built-in is a `BuiltinModule` with `ToolDescriptor` values and a Rust
executor mapping. The descriptor is the policy surface; the executor consumes
already prepared canonical input.

Important locations:

- `crates/kuzushi-descriptor/src/` — tool metadata, `OptionSpec`, prompts,
  phase, effect, approval, and runtime/workspace requirements.
- `crates/kuzushi-core/src/modules/builtins/with_v2_builtins/` — registration,
  lookup, execution, DAG metadata, and output normalization.
- `crates/kuzushi-core/src/modules/registry/` — registry facade and dynamic
  module installation.
- `crates/kuzushi-core/src/modules/options/` — stored-option merging,
  validation, coercion, defaults, aliases, and unknown-key rejection.
- `crates/kuzushi-core/src/modules/application/sast_scan/` — umbrella scan
  orchestration and continuation stages.

### Dispatch contract

CLI scan, shell, and headless run must converge on the authorization-bound
registry path:

1. `ModuleRegistry::prepare_dispatch_input(...)` merges and validates options,
   normalizes paths, applies declared prompt defaults, binds any repository
   execution input, and returns an opaque `PreparedToolInput`.
2. The launching mode adds any required explicit or interactive authorization.
3. It dispatches with `dispatch_prepared_input_with_runtime(...)` or
   `dispatch_prepared_input_observed_with_runtime(...)` when lifecycle
   observation is required.

The raw `dispatch_prepared_tool_with_runtime(name, Value, ...)` method remains a
compatibility boundary. It deliberately re-runs preparation and should not be
the model for new callers. Direct executor calls from a mode-specific path are
not allowed.

### Adding a built-in tool

1. Choose a stable kebab-case module id and a tool name in
   `<module-id>:<action>` form.
2. Add a `ToolDescriptor` with an honest description, `headless` value, journey
   phase, effect, approval policy, runtime/workspace/findings requirements, and
   complete `OptionSpec` list.
3. Add the executor and register it atomically with the module.
4. Consume canonical prepared option names in the executor. Do not parse a
   second CLI/TUI/env-only input surface.
5. Add focused descriptor, preparation, executor, and mode-parity tests.
6. Document the operator-visible tool in this guide or `docs/OPERATOR.md` /
   `docs/assessments/mode-parity.md` as appropriate.

`hidden: true` is reserved for internal nodes that must not appear in operator
or model tool lists. `headless: false` means `kuzushi run` must reject the tool.
DAG `depends_on` metadata does not schedule work unless the owning executor
explicitly consumes it.

### Options and prompts

`OptionSpec` is the canonical user-input surface. It owns type coercion,
defaults, choices, integer bounds, path semantics, aliases, and deprecated
aliases. Unknown keys fail at preparation.

Prompt-aware tools declare both prompt metadata and its canonical option. When
that option is unset and an explicit workspace is available, dispatch
preparation may load:

```text
<target>/.kuzushi/prompts/<module-id>/<verb>.md
```

Explicit tool input takes precedence. A mode must not add its own undisclosed
prompt search path. The `sast:scan` umbrella forwards its declared triage and
verification prompt values to the corresponding stages.

### Runtime and model selection

Descriptor-backed agent tools use `resolve_tool_model`; adapters that have
already parsed an explicit inline model use `resolve_explicit_model`. Once
execution policy is resolved, missing or incompatible runtime/model selection
is an error. A tool must not add a literal default model, a provider fallback
chain, or a target-local model override.

## Dynamic KWP modules

Local KWP modules are self-contained `.mjs` files. They export a plain module
object; they do not import Kuzushi helpers.

```js
export default {
  id: "example",
  displayName: "Example",
  category: "internal",
  description: "Read a workspace file through the KWP broker.",
  tools: [
    {
      name: "example:inspect",
      description: "Inspect one workspace-relative text file.",
      headless: true,
      runtimeRequirement: "never",
      phase: "map",
      effect: "read",
      approval: "none",
      workspaceRequirement: "required",
      options: [
        {
          name: "path",
          type: "path",
          pathSemantics: "workspace-read",
          description: "Workspace-relative file to read.",
          required: true,
        },
      ],
      async execute(input, ctx) {
        const text = await ctx.fs.readText("workspace", input.path);
        return {
          status: "completed",
          output: `Read ${input.path}`,
          data: { bytes: new TextEncoder().encode(text).byteLength },
        };
      },
    },
  ],
};
```

The default export, named `module` export, or imported object itself may be the
module. A tool may expose `execute(input, ctx)` or the compatibility spelling
`run(input, ctx)`.

### Module descriptor

| Field | Requirement | Meaning |
| --- | --- | --- |
| `id` | required | Kebab-case module id; every tool name must start with `<id>:`. |
| `displayName` / `name` | optional | Operator-facing name. `displayName` is preferred. |
| `category` / `kind` | optional | Module grouping; defaults to `internal`. |
| `description` | optional | Operator-facing summary. |
| `hidden` | unsupported | Dynamic modules must remain operator-visible; `true` is rejected. |
| `tools` | required | Array of tool descriptors. |

The host rejects unsupported module lifecycle fields (`init`, `ready`,
`dispose`, `requires`, `knowledge`, and `events`) rather than pretending to run
them.

### Tool descriptor

| Field | Requirement | Meaning |
| --- | --- | --- |
| `name` | required | Globally unique `<module-id>:<action>` name. |
| `description` | optional | Operator/model-facing summary. |
| `headless` | required | Whether `kuzushi run` may invoke the tool. |
| `runtimeRequirement` | optional | `never` or `always`; defaults to `never`. |
| `phase` | required for effectful tools | `map`, `scan`, `review`, `prove`, `fix`, or `operate`. Deprecated `hunt` and `confirm` inputs normalize to `scan` and `prove`. |
| `effect` | required | `read`, `workspace-write`, `target-write`, `repository-execute`, or `external-action`. |
| `approval` | required | `none` or `explicit`. Target writes, repository execution, and external actions require `explicit`. |
| `workspaceRequirement` | required | `optional` or `required`. |
| `hidden` | unsupported | Dynamic tools must remain operator-visible; `true` is rejected. |
| `options` / `inputSchema` | optional | Canonical descriptor options or the restricted schema form below. |
| `prompts` | optional | Declared editable prompt boundaries tied to named options. |

Dynamic policy has no permissive defaults for `headless`, `effect`, `approval`,
or `workspaceRequirement`. Registration is atomic, duplicate tool names and
aliases fail, and a dynamic module cannot replace an active or retired built-in
id. Unsupported tool lifecycle/DAG fields (`init`, `dag`, `runLifecycle`) fail
during description.

### Dynamic options

Explicit options support these types:

```text
string | bool | int | float | path | enum | string-list | json
```

Common fields are `name`, `type`, `description`, `required`, `default`,
`choices`, `aliases`, `deprecatedAliases`, `advanced`, and `evasion`. Integer
options may add inclusive `minimum` and `maximum` bounds.

Every `path` option must declare one of these semantics:

```text
workspace-read | state-write | target-write |
external-read | external-write | executable
```

The host uses those semantics during canonical path preparation and
authorization. It never guesses whether an unlabeled path may read, write, or
execute.

As an alternative, `inputSchema` may describe a closed top-level object. It
must set `additionalProperties: false`. Supported property shapes are strings,
booleans, integers, numbers, string enums, arrays of strings, and unconstrained
JSON objects. Supported property metadata is `description`, `default`, `enum`,
`items`, and integer `minimum`/`maximum`. Unsupported keywords fail during
description. Use explicit `options` whenever path semantics or richer option
metadata is required.

### Declared prompts

A prompt entry declares `role`, `verb`, `optionKey`, and `defaultContent`.
`moduleId` defaults to the current module and must match it. `optionKey` must
name an option on the same tool. `contextNote` is optional. This declaration is
what authorizes the shared prompt override behavior; adding an ad hoc JSON key
does not.

### Worker context and grants

Approved local workers execute from an operator-owned read-only snapshot with a
stripped environment. Ambient filesystem, network, process, secret, or MCP
authority is not inherited. Privileged work goes through grant-checked handles:

| Handle | Purpose |
| --- | --- |
| `ctx.fs` | Read/write approved `workspace`, `module-data`, or read-only `input` scopes. |
| `ctx.runtime` | Query the host-selected runtime within the approved model/cost budget. |
| `ctx.net` | Fetch approved hosts with request and byte quotas. |
| `ctx.mcp` | Call an operator-mounted, explicitly aliased MCP tool. |
| `ctx.fuzz` | Run an approved host-mounted fuzz engine. |
| `ctx.findings` | Persist bounded, allowed-severity findings. |
| `ctx.artifacts` | Record bounded artifact references. |
| `ctx.bus` | Publish to approved topic patterns. |

The local-worker context also carries host-provided `cwd`, a bounded `config`
projection, KWP metadata, `invocationId`, `runId`, and an abort `signal`.
Treat these as invocation data, not ambient authority. Compatibility package
execution may project additional target/tool identity; local modules must not
depend on that wider shape.

The approval grant is deny-by-default and is stored with the module digest in
`kuzushi.lock`. Current grant families are `fs`, `net`, `runtime`, `bus`,
`findings`, `artifacts`, `mcp`, and `fuzz`. Direct Node-worker `exec` grants are
not supported. See `examples/kwp/agentic-fuzz/grant.example.toml` for a complete
working subset and `crates/kuzushi-core/src/worker_protocol.rs` for the exact
serialized fields and quotas.

Every broker request carries a host-issued invocation id and epoch. Missing,
mismatched, stale, post-cancellation, or post-settlement authority is rejected.
Cancellation and watchdog expiry stop the worker process group and discard
stale results.

### Runtime queries

Set `runtimeRequirement: "always"` before calling `ctx.runtime.query(...)`.
The host owns model and cwd selection. A worker may provide the prompt and
supported query controls, but it may not inject custom tools, a fallback model,
host-owned runtime options, or permission callbacks. Unsupported fields fail
explicitly.

Runtime-free tools receive an unavailable-runtime handle so accidental use is
an error rather than a silent fallback.

### Results

A tool returns JSON-serializable data. The common result envelope uses
`status`, `output`, and optional `data`, `artifacts`, and `findings`. Shared Rust
dispatch normalizes the output and owns lifecycle/cost recording. Worker-returned
`costUsd` is not trusted as authoritative accounting.

Finding identity remains host-owned at this boundary. A KWP
`findings.create` payload must omit `fingerprint`, `dedupKey`, and
`sourceSignature`; the broker rejects those canonical-identity overrides.
Workers may send `actorFingerprint` when they need to retain a producer-side
observation id as non-authoritative provenance.

## Approval, loading, and audit

Local file/path modules must be approved before Kuzushi describes or executes
their code. Approval binds the exact file digest, normalized descriptor hash,
grant, version, and optional signature chain in `kuzushi.lock`.

```sh
kuzushi kwp approve file:///abs/path/to/example.mjs \
  --grant /abs/path/to/grant.toml

kuzushi --target /abs/workspace \
  --load file:///abs/path/to/example.mjs \
  run example:inspect --input '{"path":"README.md"}'
```

Headless dynamic invocation requires an explicit global `--target`; an inline
path option cannot establish the trust root. A changed file or descriptor must
be approved again. A revoked or changed approval is rejected before execution.

Local v0.1 workers are single-file bundles. Kuzushi snapshots the approved
bytes, makes the snapshot read-only, and starts the Node worker over versioned
JSON-RPC stdio. Descriptor probing and execution both use the sandboxed host.
Module stdout is redirected to tagged stderr so it cannot corrupt protocol
output.

Workspace-backed runs record broker decisions and invocation lifecycle in:

```text
<target>/.kuzushi/v3/runs/<run-id>/kwp-audit.jsonl
<target>/.kuzushi/v3/runs/<run-id>/kwp-bus.jsonl
```

Verify the hash-linked audit chain with:

```sh
kuzushi kwp audit --target /abs/workspace --run-id <run-id> --json
```

An empty `signatureChain` represents local operator approval. Non-empty entries
use `ed25519:v1:<key-id>:<base64-signature>` and must verify against
operator-owned signing keys.

### Specifiers and mode support

| Specifier | Behavior |
| --- | --- |
| `builtin:<id>` | Rust built-in lookup. |
| `file://<absolute-entry>` or local path | Approved, digest-bound single-file KWP worker. |
| `package:<npm-name>` | Trusted compatibility path; must appear in operator `trusted_modules`. |
| `mcp:<server-spec>` | Not a dynamic module load path; use the native MCP controls below. |

Only shell and `kuzushi run` consume `--load`. `kuzushi scan` and unrelated
commands reject the flag instead of ignoring it or treating a dynamic tool as a
scan engine.

`package:` is a compatibility trust path, not a way to bypass local-file
approval. Local-looking, relative, absolute, or colon-bearing package names are
rejected.

## Published manifest schema

`schemas/module.manifest.schema.json` remains a public compatibility metadata
contract for package/file ecosystems that need `module.manifest.json`. It
describes identity, display metadata, version, entry, optional host-version
compatibility, requirements, and config metadata.

The manifest is not the authorization record for a local KWP worker:

- `kuzushi.lock` binds executable bytes, descriptor, and broker grants.
- The live worker export supplies the executable module/tool descriptor.
- The native and Node sides negotiate the worker protocol and exact host package
  version at startup.

Do not infer filesystem, network, runtime, model, MCP, or process authority from
manifest `requires` or `configSchema` fields.

## MCP servers

MCP servers are native agent tools, not dynamic module specifiers. Inspect and
serve them with:

```sh
kuzushi mcp health <backend>
kuzushi mcp serve <backend>
```

The bridge's legacy forced fallback attaches tree-sitter, CPG, and CodeQL. A
normal agent-tool request uses an artifact-gated attachment plan and can select
other shipped servers, including context, entry-points, threat-model,
threat-intel, x-ray, and findings. Do not treat the three-server fallback as the
complete inventory.

The CodeQL MCP keeps an in-process result memo for dependency-free local query
selectors. A memo hit skips `codeql database analyze`, but every request still
performs full content authentication of the database tree, so memo-hit latency
remains proportional to database size. Pack selectors bypass the memo, and
local queries with imports are rejected because their dependency closure cannot
be authenticated. First use of a database revision copies the authenticated
tree into operator-owned session storage; analysis and prewarm run only on
OS-sandboxed snapshot paths.

For descriptor-backed agent tools, MCP and bridge controls are ordinary tool
options such as `mcpToolTimeoutMs`, `bridgeVerbose`, and `bridgeLogPath`. The
adapter compatibility/debug switch `KUZUSHI_AGENT_MCPS` may force MCP
attachment, but it is not a product-option substitute.

## Testing

Built-ins should have focused Rust tests for descriptor shape, option
preparation, authorization, executor behavior, output normalization, and each
intentional mode asymmetry.

Dynamic modules should be tested at two levels:

1. Import the `.mjs` file directly in a Node test and exercise pure helper/tool
   behavior with deliberately small fake broker handles.
2. Approve and load the real file through `ModuleRegistry`, then invoke it
   through canonical dispatch. This catches descriptor normalization, grant,
   sandbox, handshake, path, cancellation, and output-contract failures that a
   direct unit test cannot.

There is no `kuzushi/testing` mock package. Keep any test doubles local to the
module and model only handles the test actually uses.

## Troubleshooting

- **Tool name does not start with the module id** — rename it to
  `<module-id>:<action>`.
- **Missing policy field** — declare `headless`, `effect`, `approval`, and
  `workspaceRequirement`; add a concrete phase for effectful tools.
- **Path option has no semantics** — add the exact `pathSemantics` value rather
  than coercing the input to a generic string.
- **Unknown input key** — add a descriptor option or remove the key. Dynamic
  schemas must set `additionalProperties: false`.
- **Module is not approved / digest changed** — rerun `kuzushi kwp approve`
  after reviewing the exact bytes and grant.
- **Package module is not trusted** — add the exact `package:` specifier to
  operator-owned `trusted_modules`; do not use that list for local files.
- **Runtime unavailable** — configure a compatible operator-selected runtime
  and declare `runtimeRequirement: "always"`.
- **Broker capability denied** — update the operator-reviewed grant only if the
  module genuinely needs that capability; do not add an ambient fallback.
- **Protocol or host version mismatch** — use the Node host shipped with the
  same Kuzushi package/native binary revision.
- **`--load` rejected** — invoke the approved tool from shell or `kuzushi run`;
  scan and unrelated commands do not load dynamic modules.
