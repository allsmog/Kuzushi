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

## Source-bound model Scan results

The registered `agentic-sast:scan`, `carlini-threat-hunt:run`, and
`offense-review:threat-hunt` paths attach `data.snapshotHash` and `data.treeHash`
from an indexed source snapshot captured before execution. A second source check
after execution marks the output partial if the source changed or cannot be
verified; the saved result and recorded spend remain available. These fields
come from the Rust adapter, not the model. Existing phase acceptance checks
authenticate the snapshot and require it to match the current source.

Agentic SAST, the offensive threat hunt, and every built-in that persists
through the shared tool-findings path (native scanners such as `secret-scan`,
`dep-hygiene`, `semgrep`, `codeql`, IaC, APK, chains, and plugin adapters) emit
typed finding deltas after the finding store commits, including a zero delta
for a clean run. Counts distinguish newly added fingerprints from existing
fingerprints seen again. A phase can infer a clean Scan from zero deltas only
when every referenced run supplied a finding observation; otherwise the phase
receipt's watermark records the gap and the shell labels the count
`findings unmeasured` (or `partly unmeasured`) instead of a measured `+0`. Older runs without
source receipts remain inspectable and require a new run before acceptance on
an unversioned or dirty target; their historical records are not rewritten.

## Audit remediation contracts

Shell composer and form fields share grapheme-aware cursor movement and deletion.
Their renderers retain whole graphemes and measure terminal cells; vertical field
navigation preserves display columns. This changes shell presentation only.
Collapsed pastes have tracked spans and undoable whole-block edits. Ctrl+Y opens
a read-only preview with expand/remove/cancel controls; Ctrl+_ restores paste
edits. Preview captures keys, pointer events and pasted input until it closes.
Payloads stay in memory and are expanded exactly when the draft is submitted;
marker text typed by an operator never resolves to a hidden payload.

Semantic response reuse requires a closed-world tool policy and a runtime
attestation binding effective backend settings and implementation revisions.
Adapters without `semantic_cache_identity` execute live; the current external
LangGraph bridge does not attest its installed dependency closure. Generation
settings participate in versioned keys; credentials and diagnostics do not.
The cache applies global `operator.semantic_cache` byte/entry quotas inside an
immediate transaction. `SemanticCache::maintain()` reports bounded eviction and
legacy-cleanup progress. Interrupted cleanup retries its unfinished shard on the
next pass; successful-prune timestamps are recorded only after pending work ends.
Model lifecycle producers must persist `ModelCallStarted` before provider
dispatch. The writer reserves completion space, rejects starts beyond its eight
in-flight slots, and commits model receipts synchronously. Normal log exhaustion
does not erase completed usage/cost or permit a healthy terminal outcome.

MCP servers validate arguments against registered schemas before dispatch. Clients
must handle invalid-argument, capacity, cancellation and shutdown responses.
CPG callers must select regex or literal query semantics and check coverage,
truncation and approximate-position metadata. Unsupported depth limits fail.
The core `cpg_taint_paths` adapter enforces its advertised `maxPaths` range
(1–25, default 10); invalid values are errors, never silent clamps.
Structural queries reject ambiguous file or method identities and return
candidates. `cpg.definitions` returns a canonical method selector for subsequent
queries. Reaching definitions require exact AST membership at the requested line;
they cannot use the approximate nearest-preceding method from `cpg.method_at`.
Slice depth is an integer in 0–32, checked before graph work.

Persisted findings retain their original primary coordinates alongside grounding.
Source-independent evidence has an explicit kind; a code citation must identify
real source lines. Static verification accepts substantive verdicts only with
source-checked source/sink or control/reachability citations. Consensus receipts retain
individual assessments and label raw confidence as uncalibrated.

Resumable tool loops journal intent before a handler runs and refuse to replay an
unresolved intent automatically. Checkpoint IO/size/ownership failures are errors;
known paid work remains recorded even when a later turn fails. Module authors must
not interpret unresolved spend as zero or an inconclusive static review as an
empirical proof. See [migration notes](../RELEASING.md#audit-remediation-compatibility)
and the [itemized ledger](quality/audit-remediation-2026-09-30.md).

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

### Map result source identity

`entry-points:extract` and `module-recommender:recommend` return additive
`data.snapshotHash` and `data.treeHash` fields from the shared registered
workspace snapshot. They capture that identity before source-sensitive work
and check the current tree before returning success. Existing catalog provenance
and recommendation payloads remain intact. Source hashing uses the existing
index bounds and emits progress during collection.

These receipts let a completed Map attempt authenticate all referenced runs
against the same source. The shell's Use/Continue controls respect the shared
ledger's source-reuse decision and refresh it before accepting a result. Missing
or changed source identity requires a fresh run; historical receipts are never
backfilled with a newly computed hash. Tool names, options, and manifest schemas
are unchanged.

### Review result source identity and current observations

Deep Review distinguishes supported positive/negative assessments from unresolved
reachability. Its model analysis accepts `triggerable: true|false|null`; null
produces `needs_review` at any confidence. A missing caller or empty reference
search alone does not refute a finding. An `implausible_trigger` refutation
without an inspected `first_link` remains unresolved. Existing Boolean analysis
JSON and persisted triage records remain readable; Rust `VulnAnalysis` callers
use `Option<bool>` for this field. Explicit retriage records new decisions while
preserving historical outcomes.

`triage:run` captures the required workspace's source identity before Review
and returns additive `data.snapshotHash` and `data.treeHash` fields. A source
change during classification makes the result partial while preserving its
classifications and observed spend. Historical attempts without source identity
require a fresh run; they are not backfilled.

Policy-aware findings lists present the latest observation in each permitted
identity group, retaining its source and evidence history. The public emitted
generation reader remains exhaustive and severity-sorted. Review records with
no identity apply only to their exact finding row, including a row that itself
has a durable identity. Shared identity records retain their declared scope.
Human decisions outrank automated decisions; recency resolves decisions by the
same kind of author. This does not enable automatic identity reconciliation.

### Rust surface extraction compatibility

Rust inventory and attack-surface extraction share a source projection that
excludes direct `#[cfg(test)]` scopes, `#[test]` functions and inner
`#![cfg(test)]` scopes before ranking and model grounding. Production code in
the same file retains its original line numbers. This is not a reachability
proof: compound cfg expressions, unknown macros and cross-file test-module
ownership remain unclassified. Current Rust rows carry
`metadata.sourcePolicy = "rust-test-scopes-v1"`; the marker is included in
catalog payload digests but does not change surface IDs. New model runs refuse
older Rust context/catalog rows with a `context:build` then
`entry-points:extract` recovery message. Existing historical models remain
readable and are not silently regenerated.

### Verification modes

Static verification distinguishes supported positive and negative assessments
from uncertainty. `data.exploitable` (and its verification/proof copies) is
nullable: true supports the claimed path, false requires cited defeating
evidence, and null leaves the assessment inconclusive. Incomplete or unsupported
responses and panels without a strict majority return `status: partial`, retain
cost and source provenance, and cannot replace accepted proof. A gate with
incomplete evidence continues to the configured verifier. A split panel stays
inconclusive unless the explicitly configured tie-break resolves it. No model
or runtime is substituted. Historical receipts keep their original content.

`verify:finding` keeps the declared `mode=model|empirical` option. Model mode
requires the explicitly selected model runtime. Empirical mode uses the shared
registry to delegate the canonical finding reference to `verify:exploit`; it does
not create a model runtime. Headless invocation binds explicit authorization to
that prepared operation. The shell requests a fresh confirmation for execution.

Local reproduction currently supports Linux with bubblewrap. Discovering the
binary is only a prerequisite: execution still checks sandbox startup, supported
language/trigger construction and source provenance. Unsupported backends record
`NotAttempted`. The Prove card shows availability before drafting, omits model
controls for empirical mode, and keeps unavailable execution from being drafted.
Selecting a completed empirical receipt validates its finding, run, generation
and durable proof snapshot; runtime evidence additionally requires current source
identity. A not-attempted receipt never becomes runtime proof. Historical receipts
missing those binding fields remain inspectable and require a rerun before
selection; they are not rewritten.

### Source evidence for model-backed Map

The default `threat-model:build` sources are `context`, `source-code`, and
`threat-model`. `source-code` supplies actual source lines to single and staged
synthesis, gap filling, and refinement. Each supplied line has a workspace-relative
file/line reference; the projection records its scope, target-tree identity,
raw-file hashes, and omitted files/lines. Source text remains untrusted input,
and a cited line does not establish a confirmed vulnerability.

`maxSourceBytes` bounds each source projection (default 200,000 bytes), and
`contextLimit` limits selected code files (default 200, maximum 2,000). Code
collection prioritizes selected surface locations, then distributes files across
components. Small files are included completely when the budget permits; larger
files supply whole lines nearest the selected locations. Explicit read ceilings
are 2 MiB per source file and 16 MiB total after inventory collection. Oversized,
binary, non-UTF-8, and budget-omitted code is disclosed. Rust code uses the test-scope
projection described above. Target drift or an incomplete inventory stops the
build with recovery guidance.

### Single-pipeline coverage: gap fill and the coverage floor

When a single-pipeline `threat-model:build` leaves grounded entry points
uncovered and budget remains, it makes one bounded gap-fill call. This is the
same repair the staged pipeline and refine use. `coverage.gapFillMethod`
records what happened:
- `none-needed`: coverage already held.
- `stride-llm`: gap fill ran.
- `budget-exhausted`: no budget was left for the call.
- `gap-fill-failed`: the call failed. The model is kept and the gaps stay
  parked and disclosed.

The build is then refused, and nothing is persisted, if it still covers less
than `minCoverage` of the grounded entry points (declared option, 0–1, default
`0.5`). The error names covered/considered and the remedies. Pass
`minCoverage: 0` to keep a low-coverage model deliberately.

### Confirmed findings as threat-model variant patterns

`threat-model:build mode=refine` reads the workspace findings ledger, including
when the calling mode supplied no findings store. It attaches each newly
confirmed finding (an automated true positive, or a `confirmed`/`to_fix` review
decision) to the threat that covers its file, and it records a bounded
`variantPatterns[]` entry on that threat. The entry is deterministic and
grounded in the repository: `findingRef`, `title`, `cwe` (from the finding, or
the threat's single related CWE), `location`, the first call-site line (taken
from the finding's detection evidence, or else read from the file; imports and
function declarations never count as call sites), and that line's distinctive
identifiers as `keywords`. A threat keeps at most eight patterns, one per
finding. The revision records `provenance.refineDelta.variantPatterns`.

Later scans use the active model's patterns. taint-iris-next adds each pattern's
leading keywords to the matching CWE's structural queries and cites the source
location as a ranking reason. The agentic-SAST threat-model digest lists the
patterns as proven call sites whose siblings the agent should look for.

`sast:scan` exposes `threatModelFeedback=off|refine` (default `off`). With
`refine`, the scan dispatches `threat-model:build mode=refine` after triage,
through the shared registry and with the configured model. The scan reports the
outcome under `data.threatModelFeedback`. A refused refine, for example when no
model exists yet, becomes a scan warning and does not fail the scan.

An explicit `sources` list remains authoritative. Use `sources=none` to omit
source artifacts, or the prior `context,threat-model` list to retain its older
behavior. `contextMode=off` excludes the default source bundle; an explicit
`sources=source-code` still requests code. Enabled code collection requires
`maxSourceBytes >= 1024`. `seedMode=fresh` drops the prior model while keeping
code. The shared registry applies these options in every supported launch mode.

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


### Trace expansion results and recovery

`trace:expand` may complete with zero new steps. Its canonical run result still
retains `openQuestions` and `evidenceDeltas`, and the Trace reader recovers them
through the result reference recorded for that exact tool call. A completed
empty question list replaces the previous list. Older static-evidence steps
remain readable; a missing source identity is disclosed rather than treated as
current. Recovery errors are explicit.

New expansions attach `data.snapshotHash` and `data.treeHash` from the shared
source-snapshot boundary. A source change during execution makes the result
partial. The reader distinguishes the last expansion's source status from the
accumulated history of recorded steps.

Trace uses the shared monetary result contract: `costUsd` means an exact
provider receipt. Incomplete metering uses `observedCostUsd` together with
`providerSpendUnresolved: true`, mirrored in the envelope and object-shaped
`data`. Zero dollars alone does not establish whether a model call occurred.
The retired Trace-only `costUsdExact` field is no longer emitted; see the
migration note in `RELEASING.md`.

After successful terminal persistence, the shell refreshes the Trace reader
from that verified history while the same target is active. The immediate
completion view therefore includes the saved run and source receipt. Failed
writes and completions for another target do not replace the current evidence.
Informational and successful completion notices clear on Escape while allowing
the reader or editor to handle the key. Warning and error notices retain their
explicit dismissal action; the banner reflects the current key ownership.

Final run receipts retain an actionable error raised during the current run
instead of replacing it with an informational summary. Current warnings are
retained unless the terminal outcome is a failure, which must be shown as an
error. Older alerts do not hide a new completion. Without a current alert,
failed, partial and blocked receipts disclose their severity and point to
`/activity` for details; the complete receipt remains recorded.

Replay and run Trace wrap their displayed rows before scrolling, preserving
styles, Unicode and path spacing. Page Up/Down uses the visible reader height;
scrolling back from the end or after resizing clamps against the current
document. Their Escape hint names return to the prior surface, or dismissal
while an alert owns the key. Existing authenticated and bounded result
projections remain the source of the displayed content.


Run Focus Output uses its rendered pane dimensions for scroll limits and page movement, including wrapped text and overflow disclosures. After `g` goes to the top or repeated upward scrolling reaches it, `j` moves down immediately. `G` resumes following the tail; `k` leaves it. The Output footer names the current Ctrl+C action and does not call a finished run live. Short Run Focus screens prioritize status, the complete run id, and reading space. Their footer keeps primary navigation and the current interrupt action, with the effective command-palette binding followed by `keys` for the complete control map. Steer editors, pending cancellation and operator questions keep their existing controls.

Long notice banners are bounded previews: dismissal remains visible and overflow names the command-palette route to `logs`, where the complete recorded message can be read. Logs pages and scroll bounds use the actual wrapped document and visible body; `G` follows new output and upward scrolling releases the tail. Short Logs screens use a compact header.

The `keys` control map places the originating view's controls first, wraps full key labels and descriptions, and pages using its visible document area. Compact screens omit unused composer space; the title shows the current line range. Closing it restores the originating view. Trace and Investigation name Escape as dismissal while an error owns the key; after dismissal, they name the back action again.

### Supporting evidence and phase results

The Rust descriptor field `phase_result` separates result ownership from the
phase used for authorization. Its default is `true`. Tools such as `trace:expand`
use `without_phase_result()` to save supporting evidence without producing a
selectable Map/Scan/Review/Prove/Fix result. Their declared phase, effect,
approval, runtime and option policies continue to apply.

Shell preparation and receipt projection use the resolved descriptor. Shared
workflow persistence and recovery recognize the built-in opt-outs: a Trace run
cannot replace a pending verification or be accepted as a proof set. Existing
Trace run artifacts and raw workflow events remain available as history; they
are excluded from active phase selection. Unknown historical tool identities
retain the existing checks and are never silently removed. See `RELEASING.md`
for the Rust descriptor migration.
