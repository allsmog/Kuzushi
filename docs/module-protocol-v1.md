# Kuzushi Module Protocol v1

Status: **frozen contract**, host **deprecation** in progress (Phase 2 of the
TypeScript-removal plan). This document freezes the JSON-over-stdio contract
that `crates/kuzushi-core/src/modules/dynamic_loader.rs` speaks to a module
host, so the host can be reimplemented in any language and the built-in Node
host (`scripts/kuzushi-dynamic-module-host.mjs`) can move out of this repo.

The declarative side of a module is the manifest at
[`schemas/module.manifest.schema.json`](../schemas/module.manifest.schema.json).
This spec covers the **runtime** side: how the loader invokes a host process
and the messages they exchange.

## 1. Why this exists

Today `dynamic_loader.rs` spawns `node scripts/kuzushi-dynamic-module-host.mjs
<command> <specifier> [tool]`. That couples Kuzushi to a Node runtime for every
third-party module, which blocks the "zero Node on PATH" goal. Protocol v1
decouples the two: the contract below is the boundary, Node is one
implementation of it, and a module (or its manifest) can declare a different
`exec` command that speaks the same protocol.

Target end-state (plan option **C**): plugins become MCP servers and the
Phase-1 `rmcp` client is the single extension mechanism. Protocol v1 (plan
option **A**) is the **bridge** that lets the Node host leave the repo before
the MCP migration lands, without breaking existing plugin authors.

## 2. Transport

- The host is a subprocess. The loader passes
  `<command> <specifier> [toolName]` as argv.
- `<specifier>` is a module load specifier: `file://<abs-path>`, an absolute or
  relative path, `package:<npm-name>`, or a bare import specifier.
- All payloads are UTF-8 JSON. `describe`/`execute` use a single JSON document;
  `execute-runtime` uses newline-delimited JSON (NDJSON), one envelope per line.
- The host writes results to **stdout** and diagnostics to **stderr**. A
  non-zero exit code signals failure; stderr carries the human-readable reason.

## 3. Commands

### 3.1 `describe <specifier>`

Load the module and print its capability descriptor as one JSON object:

```jsonc
{
  "module": {
    "id": "<kebab-case-id>",
    "name": "<display name>",
    "kind": "Internal | Offense | Defense | Governance | Intel",
    "description": "<one-line>"
  },
  "tools": [
    {
      "name": "<id>:<action>",        // MUST start with "<module.id>:"
      "description": "<one-line>",
      "headless": true,                // false ⇒ shell-only
      "hidden": false,                 // true ⇒ hidden from /use and the LLM tool list
      "runtime_requirement": "always | never",
      "options": [ /* OptionSpec, see §4 */ ]
    }
  ]
}
```

### 3.2 `execute <specifier> <tool>`

Read one request document from **stdin**, run the named tool, print the result
to stdout:

```jsonc
// stdin
{ "input": { /* validated tool input */ }, "context": { /* see §5 */ } }
// stdout
{ /* arbitrary tool result JSON */ }
```

A tool whose descriptor sets `runtime_requirement: "always"` (manifest
`requires.runtime === true`) MUST NOT be invoked through `execute`; the host
rejects it because runtime callbacks are unavailable on this command. Use
`execute-runtime` instead.

### 3.3 `execute-runtime <specifier> <tool>`

Bidirectional NDJSON for tools that call back into the Rust agent runtime
mid-execution. Each line is one envelope.

1. Loader → host, first line: `{ "type": "request", "payload": { "input": …, "context": … } }`
2. While running, host → loader for each runtime call:
   `{ "type": "runtime.query", "id": <n>, "request": { "model", "cwd", "system_prompt", "prompt", "tool_policy"? } }`
3. Loader → host, response for that `id`:
   `{ "type": "runtime.response", "id": <n>, "response": { … } }`
   or `{ "type": "runtime.error", "id": <n>, "error": "<message>" }`
4. On completion, host → loader, final line:
   `{ "type": "result", "value": { /* tool result */ } }`

`id` correlates each `runtime.query` with its response; a mismatched or
out-of-order `id` is a protocol error. `request.model` falls back to
`context.config.model`; absence of both is an error.

## 4. OptionSpec (tool input surface)

Each entry in `tools[].options` is the canonical user-facing knob. Fields:

| field | type | meaning |
|---|---|---|
| `name` | string | option key |
| `type` | `string \| bool \| int \| float \| enum \| string-list \| json` | value type |
| `description` | string | help text |
| `required` | bool | must be supplied |
| `advanced` | bool | hidden from the basic option view |
| `evasion` | bool | flagged as an evasion/OPSEC knob |
| `default` | any (optional) | default value; omitted when none |
| `choices` | string[] | allowed values for `enum` |
| `aliases` | string[] | accepted alternate keys |
| `deprecatedAliases` | string[] | accepted-but-warned alternate keys |

A host MAY derive options from a JSON Schema `inputSchema` (object schema;
`properties` → options, `enum` → `choices`, `required` → `required`) when the
module does not declare `options` explicitly.

## 5. Execution context

The `context` object carries the ambient handles a tool may use. All are
optional; a tool MUST treat a missing handle as "capability absent" and fail
with an explicit message rather than assume a default:

- `cwd` — working directory (defaults to `"."`).
- `config` — resolved config, including `config.model` (used as the runtime
  query fallback model).
- `runtime` — present only under `execute-runtime`; exposes `query(request)`.

## 6. Versioning & compatibility

- This is **v1**. Additive fields are backward-compatible; a host MUST ignore
  unknown fields it does not understand.
- Manifest `kuzushiSdkVersion` still governs SDK drift (the loader warns on
  major-version mismatch); Protocol v1 governs the wire contract independently.
- The `<moduleId>:<action>` tool-name convention is load-bearing across
  built-ins, dynamic modules, help, and visibility filtering, and is **not**
  negotiable in v1.

## 7. Migration path (Phase 2)

1. **Now:** publish this spec + the manifest schema; mark the bundled Node host
   deprecated (`CHANGELOG.md`).
2. **Bridge (option A):** the Node host moves to an external `@kuzushi/node-host`
   package owned by plugin authors; manifests declare their own `exec` command
   that speaks Protocol v1. `dynamic_loader.rs` learns to launch a
   manifest-declared `exec` instead of hard-coding `node <host>`.
3. **Target (option C):** each of the four pinned plugins ships a thin MCP stdio
   adapter; `dynamic_loader.rs` gains an MCP-server module source (reusing the
   Phase-1 `rmcp` client) and the Node spawn path — `Command::new("node")` and
   the `KUZUSHI_DYNAMIC_MODULE_HOST` resolution chain — is deleted along with
   `scripts/kuzushi-dynamic-module-host.mjs`.

Steps 2–3 require a plugin-author deprecation window and changes in the four
external plugin repositories (`@kuzushi/tob-skills`, `@kuzushi/vuln-scout`,
`promptarmor-plugin`, `shinsa-plugin`), so they cannot land in-repo alone. This
document is the contract those adapters implement against.
