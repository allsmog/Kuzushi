# V3 Plugin Sandbox

V3 plugins are capability-scoped analyzers. They return untrusted finding
candidates; they do not write findings, proofs, triage decisions, or workspace
files.

## Boundary

Trusted Kuzushi code grants a snapshot:

```text
GrantedSnapshot {
  blob_hash -> size_bytes
  optional CAS object path
}
```

The plugin receives only that grant. It has no ambient filesystem, environment,
network, subprocess, or workspace-write access.

The host accepts only this output shape:

```json
{
  "findings": [
    {
      "ruleId": "rule",
      "title": "short title",
      "severity": "high",
      "blobHash": "...",
      "byteStart": 10,
      "byteEnd": 42,
      "message": "why this matters"
    }
  ]
}
```

Serde `deny_unknown_fields` is part of the security boundary. Spoofed canonical
fields are rejected instead of ignored.

## Policy

Default policy:

| Capability | Default |
| --- | --- |
| read snapshot | false unless explicitly granted |
| read AST | false unless explicitly granted |
| workspace writes | denied |
| network | denied |
| subprocess | denied |
| environment | denied |
| memory | 256 MiB |
| fuel | bounded |
| wall time | bounded |
| bytes served | bounded |
| output bytes | bounded |
| returned findings | bounded |

The current validator rejects policies that grant workspace writes, ambient
network, environment inheritance, or subprocess execution.

## Process Backend

The process backend uses `kuzushi-sandbox` and requires an isolating backend.
It clears environment variables, disables network, mounts granted CAS objects
read-only under `/snapshot/<hash>`, passes a manifest on stdin, and validates
stdout before committing anything.

## Wasmtime Backend

The Wasmtime backend denies WASI by default. The only host imports expose:

- manifest length/read
- granted blob length/read

The store limits instances, memories, tables, fuel, total bytes served, output
bytes, and memory size. The plugin exports `kuzushi_analyze() -> i64`, returning
a pointer/length pair to UTF-8 JSON that is parsed through the same strict
validator as the process backend.

## Commit Flow

```text
plugin stdout
  -> strict JSON schema
  -> candidate field caps
  -> severity enum validation
  -> granted blob/span validation
  -> host computes stable_fp + observation_hash
  -> WriterCommand::Watcher(CandidateObservation)
  -> event log + projection transaction
```

Until the writer actor commits, plugin output is not Kuzushi state.

## Implementation Map

- `crates/kuzushi-core/src/plugin_sandbox/mod.rs` - invocation, validation, and
  commit entry points.
- `crates/kuzushi-core/src/plugin_sandbox/policy.rs` - capability and budget
  policy.
- `crates/kuzushi-core/src/plugin_sandbox/policy_validation.rs` - deny ambient
  capabilities.
- `crates/kuzushi-core/src/plugin_sandbox/snapshot.rs` - granted snapshot and
  read-only CAS mounts.
- `crates/kuzushi-core/src/plugin_sandbox/wasm.rs` - Wasmtime host ABI and
  store limits.
- `crates/kuzushi-core/src/storage_v3/writer_actor/` - durable commit boundary.
