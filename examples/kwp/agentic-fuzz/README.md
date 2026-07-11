# Agentic Fuzz KWP Module

This is a first-party example of `agentic-fuzz:hunt` as a KWP dynamic module.
It intentionally does not import `child_process`, read process secrets, or call
MCP/fuzz tools directly. Every privileged operation goes through the host
broker:

- `ctx.fs.writeText("workspace", ...)` for the target plan artifact.
- `ctx.mcp.call("symcc", "compile", ...)` when `useSymcc` is true.
- `ctx.fuzz.run(...)` for the fuzz job.
- `ctx.artifacts.record(...)` before returning artifact refs.
- `ctx.findings.create(...)` only when `createFindings` is true and granted.

Approve the exact file digest before loading it:

```bash
kuzushi kwp approve file://$PWD/examples/kwp/agentic-fuzz/module.mjs \
  --lockfile ./kuzushi.lock \
  --grant ./examples/kwp/agentic-fuzz/grant.example.toml
```

Load and run it with an explicit target workspace:

```bash
kuzushi --target /path/to/workspace \
  --load file://$PWD/examples/kwp/agentic-fuzz/module.mjs \
  run agentic-fuzz:hunt \
  --input '{"projectPath":"fuzz-project","harnessPath":"fuzz-project/harness.js"}'
```

The host must also mount a fuzz executor in global operator config. SymCC is
optional; set `useSymcc: true` only after adding both a `symcc` MCP mount and a
matching `[[mcp]]` grant.
