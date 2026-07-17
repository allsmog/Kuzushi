# Plan 026: Constrain clang and rev.ng MCP effects to granted roots

> Executor: these servers run agent-selected native tools. Treat paths,
> subprocesses, container images, outputs, and caches as untrusted inputs.

## Status

- **Status**: DONE
- **Priority**: P1
- **Effort**: L
- **Risk**: HIGH
- **Category**: security/correctness/resource management
- **Depends on**: Plans 002 and 021
- **Planned at**: commit `775a4134f2cb`, Cycle 5

## Why this matters

Most Rust MCP servers now require `KUZUSHI_MCP_READ_ROOTS`, but the workspace
members `kuzushi-mcp-clang` and `kuzushi-mcp-revng` do not. Clang accepts an
arbitrary `repoPath`; joining an absolute `file` discards that repo and lets
clangd open any host file. Compile-database tools run CMake/Make and write into
the selected path. rev.ng accepts any host binary and a caller-selected local
container image, then mounts the binary's whole parent directory. Both families
capture subprocess output without a byte or time bound. Common cache/Git
fingerprint reads also bypass bounded file helpers.

## Steps

1. Require the shared root capability when constructing clang and rev.ng
   registries. Authorize repository directories and every file beneath the most
   specific retained root; reject absolute child paths, `..`, symlinks,
   junctions/reparse points, root swaps, and case/volume escapes.
2. Separate read and write intent. Clang build-generation writes may occur only
   in an explicitly authorized workspace subtree and through no-follow output
   preparation; read-only tools cannot trigger CMake/Make/Bear or create build
   directories. Make the capability/mode visible in descriptors and errors.
3. For rev.ng, open and identity-check a bounded regular binary through the
   capability, copy it into a private bounded scratch directory, and give native
   or container analysis only that file. Never mount the source file's parent.
   Remove caller-selected images or validate them against an operator-owned
   allowlist/pinned configuration; keep `--pull=never`.
4. Put deadlines, cancellation, process-group kill/reap, stdout/stderr byte
   caps, terminal-control escaping, and result-size limits around clangd,
   generators, host tools, rev.ng, and container runtimes. Cached output must
   obey the same cap and use private atomic/no-follow files.
5. Route common cache manifests, Git HEAD/config/ref reads, compile databases,
   and source-document reads through bounded helpers. Malformed cache data must
   fail or rebuild explicitly rather than silently become an unbounded default.

## Verification

- Direct registry calls cannot open `/etc`, another temp root, an absolute
  `file` under an allowed repo, or a swapped symlink/junction.
- A malicious rev.ng image cannot see source-parent sibling files; unapproved
  images are rejected before the runtime starts.
- Huge binaries, compile databases, cache files, and subprocess output fail at
  limit+1 without large allocation/disk growth; hanging tools are killed/reaped.
- Read-only mode cannot create build output or run generators; authorized
  read-write fixtures still work.
- MCP clang/revng/common tests, platform cfg checks, Clippy, architecture,
  model-safety, and CRAP gates pass.

## Done criteria

Agent-callable clang and rev.ng operations can observe or mutate only their
granted workspace/scratch scope and consume finite host resources.

## Implementation disposition

- The clang compile-database surface is deliberately locate-only. Build
  generation and its write capability were removed, so read-only calls cannot
  run CMake, Make, Bear, or `intercept-build` or create a build directory.
- Clangd and native rev.ng/host parsers run only behind a self-probed read-only
  process sandbox (macOS Seatbelt or a fixed trusted Linux bubblewrap
  launcher). The sandbox exposes the retained target directory, fixed trusted
  system/toolchain roots, and private scratch; it clears ambient environment,
  denies target writes and network, and fails closed when unavailable.
- rev.ng prefers a hardened container addressed by its bounded-inspect
  immutable image ID. Native cache keys bind the canonical executable path and
  byte digest; container keys bind the immutable image ID. Container removal
  disarms only after verified success or a recognized already-absent result.
- The UAF-hunt subprocess launcher clears ambient environment and grants the
  canonical target as its sole `KUZUSHI_MCP_READ_ROOTS` entry.

## Verification evidence

- `cargo test -p kuzushi-mcp-common -p kuzushi-mcp-clang -p kuzushi-mcp-revng`
  passed (55 common, 36 clang, and 16 rev.ng tests).
- Strict Clippy passed for all targets in those three packages.
- Windows cfg checks passed for common, clang, and rev.ng with
  `x86_64-pc-windows-msvc`, including the kill-on-close Job Object path.
- Focused UAF-hunt command-environment tests passed in `kuzushi-core`.
- Model-safety, environment-discipline, dispatch-boundary, and artifact
  contracts passed. The whole-tree architecture and CRAP commands remained
  blocked only by concurrently edited files outside Plan 026; no Plan 026 file
  appeared in either failure report.
