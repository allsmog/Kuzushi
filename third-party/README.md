# Terminal dependency maintenance

`crossterm/` is the crates.io 0.29.0 package with a small local Unix input patch.
The unmodified package is preserved in `upstream/crossterm-0.29.0.crate`.
Its SHA-256 is
`d8b9f2e4c67f833b660cdb0a3523065869fb35570177239812ed4c905aeff87b`,
matching the registry checksum formerly recorded in the workspace lockfile.
The package retains its upstream MIT license and authorship.

The only production changes are the `Parser` methods in
`src/event/source/unix/{mio,tty}.rs`. A second Escape byte now completes the
pending standalone Escape and begins the next sequence. Each backend imports
the shared local regression test file. The standalone test lockfile was updated
to resolve the package's declared test dependencies; the workspace dependency
versions remain unchanged.

Legacy Escape followed by a navigation sequence is ambiguous with Alt plus
that navigation key. This patch interprets the double prefix as Escape followed
by navigation. Ordinary Alt characters and encoded modifier sequences keep
their existing behavior. Bracketed paste content is preserved byte for byte.
The patch does not enable or change terminal keyboard reporting modes.

`scripts/vendored-terminal-baseline.mjs` authenticates the original archive,
checks all untouched package files, and supplies original function bodies to
the CRAP-risk gate. Only identical upstream functions are outside local-change
scoring. New and modified production functions receive the ordinary limits;
unexpected changes to other upstream files fail closed. The patch files are
excluded from workspace formatting so that upstream layout remains intact.

Run dependency tests with:

```sh
cargo test --manifest-path third-party/crossterm/Cargo.toml --lib --locked
cargo test --manifest-path third-party/crossterm/Cargo.toml --lib kuzushi_parser_tests --features use-dev-tty --locked
pnpm quality:crap-risk
```

Remove the override only after an authenticated upstream release passes the
local parser tests and the native terminal journey. Do not edit cached registry
sources or publish this patched package as an upstream release.
