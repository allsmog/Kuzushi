# Contributing to Kuzushi

Thanks for your interest in contributing!

## Getting Started

One command, deterministic, loud on failure:

```sh
git clone <your-fork>
cd Kuzushi
pnpm setup          # verifies pinned Rust + Node 22, then runs pnpm install
pnpm doctor         # re-check the environment at any time (read-only)
pnpm verify:quick    # types, tests, formatting, architecture, docs, and policy gates
```

Before a release or when reproducing CI end to end, run `pnpm verify:ci`.
It adds coverage, codegen drift, Clippy, cargo-deny, the full Rust workspace,
native/package assembly, and e2e smoke, and reserves stdout for one
machine-readable receipt. CI keeps those gates parallel for latency. The
dedicated Node 22 compatibility lane, Linux bubblewrap/AppArmor setup, and
artifact transfer are matrix/infrastructure checks and remain CI-only; the
receipt lists those exceptions explicitly.

Requires Rust 1.96.1 (including rustfmt and Clippy) and Node 22+. The repo has
`rust-toolchain.toml`, `.nvmrc`, and `.tool-versions` so `rustup`, `nvm use`,
`asdf install`, and `mise install` all pick up the right version
automatically. pnpm is pinned via `packageManager` in `package.json` and
activated by `pnpm setup` through corepack — you don't need to install
pnpm yourself.

Using VS Code / Codespaces? Open the repo and "Reopen in Container"; the
`.devcontainer/` definition runs bootstrap + installs semgrep + python for you.

## Development

```sh
pnpm dev -- --target /path/to/repo  # run the Rust operator shell
pnpm dev -- scan /path/to/repo      # run a Rust scan from source
cargo test --workspace              # test the native product
pnpm typecheck:all                  # type check the retained TypeScript SDK and tooling
pnpm test                           # test the TypeScript SDK and scripts
pnpm quality:architecture           # enforce shared Rust boundaries and artifact contracts
pnpm quality:model-safety           # enforce no-silent-fallback model policy
pnpm quality:crap-risk              # enforce complexity/test-risk limits on changed code
cargo deny check advisories licenses bans sources  # dependency policy used by CI
pnpm build                          # compile the retained TypeScript SDK to dist/
cargo build --workspace             # build the native product and MCP servers
```

Benchmark corpus setup:

```sh
pnpm setup:benchmarks list
pnpm setup:benchmarks govwa juice-shop
pnpm setup:benchmarks all
```

## Submitting Changes

1. Create a branch from `main`
2. Make your changes
3. Run `pnpm verify:quick`, the focused tests for your change, and
   `cargo deny check advisories licenses bans sources`. Use `pnpm verify:ci`
   before release-bound changes.
4. Open a pull request against `main`

Keep PRs focused — one feature or fix per PR.

## Adding a New Built-in Tool

See [AGENTS.md](AGENTS.md) and [docs/modules.md](docs/modules.md) for the full
runtime and compatibility contracts. The short version:

1. Define the Rust `ToolDescriptor`, including every user-facing `OptionSpec`,
   under `crates/kuzushi-core/src/modules/`.
2. Add the Rust executor and route it through the shared `ModuleRegistry`
   preparation/dispatch boundary used by scan, shell, and run modes.
3. Add focused descriptor, option-validation, executor, and cross-mode tests.

There is no TypeScript SDK in this repository; third-party module authors
target `schemas/module.manifest.schema.json` and the KWP worker protocol.

## Reporting Bugs

Open an issue with:
- What you expected
- What happened
- Steps to reproduce
- Kuzushi version (`kuzushi --version`), Node version, OS

## Security Vulnerabilities

**Do not open a public issue.** See [SECURITY.md](SECURITY.md) for responsible disclosure instructions.

## License

By contributing, you agree that your contributions will be licensed under the MIT License.
