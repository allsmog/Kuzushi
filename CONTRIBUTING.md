# Contributing to Kuzushi

Thanks for your interest in contributing!

## Getting Started

One command, deterministic, loud on failure:

```sh
git clone <your-fork>
cd Kuzushi
pnpm setup          # verifies pinned Rust + Node 22, then runs pnpm install
pnpm doctor         # re-check the environment at any time (read-only)
pnpm verify:quick    # Node tests, Rust format/check, architecture, docs, and policy gates
```

`pnpm setup` also adds the `upstream-codex` git remote
(`https://github.com/openai/codex.git`) so you can diff Kuzushi against the
upstream substrate. Nothing in the build fetches it, so it is safe to skip. A
remote you have already pointed at your own fork is never overwritten; setup
warns that it differs from the canonical URL and moves on. Add it by hand with
`node scripts/ensure-upstream-remote.mjs` in a clone that skipped setup.

Before a release or when reproducing CI end to end, install the pinned
`cargo-llvm-cov` and `cargo-mutants` versions printed by the commands, then run
`pnpm verify:ci`. It runs the quick checks plus measured coverage, strict
Clippy, cargo-deny, full Rust tests, changed-code mutation sampling, native/package
assembly, and e2e smoke serially. The dedicated Node 22 compatibility lane,
Linux bubblewrap/AppArmor setup, and artifact transfer are
matrix/infrastructure checks and remain CI-only; the receipt lists those
exceptions explicitly.

Pull requests run one fail-fast Linux quality gauntlet when they are opened,
reopened, or marked ready for review. Pushing more commits does not start more
runs; use the manual command below when you deliberately need fresh results.
Merge-queue candidates and pushes to `main` also get one quick pass. The quick
workflow contains no cross-platform or deep-quality jobs, so ordinary PR events
cannot instantiate that paid fan-out. The full suite runs weekly, before every
tagged release, or when deliberately requested for a branch:

```sh
gh workflow run ci-full.yml --ref <branch>
```

Use a full run before merging platform, packaging, release, coverage-policy, or
mutation-policy changes. For an ordinary PR, run the quick local contract after
intermediate pushes; marking a draft ready requests the hosted quick gate once.

Requires Rust 1.96.1 (including rustfmt and Clippy) and Node 22+. The repo has
`rust-toolchain.toml`, `.nvmrc`, and `.tool-versions` so `rustup`, `nvm use`,
`asdf install`, and `mise install` all pick up the right version
automatically. pnpm is pinned via `packageManager` in `package.json` and
activated by `pnpm setup` through corepack — you don't need to install
pnpm yourself.

### Engine-disabled Rust core validation

The default product includes the public `oxidized-joern` CPG engine at the
revision pinned in the workspace manifest and lockfile. Ordinary setup, CI,
fork PRs, and release builds resolve it anonymously over HTTPS and exercise the
complete product without a cross-repository secret.

Embedding consumers may still disable the historical `private-cpg` feature
name. Use the repository contract to validate that fail-closed surface:

```sh
bash scripts/check-public-rust-core.sh
```

The command resolves the same pinned public source, then runs core check,
Clippy, focused tests, and rustfmt with the CPG feature disabled. The adapter
reports no supported languages or graph readiness instead of manufacturing an
empty success. The default CI lanes separately compile, test, package, and run
the real engine-backed product.

Using VS Code / Codespaces? Open the repo and "Reopen in Container"; the
`.devcontainer/` definition runs bootstrap + installs semgrep + python for you.

## Development

```sh
pnpm dev -- --target /path/to/repo  # run the Rust operator shell
pnpm dev -- scan /path/to/repo      # run a Rust scan from source
cargo test --workspace --locked     # test the native product
pnpm test:performance               # run the serial Workbench input-to-paint budget
pnpm test                           # test Node scripts and repository contracts
pnpm check                          # run Biome checks
pnpm quality:architecture           # enforce shared Rust boundaries and artifact contracts
pnpm quality:model-safety           # enforce no-silent-fallback model policy
pnpm quality:crap-risk              # enforce complexity/test-risk limits on changed code
pnpm test:coverage                  # enforce Node and changed-line Rust coverage
pnpm test:mutations                 # kill all platform-active mutants for small Rust diffs, or a deterministic distributed sample of 12
cargo deny check advisories licenses bans sources  # dependency policy used by CI
pnpm build:native                   # assemble the native npm runtime
cargo build --workspace --locked    # build the native product and MCP servers
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
