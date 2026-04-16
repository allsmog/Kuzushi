# Contributing to Kuzushi

Thanks for your interest in contributing!

## Getting Started

One command, deterministic, loud on failure:

```sh
git clone <your-fork>
cd Kuzushi
pnpm setup          # verifies Node 22+, pins pnpm via corepack, runs pnpm install
pnpm doctor         # re-check the environment at any time (read-only)
pnpm test           # confirm everything works
```

Requires Node 22+. The repo has `.nvmrc` / `.tool-versions` so `nvm use`,
`asdf install`, and `mise install` all pick up the right version
automatically. pnpm is pinned via `packageManager` in `package.json` and
activated by `pnpm setup` through corepack — you don't need to install
pnpm yourself.

Using VS Code / Codespaces? Open the repo and "Reopen in Container"; the
`.devcontainer/` definition runs bootstrap + installs semgrep + python for you.

## Development

```sh
pnpm dev -- /path/to/repo    # run the CLI in dev mode (tsx)
pnpm typecheck                # type check src/
pnpm check:types              # type check src + benchmarks + perf in parallel
pnpm test                     # run unit tests
pnpm test:coverage            # tests + coverage
pnpm build                    # compile to dist/ (incremental, fast)
pnpm build:clean              # wipe dist/ and rebuild from scratch
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
3. Ensure `pnpm typecheck` and `pnpm test` pass
4. Open a pull request against `main`

Keep PRs focused — one feature or fix per PR.

## Adding a New Agent Task

See [AGENTS.md](AGENTS.md) for the full guide. The short version:

1. Create `src/agents/tasks/<name>.ts` implementing `AgentTask`
2. Register it in `src/agents/index.ts`
3. Add tests in `tests/agents/tasks/`

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
