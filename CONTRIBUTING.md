# Contributing to Kuzushi

Thanks for your interest in contributing!

## Getting Started

1. Fork the repo and clone your fork
2. Install dependencies: `pnpm install`
3. Run tests: `pnpm test`
4. Run type checks: `pnpm typecheck`

Requires Node 22+.

## Development

```sh
pnpm dev -- /path/to/repo    # run in dev mode
pnpm typecheck                # type check
pnpm test                     # run tests
pnpm test:coverage            # tests + coverage
pnpm build                    # compile to dist/
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
