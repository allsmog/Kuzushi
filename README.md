<p align="center">
  <img src="kuzushi.png" alt="Kuzushi" width="200" />
</p>

# Kuzushi — Agentic SAST Scanner

Static analysis + AI triage in one command. Runs Opengrep/Semgrep on your codebase, sends every finding to an LLM for semantic verification, and tells you what's actually dangerous. No more drowning in false positives.

## Quick Start

Prereqs: Node 22+, an Anthropic API key.

1. Get an API key at https://console.anthropic.com/
2. Set it: `export ANTHROPIC_API_KEY=sk-ant-...`
3. Scan: `npx kuzushi /path/to/your/repo`

That's it. Kuzushi auto-downloads Opengrep if you don't have a scanner installed.

## What It Does

- **Runs Opengrep/Semgrep** with severity-ranked rule matching
- **Scores and deduplicates** findings by severity, likelihood, impact, and subcategory
- **AI-triages every finding** — reads ~60 lines of source context, traces data flow, assigns tp/fp/needs_review with confidence and rationale
- **Persists results** in SQLite — resume interrupted scans, skip already-triaged findings
- **Prints a styled report** showing only what matters: true positives and needs-review items

## How It Works

Semgrep/Opengrep catches syntactic patterns but can't verify data flow or intent. LLMs can reason about code but hallucinate when scanning from scratch (95%+ false positive rate). Kuzushi combines both: SAST signal narrows the search space, LLM reasoning eliminates false positives. This hybrid approach matches human researcher agreement rates.

## Commands

### Scan (default)

```
kuzushi <repo>                        # scan with defaults
kuzushi <repo> --severity ERROR       # only ERROR-level findings
kuzushi <repo> --max 20               # triage top 20 findings only
kuzushi <repo> --model claude-opus-4-20250514  # use a different model
kuzushi <repo> --fresh                # clear prior results, re-triage everything
kuzushi <repo> --db ./my.sqlite3      # custom database path
```

### Config

```
kuzushi config get                    # show all config
kuzushi config get model              # show one key
kuzushi config set model claude-opus-4-20250514
kuzushi config set maxTokens 2048
kuzushi config set severity ERROR,WARNING,INFO
kuzushi config unset model            # reset to default
kuzushi config path                   # print config file location
```

Config lives at `~/.kuzushi/config.json`. CLI flags override config values.

## Configuration

| Key | Default | Description |
| --- | --- | --- |
| `model` | `claude-sonnet-4-20250514` | LLM model for triage |
| `maxTokens` | `1024` | Max tokens per LLM response |
| `severity` | `["ERROR","WARNING"]` | Semgrep severity filter |
| `excludePatterns` | `["test","tests","node_modules",...]` | Directories/globs to skip |

### Environment Variables

| Variable | Required | Description |
| --- | --- | --- |
| `ANTHROPIC_API_KEY` | Yes | Anthropic API key for LLM triage |

## Scanner Resolution

Kuzushi finds a scanner in this order:

1. `opengrep` on your PATH
2. `semgrep` on your PATH
3. Previously downloaded binary at `~/.kuzushi/bin/opengrep`
4. Auto-downloads Opengrep from GitHub releases (~40 MB, cached for future runs)

No pip, no brew, no manual install needed.

## Output

Results are stored in SQLite at `<repo>/.kuzushi/findings.sqlite3`. Each finding includes:

- **verdict**: `tp` (true positive), `fp` (false positive), or `needs_review`
- **confidence**: 0.0-1.0
- **rationale**: why the LLM reached that verdict, referencing specific code
- **verification_steps**: 2-6 steps a human reviewer can follow
- **fix_patch**: suggested fix (when applicable)

The terminal report shows true positives first, then needs-review items. False positives are counted but hidden.

## Resume Support

Kuzushi fingerprints every finding (content-based SHA-256 that survives line shifts). Re-running a scan skips already-triaged findings automatically. Use `--fresh` to start over.

## Development

```
pnpm install                          # install deps
pnpm dev -- /path/to/repo             # run in dev mode
pnpm typecheck                        # type check
pnpm test                             # run tests (82 tests)
pnpm test:coverage                    # tests + coverage (70% threshold)
pnpm build                            # compile to dist/
```

## Troubleshooting

- **"ANTHROPIC_API_KEY environment variable is required"**: Export your key — `export ANTHROPIC_API_KEY=sk-ant-...`
- **"No findings from scanner"**: Your code is clean, or try `--severity ERROR,WARNING,INFO` to include lower-severity rules
- **Scan interrupted**: Just re-run the same command. Already-triaged findings are skipped automatically.
- **Wrong model**: `kuzushi config set model claude-opus-4-20250514` or pass `--model` per-scan
- **Scanner download fails**: Install Opengrep or Semgrep manually, ensure it's on your PATH

## License

MIT
