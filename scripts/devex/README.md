# TUI DevEx audit harness

A tmux driver that makes the 16 DevEx audit journeys in
[docs/devex/tui-devex-audit-journeys.md](../../docs/devex/tui-devex-audit-journeys.md)
plus the canonical five-phase reference (J17) repeatable. It launches the Kuzushi
TUI in a controlled-size tmux session, feeds real keystrokes, and captures
per-step pane snapshots (plain `.txt` + ANSI `.ansi`) for
signifier↔state↔intent review.

## Run it

```bash
cargo build -p kuzushi-cli              # harness drives target/debug/kuzushi

./scripts/devex/run-journey.sh --list   # journey catalog
./scripts/devex/run-journey.sh J1       # one journey
./scripts/devex/run-journey.sh J1 J8    # several
./scripts/devex/run-journey.sh all      # J1..J17
./scripts/devex/run-journey.sh --size 80x24 J14   # environment-matrix cell
./scripts/devex/run-journey.sh --artifact-root /tmp/kuzushi-audit J17
```

Overrides:

- `KUZUSHI_BIN=<path>` (or `--bin <path>`) — binary to drive (default
  `target/debug/kuzushi`).
- `KUZUSHI_DEVEX_TARGET=<dir>` — what the `@TARGET` token points at (default:
  a tiny seeded fixture repo per journey).
- `KUZUSHI_DEVEX_ARTIFACT_ROOT=<dir>` (or `--artifact-root <dir>`) — capture
  destination. The default remains `scripts/devex/artifacts`.

Journeys that need a live model key (`require-any-env: ANTHROPIC_API_KEY …`,
e.g. J4) **skip honestly** when no key is set — they are never faked.

Every tmux session the harness creates is tracked and killed on exit
(trap on `EXIT INT TERM`), and every wait is bounded, so a run can neither
hang nor orphan sessions.

## Artifacts

`scripts/devex/artifacts/<timestamp>/<Jn>/` (gitignored; `artifacts/latest`
symlinks the newest run):

- `NN-<label>.txt` — plain pane capture (content / honesty audit)
- `NN-<label>.ansi` — capture with escape sequences (palette audit, J15)
- `NN-<label>.provenance.json` — capture kind, exact binary identity, Git
  state, target context, profile, requested/actual dimensions, tmux state, and
  journey step
- `report.txt` — the PASS / FAIL / REVIEW log for the journey
- `fixture-target/`, `home/` — the seeded target repo and temp `$HOME`, kept
  for inspection

## Honest verdicts

Three kinds of checkpoint, deliberately distinct:

- **PASS/FAIL** — `expect:` / `expect-not:` / `wait-for:` substring checks a
  machine can honestly decide against the captured pane.
- **REVIEW** — `ask:` lines. Judgment calls (the signifier↔state↔intent
  invariant) are emitted as open questions next to their snapshot. The
  harness never converts these into a verdict.
- **SKIP** — missing required env (e.g. no API key). Reported, not hidden.

Color-profile checks read the ANSI capture directly. J15 requires indexed
SGR (`38;5` / `48;5`) for its xterm-256color launch and RGB SGR (`38;2` /
`48;2`) for truecolor launches; inherited `NO_COLOR` is explicitly removed
before each matrix cell.

Exit code is non-zero iff any machine check failed.

## Adding or editing a journey

One file per journey under `journeys/`, named `J<n>-<slug>.journey`. Plain
line-oriented directives — data, not code. Example:

```
# comment
name: What this journey audits
size: 110x32                       # optional; --size overrides
cwd: @TMP_TARGET                   # working dir for the session
env: HOME=@TMP_HOME K=V            # env for the NEXT launch only
env-unset: ANTHROPIC_API_KEY       # unset for the NEXT launch only
require-any-env: ANTHROPIC_API_KEY OPENAI_API_KEY   # else SKIP (require-env = all)
shell: printf 'x' > @ART/seed.txt  # host-side setup command
launch: --target @TARGET           # kuzushi <args>; empty = bare launch
launch-raw: @KUZUSHI demo | cat    # full shell line (pipes, --plain)
wait: 2                            # fixed sleep (seconds)
wait-for: 25 CHOOSE A TARGET       # poll pane for substring; [timeout] first
wait-snap: 5 RUN FOCUS | run-focus # match and capture one transient frame
wait-live-snap: 5 VIEW MAP | map   # match only while alternate_on=1
keys: Enter                        # raw tmux send-keys (Escape, C-c, C-Up, d…)
type: sc                           # literal text, no Enter
submit: findings                   # literal text + Enter
snap: target-gate                  # capture pane + provenance (legacy fallback)
live-snap: map                     # fail unless the live alternate screen owns the pane
saved-snap: post-exit              # explicitly capture the saved alternate screen
expect: Nothing defaults to cwd silently   # substring in last snap → PASS/FAIL
expect-not: ✓ done
ask: Is the next action obvious?   # human-judgment → REVIEW item
```

Tokens expanded in values: `@KUZUSHI` (binary), `@REPO` (repo root),
`@ART` (journey artifact dir), `@TMP_HOME` (fresh temp `$HOME`),
`@TMP_TARGET` (seeded fixture git repo with a command-injection `app.py` and a
documentation-example AWS key), `@TARGET` (`KUZUSHI_DEVEX_TARGET` or the
fixture).

Notes:

- A journey session is a plain `/bin/sh`; `launch:` types the command line
  like a real operator. After the TUI exits (`submit: quit`) the shell
  remains, so one journey can relaunch under different env (see J15).
- `wait-for:` needles starting with a digit need an explicit leading timeout
  (the first digit-run is parsed as seconds).
- `wait-snap:` uses the same timeout grammar, followed by ` | <label>`, and
  saves the exact pane frame that satisfied the substring check.
- `live-snap:` and `wait-live-snap:` never substitute saved or ordinary shell
  output; they fail unless `tmux` reports `alternate_on=1`. `saved-snap:` is
  the explicit post-exit path. Legacy `snap:` / `wait-snap:` retain automatic
  fallback for mixed fullscreen/headless journeys, and provenance labels that
  fallback rather than presenting it as live evidence.
- Every successful capture writes adjacent provenance. A custom artifact root
  owns its own timestamp directory and `latest` link, leaving
  `scripts/devex/artifacts` untouched.
- Keep `expect:` for stable, load-bearing strings; use `ask:` for anything
  that needs eyes. Don't fake judgment as assertion.
- macOS keychain / OAuth-cached credentials cannot be masked by `env-unset:`;
  keyless journeys note this caveat inline.

## Relationship to the docs

- Journey intent, personas, and known risks: `docs/devex/tui-devex-audit-journeys.md`
  (read-only source of truth — update it first, then mirror here).
- Judgment rubric for REVIEW items: `docs/devex/tui-devex-audit-kickoff-prompt.md`
  (State / Intent / Honesty / Craft lenses).
- Claude Code wrapper: `.claude/skills/tui-devex-audit/SKILL.md` runs this
  harness and then judges the REVIEW items; the harness stays fully usable
  standalone.
