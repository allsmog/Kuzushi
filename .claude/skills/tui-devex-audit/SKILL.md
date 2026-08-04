---
name: tui-devex-audit
description: Run the tmux-driven TUI DevEx audit journeys (J1-J17) and judge the captured screens against the signifier-state-intent invariant. Use when asked to audit the Kuzushi TUI's developer experience, re-run a DevEx journey, or verify a TUI fix didn't regress an audited journey. Args: journey ids (e.g. "J1 J8"), "all", or empty for J1 only.
---

# TUI DevEx audit

Drive the Kuzushi TUI through scripted keystroke journeys and audit the
captured screens. The driver is the standalone harness at
`scripts/devex/run-journey.sh` (see `scripts/devex/README.md`); this skill
adds the judgment pass the harness deliberately refuses to fake.

## 1. Run the harness

```bash
cargo build -p kuzushi-cli   # only if target/debug/kuzushi is stale/missing
KUZUSHI_NATIVE_BIN="$PWD/target/debug/kuzushi" \
  KUZUSHI_BIN="$(command -v kz)" \
  ./scripts/devex/run-journey.sh <args>
```

- Args given to the skill are journey ids (`J1 J8`, `all`, `--size 60x20 J14`).
- No args → run only `J1`, the highest-priority first-contact journey.
- Run journeys sequentially by default. Multiple journey IDs or `all` must come
  from the operator explicitly; do not delegate one journey per subagent unless
  the operator approves that parallelism.
- The harness bounds every wait and kills its tmux sessions on exit; never
  bypass it with ad-hoc long-lived tmux sessions.

## 2. Judge the REVIEW items

The run dir is `scripts/devex/artifacts/latest/<Jn>/`. For each `[REVIEW]`
line in `report.txt`, read the referenced snapshot (`.txt`; use `.ansi` for
palette questions) and judge it with the lenses from
`docs/devex/tui-devex-audit-kickoff-prompt.md`:

1. **State** — what does the operator actually know right now?
2. **Intent** — what does the screen suggest they do next?
3. **Honesty** — is any glyph, status, or keybind lying about reality?
4. **Craft** — per the kickoff prompt's rubric.

A journey fails the audit if the operator would get stuck, misled, or
dead-ended — even when every machine check passed. `[FAIL]` lines from the
harness are hard findings; do not explain them away.

The harness exits `4` while any `[REVIEW]` item remains open. Treat that as
`REVIEW REQUIRED`, not a machine failure and never a pass; answer every item
before issuing the final journey verdict.

## 3. Report

Summarize per journey: machine result (pass/fail/skip), each REVIEW verdict
with the snapshot path as evidence, and any new finding worth adding to the
journey catalog. Journey intent and known risks live in
`docs/devex/tui-devex-audit-journeys.md` — cite the matching known risk when
a July finding reproduces or is fixed.

To make a new manual audit repeatable, encode it as a
`scripts/devex/journeys/J<n>-<slug>.journey` file (directive reference in
`scripts/devex/README.md`) — keep judgment as `ask:` lines, never fake it
into `expect:`.
