# Shell UX/DX Gaps Assessment

Status: historical Ink-era audit. The current operator-facing shell is Rust
Ratatui under `crates/kuzushi-tui`; do not use the TypeScript/Ink paths below
as places to add new interactive shell behavior.

This historical audit covered the former interactive Kuzushi shell, its
slash-verb dispatch, plain-text fallback, and keybind reducer. Current
interactive shell work belongs in the Rust Ratatui files under
`crates/kuzushi-tui`.

Historical scope:
- `src/ui/components/*View.tsx`
- `src/copilot/shell.ts` (slash-verb dispatcher — switch-statement based on
  this branch; not a registry)
- `src/copilot/shell-commands.ts` — `SHELL_COMMAND_CATALOG`
- `src/ui/plain-renderer.ts`
- `src/ui/components/CopilotShell.tsx` and `src/ui/shell-keybinds.ts`

## Methodology

- Walk the whole verb table in `SHELL_COMMAND_CATALOG`.
- Cross-reference with `handleSlashCommand` switch and the bare-verb
  pre-pass at the top of `handleLocalCommand` (around `shell.ts:4760`).
- Spot drift between CLAUDE.md, `/help`, and the actual handler set.
- Cross-check sibling-view keybind parity (1..5 in threats, 1..4 in
  module-run) and `/back` coverage in `handleBackCommand`.

## Findings

### F1 — High confidence: missing `/h` alias for `/help`

Other one-letter aliases land at parity (`/f` findings, `/t` tune,
`/m` modules, `/b` back), but `/h` is not registered. New users reach
for it constantly because every other modern CLI accepts it.

**Action:** Add `case "h":` to `handleSlashCommand` and bare `h` to the
top pre-pass; advertise the alias on the `/help` row.

### F2 — High confidence: bare `quit` and `q` exit but bare `help`/`h` doesn't always

Bare `help` is wired (`shell.ts:4776`), bare `help advanced` works, but
bare `h` does not. Add a parallel alias.

### F3 — High confidence: `/since` only accepts `reset` to clear scope

The doc string and operator habit suggest `clear`/`off` should also work.
The error message also points at `/since reset` only.

**Action:** Accept `clear` and `off` as synonyms; widen the usage line.

### F4 — High confidence: no `/help` row mentions the planner short keys

`/yes | /no` is documented but the keystroke equivalents (`y`/`n` while
the plan card is up, mirrored in keybinds.ts) only appear in CLAUDE.md.
Mention them inline in the description so operators discover them from
`/help`.

### F5 — Medium confidence: CLAUDE.md drift — `/m` not in the verb table

`SHELL_COMMAND_CATALOG` advertises `/modules (alias: /m)`. CLAUDE.md's
"Module + view navigation" table omits `/m`. Same for `/h` once added.
Fixed implicitly by F1.

### F6 — Medium: `actor-detail` view lacks plain-renderer-side guidance

`printActorDetailView` doesn't print a hint line ("hint: /back returns
to module run"); other views all do. Plain-text users don't know how
to leave the view.

**Action:** Add the hint line consistent with sibling views.

### F7 — Medium: handleBackCommand "Returned to top level." is the only spot
that drops focus silently

`/back` from `module` view (focused) clears focus and lands on
catalog; the message is "Returned to top level." but the operator
loses module context with no second-line context. Existing — leave.

### F8 — Low: `formatHelpForVerb` accepts a leading slash but not bare aliases

`/help f` returns the unknown-verb fallback even though `/f` is a real
alias (because the catalog only stores the long form). Wire the alias
table into the lookup.

**Action:** Extend `formatHelpForVerb` to fall back through a small
alias map (h→help, f→findings, t→tune, m→modules, b→back).

### F9 — Tests

- `tests/copilot/shell.test.ts` already locks in `/f /t /b /m`. Add
  `/h` parity and the `since clear`/`since off` synonyms.
- Add a test that `formatHelpForVerb` resolves a one-letter alias to
  its long-form description (covers F8).
- Add a plain-renderer test that `printActorDetailView` emits a hint
  line for non-empty + empty cases.

## Out of scope for this pass

- The `c` key hint in `printFindingsView` ("c clear filter") is not
  wired in the keybind reducer — wiring it requires a filter state
  redesign in `FindingsView`. Track separately.
- `kbd` plumbing for context-build's `L` toggle (`shell-keybinds.ts`
  handles it but help text doesn't surface). Could be a docs fix later.

## Implementation log

This pass shipped F1, F2, F3, F4, F6, F8, F9. F7 left untouched.
